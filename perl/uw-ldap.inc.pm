#!/usr/bin/perl
#
# UserWatch
# LDAP stuff
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

#
# require: perl-LDAP
#
use Net::LDAP;

our (%uw_config, $in_parent);

my $ldap_maxtries = 2;

my  (%uid_cache);
my  ($ldap_fork, $ldap_remote, $ldap_pid, $ldap_pipe_req, $ldap_pipe_reply);
my  ($ldap_conn);

#
# initialize ldap subsystem
#
sub ldap_init (;$) {
    my ($just_test) = @_;

    ldap_close();
    $ldap_remote = 0;
    # flush ldap cache at every re-connection
    %uid_cache = ();

    #
    # Due to a bug in Net::SSLeay SSL in OpenLDAP
    # badly affects main SSL exchange.
    # Workaround: fork a subprocess for LDAP.
    #
    $ldap_fork = ($uw_config{ldap_uri} =~ /^ldaps:/);
    $ldap_fork = 1 if $uw_config{ldap_force_fork};
    $ldap_fork = 0 if $just_test;

    if ($ldap_fork) {
        $SIG{PIPE} = "IGNORE";
        $| = 1;
        debug("forking off ldap child");
        pipe(my ($pipe_req_r, $pipe_req_w)) or fail("pipe: $!");
        $pipe_req_w->autoflush(1);
        debug("pipe_req=($pipe_req_r,$pipe_req_w)");
        pipe(my ($pipe_reply_r, $pipe_reply_w)) or fail("pipe: $!");
        $pipe_reply_w->autoflush(1);
        debug("pipe_reply=($pipe_reply_r,$pipe_reply_w)");
        defined($ldap_pid = fork()) or fail("can't fork: $!");
        if ($ldap_pid) {
            # in the parent
            $ldap_remote = 1;
            $ldap_pipe_req = $pipe_req_w;
            close $pipe_req_r;
            $ldap_pipe_reply = $pipe_reply_r;
            close $pipe_reply_w;
            # FIXME: check for errors
            debug("ldap parent pipes:($ldap_pipe_req,$ldap_pipe_reply)");
            debug("wait for status from ldap child");
            print $ldap_pipe_req "PING\n";
            chomp(my $reply = <$ldap_pipe_reply>);
            debug("status from ldap child: $reply");
            return;
        } else {
            # in the child
            $in_parent = 1; # avoid additional forking
            $ldap_remote = 0;
            $ldap_pipe_req = $pipe_req_r;
            close $pipe_req_w;
            $ldap_pipe_reply = $pipe_reply_w;
            close $pipe_reply_r;
            detach_stdio();
            cleanup(1); # close mysql connection et al
            debug("ldap child pipes:($ldap_pipe_req,$ldap_pipe_reply)");
            debug("ldap child started");
            print $ldap_pipe_reply "OK\n";
        }
    }

    my $msg = _ldap_init($just_test);

    if ($ldap_fork && !$ldap_remote) {
        _ldap_child_loop();
        exit(0);
    }

    return $msg;
}

#
# stop ldap subsystem
#
sub ldap_close () {
    if ($ldap_fork && $ldap_remote) {
        print $ldap_pipe_req "QUIT\n";
        waitpid $ldap_pid, 0;
        debug("ldap child terminated");
        close $ldap_pipe_req;
        close $ldap_pipe_reply;
        $ldap_fork = $ldap_remote = $ldap_pid = 0;
        undef $ldap_pipe_req;
        undef $ldap_pipe_reply;
        return;
    }
    # in ldap child or in a single process
    if (defined $ldap_conn) {
        eval { $ldap_conn->unbind() };
        undef $ldap_conn;
    }
}

#
# verify ldap credentials
#
sub ldap_auth ($$) {
    my ($user, $pass) = @_;
    if ($ldap_remote) {
        print $ldap_pipe_req "AUTH $user $pass\n";
        chomp(my $reply = <$ldap_pipe_reply>);
        return $reply;
    } else {
        return _ldap_connect(undef, $user, $pass, 1);
    }
}

#
# return uidNumber for a user
#
sub ldap_get_uid ($) {
    my ($user) = @_;
    my ($uid, $msg);

    # try to fetch uid from cache
    my $stamp = time();
    if (exists($uid_cache{$user})) {
        if ($stamp - $uid_cache{$user}{stamp} < $uw_config{cache_retention}) {
            $uid = $uid_cache{$user}{uid};
            debug("ldap get uid user:$user uid:$uid from cache");
            return $uid;
        }
        delete $uid_cache{$user};
    }

    ($uid, $msg) = _ldap_get_uid($user);
    if ($msg) {
        debug("ldap get uid for user=$user: $msg");
        return;
    }

    # update cache with defined or undefined uid
    $uid_cache{$user}{uid} = $uid;
    $uid_cache{$user}{stamp} = $stamp;
    debug("ldap_get_uid user:$user uid:$uid message:$msg");
    return $uid;
}

sub _ldap_get_uid ($) {
    my ($user) = @_;
    my ($uid, $msg);
    my $uid_attr = $uw_config{ldap_attr_user};
    if ($ldap_remote) {
        print $ldap_pipe_req "UID $user\n";
        chomp(my $reply = <$ldap_pipe_reply>);
        ($uid, $msg) = ($1, $2) if $reply =~ /^(\S+) (.*)$/;
        undef $uid if $uid eq "-";
    } else {
        my (@res) = _ldap_search("($uid_attr=$user)", [ $uid_attr ]);
        $msg = $res[0];
        $uid = $res[1]->{$uid_attr};
    }
    return ($uid, $msg);
}

#
# forked ldap process
#
sub _ldap_child_loop () {
    # child lives in the loop
    debug("ldap child waiting for commands");
    while (<$ldap_pipe_req>) {
        chomp;
        my @cmd = split / /;
        debug("ldap child got command: %s", join(' ', @cmd));
        if ($cmd[0] eq "PING") {
            print $ldap_pipe_reply "OK\n";
            next;
        }
        if ($cmd[0] eq "QUIT") {
            debug("quitting ldap child");
            ldap_close();
            exit(0);
        }
        if ($cmd[0] eq "UID") {
            my ($uid, $msg) = _ldap_get_uid($cmd[1]);
            $uid = "-" if !defined($uid) || $uid eq "";
            print $ldap_pipe_reply "$uid $msg\n";
            next;
        }
        if ($cmd[0] eq "AUTH") {
            print $ldap_pipe_reply ldap_auth($cmd[1], $cmd[2]) . "\n";
            next;
        }
    }
}

#
# connection to ldap for browsing
#
sub _ldap_init (;$) {
    my ($just_test) = @_;
    my ($msg, $conn) = _ldap_connect($uw_config{ldap_bind_dn},
                                    undef, $uw_config{ldap_bind_pass},
                                    $just_test);
    if ($just_test) {
        info("warning: ldap init failed: $msg") if $msg;
        return $msg;
    }

    $ldap_conn = $conn unless $msg;
    return $msg;
}

#
# permanent/temporary connection to ldap for different purposes
#
sub _ldap_connect ($$$$) {
    my ($bind_dn, $user, $pass, $just_check) = @_;

    my $conn = Net::LDAP->new($uw_config{ldap_uri},
                                timeout => $uw_config{ldap_timeout},
                                version => 3)
        or return "ldap server down";

    if ($uw_config{ldap_start_tls}) {
        $conn->start_tls()
            or return "ldap tls failed";
    }

    if (!$bind_dn) {
        $bind_dn = sprintf('%s=%s,%s', $uw_config{ldap_attr_user},
                            $user, $uw_config{ldap_user_base});
    }
    my $res = $conn->bind($bind_dn, password => $pass);

    $conn->unbind() if $just_check;

    debug("ldap auth uri:%s tls:%s bind:%s pass:%s returns: %s",
            $uw_config{ldap_uri}, $uw_config{ldap_start_tls},
            $bind_dn, $pass, $res->error());
    return "invalid password" if $res->code();

    # success
    return (0, $conn);
}

#
# generic ldap search
#
sub _ldap_search ($$) {
    my ($filter, $attrs) = @_;
    my $res;
    # search in ldap.
    # ldap server might have disconnected due to timeout.
    # if so, we try to re-connect and repeat the search.
    for (my $try = 1; $try <= $ldap_maxtries; $try++) {
        if ($ldap_conn) {
            $res = $ldap_conn->search(
                    base => $uw_config{ldap_user_base},
                    filter => $filter,
                    scope => 'one', defer => 'never',
                    attrs => $attrs
                    );
        }
        if (!$ldap_conn || $res->code() == 1) {
            # unexpected eof. try to reconnect
            debug("restoring ldap connection ($try)");
            undef $ldap_conn;
            _ldap_init();
            # a little delay
            select(undef, undef, undef, ($try - 1) * 0.100);
        } else {
            last;
        }
    }

    return ($res->error()) if $res->code();

    my @res = ("");
    for my $entry ($res->entries()) {
        my $item = {};
        for my $attr (@$attrs) {
            $item->{$attr} = $entry->get_value($attr);
        }
        push @res, $item;
    }

    return @res;
}

##############################################
1;

