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
use Socket;
use IO::Handle;

our (%uw_config);

my $ldap_maxtries = 2;
my $ldap_try_delay = 0.100;

our ($ldap_parent, $ldap_child);
my  ($ldap_pid, $ldap_sock, $ldap_restart_count);
my  ($ldap_conn, %uid_cache);

#
# initialize ldap subsystem
#
sub ldap_init (;$) {
    my ($just_test) = @_;
    ldap_close();

    #
    # Due to a bug in Net::SSLeay SSL in OpenLDAP
    # badly affects main SSL exchange.
    # Workaround: fork a subprocess for LDAP.
    #
    my $need_fork = ($uw_config{ldap_uri} =~ m/^ldaps:/);
    $need_fork = 1 if $uw_config{ldap_force_fork};
    $need_fork = 0 if $just_test;

    if ($need_fork) {
        _ldap_child_start();
        # will not return in child
    }

    my $msg = _ldap_init($just_test);
    return $msg;
}

#
# stop ldap subsystem
#
sub ldap_close () {
    _ldap_cache_flush();

    if ($ldap_parent) {
        _ldap_child_stop();
    }

    # in ldap child or in a single process
    if (defined $ldap_conn) {
        eval { $ldap_conn->unbind() };
        undef $ldap_conn;
    }
}

sub _ldap_cache_flush () {
    %uid_cache = ();
}

#
# verify ldap credentials
#
sub ldap_auth ($$) {
    my ($user, $pass) = @_;
    if ($ldap_parent) {
        return _ldap_wait_reply("AUTH $user $pass");
    }
    # child or main process
    my ($msg, $conn) = _ldap_connect(undef, $user, $pass, 1);
    return $msg;
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
    if ($ldap_parent) {
        my $reply = _ldap_wait_reply("UID $user");
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
# main child loop
#
sub _ldap_child_loop () {
    # child lives in the loop
    debug("ldap child waiting for commands");
    while (<$ldap_sock>) {
        chomp;
        my @cmd = split / /;
        debug("ldap child got command: %s", join(' ', @cmd));
        my ($quit, $reply);
        if ($cmd[0] eq "QUIT") {
            $reply = "BYE";
            $quit = 1;
        }
        elsif ($cmd[0] eq "HELLO") {
            #if ($ldap_restart_count < 3) { debug("child sleep"); sleep(1) for (0 .. 9); }
            $reply = "OK";
        }
        elsif ($cmd[0] eq "UID") {
            my ($uid, $msg) = _ldap_get_uid($cmd[1]);
            $uid = "-" if !defined($uid) || $uid eq "";
            $reply = "$uid $msg";
        }
        elsif ($cmd[0] eq "AUTH") {
            $reply = ldap_auth($cmd[1], $cmd[2]);
        }
        else {
            $reply = "ERROR";
        }
        print $ldap_sock "$reply\n";
        last if $quit;
    }
}

#
# child process management
#

sub _ldap_child_start () {
    $SIG{PIPE} = "IGNORE";
    my ($sock_parent, $sock_child);

    while (1) {
        _ldap_child_stop(1);
        $ldap_restart_count++;
        debug("forking off ldap child $ldap_restart_count");

        socketpair($sock_parent, $sock_child, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
            or fail("socketpair: $!");

        defined($ldap_pid = fork()) or fail("can't fork: $!");

        last unless $ldap_pid;

        # in the parent
        $ldap_parent = 1;

        close $sock_child;
        $ldap_sock = $sock_parent;
        $ldap_sock->autoflush(1);
        
        debug("wait for status from ldap child");
        my $reply = _ldap_wait_reply("HELLO", 1);
        next unless $reply;
        debug("status from ldap child: $reply");
        return $reply;
    }

    # in the child
    debug("ldap child starting");
    $ldap_child = 1;

    close $sock_parent;
    $ldap_sock = $sock_child;
    $ldap_sock->autoflush(1);

    # close ssl connections
    cleanup();
    detach_stdio() if $uw_config{daemonize};

    _ldap_init();
    _ldap_child_loop();

    debug("quitting ldap child");
    ldap_close();
    exit(0);
}

sub _ldap_child_stop ($) {
    my ($force) = @_;

    if (defined $ldap_pid) {
        if ($force) {
            kill(9, $ldap_pid);
        } elsif (!_ldap_wait_reply("QUIT", 1)) {
            info("ldap child hung during exit");
            kill(9, $ldap_child);
        }
        waitpid($ldap_pid, WNOHANG);
        undef $ldap_pid;
        debug("ldap child terminated");
    }

    if (defined $ldap_sock) {
        shutdown $ldap_sock, 2;
        close $ldap_sock;
        undef $ldap_sock;
    }

    $ldap_parent = $ldap_child = 0;
}

#
# exchange with child process
#

sub _ldap_send_req ($) {
    my ($req) = @_;
    debug("to ldap child: \"$req\"");
    print $ldap_sock "$req\n";
}

sub _ldap_wait_reply ($$) {
    my ($req, $norestart) = @_;
    my $timeout = $uw_config{ldap_timeout}
                + ($ldap_maxtries + 1) * $ldap_try_delay;

    for (my $try = 1; $try <= $ldap_maxtries; $try++) {
        _ldap_send_req($req) if defined $req;
        my ($vec, $nfound);
        my $begtime = time();
        my $remaining = $timeout;
        while ($remaining > 0) {
            vec($vec, fileno($ldap_sock), 1) = 1;
            debug("DEBUG: parent wait for %f seconds", $remaining);
            ($nfound) = select($vec, undef, undef, $remaining);
            last if $nfound > 0;
            $remaining = $timeout - (time() - $begtime);
        }
        debug("DEBUG: parent got $nfound after wait: $!");
        if ($nfound > 0) {
            # read the reply
            chomp(my $reply = <$ldap_sock>);
            debug("from ldap child: \"%s\"", $reply);
            return $reply if defined $reply;
        }
        last if $norestart;
        info("ldap child hung");
        _ldap_child_start(); # restart and try again
    }

    debug("nothing from ldap child");
    return;
}

#
# connection to ldap for browsing
#
sub _ldap_init (;$) {
    my ($just_test) = @_;

    _ldap_cache_flush();

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
            select(undef, undef, undef, $ldap_try_delay);
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

