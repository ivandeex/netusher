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

our (%uw_config, $config_file);

my $ldap_maxtries = 2;
my $ldap_try_delay = 0.100;

our ($ldap_parent, $ldap_child);
my  ($ldap_conn, $ldap_pid, $ldap_sock, $ldap_restart_count);

#
# initialize ldap subsystem
#
sub ldap_init ($) {
    my ($first_init) = @_;

    if (!$first_init && $ldap_conn) {
        debug("ldap already initialized");
        return "";
    }

    ldap_close();

    for (qw[ldap_uri ldap_bind_dn ldap_bind_pass
            ldap_user_base ldap_group_base]) {
        next if defined $uw_config{$_};
        fail("$config_file: missing ldap parameter \"$_\"");
    }

    #
    # Due to a bug in Net::SSLeay SSL in OpenLDAP
    # badly affects main SSL exchange.
    # Workaround: fork a subprocess for LDAP.
    #
    my $need_fork;
    if ($uw_config{ldap_force_fork} eq "never") {
        $need_fork = 0;
    } elsif ($uw_config{ldap_force_fork} eq "always") {
        $need_fork = 1;
    } elsif ($uw_config{ldap_force_fork} eq "auto") {
        # fork only if connection is ssl
        my $conn_is_ssl = ($uw_config{ldap_uri} =~ m/^ldaps:/)
                        || $uw_config{ldap_start_tls};
        $need_fork = $conn_is_ssl;
    } else {
        fail("$config_file: ldap_force_fork should be one of never,always,auto");
    }

    if ($first_init && $need_fork) {
        info("connecting to ldap later as connecting now would screw up ssl");
        return "ssl";
    }

    if ($need_fork) {
        _ldap_child_start();
        # will not return in child
        return "";
    }

    return _ldap_init($first_init);
}

#
# stop ldap subsystem
#
sub ldap_close () {
    cache_flush();

    if ($ldap_parent) {
        _ldap_child_stop();
    }

    # in ldap child or in a single process
    if (defined $ldap_conn) {
        eval { $ldap_conn->unbind() };
        eval { $ldap_conn->disconnect() };
        undef $ldap_conn;
    }
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
    my ($err, $conn) = _ldap_connect(undef, $user, $pass, 1);
    return $err;
}

#
# return uidNumber for a user
#
sub ldap_get_user_uid_grp ($) {
    my ($user) = @_;
    my ($err, $uid, $grp);
    if ($ldap_parent) {
        my $reply = _ldap_wait_reply("UID_GRP $user");
        ($err, $uid, $grp) = split /\|/, $reply;
    } else {
        my ($attr_user, $attr_uid, $attr_gid, $attr_group)
             = @uw_config{qw(ldap_attr_user ldap_attr_uid
                            ldap_attr_gid ldap_attr_group)};
        my (@res) = _ldap_search("($attr_user=$user)",
                                [ $attr_uid, $attr_gid ],
                                $uw_config{ldap_user_base});
        $err = $res[0];
        $uid = $res[1]->{$attr_uid};
        my $gid = $res[1]->{$attr_gid};
        if ($gid) {
            (@res) = _ldap_search("($attr_gid=$gid)", [ $attr_group ],
                                $uw_config{ldap_group_base});
            $grp = $res[1]->{$attr_group};
        }
        $grp = $gid unless $grp;
    }
    undef $uid if $uid eq "";
    undef $grp if $grp eq "";
    return ($err, $uid, $grp);
}

#
# return list of groups for a user
#
sub ldap_get_user_groups ($) {
    my ($user) = @_;
    my ($err, @groups);

    if ($ldap_parent) {
        my $reply = _ldap_wait_reply("GROUPS $user");
        ($err, @groups) = split /\|/, $reply;
    } else {
        my ($attr_group, $attr_member)
                = @uw_config{qw(ldap_attr_group ldap_attr_member)};
        my (@res) = _ldap_search("($attr_member=$user)", [ $attr_group ],
                                $uw_config{ldap_group_base});
        $err = shift @res;
        push @groups, $_->{$attr_group} for (@res);
    }
    return ($err, \@groups);
}

#
# main child loop
#
sub _ldap_child_loop () {
    debug("ldap child waiting for commands");
    while (<$ldap_sock>) {
        chomp;
        my @cmd = split / /;
        my $op = $cmd[0];
        my ($quit, $reply);

        if ($op eq "QUIT") {
            $reply = "BYE";
            $quit = 1;
        }
        elsif ($op eq "HELLO") {
            $reply = "OK";
        }
        elsif ($op eq "UID_GRP") {
            my ($err, $uid, $grp) = ldap_get_user_uid_grp($cmd[1]);
            $err =~ s/\|/,/g;
            $reply = "$err|$uid|$grp";
        } elsif ($op eq "GROUPS") {
            my ($err, $groups) = ldap_get_user_groups($cmd[1]);
            $err =~ s/\|/,/g;
            $groups = [] unless $groups;
            $reply = join("|", $err, @$groups);
        }
        elsif ($op eq "AUTH") {
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
        
        my $reply = _ldap_wait_reply("HELLO", 1);
        next unless $reply;
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

    _ldap_init(0);
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
            kill(9, $ldap_pid);
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
        my $begtime = monotonic_time();
        my $remaining = $timeout;
        while ($remaining > 0) {
            vec($vec, fileno($ldap_sock), 1) = 1;
            ($nfound) = select($vec, undef, undef, $remaining);
            last if $nfound > 0;
            $remaining = $timeout - (monotonic_time() - $begtime);
        }
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
sub _ldap_init ($) {
    my ($first_init) = @_;
    cache_flush();

    my ($err, $conn) = _ldap_connect($uw_config{ldap_bind_dn},
                                    undef, $uw_config{ldap_bind_pass},
                                    0);
    if ($first_init && $err) {
        info("warning: ldap init failed: $err");
    }

    unless ($err) {
        $ldap_conn = $conn;
        $err = 0;
    }
    return $err;
}

#
# permanent/temporary connection to ldap for different purposes
#
sub _ldap_connect ($$$$) {
    my ($bind_dn, $user, $pass, $just_check) = @_;

    #debug("connecting to ldap uri:%s", $uw_config{ldap_uri});
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

    my $error = 0;
    $error = "server down" unless $res;
    $error = $res->error() if $res && $res->code();
    debug("ldap uri:%s tls:%s bind:%s err:%s",
            $uw_config{ldap_uri}, $uw_config{ldap_start_tls},
            $bind_dn, $res->error());
    $error = "invalid password" if $error && $user;
    undef $conn if $error;

    # success
    return ($error, $conn);
}

#
# generic ldap search
#
sub _ldap_search ($$$) {
    my ($filter, $attrs, $base) = @_;
    my $res;
    # search in ldap.
    # ldap server might have disconnected due to timeout.
    # if so, we try to re-connect and repeat the search.
    for (my $try = 1; $try <= $ldap_maxtries; $try++) {
        if ($ldap_conn) {
            $res = $ldap_conn->search(
                    base => $base,
                    filter => $filter,
                    scope => 'one', defer => 'never',
                    attrs => $attrs
                    );
            #debug("ldap_search filter:$filter base:$base res=".$res->code());
        }
        if (!$ldap_conn || $res->code() == 1) {
            # unexpected eof. try to reconnect
            debug("restoring ldap connection ($try)");
            undef $ldap_conn;
            _ldap_init(0);
            # a little delay
            select(undef, undef, undef, $ldap_try_delay);
        } else {
            last;
        }
    }

    return ("server down") unless $res;
    return ($res->error()) if $res->code();

    my @res = ("");
    for my $entry ($res->entries()) {
        my $item = {};
        for my $attr (@$attrs) {
            $item->{$attr} = $entry->get_value($attr);
        }
        #debug("ldap_search item: %s", join(",", map("$_:\"$item->{$_}\"", @$attrs)));
        push @res, $item;
    }

    return @res;
}

##############################################
1;

