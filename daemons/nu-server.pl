#!/usr/bin/perl
#
# NetUsher
# Server daemon
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/nu-common.inc.pm";
require "$Bin/nu-ssl.inc.pm";
require "$Bin/nu-ldap.inc.pm";
require "$Bin/nu-cache.inc.pm";
require "$Bin/nu-vpn.inc.pm";

#
# require: perl-EV
#
use EV;

our ($config_file, $progname, %nu_config);
our ($ev_loop, %ev_watch, $ev_reload);
our ($ldap_child);
our ($vpn_regex);

our %nss = (
            name => "nss",
            get_user_uid_grp    => \&nss_get_user_uid_grp,
            get_user_groups     => \&nss_get_user_groups,
            user_auth           => sub { "not implemented" }
        );

#
# Currently only one "main" user per host is allowed.
# We prefer GDM/KDM logins to SSH logins.
# If several users are active, prefer user which has logged in earlier.
#

my %login_methods;

my %method_weight = (
    'top' => 9,
    'xdm' => 5,
    'net' => 4,
    'con' => 3,
    'pty' => 2,
    );

##############################################
# requests
#

#
# handle client request.
#
sub handle_request (@) {
    my (@arg) = @_;
    my $cmd = $arg[0];
    my ($err, $ip, $opts, $utmp, $user, $groups);
    
    rescan_etc();

    if ($cmd eq "update") {
        return "3 arguments required" if $#arg != 3;

        $opts = $arg[1];

        ($err, $ip) = select_ip($arg[2]);
        return $err if $err;

        ($err, $utmp) = unpack_utmp($arg[3]);
        return $err if $err;

        $err = update_user_mapping($cmd, $ip, $utmp, undef);
        return $err if $err;

        $groups = pack_groups($utmp) if $opts =~ /g/;
    }
    elsif ($cmd eq "auth") {
        return "2 arguments required" if $#arg != 2;

        $err = verify_user($arg[1]);
        return $err if $err;

        return "success" if $nu_config{authorize_permit};

        $err = &{$nss{user_auth}}($arg[1], $arg[2]);
    }
    elsif ($cmd eq "login") {
        ($err, $ip, $opts, $user, $utmp) = verify_login_arguments(@arg);
        return $err if $err;

        $err = update_user_mapping($cmd, $ip, $utmp, $user);
        return $err if $err;

        if ($opts =~ /g/) {
            push @$utmp, $user;
            $groups = pack_groups($utmp);
        }
    }
    elsif ($cmd eq "logout") {
        ($err, $ip, $opts, $user, $utmp) = verify_login_arguments(@arg);
        return $err if $err;
        $err = update_user_mapping($cmd, $ip, $utmp, $user);
    }
    else {
        return "unknown command";
    }
    return $err if $err;
    return defined($groups) ? "success|$groups" : "success";
}

sub pack_groups ($) {
    my ($users) = @_;
    my $ug = inquire_groups($users);
    return join("~", map { join("!", $_, @{ $ug->{$_} }) } sort keys %$ug);
}

sub unpack_utmp ($) {
    my ($arg) = @_;
    my ($err, @utmp);
    $arg = "" if $arg eq "-";
    for my $part (split /~/, $arg) {
        my ($user, $sid, $btime, @rest) = split /!/, $part;
        return "invalid utmp record" if @rest;
        return "invalid utmp btime" if $btime !~ /^\d+$/;
        push @utmp, { user => $user, sid => $sid, btime => $btime };
    }
    return (0, \@utmp);
}

sub verify_login_arguments (@) {
    my (@arg) = @_;
    my ($err, $ip, $user, $opts, $utmp);
    return "6 arguments required" if $#arg != 6;

    $err = verify_user($arg[1]);
    return $err if $err;

    return "invalid sid" if !$arg[2];
    return "invalid time" if $arg[3] !~ /^(\-|\d+)$/;
    my $btime;
    $btime = int($arg[3]) if $arg[3] ne "-";

    $opts = $arg[4];

    ($err, $ip) = select_ip($arg[5]);
    return $err if $err;

    ($err, $utmp) = unpack_utmp($arg[6]);
    return $err if $err;
    
    $user = { user => $arg[1], sid => $arg[2], btime => $btime };
    return (0, $ip, $opts, $user, $utmp);
}

sub verify_user ($) {
    my ($user) = @_;
    return "user not found" unless defined get_user_uid_grp($user, undef);
    return "user is local" if is_local_user($user);
    return 0;
}

sub select_ip ($) {
    my ($ips) = @_;
    my $vpn_ip;
    for my $ip (split /,/, $ips) {
        return "bad ip" if $ip !~ m/^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        next if $ip !~ $vpn_regex;
        if (defined $vpn_ip) {
            debug("duplicate vpn ip");
            next;
        }
        $vpn_ip = $ip;
    }
    return "foreign ip" unless $vpn_ip;
    #debug("client vpn ip: $vpn_ip");
    return (0, $vpn_ip);
}

##############################################
# user mapping
#

#
# update user mapping in database
#
sub update_user_mapping ($$$$) {
    my ($cmd, $vpn_ip, $utmp, $user) = @_;
    my ($best, $more_user, $less_user);
    $more_user = $user if $cmd eq "login";
    $less_user = $user if $cmd eq "logout";

    #
    # currently only one "main" user per host is allowed.
    # we preferr GDM/KDM users, and if several users are active,
    # we prefer the one that has logged in earlier
    #

    for my $u ($more_user, @$utmp) {
        next unless defined $u;

        my $uid = get_user_uid_grp($u->{user}, undef);
        if (!$uid && $nu_config{skip_local}) {
            debug("%s: user not found, skip", $u->{user});
            next;
        }

        if (is_local_user($u->{user})) {
            debug("%s: skip local user", $u->{user});
            next;
        }

        if (defined($less_user)
                && $u->{user} eq $less_user->{user}
                && $u->{sid} eq $less_user->{sid}) {
            debug("skip logged out user");
            next;
        }

        $u->{method} = detect_login_method($u->{sid});
        $u->{weight} = login_weight($u->{method});

        debug("next: user:%s method:%s weight:%s btime:%s sid:\"%s\"",
            $u->{user}, $u->{method}, $u->{weight}, $u->{btime}, $u->{sid});

        if (!defined($best)) {
            $best = $u;
        }
        elsif ($best->{weight} eq $u->{weight}) {
            $best = $u if $best->{btime} > $u->{btime};
        }
        else {
            $best = $u if $best->{weight} < $u->{weight};
        }
    }

    if ($best && !$login_methods{$best->{method}} && $cmd ne "logout") {
        # if method is not allowed, remove the user from database
        debug("(disabled) user:%s method:%s sid:\"%s\" btime:%s cmd:%s",
            $best->{user}, $best->{method}, $best->{sid}, $best->{btime}, $cmd);
        $cmd = "logout";
        $user = $best;
        undef $best;
    }

    if ($cmd eq "logout" && $user) {
        debug("logout: user:%s method:%s sid:\"%s\" btime:%s vpn:$vpn_ip",
            $user->{user}, $user->{method}, $user->{sid}, $user->{btime});

        # update existing record
        db_execute(
            "UPDATE nu_users SET end_time = NOW(), running = 0
            WHERE username = ? AND vpn_ip = ?
            AND ('' = ? OR sid = ?)
            AND ('' = ? OR method = ?)
            AND ('' = ? OR beg_time = FROM_UNIXTIME(?))",
            $user->{user}, $vpn_ip,
            xtrim($user->{sid}), $user->{sid},
            xtrim($user->{method}), $user->{method},
            xtrim($user->{btime}), $user->{btime});

        db_commit();
    }

    if ($best) {
        debug("login: user:%s method:%s sid:\"%s\" btime:%s cmd:%s vpn:$vpn_ip",
            $best->{user}, $best->{method}, $best->{sid}, $best->{btime}, $cmd);

        # if there were previous active users, end their sessions
        db_execute(
            "UPDATE nu_users
            SET end_time = FROM_UNIXTIME(?), running = 0
            WHERE vpn_ip = ? AND running = 1 AND beg_time < FROM_UNIXTIME(?)",
            $best->{btime} - 1, $vpn_ip, $best->{btime}
            );

        # insert or update existing record
        if ($nu_config{db_type} eq "mysql") {
            db_execute(
                "INSERT INTO nu_users
                (vpn_ip,username,beg_time,end_time,method,sid,running)
                VALUES (?, ?, FROM_UNIXTIME(?), NOW(), ?, ?, 1)
                ON DUPLICATE KEY UPDATE
                end_time = NOW(), running = 1",
                $vpn_ip, $best->{user}, $best->{btime}, $best->{method}, $best->{sid}
                );
        }
        else {
            # postgresql
            my $sth = db_execute(
                "UPDATE nu_users
                SET end_time = NOW(), running = 1
                WHERE beg_time = FROM_UNIXTIME(?) AND username = ? AND vpn_ip = ?",
                $best->{btime}, $best->{user}, $vpn_ip
                );
            if ($sth->rows() < 1) {
                db_execute(
                    "INSERT INTO nu_users
                    (vpn_ip,username,beg_time,end_time,method,sid,running)
                    VALUES (?, ?, FROM_UNIXTIME(?), NOW(), ?, ?, 1)",
                    $vpn_ip, $best->{user}, $best->{btime}, $best->{method}, $best->{sid}
                    );
            }
        }

        db_commit();
    }

    iptables_update($vpn_ip, 1, users_from_ip($vpn_ip));
}

sub purge_expired_users () {
    debug("purge expired users");
    cache_gc();
    my $last_time = sprintf($nu_config{db_type} eq "mysql"
                                ? "DATE_SUB(NOW(), INTERVAL \%s SECOND)"
                                : "NOW() - INTERVAL '\%s SECOND'",
                           $nu_config{user_retention});
    db_execute("UPDATE nu_users SET running = 0
                WHERE running = 1 AND end_time < $last_time");
}

sub login_weight ($) {
    my ($method) = @_;
    my $weight = $method_weight{$method};
    return defined($weight) ? $weight : 0;
}

sub detect_login_method ($) {
    my ($sid) = @_;
    my ($tty, $rhost) = split /\@/, $sid;

    return "net" if $tty =~ /^\/\d+$/;
    return "con" if $tty =~ /^\d+$/;
    return "xdm" if $tty =~ /^\:\d+(\.\d+)?$/;
    return "pty" if $tty =~ /^\/\d+$/;
    return "net" if $rhost;

    return "net" if $tty =~ /^(rsh|ssh|net)\//;
    return "con" if $tty =~ /^con\//;
    return "xdm" if $tty =~ /^(gdm|kdm|xdm)\//;
    return "pty" if $tty =~ /^(pty|pts)\//;
    return "top" if $tty =~ /^(test|top)\//;

    return "";
}

#
# number of users logged from a given ip
#
sub users_from_ip ($) {
    my ($vpn_ip) = @_;
    return 0 unless $vpn_ip;
    my $sth = db_execute("SELECT COUNT(*) FROM nu_users
                            WHERE running = 1 AND vpn_ip = ?",
                            $vpn_ip);
    my $count = db_fetch1($sth);
    $count = 0 unless $count;
    debug("got $count active users from vpn:$vpn_ip");
    return $count;
}

##############################################
# main code
#

sub main_loop () {
    read_config($config_file,
                # required parameters
                [ qw(
                    vpn_net db_host db_dbname db_user db_pass
                )],
                # optional parameters
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    syslog stdout debug stacktrace daemonize
                    prefer_nss skip_local authorize_permit
                    db_type db_port login_methods
                    uid_cache_ttl group_cache_ttl
                    user_retention purge_interval
                    ldap_uri ldap_bind_dn ldap_bind_pass
                    ldap_user_base ldap_group_base
                    ldap_attr_user ldap_attr_uid ldap_attr_gid
                    ldap_attr_group ldap_attr_member
                    ldap_start_tls ldap_timeout ldap_force_fork
                    iptables_user_vpn iptables_user_real
                    iptables_host_real iptables_status
                    vpn_scan_interval vpn_scan_pause
                    vpn_cfg_mask vpn_status_file
                    vpn_event_dir vpn_event_mask vpn_archive_dir
                    ns_server ns_zone_real ns_rr_time
                )]);
    log_init();

    debug("setting up");

    for my $method (split /,/, $nu_config{login_methods}) {
        fail("$config_file: unknown login method \"$method\"")
            unless exists $method_weight{$method};
        $login_methods{$method} = $method_weight{$method};
    }

    if (!$nu_config{prefer_nss}) {
        # switch from NSS to LDAP
        ldap_init(1);
        %nss = (
            name => "ldap",
            get_user_uid_grp    => \&ldap_get_user_uid_grp,
            get_user_groups     => \&ldap_get_user_groups,
            user_auth           => \&ldap_auth
            );
    }

    db_connect();
    ev_create_loop();
    vpn_init();
    iptables_init();
    dyndns_init();

    if (daemonize()) {
        # clone dbi and event loop in the child
        db_clone();
        $ev_loop->loop_fork();
    }

    debug("post-fork setup");
    ldap_init(0) unless $nu_config{prefer_nss};
    ssl_startup();
    ssl_create_context($nu_config{peer_pem}, $nu_config{ca_cert});

    my $s_chan = ssl_listen($nu_config{port});
    ev_add_chan($s_chan, "s_acccept", &EV::READ, \&ssl_accept_pending);

    $ev_watch{purge} = $ev_loop->timer(0, $nu_config{purge_interval},
                                        \&purge_expired_users);

    info("$progname started");
    $ev_loop->loop();
}

sub ssl_accept_pending ($) {
    my ($s_chan) = @_;
    my $c_chan = ssl_accept($s_chan, \&ev_close);
    return unless $c_chan;
    ev_add_chan($c_chan);
    debug("[%s] connection accepted", $c_chan->{addr});
    ssl_read_packet($c_chan, \&_ssl_read_done, 0);
}

sub _ssl_read_done ($$$) {
    my ($c_chan, $pkt, $param) = @_;

    if (!defined($pkt)) {
        debug("[%s] disconnected during read", $c_chan->{addr});
        ev_close($c_chan);
        return;
    }

    if ($nu_config{debug}) {
    	my $req = $pkt;
    	# hide password from log
    	$req =~ s/\|[^\|]*$/\|\*\*\*/ if $req =~ /^auth\|/;
    	debug("request \"%s\" from [%s]", $req, $c_chan->{addr});
    }
    my $ret = handle_request(split /\|/, $pkt);
    debug("reply \"%s\" to [%s]", $ret, $c_chan->{addr});
    ssl_write_packet($c_chan, $ret, \&_ssl_write_done, 0);
}

sub _ssl_write_done ($$$) {
    my ($c_chan, $success, $param) = @_;

    if ($success) {
        #debug("%s: reply completed", $c_chan->{addr});
        ssl_read_packet($c_chan, \&_ssl_read_done, $c_chan);
    } else {
        debug("[%s] disconnected during write", $c_chan->{addr});
        ev_close($c_chan);
    }
}

sub cleanup () {
    iptables_close();
    ev_close_all();
    ssl_destroy_context();
    ldap_close();
    vpn_close();
    if (!$ldap_child) {
        ev_remove_handlers();
        # disconnecting from mysql in a child process screws up parent
        db_close();
        end_daemon();
    }
}

END { cleanup(); }

$ENV{LANGUAGE} = "en";

while (1) {
    main_loop();
    last unless $ev_reload;
    info("$progname reloading");
    cleanup();
    $ev_reload = 0;
}

exit(0);


