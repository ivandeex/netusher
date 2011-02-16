#!/usr/bin/perl
#
# UserWatch
# Server daemon
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";
require "$Bin/uw-ssl.inc.pm";
require "$Bin/uw-ldap.inc.pm";
require "$Bin/uw-cache.inc.pm";
require "$Bin/uw-vpn.inc.pm";

#
# require: perl-EV
#
use EV;

our ($config_file, $progname, %uw_config);
our ($ev_loop, %ev_watch, $ev_reload);
our ($ldap_child);
our ($vpn_regex);

our %cache_backend = (
            get_user_uid_grp    => \&nss_get_user_uid_grp,
            get_user_groups     => \&nss_get_user_groups,
            user_auth           => sub { "not implemented" }
        );

#
# Currently only one "main" user per host is allowed.
# We prefer GDM/KDM logins to SSH logins.
# If several users are active, prefer user which has logged in earlier.
#

my %method_weight = (
    'xdm' => 5,
    'net' => 4,
    'con' => 3,
    'pty' => 2,
    );
my $min_method_weight = 4;

##############################################
# requests
#

#
# handle client request.
#
sub handle_request (@) {
    my (@arg) = @_;
    my $cmd = $arg[0];
    my ($msg, $vpn_ip);

    if ($cmd eq "update") {
        return "3 arguments required" if $#arg != 3;

        ($msg, $vpn_ip) = select_vpn_ip($arg[2]);
        return $msg if $msg;

        my (@users);
        for my $chunk (split /\|/, $arg[3]) {
            my ($user, $method, $time) = split /,/, $chunk;
            push @users, { user => $user, method => $method, beg_time => $time };
        }

        $msg = update_user_mapping($cmd, $vpn_ip, \@users);
        return $msg if $msg;

        $msg = "success";
        if ($arg[1] =~ /g/) {
            $msg .= ":" . format_groups(\@users);
        }
        return $msg;
    }
    elsif ($cmd eq "auth") {
        return "2 arguments required" if $#arg != 2;

        $msg = verify_user($arg[1]);
        return $msg if $msg;

        return "success" if $uw_config{authorize_permit};

        $msg = &{$cache_backend{user_auth}}($arg[1], $arg[2]);
        return $msg if $msg;

        return "success";
    }
    elsif ($cmd eq "groups") {
        return "1 argument required" if $#arg != 1;

        return "success:" . format_groups( [ { user => $arg[1] } ] );
    }
    elsif ($cmd eq "login") {
        ($msg, $vpn_ip) = verify_login_arguments(@arg);
        return $msg if $msg;

        return "success";
    }
    elsif ($cmd eq "logout") {
        ($msg, $vpn_ip) = verify_login_arguments(@arg);
        return $msg if $msg;

        return "success";
    }
    else {
        return "unknown command";
    }
}

sub format_groups ($) {
    my ($users) = @_;
    my $ug = inquire_groups($users);
    return join("|", map { join(",", $_, @{ $ug->{$_} }) } sort keys %$ug);
}

sub verify_login_arguments (@) {
    my (@arg) = @_;
    my ($msg, $vpn_ip);
    return "4 arguments required" if $#arg != 4;

    $msg = verify_user($arg[1]);
    return $msg if $msg;

    return "unknown method" if !$method_weight{$arg[2]};
    return "invalid time" if $arg[3] !~ /^\d+$/;

    ($msg, $vpn_ip) = select_vpn_ip($arg[4]);
    return $msg if $msg;

    return (0, $vpn_ip);
}

sub verify_user ($) {
    my ($user) = @_;
    if (!defined get_user_uid_grp($user, undef)) {
        return "user not found";
    }
    if (is_local_user($user)) {
        return "user is local";
    }
    return 0;
}

sub select_vpn_ip ($) {
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
sub update_user_mapping ($$$) {
    my ($cmd, $vpn_ip, $users) = @_;

    #
    # currently only one "main" user per host is allowed.
    # we preferr GDM/KDM users, and if several users are active,
    # we prefer the one that has logged in earlier
    #
    my ($best);

    for my $u (@$users) {
        my $uid = get_user_uid_grp($u->{user}, undef);
        if (!$uid && !$uw_config{also_local}) {
            debug("%s: user not found, skip", $u->{user});
            next;
        }
        if (is_local_user($u->{user})) {
            debug("%s: skip local user", $u->{user});
            next;
        }

        if (!defined($best)) {
            $best = $u;
        }
        elsif ($best->{method} eq $u->{method}) {
            $best = $u if $best->{beg_time} > $u->{beg_time};
        }
        else {
            $best = $u if login_weight($best) < login_weight($u);
        }
    }

    unless (defined $best) {
        debug("ldap users not found");
        iptables_update($vpn_ip, 1, users_from_ip($vpn_ip));
        return;
    }

    my $best_weight = login_weight($best);
    debug("best: user:%s method:%s id:%s beg_time:%s weight:%s cmd:%s",
            $best->{user}, $best->{method}, $best->{uid},
            $best->{beg_time}, $best_weight, $cmd);
    if ($best_weight < $min_method_weight) {
        # if weight is less then allowed, remove the user from database
        $cmd = "logout";
    }

    if ($cmd eq "login" || $cmd eq "logout") {
        # if there were previous active users, end their sessions
        mysql_execute(
            "UPDATE uw_users
            SET end_time = FROM_UNIXTIME(?), running = 0
            WHERE vpn_ip = ? AND running = 1 AND beg_time < FROM_UNIXTIME(?)",
            $best->{beg_time} - 1, $vpn_ip, $best->{beg_time}
            );

        # insert or update existing record
        mysql_execute(
            "INSERT INTO uw_users
            (vpn_ip,username,beg_time,end_time,method,running)
            VALUES (?, ?, FROM_UNIXTIME(?), NOW(), ?, 1)
            ON DUPLICATE KEY UPDATE
            end_time = NOW(), running = 1",
            $vpn_ip, $best->{user}, $best->{beg_time}, $best->{method}
            );
    }

    # logout: update existing user record
    if ($cmd eq "logout") {
        mysql_execute(
            "UPDATE uw_users SET end_time = NOW(), running = 0
            WHERE username = ? AND vpn_ip = ?
            AND ('' = ? OR method = ?)
            AND ('' = ? OR beg_time = FROM_UNIXTIME(?))",
            $best->{user}, $vpn_ip,
            $best->{method}, $best->{method},
            $best->{beg_time}, $best->{beg_time});
    }

    mysql_commit();
    iptables_update($vpn_ip, 1, users_from_ip($vpn_ip));
}

sub purge_expired_users () {
    debug("purge expired users");
    mysql_execute(sprintf("
        UPDATE uw_users SET running = 0
        WHERE running = 1 AND end_time < DATE_SUB(NOW(), INTERVAL %s SECOND)",
        $uw_config{user_retention}));
}

sub login_weight ($) {
    my ($u) = @_;
    return 0 if !defined($u) || !defined($u->{method});
    my $weight = $method_weight{$u->{method}};
    return defined($weight) ? $weight : 0;
}

#
# number of users logged from a given ip
#
sub users_from_ip ($) {
    my ($vpn_ip) = @_;
    return 0 unless $vpn_ip;
    my $sth = mysql_execute("SELECT COUNT(*) FROM uw_users
                            WHERE running = 1 AND vpn_ip = ?",
                            $vpn_ip);
    my $count = mysql_fetch1($sth);
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
                    vpn_net mysql_host mysql_db mysql_user mysql_pass
                )],
                # optional parameters
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    also_local syslog stdout debug stacktrace daemonize
                    ldap_uri ldap_bind_dn ldap_bind_pass
                    ldap_user_base ldap_group_base
                    ldap_attr_user ldap_attr_uid ldap_attr_gid
                    ldap_attr_group ldap_attr_member
                    ldap_start_tls ldap_timeout ldap_force_fork
                    uid_cache_ttl group_cache_ttl
                    user_retention purge_interval
                    mysql_port authorize_permit
                    iptables_user_vpn iptables_user_real
                    iptables_host_real iptables_status
                    vpn_scan_interval vpn_scan_pause
                    vpn_cfg_mask vpn_status_file
                    vpn_event_dir vpn_event_mask vpn_archive_dir
                    ns_server ns_zone_real ns_rr_time
                )]);
    log_init();

    debug("setting up");
    if (defined ldap_init(1)) {
        # switch from NSS to LDAP
        %cache_backend = (
            get_user_uid_grp    => \&ldap_get_user_uid_grp,
            get_user_groups     => \&ldap_get_user_groups,
            user_auth           => \&ldap_auth
            );
    }
    mysql_connect();
    ev_create_loop();
    vpn_init();
    iptables_init();
    dyndns_init();

    if (daemonize()) {
        # clone dbi-mysql and event loop in the child
        mysql_clone();
        $ev_loop->loop_fork();
    }

    debug("post-fork setup");
    ldap_init(0);
    ssl_startup();
    ssl_create_context($uw_config{peer_pem}, $uw_config{ca_cert});

    my $s_chan = ssl_listen($uw_config{port});
    ev_add_chan($s_chan, "s_acccept", &EV::READ, \&ssl_accept_pending);

    $ev_watch{purge} = $ev_loop->timer(0, $uw_config{purge_interval},
                                        \&purge_expired_users);

    info("$progname started");
    $ev_loop->loop();
}

sub ssl_accept_pending ($) {
    my ($s_chan) = @_;
    my $c_chan = ssl_accept($s_chan, \&ev_close);
    return unless $c_chan;
    ev_add_chan($c_chan);
    debug("%s: client accepted", $c_chan->{addr});
    ssl_read_packet($c_chan, \&_ssl_read_done, 0);
}

sub _ssl_read_done ($$$) {
    my ($c_chan, $pkt, $param) = @_;

    unless (defined $pkt) {
        debug("%s: disconnected during read", $c_chan->{addr});
        ev_close($c_chan);
        return;
    }

    debug("request \"%s\" from %s", $pkt, $c_chan->{addr});
    rescan_etc();
    my $ret = handle_request(split /:/, $pkt);
    debug("reply \"%s\" to %s", $ret, $c_chan->{addr});
    ssl_write_packet($c_chan, $ret, \&_ssl_write_done, 0);
}

sub _ssl_write_done ($$$) {
    my ($c_chan, $success, $param) = @_;

    if ($success) {
        #debug("%s: reply completed", $c_chan->{addr});
        ssl_read_packet($c_chan, \&_ssl_read_done, $c_chan);
    } else {
        debug("%s: disconnected during write", $c_chan->{addr});
        ev_close($c_chan);
    }
}

sub cleanup () {
    iptables_close();
    ev_close_all();
    ssl_destroy_context();
    ldap_close();
    vpn_close();
    unless ($ldap_child) {
        ev_remove_handlers();
        # disconnecting from mysql in a child process screws up parent
        mysql_close();
        end_daemon();
    }
}

END { cleanup(); }

while (1) {
    main_loop();
    last unless $ev_reload;
    info("$progname reloading");
    cleanup();
    $ev_reload = 0;
}

exit(0);


