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
            get_user_uid_grp    => \&ldap_get_user_uid_grp,
            get_user_groups     => \&ldap_get_user_groups
        );

#
# Currently only one "main" user per host is allowed.
# We prefer GDM/KDM logins to SSH logins.
# If several users are active, prefer user which has logged in earlier.
#

my %login_method_weight = (
    'XDM' => 5,
    'RSH' => 4,
    'CON' => 2,
    'XTY' => 1,
    );
my $min_login_weight = 4;

##############################################
# requests
#

#
# parse request string.
#
sub parse_request ($) {
    my ($str) = @_;

    # typical request:
    # C:1296872500:::::~:002:192.168.203.4:10.30.4.1:~:002:1296600643:XDM:root:0:/:1296856317:XTY:root:0:/:~

    my @arr = split /:/, $str;
    #debug("arr: %s", join(',', map { "$_=$arr[$_]" } (0 .. $#arr)));
    return "invalid delimiters"
        if $arr[7] ne '~' || $arr[$#arr] ne "~" || $arr[$arr[8] + 9] ne "~";

    # command
    my $cmd = $arr[0];
    return "invalid command"
        if length($cmd) != 1 || index("IOC", $cmd) < 0;
    my $opts = $arr[1];

    # logon user
    my $usr = {
            beg_time => $arr[2],
            method => $arr[3],
            user => $arr[4],
            uid => $arr[5],
            pass => $arr[6]
            };
    return "invalid begin time"
        if $usr->{beg_time} ne "" && $usr->{beg_time} !~ /^\d+$/;
    return "invalid uid"
        if $usr->{uid} && $usr->{uid} !~ /^\d+$/;

    # parse IP list
    my @ips;
    for (my $i = 9; $i < $arr[8] + 9; $i++) {
        return "invalid ip"
            if $arr[$i] !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        push @ips, $arr[$i];
    }

    # create user list
    my @users;
    my $beg_idx = $arr[8] + 11;
    my $num = $arr[$beg_idx - 1];
    my $end_idx = $beg_idx + $num * 5;
    #debug("req user list beg_idx:$beg_idx end_idx:$end_idx end:$#arr");
    return "user list too long ($beg_idx,$num,$#arr)"
        if $end_idx > $#arr;

    for (my $i = $beg_idx; $i < $end_idx; $i += 5) {
        my $u = {
                beg_time => $arr[$i],
                method => $arr[$i + 1],
                user => $arr[$i + 2],
                uid => $arr[$i + 3],
                };
        return "invalid user delimiter $i"
            if $arr[$i + 4] ne "/";
        return "invalid beg_time $i"
            if $u->{beg_time} !~ /^\d+$/;
        return "invalid method $i"
            if length($u->{method}) != 3;
        return "invalid uid $i"
            if $u->{uid} && $u->{uid} !~ /^\d+/;
        #debug("next req user:%s uid:%s method:%s beg_time:%s",
        #        $u->{user}, $u->{uid}, $u->{method}, $u->{beg_time});
        push @users, $u;
    }

    my $req = {
        cmd => $cmd,
        opts => $opts,
        log_usr => $usr,
        ips => \@ips,
        users => \@users
        };
    return $req;
}

#
# handle client request.
#
sub handle_request ($) {
    my ($req) = @_;
    my $cmd = $req->{cmd};
    my $usr = $req->{log_usr};
    my $users = $req->{users};

    # select client ip belonging to vpn
    my $vpn_ip;
    for my $ip (@{ $req->{ips} }) {
        next unless $ip =~ $vpn_regex;
        if (defined $vpn_ip) {
            debug("duplicate vpn ip");
            next;
        }
        $vpn_ip = $ip;
    }
    return "vpn ip not found"
        unless defined $vpn_ip;
    debug("client vpn ip: $vpn_ip");

    if ($cmd eq 'I' || $cmd eq 'O') {
        # first, verify that user exists at all
        my $uid = get_user_uid_grp($usr->{user}, undef);
        return "user not found" unless defined $uid;

        # verify that user id matches ldap
        if (defined($usr->{uid}) && $usr->{uid} ne '' && $usr->{uid} != $uid) {
            debug("%s: uid %s does not match ldap %s",
                   $usr->{user}, $usr->{uid}, $uid);
            return "invalid uid";
        }
    }

    if ($cmd eq 'I') {
        # verify login time
        return "invalid login time"
            if $usr->{beg_time} !~ /^\d+$/;
        # verify user password
        my $msg = ldap_auth($usr->{user}, $usr->{pass});
        return $msg if $msg;
        # add this user to the beginning of the big list
        unshift @$users, $usr;
    }

    if ($cmd eq 'O') {
        # user logout
        $users = [ $usr ];
    }

    update_user_mapping($cmd, $vpn_ip, $users);

    my $reply = "OK";
    if (&OPT_GET_GROUPS & $req->{opts}) {
        my $group_map = inquire_groups($users);
        $reply .= ":~:" . scalar(keys %$group_map);
        for my $user (sort keys %$group_map) {
            my $groups = $group_map->{$user};
            $reply .= sprintf(":%s:%d:%s/", $user, scalar(@$groups),
                                join("", map("$_:", @$groups)));
        }
        $reply .= ":~";
    }

    return $reply;
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
        # skip local users and users with id that does not match
        unless ($uw_config{also_local}) {
            my $uid = get_user_uid($u->{user});
            unless (defined $uid) {
                debug("%s: skip local user", $u->{user});
                next;
            }
            if (defined($u->{uid}) && $u->{uid} ne '' && $u->{uid} != $uid) {
                debug("%s: uid %s does not match ldap %s",
                        $u->{user}, $u->{uid}, $uid);
                next;
            }
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
    if ($best_weight < $min_login_weight) {
        # if weight is less then allowed, remove the user from database
        $cmd = 'O';
    }

    if ($cmd eq 'I' || $cmd eq 'C') {
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
    if ($cmd eq 'O') {
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
    my $weight = $login_method_weight{$u->{method}};
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
                    ldap_uri ldap_bind_dn ldap_bind_pass
                    ldap_user_base ldap_group_base
                )],
                # optional parameters
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    also_local syslog stdout debug stacktrace daemonize
                    ldap_attr_user ldap_attr_uid ldap_attr_gid
                    ldap_attr_group ldap_attr_member
                    ldap_start_tls ldap_timeout ldap_force_fork
                    uid_cache_ttl group_cache_ttl
                    user_retention purge_interval mysql_port
                    iptables_user_vpn iptables_user_real
                    iptables_host_real iptables_status
                    vpn_scan_interval vpn_scan_pause
                    vpn_cfg_mask vpn_status_file
                    vpn_event_dir vpn_event_mask vpn_archive_dir
                    ns_server ns_zone_real ns_rr_time
                )]);
    log_init();

    debug("setting up");
    ldap_init(1);
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

    my $req = parse_request($pkt);
    my $ret;
    if (ref($req) eq 'HASH') {
        debug("request from %s \"%s\"", $c_chan->{addr}, $pkt);
        $ret = handle_request($req);
    } else {
        info("%s: invalid request (error:%s)", $c_chan->{addr}, $req);
        $ret = "invalid request";
    }

    debug("reply to %s \"%s\"", $c_chan->{addr}, $ret);
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


