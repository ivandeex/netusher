#!/usr/bin/perl
#
# UserWatch SSL server
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/userwatch.inc.pm";

#
# require: perl-DBD-mysql, perl-LDAP, perl-EV
#
use DBI;
use Net::LDAP;
use EV;

our ($config_file, %uw_config, $ev_loop, %ev_watch);
my  (%chans);
my  ($dbh, %sth_cache);
my  ($ldap, %uid_cache, $vpn_regex);

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
my $min_login_weight = 5;

#
# connection to ldap for browsing
#
sub ldap_init () {
    my ($msg, $ldap_conn)
        = ldap_connect($uw_config{ldap_bind_dn}, undef,
                        $uw_config{ldap_bind_pass}, 0);
    $ldap = $ldap_conn unless $msg;
    # flush ldap cache at every re-connection
    %uid_cache = ();
    return $msg;
}

#
# connection to ldap for browsing or to to check credentials
#
sub ldap_connect ($$$$) {
    my ($bind_dn, $user, $pass, $just_check) = @_;

    my $ldap_conn = Net::LDAP->new($uw_config{ldap_uri},
                                timeout => $uw_config{timeout},
                                version => 3)
        or return "ldap server down";

    if ($uw_config{ldap_start_tls}) {
        $ldap_conn->start_tls()
            or return "ldap tls failed";
    }

    if (!$bind_dn) {
        $bind_dn = sprintf('%s=%s,%s', $uw_config{ldap_attr_user},
                            $user, $uw_config{ldap_user_base});
    }
    my $res = $ldap_conn->bind($bind_dn, password => $pass);

    $ldap_conn->unbind() if $just_check;

    debug("ldap auth uri:%s tls:%s bind:%s pass:%s returns: %s",
            $uw_config{ldap_uri}, $uw_config{ldap_start_tls},
            $bind_dn, $pass, $res->error());
    return "invalid password" if $res->code();

    # success
    return (0, $ldap_conn);
}

#
# return ldap uidNumber for given user
#
sub ldap_get_uid ($) {
    my ($user) = @_;
    my ($uid, $res);

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

    # search for uid in ldap.
    # ldap server might have disconnected due to timeout.
    # if so, we try to re-connect and repeat the search.
    for (my $try = 1; $try <= 2; $try++) {
        if ($ldap) {
            $res = $ldap->search(
                    base => $uw_config{ldap_user_base},
                    filter => sprintf('(%s=%s)', $uw_config{ldap_attr_user}, $user),
                    scope => 'one', defer => 'never',
                    attrs => [ $uw_config{ldap_attr_uid} ]
                    );
        }
        if (!$ldap || $res->code() == 1) {
            # unexpected eof. try to reconnect
            debug("restoring ldap connection ($try)");
            undef $ldap;
            ldap_init();
            # a little delay
            select(undef, undef, undef, ($try - 1) * 0.100);
        } else {
            last;
        }
    }

    # fetch uid from ldap array
    unless ($res) {
        debug("ldap get uid user:$user server down");
        return;
    }
    if (!$res->code()) {
        my $entry = $res->pop_entry();
        if ($entry) {
            $uid  = $entry->get_value($uw_config{ldap_attr_uid});
        }
        # update cache with defined or undefined uid
        $uid_cache{$user}{uid} = $uid;
        $uid_cache{$user}{stamp} = $stamp;
    }

    debug("ldap_get_uid user:%s uid:%s message:%s", $user, $uid, $res->error());

    return $uid;
}

#
# parse request string.
#
sub parse_req ($) {
    my ($str) = @_;

    # typical request:
    # C:1296872500:::::~:002:192.168.203.4:10.30.4.1:~:002:1296600643:XDM:root:0:/:1296856317:XTY:root:0:/:~

    my @arr = split /:/, $str;
    debug("arr: %s", join(',', map { "$_=$arr[$_]" } (0 .. $#arr)));
    return "invalid array delimiters"
        if $arr[6] ne '~' || $arr[$#arr] ne "~" || $arr[$arr[7] + 8] ne "~";

    # command
    my $cmd = $arr[0];
    return "invalid command"
        if length($cmd) != 1 || index("IOC", $cmd) < 0;

    # logon user
    my $log_usr = {
            beg_time => $arr[1],
            method => $arr[2],
            user => $arr[3],
            uid => $arr[4],
            pass => $arr[5]
            };
    return "invalid begin time"
        if $log_usr->{beg_time} !~ /^\d+$/;
    return "invalid uid"
        if $log_usr->{uid} && $log_usr->{uid} !~ /^\d+$/;

    # parse IP list
    my @ips;
    for (my $i = 8; $i < $arr[7] + 8; $i++) {
        return "invalid ip"
            if $arr[$i] !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        push @ips, $arr[$i];
    }

    # create user list
    my @users;
    my $beg_idx = $arr[7] + 10;
    my $num = $arr[$beg_idx - 1];
    my $end_idx = $beg_idx + $num * 5;
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
        push @users, $u;
    }

    return { cmd => $cmd, log_usr => $log_usr, ips => \@ips, users => \@users };
}

#
# handle client request.
#
sub handle_req ($) {
    my ($req) = @_;

    # select client ip belonging to vpn
    my $vpn_ip;
    for my $ip (@{ $req->{ips} }) {
        next unless $ip =~ $vpn_regex;
        if (defined $vpn_ip) {
            debug("duplicate vpn ip address");
            next;
        }
        $vpn_ip = $ip;
    }
    return "vpn ip not found"
        unless defined $vpn_ip;
    debug("client vpn ip: $vpn_ip");

    if ($req->{cmd} eq 'I') {
        # user login handler
        my $log_usr = $req->{log_usr};

        # first, verify that user exists at all
        my $uid = ldap_get_uid($log_usr->{user});
        return "user not found"
            unless defined $uid;

        # verify that user id matches ldap
        if (defined($log_usr->{uid}) && $log_usr->{uid} ne ''
                && $log_usr->{uid} != $uid) {
            debug("%s: uid %s does not match ldap %s",
                   $log_usr->{user}, $log_usr->{uid}, $uid);
            return "invalid uid";
        }

        # verify user password
        my ($msg, $dummy_conn) = ldap_connect(undef, $log_usr->{user},
                                                $log_usr->{pass}, 1);
        return $msg if $msg;

        # add this user to the beginning of the big list
        unshift @{ $req->{users} }, $log_usr;
    }
    elsif ($req->{cmd} eq 'O') {
        # logout
    }

    update_user_mapping($req->{cmd}, $vpn_ip, $req->{users});
    return "OK";
}

#
# connect to mysql.
#
sub mysql_connect () {
    $dbh = DBI->connect(
                "DBI:mysql:$uw_config{mysql_db};host=$uw_config{mysql_host}",
                $uw_config{mysql_user}, $uw_config{mysql_pass})
		or fail("cannot connect to database");
    $dbh->{mysql_enable_utf8} = 1;
    $dbh->{mysql_auto_reconnect} = 1;
    $dbh->{AutoCommit} = 0;
    $dbh->do("SET NAMES 'utf8'");
    %sth_cache = ();
}

sub mysql_execute ($@) {
    my ($sql, @params) = @_;
    my $sth = $sth_cache{$sql};
    unless (defined $sth) {
        $sth = $dbh->prepare($sql);
        $sth_cache{$sql} = $sth;
    }
    my $ok = { $sth->execute(@params) };
    my $num = $sth->rows();
    if (!$ok) {
        info("mysql error: %s\n", $sth->errstr());
        $num = -1;
    }
    debug("execute: %s\n\t((%s)) = \"%s\"", $sql,
         join(',', map { defined($_) ? "\"$_\"" : "NULL" } @params),
         $num);
    return $sth;
}

sub mysql_commit () {
    eval { $dbh->commit(); };
}

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
    for (my $i = 0; $i < scalar(@$users); $i++) {
        my $u = $users->[$i];

        # skip local users and users with id that does not match
        unless ($uw_config{also_local}) {
            my $uid = ldap_get_uid($u->{user});
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

    my $best_weight = login_weight($best);
    $cmd = 'O' if $best_weight < $min_login_weight;

    if (defined $best) {
        debug("best: user:%s method:%s id:%s beg_time:%s weight:%s cmd:%s",
                $best->{user}, $best->{method}, $best->{uid},
                $best->{beg_time}, $best_weight, $cmd);
    } else {
        debug("ldap users not found");
    }

    if ($best && ($cmd eq 'I' || $cmd eq 'C')) {
        # if there were previous active users, end their sessions
        mysql_execute("UPDATE uw_users
            SET end_time = FROM_UNIXTIME(?), running = 0
            WHERE vpn_ip = ? AND running = 1 AND beg_time < FROM_UNIXTIME(?)",
            $best->{beg_time} - 1, $vpn_ip, $best->{beg_time}
            );

        # insert or update existing record
        mysql_execute("INSERT INTO uw_users
            (vpn_ip,username,beg_time,end_time,method,running)
            VALUES (?, ?, FROM_UNIXTIME(?), NOW(), ?, 1)
            ON DUPLICATE KEY UPDATE
            end_time = NOW(), running = 1",
            $vpn_ip, $best->{user}, $best->{beg_time}, $best->{method}
            );

        mysql_commit();
    }

    # logout: update existing user record
    if ($best && $cmd eq 'O') {
        mysql_execute("UPDATE uw_users SET end_time = NOW(), running = 0
            WHERE beg_time = FROM_UNIXTIME(?)
            AND username = ? AND vpn_ip = ?",
            $best->{beg_time}, $best->{user}, $vpn_ip);
        mysql_commit();
    }
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
# main code
#
sub main () {
    read_config($config_file, [ qw(
                    vpn_net mysql_host mysql_db mysql_user mysql_pass
                    ldap_uri ldap_bind_dn ldap_bind_pass ldap_user_base
                )],
                [ qw(
                    port ca_cert peer_pem mysql_port
                    ldap_attr_user ldap_attr_uid ldap_start_tls
                    user_retention purge_interval also_local
                    cache_retention idle_timeout timeout
                    syslog stdout debug
                )]);
    log_init();

    # create regular expression for vpn network
    $vpn_regex = $uw_config{vpn_net};
    fail("vpn_net: invalid format \"$vpn_regex\", shall be A.B.C.0")
        if $vpn_regex !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    $vpn_regex =~ s/(\.0+)+$//;
    $vpn_regex .= ".";
    $vpn_regex =~ s/\./\\./g;
    $vpn_regex = qr[$vpn_regex];

    my $msg = ldap_init();
    info("warning: ldap init failed: $msg") if $msg;
    mysql_connect();

    ssl_startup();
    ssl_create_context($uw_config{peer_pem}, $uw_config{ca_cert});
    ev_create_loop();

    my $s_chan = ssl_listen($uw_config{port});
    $chans{$s_chan} = $s_chan;
    $ev_watch{s_accept} = $ev_loop->io($s_chan->{conn}, &EV::READ,
                                        sub { accept_pending($s_chan) });

    $ev_watch{purge} = $ev_loop->timer(0, $uw_config{purge_interval},
                                        \&purge_expired_users);

    debug("waiting for clients...");
    $ev_loop->loop();
    exit(0);
}

sub accept_pending ($) {
    my ($s_chan) = @_;
    my $c_chan = ssl_accept($s_chan, \&close_channel);
    next unless $c_chan;
    $chans{$c_chan} = $c_chan;
    debug('client accepted: %s', $c_chan->{addr});
    ssl_read_packet($c_chan, \&reading_done, $c_chan);
}

sub reading_done ($$$) {
    my ($c_chan, $pkt, $param) = @_;

    unless (defined $pkt) {
        debug('client disconnected during read: %s', $c_chan->{addr});
        close_channel($c_chan);
        return;
    }

    my $req = parse_req($pkt);
    my $ret;
    if (ref($req) eq 'HASH') {
        debug('request from %s', $c_chan->{addr});
        $ret = handle_req($req);
    } else {
        info("invalid request (error:$req)");
        $ret = "invalid request";
    }

    ssl_write_packet($c_chan, $ret, \&writing_done, $c_chan);
}

sub writing_done ($$$) {
    my ($c_chan, $success, $c_chan) = @_;

    if ($success) {
        debug('finished reply to %s', $c_chan->{addr});
        ssl_read_packet($c_chan, \&reading_done, $c_chan);
    } else {
        debug('client disconnected during write: %s', $c_chan->{addr});
        close_channel($c_chan);
    }
}

sub close_channel ($) {
    my ($chan) = @_;
    ssl_disconnect($chan);
    delete $chans{$chan};
}

sub cleanup () {
    close_channel($_) for (values %chans);
    %chans = ();

    ssl_destroy_context();

    eval { $dbh->disconnect } if defined $dbh;
    undef $dbh;

    eval { $ldap->unbind } if defined $ldap;
    undef $ldap;

    info("uwserver finished");
}

END { cleanup(); }
main();


