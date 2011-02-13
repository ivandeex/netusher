#!/usr/bin/perl
#
# UserWatch SSL server
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";
require "$Bin/uw-ssl.inc.pm";
require "$Bin/uw-ldap.inc.pm";
require "$Bin/uw-cache.inc.pm";

#
# require: perl-DBD-mysql, perl-LDAP, perl-EV
#
use DBI;
use EV;

our ($config_file, $progname, %uw_config);
our ($ev_loop, %ev_watch, $ev_reload);
our ($ldap_child);

my  ($dbh, %sth_cache);
my  ($vpn_regex);

our %cache_backend = (
            get_user_uid    => \&ldap_get_user_uid
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
sub parse_req ($) {
    my ($str) = @_;

    # typical request:
    # C:1296872500:::::~:002:192.168.203.4:10.30.4.1:~:002:1296600643:XDM:root:0:/:1296856317:XTY:root:0:/:~

    my @arr = split /:/, $str;
    #debug("arr: %s", join(',', map { "$_=$arr[$_]" } (0 .. $#arr)));
    return "invalid array delimiters"
        if $arr[6] ne '~' || $arr[$#arr] ne "~" || $arr[$arr[7] + 8] ne "~";

    # command
    my $cmd = $arr[0];
    return "invalid command"
        if length($cmd) != 1 || index("IOC", $cmd) < 0;

    # logon user
    my $usr = {
            beg_time => $arr[1],
            method => $arr[2],
            user => $arr[3],
            uid => $arr[4],
            pass => $arr[5]
            };
    return "invalid begin time"
        if $usr->{beg_time} ne "" && $usr->{beg_time} !~ /^\d+$/;
    return "invalid uid"
        if $usr->{uid} && $usr->{uid} !~ /^\d+$/;

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

    return { cmd => $cmd, log_usr => $usr, ips => \@ips, users => \@users };
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
            debug("duplicate vpn ip address");
            next;
        }
        $vpn_ip = $ip;
    }
    return "vpn ip not found"
        unless defined $vpn_ip;
    debug("client vpn ip: $vpn_ip");

    if ($cmd eq 'I' || $cmd eq 'O') {
        # first, verify that user exists at all
        my $uid = get_user_uid($usr->{user});
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
        return "invalid login time" if $usr->{beg_time} !~ /^\d+$/;
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
    return "OK";
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
    for (my $i = 0; $i < scalar(@$users); $i++) {
        my $u = $users->[$i];

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
        iptables_update($vpn_ip, users_from_ip($vpn_ip));
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
    iptables_update($vpn_ip);
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
    return $count;
}

##############################################
# iptables control
#

my ($chains_enable, %chains_ips, %chains_extra);
my (%chains_vpn, %chains_real, %chains_all);
my ($iptables_fail_num, $iptables_fail_log);

sub iptables_update ($) {
    my ($vpn_ip) = @_;
    return unless $chains_enable;
    my $active = users_from_ip($vpn_ip);
    my $real_ip = get_real_ip($vpn_ip);
    debug("got $active active users from vpn:$vpn_ip real:$real_ip");

    my ($chain, $changed);
    if ($active) {
        # enable
        if ($vpn_ip) {
            for $chain (keys %chains_vpn) {
                if (!$chains_ips{$chain}{$vpn_ip}) {
                    enable_ip($chain, $vpn_ip, 1, 0);
                    $changed = 1;
                }
            }
        }
        if ($real_ip) {
            for $chain (keys %chains_real) {
                if (!$chains_ips{$chain}{$real_ip}) {
                    enable_ip($chain, $real_ip, 1, 0);
                    $changed = 1;
                }
            }
        }
    } else {
        # disable
        if ($vpn_ip) {
            for $chain (keys %chains_vpn) {
                if ($chains_ips{$chain}{$vpn_ip}) {
                    enable_ip($chain, $vpn_ip, 0, 0);
                    $changed = 1;
                }
            }
        }
        if ($real_ip) {
            for $chain (keys %chains_real) {
                if ($chains_ips{$chain}{$real_ip}) {
                    enable_ip($chain, $real_ip, 0, 0);
                    $changed = 1;
                }
            }
        }
    }

    if ($changed) {
        iptables_save_status();
        debug("iptables: enable:%s vpn:%s real:%s ",
                $active, $vpn_ip, $real_ip);
    }
}

sub get_real_ip ($) {
    my ($vpn_ip) = @_;
    return unless $vpn_ip;
    my $sth = mysql_execute("SELECT real_ip FROM uw_openvpn
                            WHERE running = 1 AND vpn_ip = ?
                            LIMIT 1",
                            $vpn_ip);
    my $real_ip = mysql_fetch1($sth);
    return $real_ip;
}

sub enable_ip ($$$$) {
    my ($chain, $ip, $enable, $log) = @_;
    my $flag = $enable ? "-I" : "-D";
    if ($enable) {
        $chains_ips{$chain}{$ip} = 1;
    } else {
        delete $chains_ips{$chain}{$ip};
    }
    return run_iptables("$flag $chain -s $ip", $log);
}

sub iptables_init () {
    iptables_close();

    # setup chain names
    $chains_all{$_} = $chains_vpn{$_} = 1
        for (split /\s+/, $uw_config{iptables_vpn});
    $chains_all{$_} = $chains_real{$_} = 1
        for (split /\s+/, $uw_config{iptables_real});
    $chains_enable = (%chains_all ? 1 : 0);
    return unless $chains_enable;

    # consistency check
    for my $chain (qw[PREROUTING INPUT FORWARD OUTPUT POSTROUTING]) {
        fail("$chain: refusing to manage internal system chain")
            if $chains_all{$chain};
    }

    create_parent_dir($uw_config{iptables_status});
    iptables_rescsan();
}

sub iptables_close () {
    $chains_enable = 0;
    %chains_ips = ();
    %chains_extra = ();
    %chains_vpn = ();
    %chains_real = ();
    %chains_all = ();
    $iptables_fail_num = 0;
    $iptables_fail_log = "";
}

sub iptables_rescan () {
    debug("rescan iptables");

    # setup structures
    my $iptables = $uw_config{iptables};
    my (%chain_exists, %chains_extra_set);
    for (keys %chains_all) {
        $chains_ips{$_} = {};
        $chains_extra{$_} = [];
        $chains_extra_set{$_} = {};
    }

    # scan saved status and current state of iptables
    for my $source ("status", "iptables") {
        my $out;

        # first scan saved status, then current state
        if ($source eq "status") {
            open(my $file, $uw_config{iptables_status}) or next;
            my $rs = $/;
            undef $/;
            $out = <$file>;
            $/ = $rs;
            close($file);
        }
        elsif ($source eq "iptables") {
            my $ret = run_prog($uw_config{iptables_save}, \$out);
        }

        # scan current source line by line
        for (split /\n/, $out) {
            # remove program name
            s/^\s*${iptables}\s+//;

            # skip empty lines and comments
            chomp; s/\s+/ /g; s/^ //; s/ $//;
            next if /^$/ || /^\#/;
            my $line = $_;
            #debug("ip scan source:$source line:$line");

            # detect whether chains exist
            if ($source eq "iptables" && $line =~ /^:(\S+) \S/) {
                my ($chain) = ($1);
                $chain_exists{$chain} = 1;
                #debug("ip scan source:$source found chain:$chain");
                next;
            }

            # simple rules for ordinary IPs
            if ($line =~ /^-A (\S+) -s ([\w\d\.\:]+) -j ACCEPT$/) {
                my ($chain, $ip) = ($1, $2);
                my $is_vpn = ($ip =~ $vpn_regex) ? 1 : 0;
                if ($chains_vpn{$chain} && $is_vpn) {
                    $chains_ips{$chain}{$ip} = $source;
                    debug("ip scan source $source chain $chain vpn: $ip");
                    next;
                }
                if ($chains_real{$chain} && !$is_vpn) {
                    $chains_ips{$chain}{$ip} = $source;
                    debug("ip scan source:$source chain:$chain real: $ip");
                    next;
                }
            }

            # custom user rules
            if ($line =~ /^-A (\S+) (\S.*)$/) {
                my ($chain, $rule) = ($1, $2);
                next unless $chains_all{$chain};
                my $exists = exists $chains_extra_set{$chain}{$rule};
                $chains_extra_set{$chain}{$rule} = $source;
                debug("ip scan source:$source chain:$chain rule: $rule");
                push(@{ $chains_extra{$chain} }, $rule)  unless $exists;
                next;
            }
        }
    }

    # augment empty chains with default drop rule
    for my $chain (keys %chains_all) {
        unless (@{ $chains_extra{$chain} }) {
            my $rule = "-j DROP";
            push @{ $chains_extra{$chain} }, $rule;
            $chains_extra_set{$chain}{$rule} = "auto";
        }
    }

    # identify chains which have to be updated
    my %need_update;
  CHAIN_FOR_UPDATE:
    for my $chain (keys %chains_all) {
        if (!$chain_exists{$chain}) {
            $need_update{$chain} = "create";
            debug("chain $chain needs: create");
            next CHAIN_FOR_UPDATE;
        }
        for my $src (values %{ $chains_extra_set{$chain} }) {
            if ($src ne "iptables") {
                $need_update{$chain} = "extra";
                debug("chain $chain needs: extra rules");
                next CHAIN_FOR_UPDATE;
            }
        }
        for my $src (values %{ $chains_ips{$chain} }) {
            if ($src ne "iptables") {
                $need_update{$chain} = "ip";
                debug("chain $chain needs: add IPs");
                next CHAIN_FOR_UPDATE;
            }
        }
    }

    # test all changes with a temporary chain
    $iptables_fail_num = 0;
    $iptables_fail_log = "";
    my $temp = "USERWATCH_TEMP";

    for my $chain (sort keys %need_update) {
        debug("begin test of chain $chain changes");
        sleep(1);
        if ($chain_exists{$temp}) {
            run_iptables("-F $temp", 0);
            run_iptables("-X $temp", 0);
            $chain_exists{$temp} = 0;
        }
        run_iptables("-N $temp", 1);
        $chain_exists{$temp} = 1;
        last if $iptables_fail_num;

        for my $ip (sort keys %{ $chains_ips{$chain} }) {
            run_iptables("-A $temp -s $ip -j ACCEPT", 1);
            last if $iptables_fail_num;
        }
        for my $rule (@{ $chains_extra{$chain} }) {
            run_iptables("-A $temp $rule", 1);
            last if $iptables_fail_num;
        }
    }

    # remove temporary chain and check the result
    if ($chain_exists{$temp}) {
        run_iptables("-F $temp", 0);
        run_iptables("-X $temp", 0);
        $chain_exists{$temp} = 0;
    }
    fail("iptables error:\n%s", $iptables_fail_log)
        if $iptables_fail_num;

    # since test is fine, repeat actions on real chains
    for my $chain (sort keys %need_update) {
        run_iptables("-N $chain", 0)
            unless $chain_exists{$chain};

        if ($need_update{$chain} eq "ip") {
            # simply add IPs to the beginning of the chain
            for my $ip (sort keys %{ $chains_ips{$chain} }) {
                if ($chains_ips{$chain}{$ip} ne "iptables") {
                    run_iptables("-I $chain -s $ip -j ACCEPT", 1);
                }
            }
        }
        else {
            # fully remake the chain
            run_iptables("-F $chain", 0);
            for my $ip (sort keys %{ $chains_ips{$chain} }) {
                run_iptables("-A $chain -s $ip -j ACCEPT", 1);
            }
            for my $rule (@{ $chains_extra{$chain} }) {
                run_iptables("-A $chain $rule", 1);
            }
        }
    }

    if ($iptables_fail_num) {
        info("warning: iptables errors: %s", $iptables_fail_log);
    } elsif (%need_update) {
        info("iptables modified successfully: %s",
            join(" ", sort keys %need_update));
    }

    iptables_save_status();
}

sub iptables_save_status () {
    my $path = $uw_config{iptables_status};
    my $iptables = $uw_config{iptables};

    my $out = "# generated by $progname on " . POSIX::ctime(time);
    for my $chain (sort keys %chains_all) {
        $out .= "$iptables -F $chain\n";
        for my $ip (sort keys %{ $chains_ips{$chain} }) {
            $out .= "$iptables -A $chain -s $ip -j ACCEPT\n";
        }
        for my $rule (@{ $chains_extra{$chain} }) {
            $out .= "$iptables -A $chain $rule\n";
        }
    }
    $out .= "# end of file\n";

    if (open(my $file, ">", $path)) {
        print $file $out;
        close($file);
        debug("iptables status saved in $path");
    } else {
        info("$path: cannot create status file");
    }
}

sub run_iptables ($$) {
    my ($cmd, $log) = @_;
    my $iptables = $uw_config{iptables};
    my $out;
    my $ret = run_prog("$iptables $cmd", \$out);
    if ($ret && $log) {
        $iptables_fail_num++;
        $iptables_fail_log .= $out;
    }
    debug("$iptables ($ret) \"$cmd\"");
    return $ret;
}

##############################################
# mysql stuff
#

sub mysql_connect () {
    mysql_close();
    my $uri = sprintf("DBI:mysql:%s;host=%s",
                    $uw_config{mysql_db}, $uw_config{mysql_host});
    $dbh = DBI->connect($uri, $uw_config{mysql_user}, $uw_config{mysql_pass})
		or fail("cannot connect to database");
    $dbh->{mysql_enable_utf8} = 1;
    $dbh->{mysql_auto_reconnect} = 1;
    $dbh->{AutoCommit} = 0;
    $dbh->do("SET NAMES 'utf8'");
}

sub mysql_close () {
    %sth_cache = ();
    if (defined $dbh) {
        eval { $dbh->disconnect() };
        undef $dbh;
    }
}

sub mysql_clone () {
    my $child_dbh = $dbh->clone();
    mysql_close();
    $dbh = $child_dbh;
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

sub mysql_fetch1 ($) {
    my ($sth) = @_;
    my @row = $sth->fetchrow_array();
    return $row[0];
}

sub mysql_commit () {
    eval { $dbh->commit(); };
}

##############################################
# main code
#

sub main_loop () {
    read_config($config_file,
                # required parameters
                [ qw(
                    vpn_net mysql_host mysql_db mysql_user mysql_pass
                    ldap_uri ldap_bind_dn ldap_bind_pass ldap_user_base
                )],
                # optional parameters
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    also_local syslog stdout debug stacktrace daemonize
                    ldap_attr_user ldap_attr_uid ldap_start_tls ldap_timeout
                    ldap_force_fork mysql_port uid_cache_ttl
                    user_retention purge_interval
                    iptables_vpn iptables_real iptables_status
                )],
                # required programs
                [ qw(
                    iptables
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

    debug("setting up");
    ldap_init(1);
    mysql_connect();
    ev_create_loop();
    iptables_init();

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
    $ev_watch{iptables} = $ev_loop->signal("USR1", \&iptables_recreate);

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

    my $req = parse_req($pkt);
    my $ret;
    if (ref($req) eq 'HASH') {
        debug('request from %s', $c_chan->{addr});
        $ret = handle_request($req);
    } else {
        info("%s: invalid request (error:%s)", $c_chan->{addr}, $req);
        $ret = "invalid request";
    }

    ssl_write_packet($c_chan, $ret, \&_ssl_write_done, 0);
}

sub _ssl_write_done ($$$) {
    my ($c_chan, $success, $param) = @_;

    if ($success) {
        debug("%s: reply completed", $c_chan->{addr});
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
    unless ($ldap_child) {
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


