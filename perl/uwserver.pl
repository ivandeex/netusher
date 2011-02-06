#!/usr/bin/perl
#
# UserWatch SSL server
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/userwatch.inc.pm";
use DBI;
use Net::LDAP;

our ($CFG_ROOT, $debug, %uw_config);
our ($ssl_ctx, $srv_sock, $ssl, $conn);
our ($vpn_regex, $dbh, $ldap, %ldap_cache);

sub ldap_init () {
    my ($msg, $ldap_conn)
        = ldap_connect($uw_config{ldap_bind_dn}, undef,
                        $uw_config{ldap_bind_pass}, 0);
    $ldap = $ldap_conn unless $msg;
    return $msg;
}

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

    if ($debug) {
        print sprintf("ldap auth uri:%s tls:%s bind:%s pass:%s returns: %s\n",
                    $uw_config{ldap_uri}, $uw_config{ldap_start_tls},
                    $bind_dn, $pass, $res->error())
    }
    return "invalid password" if $res->code();

    # success
    return (0, $ldap_conn);
}

sub ldap_get_uid ($) {
    my ($user) = @_;
    my ($uid, $res);

    for (my $try = 1; $try < 4; $try++) {
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
            print "restoring ldap connection ($try)\n" if $debug;
            undef $ldap;
            ldap_init();
            # a little delay
            select(undef, undef, undef, ($try - 1) * 0.100);
        } else {
            last;
        }
    }

    my $entry = $res->pop_entry();
    if (!$res->code() && $entry) {
        $uid  = $entry->get_value($uw_config{ldap_attr_uid});
    }

    if ($debug) {
        print sprintf("ldap_get_uid (%s) = (%s) (mesage(%s): %s)\n",
                    $user, $uid, $res->code(), $res->error())
    }
    return $uid;
}

sub mysql_connect () {
    $dbh = DBI->connect(
                "DBI:mysql:$uw_config{mysql_db};host=$uw_config{mysql_host}",
                $uw_config{mysql_user}, $uw_config{mysql_pass})
		or die "cannot connect to database\n";
    $dbh->{mysql_enable_utf8} = 1;
    $dbh->{AutoCommit} = 1;
    $dbh->do("SET NAMES 'utf8'");
}

sub parse_req ($) {
    my ($str) = @_;
    #C:1296872500:::::~:002:192.168.203.4:10.30.4.1:~:002:1296600643:XDM:root:0:/:1296856317:XTY:root:0:/:~

    my @arr = split /:/, $str;
    print "arr:".join(',',map { "$_=$arr[$_]" } (0 .. $#arr))."\n" if $debug;
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

    # find vpn ip
    my $ip;
    for (my $i = 8; $i < $arr[7] + 7; $i++) {
        return "invalid ip"
            if $arr[$i] !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if ($arr[$i] =~ $vpn_regex) {
            if (defined $ip) {
                print "duplicate vpn ip address\n" if $debug;
                next;
            }
            $ip = $arr[$i];
        }
    }
    return "vpn ip not found"
        unless defined $ip;

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

    return { cmd => $cmd, log_usr => $log_usr, ip => $ip, users => \@users };
}

sub handle_req ($) {
    my ($req) = @_;
    my @users = @{ $req->{users} };
    if ($req->{cmd} eq 'I') {
        # login
        my $log_usr = $req->{log_usr};

        my $uid = ldap_get_uid($log_usr->{user});
        return "user not found" unless defined $uid;

        my ($msg) = ldap_connect(undef, $log_usr->{user}, $log_usr->{pass}, 1);
        return $msg if $msg;

        for (my $i = 0; $i <= $#users; $i++) {
            if ($users[$i]->{user} eq $log_usr->{user}) {
                splice @users, $i, 1;
            }
        }
        unshift @users, $log_usr;
    } elsif ($req->{cmd} eq 'O') {
        # logout
    }
    # update database from the array of users
    return "OK";
}

sub main {
    my $config = "$CFG_ROOT/uwserver.conf";
    read_config($config, [ qw(
                    vpn_net mysql_host mysql_db mysql_user mysql_pass
                    ldap_uri ldap_bind_dn ldap_bind_pass ldap_user_base
                ) ],
                [ qw(
                    port ca_cert server_pem mysql_port debug timeout
                    ldap_attr_user ldap_attr_uid ldap_start_tls
                    cache_retention
                ) ]);

    # create regular expression for vpn network
    $vpn_regex = $uw_config{vpn_net};
    die "vpn_net: invalid format \"$vpn_regex\", shall be A.B.C.0\n"
        if $vpn_regex !~ /^[1-9]\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    $vpn_regex =~ s/(\.0+)+$//;
    $vpn_regex .= ".";
    $vpn_regex =~ s/\./\\./g;
    $vpn_regex = qr[$vpn_regex];

    my $msg = ldap_init();
    die "ldap init failed: $msg\n" if $msg;
    mysql_connect();
    ssl_startup();

    $ssl_ctx = ssl_create_context($uw_config{server_pem}, $uw_config{ca_cert});
    $srv_sock = ssl_listen($uw_config{port});
    while ($srv_sock) {
        print "waiting for client...\n" if $debug;
        ($ssl, $conn) = ssl_accept($srv_sock, $ssl_ctx);
        next unless defined $ssl;

        my $ok = 0;
        my $str = ssl_read_packet($ssl, $conn);
        if (defined $str) {
            my $req = parse_req($str);
            if (ref($req) eq 'HASH') {
                print "request ok\n";
                my $ret = handle_req($req);
                ssl_write_packet($ssl, $conn, $ret);
            } else {
                print "invalid request (error:$req)\n";
                ssl_write_packet($ssl, $conn, "invalid request");
            }
        }

        ssl_detach($ssl, $conn);
        undef $ssl;
        undef $conn;
    }
}

my $cleanup_done;

sub cleanup () {
    return if $cleanup_done;
    $cleanup_done = 1;

    ssl_detach($ssl, $conn);
    ssl_detach(undef, $srv_sock);
    undef $ssl;
    undef $conn;
    undef $srv_sock;

    ssl_free_context($ssl_ctx);
    undef $ssl_ctx;

    $dbh->disconnect() if defined $dbh;
    undef $dbh;

    $ldap->unbind() if defined $ldap;
    undef $ldap;

    print "bye\n";
}

$SIG{INT} = $SIG{TERM} = $SIG{QUIT} = \&cleanup;
END { cleanup(); }
main();


