#!/usr/bin/perl
#
# UserWatch SSL client
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/userwatch.inc.pm";

#
# require: perl-User-Utmp
#
# you can obtain perl-User-Utmp RPM from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/perl-User-Utmp.html
#
use User::Utmp qw(:constants :utmpx);

our ($CFG_ROOT, $debug, %uw_config);
our ($ssl_ctx, $ssl, $conn);
our (%local_users, $passwd_modified_stamp);

#
# scan interfaces
#
sub get_ip_list () {
    my @ip_list;
    my $ifconfig = "/sbin/ifconfig";
    $SIG{PIPE} = "IGNORE";
    my $pid = open(my $out, "$ifconfig 2>/dev/null |");
    die "$ifconfig: executable not found\n" unless $pid;
    while (<$out>) {
        next unless m"^\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w";
        next if $1 eq "127.0.0.1";
        push @ip_list, $1;
    }
    close($out);
    my $kid = waitpid($pid, 0);
    print "ip_list:" . join(',', @ip_list) . "\n"
        if $debug;
    return @ip_list;
}

#
# get list of local user names from /etc/passwd
#
sub get_local_users () {
    # check whether file was modified
    my $passwd_path = "/etc/passwd";
    my $modified = -M($passwd_path);
    return if $modified eq $passwd_modified_stamp;
    $passwd_modified_stamp = $modified;

    # if the file was modified, refresh the hash
    print "updating local user list\n" if $debug;
    %local_users = ();
    open(my $passwd, $passwd_path)
        or die "$passwd_path: cannot open\n";
    while (<$passwd>) {
        next unless m"^([a-xA-Z0-9\.\-_]+):\w+:(\d+):\d+:";
        $local_users{$1} = $2;
    }
    close($passwd);
}

#
# get list of active users
#
sub get_user_list () {
    # scan utmpx
    print "user_list" if $debug;
    my @user_list;

    for my $ut (sort { $a->{ut_time} <=> $b->{ut_time} } getutx()) {
        next unless $ut->{ut_type} == USER_PROCESS;
        # filter out local users
        my $user = $ut->{ut_user};
        next if !$uw_config{also_local} && exists($local_users{$user});

        # detect login methos
        my $method;
        my $id = $ut->{ut_id};
        if ($id =~ m"^s/\d+$") { $method = "RSH" }
        elsif ($id =~ m"^\d+$") { $method = "CON" }
        elsif ($id =~ m"^:\d+(\.\d+)?$") { $method = "XDM" }
        elsif ($id =~ m"^/\d+$") { $method = "XTY" }
        elsif ($ut->{ut_addr}) { $method = "RSH" }
        else { $method = "UNK" }

        # detect user id
        my $uid = "";
        if (exists $local_users{$user}) {
            $uid = $local_users{$user};
        } else {
            my ($xname, $xpass, $xuid) = getpwnam($user);
            $uid = $xuid if defined $xuid;
        }

        my $u = {
                beg_time => $ut->{ut_time},
                method => $method,
                user => $user,
                uid => $uid,
                };
        push @user_list, $u;
        print ":[$user,$uid,$method,".$u->{beg_time}."]" if $debug;
    }

    print ".\n" if $debug;
    return @user_list;
}

#
# make the request packet
#
sub create_request ($$;$) {
    my ($cmd, $do_get_list, $log_usr) = @_;

    my $line = sprintf('%s:%09d:', $cmd, time);

    $log_usr = {} unless defined $log_usr;
    $line .= sprintf('%s:%s:%s:%s',
                    $log_usr->{method}, $log_usr->{user},
                    $log_usr->{uid}, $log_usr->{pass});

    my @ip_list = get_ip_list();
    $line .= ":~:" . sprintf('%03d:', $#ip_list + 1)
            . join(':', @ip_list) . ":~:";

    if ($do_get_list) {
        get_local_users();
        my (@user_list) = get_user_list();
        $line .= sprintf('%03d', $#user_list + 1);
        for my $u (@user_list) {
            $line .= sprintf(':%09d:%3s:%s:%s:/',
                            $u->{beg_time}, $u->{method},
                            $u->{user}, $u->{uid});
        }
    } else {
        $line .= "---";
    }

    return $line . ":~";
}

#
# wrappers
#
sub cron_job () {
    my $req = create_request("C", 1);
    ssl_write_packet($ssl, $conn, $req);
    return ssl_read_packet($ssl, $conn);
}

sub user_login ($$$;$) {
    my ($method, $user, $pass, $uid) = @_;
    get_local_users();
    if (!$uw_config{also_local} && exists($local_users{$user})) {
        print "$user: is local user\n" if $debug;
        return "OK";
    }
    my $req = create_request("I", 0, {
                method => $method, user => $user, pass => $pass, uid => $uid
                });
    ssl_write_packet($ssl, $conn, $req);
    return ssl_read_packet($ssl, $conn);
}

sub user_logout ($$) {
    my ($method, $user) = @_;
    my $req = create_request("O", 0, {
                method => $method, user => $user, uid => 0
                });
    ssl_write_packet($ssl, $conn, $req);
    return ssl_read_packet($ssl, $conn);    
}

sub main () {
    my $config = "$CFG_ROOT/uwclient.conf";
    read_config($config,
                [ qw(server) ],
                [ qw(port ca_cert client_pem also_local debug timeout) ]);
    die "$config: server host undefined\n" unless $uw_config{server};
    ssl_startup();
    $ssl_ctx = ssl_create_context($uw_config{client_pem}, $uw_config{ca_cert});
    ($ssl, $conn) = ssl_connect($uw_config{server}, $uw_config{port}, $ssl_ctx);
    unless (defined $ssl) {
        print "cannot connect to server\n";
        return;
    }
    print "connected\n";
    cron_job();
}

my $cleanup_done;

sub cleanup () {
    return if $cleanup_done;
    $cleanup_done = 1;

    ssl_detach($ssl, $conn);
    undef $ssl;
    undef $conn;

    ssl_free_context($ssl_ctx);
    undef $ssl_ctx;

    print "bye\n";
}

$SIG{INT} = $SIG{TERM} = $SIG{QUIT} = \&cleanup;
END { cleanup(); }
main();

