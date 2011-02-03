#!/usr/bin/perl
#
# UserWatch SSL client
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/userwatch.inc.pm";

#
# you can obtain RPM from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/perl-User-Utmp.html
#
use User::Utmp qw(:constants :utmpx);

our ($CFG_ROOT, $debug, %uw_config);

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

sub get_user_list () {
    my @user_list;
    print "user_list" if $debug;

    # read user names from /etc/passwd
    my %local_uid;
    open(my $passwd, "/etc/passwd")
        or die "/etc/passwd: cannot open\n";
    while (<$passwd>) {
        next unless m"^([a-xA-Z0-9\.\-_]+):\w+:(\d+):\d+:";
        $local_uid{$1} = $2;
    }
    close($passwd);
    

    for my $ut (sort { $a->{ut_time} <=> $b->{ut_time} } getutx) {
        next unless $ut->{ut_type} == USER_PROCESS;

        # filter out local users
        my $user = $ut->{ut_user};
        next if !$uw_config{also_local} && exists($local_uid{$user});

        # detect login methos
        my $method;
        my $id = $ut->{ut_id};
        if ($id =~ m"^s/\d+$") { $method = "RSH" }
        elsif ($id =~ m"^\d+$") { $method = "CON" }
        elsif ($id =~ m"^:\d+(\.\d+)?$") { $method = "XDM" }
        elsif ($id =~ m"^/\d+$") { $method = "XTY" }
        else { $method = "UNK" }

        # detect user id
        my $uid = "";
        if (exists $local_uid{$user}) {
            $uid = $local_uid{$user};
        } else {
            my ($xname, $xpass, $xuid) = getpwnam($user);
            $uid = $xuid if defined $xuid;
        }

        my $u = [ $user, $uid, $method, $ut->{ut_time} ];
        push @user_list, $u;
        print ":[$user,$uid,$method,".$ut->{ut_time}."]" if $debug;
    }

    print ".\n" if $debug;
    return @user_list;
}

sub create_request ($$;$$) {
    my ($cmd, $do_get_list, $log_usr, $pass) = @_;

    my $line = sprintf(':%s:%09d:', $cmd, time);

    if ($log_usr) {
        $line .= sprintf('%3s:%s:%s:%s',
                    $log_usr->[2], $log_usr->[0], $log_usr->[1],
                    defined($pass) ? $pass : "");
    } else {
        $line .= ":::";
    }

    my @ip_list = get_ip_list();
    $line .= ":~:" . sprintf('%03d:', $#ip_list + 1)
            . join(':', @ip_list) . ":~:";

    if ($do_get_list) {
        my (@user_list) = get_user_list();
        $line .= sprintf('%03d', $#user_list + 1);
        for my $u (@user_list) {
            $line .= sprintf(':%09d:%3s:%s:%s:/',
                    $u->[3], $u->[2], $u->[0], $u->[1]);
        }
    } else {
        $line .= "---";
    }

    $line .= ":~\n";
    $line = sprintf("%04d", length($line) + 4) . $line;
    return $line;
}

sub main () {
    my $config = "$CFG_ROOT/uwclient.conf";
    read_config($config);
    die "$config: server host undefined\n" unless $uw_config{server};
    my $request = create_request("C", 1);
    print $request if $debug;
    print "done\n";
}

main();

