#!/usr/bin/perl
#
# UserWatch
# Common functions
# $Id$
#

use strict;

#
# require: perl-EV
#
use Carp;
use Sys::Syslog;
use POSIX;
use EV;
use Time::HiRes qw(gettimeofday clock_gettime CLOCK_MONOTONIC);

# request header options
use constant OPT_USER_LIST  => 1;
use constant OPT_GET_GROUPS => 2;

##############################################
# Configuration file
#

our $progname = $0;
$progname =~ s!.*/!!g;
$progname =~ s!\..*$!!g;

our $config_root = "/etc/userwatch";
our $status_root = "/var/run/userwatch";
our $config_file = "$config_root/$progname.conf";

our %uw_config =
    (
        # constants
        ifconfig            => "/sbin/ifconfig",
        iptables            => "/sbin/iptables",
        iptables_save       => "/sbin/iptables-save",
        nsupdate            => "/usr/bin/nsupdate",
        etc_passwd          => "/etc/passwd",
        etc_group           => "/etc/group",

        # common parameters
        port                => 7501,
        peer_pem            => "$config_root/$progname.pem",
        ca_cert             => "$config_root/ca.crt",
        pid_file            => "$status_root/$progname.pid",
        daemonize           => 1,
        debug               => 0,
        stacktrace          => 0,
        syslog              => 1,
        stdout              => 0,
        idle_timeout        => 240,
        rw_timeout          => 10,

        # client parameters
        server              => undef,
        also_local          => 0,
        update_interval     => 120,
        connect_interval    => 5,
        unix_socket         => "$status_root/$progname.sock",
        auth_cache_ttl      => 0,
        enable_gmirror      => 0,
        gmirror_conf        => "$config_root/gmirror.conf",
        update_nscd         => 1,
        nscd_pid_file       => "/var/run/nscd/nscd.pid",

        # server parameters (mysql)
        mysql_host          => "localhost",
        mysql_port          => 3306,
        mysql_db            => undef,
        mysql_user          => undef,
        mysql_pass          => undef,

        # server parameters (vpn)
        vpn_net             => undef,
        vpn_scan_interval   => 0,
        vpn_scan_pause      => 3,
        vpn_status_file     => undef,
        vpn_cfg_mask        => undef,
        vpn_event_dir       => $status_root,
        vpn_event_mask      => "openvpn-event.*",
        vpn_archive_dir     => undef,

        # server parameters (ldap)
        ldap_uri            => undef,
        ldap_bind_dn        => undef,
        ldap_bind_pass      => undef,
        ldap_start_tls      => 0,
        ldap_user_base      => undef,
        ldap_group_base     => undef,
        ldap_attr_user      => "uid",
        ldap_attr_uid       => "uidNumber",
        ldap_attr_gid       => "gidNumber",
        ldap_attr_group     => "cn",
        ldap_attr_member    => "memberUid",
        ldap_timeout        => 5,
        ldap_force_fork     => 0,

        # server parameters (operation)
        uid_cache_ttl       => 2,
        group_cache_ttl     => 2,
        user_retention      => 300,
        purge_interval      => 300,
        authorize_permit    => 0,

        # server parameters (iptables)
        iptables_user_vpn   => "",
        iptables_user_real  => "",
        iptables_host_real  => "",
        iptables_status     => "$status_root/$progname.iptables",

        # server parameters (dns)
        ns_server           => "127.0.0.1",
        ns_zone_real        => undef,
        ns_rr_time          => 600,

        # end of parameters
    );

sub read_config ($$$) {
    my ($config, $required, $optional) = @_;
    my (%h_required, %h_allowed);
    $h_allowed{$_} = 1 for (@$required, @$optional);
    $h_required{$_} = 1 for (@$required);

    open (my $file, $config)
        or fail("$config: configuration file not found");
    while (<$file>) {
        next if /^\s*$/ || /^\s*#/;
        if (/^\s*(\w+)\s*=\s*(\S+)\s*$/) {
            my ($param, $value) = ($1, $2);
            $value = "" if $value eq '""' || $value eq "''";
            fail("$config: unknown parameter \"$param\"")
                if !exists($uw_config{$param}) || !exists($h_allowed{$param});
            if ($uw_config{$param} !~ /^\d+$/ || $value =~ /^\d+$/) {
                $uw_config{$param} = $value;
                next;
            }
        }
        fail("$config: configuration syntax error in line $.");
    }
    close ($file);

    for my $param (sort keys %h_required) {
        fail("$config: missing required parameter \"$param\"")
            unless defined $uw_config{$param};
    }

    $uw_config{stdout} = 1 unless $uw_config{syslog};
}

sub require_program ($) {
    my ($prog) = @_;
    my $path = $uw_config{$prog};
    fail("$path: required program not found") unless -x $path;
}

##############################################
# Logging
#

sub log_init () {
    return unless $uw_config{syslog};
    my $prog = $0;
    $prog =~ s!^.*/!!;
    $prog =~ s!\..*$!!;
    openlog($prog, "cons,pid", "daemon");
}

$SIG{__DIE__} = sub { fail(join("\n", @_)); };
$SIG{__WARN__} = sub { info(join("\n", @_)); };

sub fail ($@) {
    my $fmt = shift;
    chomp(my $msg = "[ fail] " . sprintf($fmt, @_));
    syslog("err", $msg) if $uw_config{syslog};
    undef $SIG{__DIE__};
    $msg = sprintf("[%5d] ", $$) . $msg;
    if ($uw_config{stacktrace}) {
        confess(_fmtmsg($msg));
    } else {
        die(_fmtmsg($msg));
    }
}

sub info ($@) {
    my $fmt = shift;
    chomp(my $msg = "[ info] " . sprintf($fmt, @_));
    syslog("notice", $msg) if $uw_config{syslog};
    print _fmtmsg($msg) if $uw_config{stdout};
}

sub debug ($@) {
    return unless $uw_config{debug};
    my $fmt = shift;
    chomp(my $msg = "[debug] " . sprintf($fmt, @_));
    syslog("info", $msg) if $uw_config{syslog};
    print _fmtmsg($msg) if $uw_config{stdout};    
}

sub _fmtmsg ($) {
    my ($msg) = @_;
    my ($sec, $usec) = gettimeofday();
    return sprintf("[%s.%03d] [%5d] %s\n",
                    POSIX::strftime('%H:%M:%S', localtime($sec)),
                    $usec/1000, $$, $msg);
}

##############################################
# Event loop
#

our ($ev_loop, %ev_watch, %ev_chans, $ev_reload);

sub ev_create_loop () {
    $ev_loop = EV::default_loop();
    for my $sig ("INT", "TERM", "QUIT", "HUP") {
        $ev_watch{"s_$sig"}  = $ev_loop->signal($sig,  sub { ev_signaled($sig) });
    }
}

sub ev_signaled ($) {
    my ($signal) = @_;
    debug("catch $signal");
    $ev_loop->unloop();
    $ev_reload++ if $signal eq "HUP";
}

sub ev_add_chan ($;$$$) {
    my ($chan, $watch_name, $event_mask, $event_handler) = @_;
    return unless defined $chan;
    $ev_chans{$chan} = $chan;
    my $watch = 0;
    if ($watch_name) {
        $watch = $ev_loop->io($chan->{conn}, $event_mask,
                                sub { &$event_handler($chan) });
        $ev_watch{$watch_name} = $watch;
        $chan->{watch_name} = $watch_name;
    }
    return $watch;
}

sub ev_close ($) {
    my ($chan) = @_;
    if (defined $chan->{destructor}) {
        &{$chan->{destructor}}($chan);
        undef $chan->{destructor};
    }
    if (defined $chan->{watch_name}) {
        delete $ev_watch{$chan->{watch_name}};
        delete $chan->{watch_name};
    }
    delete $ev_chans{$chan};
}

sub ev_close_all () {
    ev_close($_) for (values %ev_chans);
    %ev_chans = ();
}

sub ev_remove_handlers () {
    delete $ev_watch{$_} for (keys %ev_watch);
    %ev_watch = ();
}

##############################################
# Idle timeout handling
#

sub init_timeouts ($$) {
    my ($chan, $close_handler) = @_;

    unless ($close_handler) {
        delete $chan->{close_handler};
        delete $chan->{idle_watch};
        delete $chan->{rwt_watch};
        return;
    }
    $chan->{close_handler} = $close_handler;

    if ($uw_config{idle_timeout} > 0) {
        $chan->{idle_timeout} = $uw_config{idle_timeout};
        $chan->{idle_watch} = $ev_loop->timer(
                                $chan->{idle_timeout}, $chan->{idle_timeout},
                                sub { _chan_timeout_handler($chan, 'idle') }
                                );
    }

    if ($uw_config{rw_timeout} > 0) {
        $chan->{rw_timeout} = $uw_config{rw_timeout};
        $chan->{rwt_watch} = $ev_loop->timer_ns(
                                $chan->{rw_timeout}, $chan->{rw_timeout},
                                sub { _chan_timeout_handler($chan, 'rw') }
                                );
    }
}

sub init_transmission ($$$) {
    my ($chan, $event_mask, $event_handler) = @_;
    $chan->{io_watch} = $ev_loop->io($chan->{conn}, $event_mask,
                                    sub { &$event_handler($chan) });
    $chan->{event_mask} = $event_mask;
    $chan->{rwt_fired} = 0;
}

sub change_event_mask ($$) {
    my ($chan, $event_mask) = @_;
    if ($chan->{event_mask} != $event_mask && $chan->{io_watch}) {
        $chan->{event_mask} = $event_mask;
        $chan->{io_watch}->events($event_mask);
    }
}

sub fire_transmission ($) {
    my ($chan) = @_;
    if ($chan->{rwt_watch} && !$chan->{rwt_fired}) {
        $chan->{rwt_watch}->again();
        $chan->{rwt_fired} = 1;
    }
}

sub end_transmission ($) {
    my ($chan) = @_;
    if ($chan->{rwt_watch} && $chan->{rwt_fired}) {
        $chan->{rwt_watch}->stop();
        $chan->{rwt_fired} = 0;
    }
    delete $chan->{io_watch};
}

sub postpone_timeouts ($) {
    my ($chan) = @_;
    $chan->{idle_watch}->again() if $chan->{idle_watch};
    $chan->{rwt_watch}->again() if $chan->{rwt_watch};
}

sub _chan_timeout_handler ($$) {
    my ($chan, $reason) = @_;
    debug("%s: %s timeout disconnect", $chan->{addr}, $reason);
    &{$chan->{close_handler}}($chan);
    ssl_disconnect($chan);
}

##############################################
# Daemonization
#

my  ($in_parent, $pid_written, $already_daemon, %temp_files);

sub daemonize () {
    return 0 if !$uw_config{daemonize} || $already_daemon;

    my $pid_file = $uw_config{pid_file};
    if ($pid_file) {
        if (-e $pid_file) {
            my $pid = read_file($pid_file);
            $pid = int($pid);
            fail("another $progname runs with pid $pid")
                if $pid && kill(0, $pid);
            unlink($pid_file);
            info("remove stale pid file $pid_file");
        }
        create_parent_dir($pid_file);
    }

    defined(my $pid = fork())  or fail("can't fork: $!");
    $in_parent = $pid;
    if ($in_parent) {
        debug("parent exits");
        exit(0);
    }

    detach_stdio();
    chdir('/')                 or fail("can't chdir to /: $!");
    setsid()                   or fail("can't start a new session: $!");
    umask(022);

    $| = 1;
    write_file($pid_file, $$) if $pid_file;
    $pid_written = 1;

    debug("daemonized");
    $already_daemon = 1;
    return $$;
}

sub detach_stdio () {
    open(STDIN,  '</dev/null') or fail("can't read /dev/null: $!");
    open(STDOUT, '>/dev/null') or fail("can't write to /dev/null: $!");
    open(STDERR, '>/dev/null') or fail("can't write to /dev/null: $!");
    $uw_config{stdout} = 0;
}

sub end_daemon () {
    unlink($_) for (keys %temp_files);
    %temp_files = ();
    return if $in_parent || $ev_reload;
    unlink($uw_config{pid_file}) if $pid_written;
    info("$progname finished");
}

##############################################
# scan /etc/passwd and /etc/group
#

our (%local_users, %local_groups);
our ($etc_passwd_str, $etc_passwd_sign);
our ($etc_group_str, $etc_group_sign);

sub rescan_etc () {
    my ($sign) = super_stat($uw_config{etc_passwd});
    if ($sign ne $etc_passwd_sign) {
        $etc_passwd_sign = $sign;
        $etc_passwd_str = read_file($uw_config{etc_passwd})
            or fail("$uw_config{etc_passwd}: cannot open");
        %local_users = ();
        for (split /\n/, $etc_passwd_str) {
            next unless m"^([a-xA-Z0-9\.\-_]+):\w+:(\d+):\d+:";
            $local_users{$1} = $2;
        }
        debug("local users: " . join(",", sort keys %local_users));
    }

    ($sign) = super_stat($uw_config{etc_group});
    if ($sign ne $etc_group_sign) {
        $etc_group_sign = $sign;
        $etc_group_str = read_file($uw_config{etc_group})
            or fail("$uw_config{etc_group}: cannot open");
        %local_groups = ();
        for (split /\n/, $etc_group_str) {
            next unless m"^([\w\d\.\-_]+):\w+:(\d+):";
            $local_groups{$1} = $2;
        }
        debug("local groups: " . join(",", sort keys %local_groups));
    }
}

##############################################
# Utilities
#

sub create_parent_dir ($) {
    my ($path) = @_;
    (my $parent = $path) =~ s!/+[^/]*$!!;
    fail("$parent: path must be absolute") if $parent !~ m!^/!;
    my @dirs;
    for (my $dir = $parent; length($dir) > 1; $dir =~ s!/+[^/]*$!!) {
        unshift @dirs, $dir;
    }
    for my $dir (@dirs) {
        mkdir($dir) unless -d $dir;
    }
    (-d $parent) or fail("$parent: directory does not exist");
    (-w $parent) or fail("$parent: directory is not writable");
}

sub add_temp_file ($) {
    my ($temp) = @_;
    $temp = "/tmp/xxx.$progname.run.".time().".$$"
        unless defined $temp;
    $temp_files{$temp} = 1;
    return $temp;
}

sub del_temp_file ($) {
    my ($temp) = @_;
    unlink($temp);
    delete $temp_files{$temp};
}

#
# run a program
# returns -1 if program not found
# returns -2 if program aborted
#
sub run_prog ($;$) {
    my ($cmd, $out_ref) = @_;
    my $kid;
    my ($prog, @params) = split(/\s+/, $cmd);
    unless (-x $prog) {
        info("$prog: program not found");
        return -1;
    }
    if ($out_ref && 1) {
        my $temp = add_temp_file(undef);
        system("$cmd >$temp 2>&1");
        $kid = $?;
        $$out_ref = read_file($temp);
        del_temp_file($temp);
    } else {
        system("$cmd >/dev/null 2>&1");
        $kid = $?;
    }
    my $ret = ($kid & 127) ? -2 : ($kid >> 8);
    return $ret;
}

sub super_stat ($) {
    my ($path) = @_;
    my @st = stat($path);
    my ($mode, $uid, $gid, $size, $mtime, $ctime) = @st[2,4,5,7,9,10];
    my $sign = "[$mode|$uid|$gid|$size|$mtime|$ctime]";
    return ($sign, $mode, $uid, $gid);
}

sub read_file ($) {
    my ($path) = @_;
    open(my $file, $path) or return;
    my $rs = $/;
    undef $/;
    my $out = <$file>;
    $/ = $rs;
    close($file);
    return $out;
}

sub write_file ($$) {
    my ($path, $out) = @_;
    open(my $file, "> $path") or return;
    print $file $out;
    close($file);
    my ($sign) = super_stat($path);
    return $sign;
}

sub monotonic_time () {
    return clock_gettime(CLOCK_MONOTONIC);
}

##############################################
1;

