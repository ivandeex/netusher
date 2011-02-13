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

##############################################
# Configuration file
#

our $progname = $0;
$progname =~ s!.*/!!g;
$progname =~ s!\..*$!!g;

our $config_root = '/etc/userwatch';
our $status_root = '/var/run/userwatch';
our $config_file = "$config_root/$progname.conf";

our %uw_config =
    (
        # constants
        ifconfig        => "/sbin/ifconfig",
        iptables        => "/sbin/iptables",
        iptables_save   => "/sbin/iptables-save",

        # common parameters
        port            => 7501,
        peer_pem        => "$config_root/$progname.pem",
        ca_cert         => "$config_root/ca.crt",
        pid_file        => "$status_root/$progname.pid",
        daemonize       => 1,
        debug           => 0,
        stacktrace      => 0,
        syslog          => 1,
        stdout          => 0,
        idle_timeout    => 240,
        rw_timeout      => 10,

        # client parameters
        server          => undef,
        also_local      => 0,
        update_interval => 120,
        connect_interval => 5,
        unix_socket     => "$status_root/$progname.sock",
        auth_cache_ttl  => 0,

        # server parameters
        mysql_host      => "localhost",
        mysql_port      => 3306,
        mysql_db        => undef,
        mysql_user      => undef,
        mysql_pass      => undef,
        vpn_net         => undef,
        ldap_uri        => undef,
        ldap_bind_dn    => undef,
        ldap_bind_pass  => undef,
        ldap_start_tls  => 0,
        ldap_force_fork => 0,
        ldap_user_base  => undef,
        ldap_attr_user  => 'uid',
        ldap_attr_uid   => 'uidNumber',
        ldap_timeout    => 5,
        uid_cache_ttl   => 2,
        user_retention  => 300,
        purge_interval  => 300,
        iptables_vpn    => '',
        iptables_real   => '',
        iptables_status => "$status_root/$progname.iptables",

        # end of parameters
    );

sub read_config ($$$$) {
    my ($config, $required, $optional, $programs) = @_;
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
        fail("$config: configuration error in line $.");
    }
    close ($file);

    for my $param (sort keys %h_required) {
        fail("$config: missing required parameter \"$param\"")
            unless defined $uw_config{$param};
    }

    $uw_config{stdout} = 1 unless $uw_config{syslog};

    for my $prog (@$programs) {
        my $path = $uw_config{$prog};
        fail("$path: required program not found") unless -x $path;
    }
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

sub monotonic_time () {
    return clock_gettime(CLOCK_MONOTONIC);
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
        fail("$pid_file: pid file already exists") if -e $pid_file;
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
    if (open(my $pf, "> $pid_file")) {
        print $pf $$;
        close $pf;
    }
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

sub create_parent_dir ($) {
    my ($path) = @_;
    (my $dir = $path) =~ s!/+[^/]*$!!;
    mkdir($dir);
    (-d $dir) or fail("$dir: directory does not exist");
    (-w $dir) or fail("$dir: directory is not writable");
}

sub end_daemon () {
    unlink($_) for (keys %temp_files);
    %temp_files = ();
    return if $in_parent || $ev_reload;
    unlink($uw_config{pid_file}) if $pid_written;
    info("$progname finished");
}

sub run_prog ($;$) {
    my ($cmd, $out_ref) = @_;
    my $kid;
    if ($out_ref && 1) {
        $SIG{PIPE} = "IGNORE";
        my ($out, $file, $temp, $rs);
        $temp = "/tmp/xxx.$progname.run.".time().".$$";
        $temp_files{$temp} = 1;
        system("$cmd >$temp 2>&1");
        $kid = $?;
        open($file, $temp);
        $rs = $/; undef $/;
        $out = <$file>; $$out_ref = $out; undef $out;
        $/ = $rs;
        close($file);
        unlink($temp);
        delete $temp_files{$temp};
    } else {
        system("$cmd >/dev/null 2>&1");
        $kid = $?;
    }
    my $ret = ($kid & 127) ? -255 : ($kid >> 8);
    return $ret;
}

##############################################
1;

