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

##############################################
# Configuration file
#

our $progname = $0;
$progname =~ s!.*/!!g;
$progname =~ s!\..*$!!g;

our $config_root = '/etc/userwatch';
our $config_file = "$config_root/$progname.conf";

our %uw_config = (
        # common parameters
        port            => 7501,
        peer_pem        => "$config_root/$progname.pem",
        ca_cert         => "$config_root/ca.crt",
        pid_file        => "/var/run/userwatch/$progname.pid",
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
        unix_socket     => "/var/run/userwatch/$progname.sock",
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
        cache_retention => 300,
        user_retention  => 300,
        purge_interval  => 300,
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
        fail("$config: configuration error in line $.");
    }
    close ($file);

    for my $param (sort keys %h_required) {
        fail("$config: missing required parameter \"$param\"")
            unless defined $uw_config{$param};
    }

    $uw_config{stdout} = 1 unless $uw_config{syslog};
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
        confess($msg);
    } else {
        die($msg);
    }
}

sub info ($@) {
    my $fmt = shift;
    chomp(my $msg = "[ info] " . sprintf($fmt, @_));
    syslog("notice", $msg) if $uw_config{syslog};
    printf("[%5d] %s\n", $$, $msg) if $uw_config{stdout};
}

sub debug ($@) {
    return unless $uw_config{debug};
    my $fmt = shift;
    chomp(my $msg = "[debug] " . sprintf($fmt, @_));
    syslog("info", $msg) if $uw_config{syslog};
    printf("[%5d] %s\n", $$, $msg) if $uw_config{stdout};    
}

##############################################
# Daemonization
#

my  ($in_parent, $pid_written);

sub daemonize () {
    return 0 unless $uw_config{daemonize};

    my $pid_file = $uw_config{pid_file};
    if ($pid_file) {
        fail("$pid_file: pid file already exists") if -e $pid_file;
        (my $pid_dir = $pid_file) =~ s!/+[^/]*$!!;
        mkdir($pid_dir);
        (-d $pid_dir) or fail("$pid_dir: directory does not exist");
        (-w $pid_dir) or fail("$pid_dir: directory is not writeable");
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
    return $$;
}

sub detach_stdio () {
    open(STDIN,  '</dev/null') or fail("can't read /dev/null: $!");
    open(STDOUT, '>/dev/null') or fail("can't write to /dev/null: $!");
    open(STDERR, '>/dev/null') or fail("can't write to /dev/null: $!");
    $uw_config{stdout} = 0;
}

sub end_daemon () {
    unless ($in_parent) {
        unlink($uw_config{pid_file}) if $pid_written;
        info("$progname finished");
    }
}

##############################################
# Event loop
#

our ($ev_loop, %ev_watch, %ev_chans);

sub ev_create_loop () {
    $ev_loop = EV::default_loop();
    $ev_watch{s_int} = $ev_loop->signal('INT', sub { ev_signaled('INT') });
    $ev_watch{s_term} = $ev_loop->signal('TERM', sub { ev_signaled('TERM') });
    $ev_watch{s_quit} = $ev_loop->signal('QUIT', sub { ev_signaled('QUIT') });
}

sub ev_signaled ($) {
    my ($signal) = @_;
    debug("catch $signal");
    $ev_loop->unloop();
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

sub fire_transmission ($;$) {
    my ($chan, $new_event_mask) = @_;
    if (defined($new_event_mask) && $chan->{event_mask} != $new_event_mask) {
        $chan->{event_mask} = $new_event_mask;
        $chan->{io_watch}->events($new_event_mask);
    }
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
1;

