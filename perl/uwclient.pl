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

our ($config_file, $progname, %uw_config, $ev_loop, %ev_watch);
my  (%chans, $srv_chan, @jobs, $finished);
my  (%local_users, $passwd_modified_stamp);

#
# scan interfaces
#
sub get_ip_list () {
    my @ip_list;
    my $ifconfig = "/sbin/ifconfig";
    $SIG{PIPE} = "IGNORE";
    my $pid = open(my $out, "$ifconfig 2>/dev/null |");
    fail("$ifconfig: executable not found") unless $pid;
    while (<$out>) {
        next unless m"^\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w";
        next if $1 eq "127.0.0.1";
        push @ip_list, $1;
    }
    close($out);
    my $kid = waitpid($pid, 0);
    debug("ip_list: %s", join(',', @ip_list));
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
    debug("updating local user list");
    %local_users = ();
    open(my $passwd, $passwd_path)
        or fail("$passwd_path: cannot open");
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
        debug("user_list next: user:%s uid:%s method:%s beg_time:%s",
                $user, $uid, $method, $u->{beg_time});
    }

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
# typical operations
#

sub update_active_users () {
    debug("update active users");
    return unless $srv_chan;
    my $req = create_request("C", 1);
    queue_job($req, undef);
}

sub user_login ($$$;$) {
    my ($method, $user, $pass, $uid) = @_;
    get_local_users();
    if (!$uw_config{also_local} && exists($local_users{$user})) {
        debug("$user: is local user");
        return "OK";
    }
    my $req = create_request("I", 0, {
                method => $method, user => $user, pass => $pass, uid => $uid
                });
    queue_job($req, undef);
}

sub user_logout ($$) {
    my ($method, $user) = @_;
    my $req = create_request("O", 0, {
                method => $method, user => $user, uid => 0
                });
    queue_job($req, undef);
}

#
# main loop
#

sub main () {
    read_config($config_file, [ qw(
                    server
                )],
                [ qw(
                    port ca_cert peer_pem update_interval also_local
                    connect_interval idle_timeout timeout
                    syslog stdout debug stacktrace daemonize
                )]);
    fail("$config_file: server host undefined")
        unless $uw_config{server};
    log_init();

    ssl_startup();
    ssl_create_context($uw_config{peer_pem}, $uw_config{ca_cert});

    ev_create_loop();
    if (daemonize()) {
        # clone event loop in the child
        $ev_loop->loop_fork();
    }

    reconnect(1);
    $ev_watch{update} = $ev_loop->timer(0, $uw_config{update_interval},
                                        \&update_active_users);

    info("$progname started");
    $ev_loop->loop();
    exit(0);
}

#
# job queue
#

sub queue_job ($$) {
    my ($req, $waiter) = @_;
    push @jobs, { req => $req, waiter => $waiter };
    handle_next_job();
}

sub handle_next_job () {
    unless (@jobs) {
        debug("no jobs");
        return;
    }
    unless ($srv_chan) {
        debug("handle next job: no connection");
        return;
    }

    my $job = shift @jobs;
    debug("sending job %s", $job->{req});
    ssl_write_packet($srv_chan, $job->{req}, \&srv_writing_done, $job);
}

#
# reconnections
#

sub reconnect (;$) {
    my ($now) = @_;

    # close previous server connection, if any
    if ($srv_chan) {
        debug("disconnect previous server connection");
        close_channel($srv_chan);
        undef $srv_chan;
    }

    # initiate new connection to server
    delete $ev_watch{try_con};
    delete $ev_watch{wait_con};
    $ev_watch{try_con} = $ev_loop->timer(
                            $now ? 0 : $uw_config{connect_interval},
                            $uw_config{connect_interval},
                            \&connect_attempt);
    debug("reconnection started...");
}

sub connect_attempt () {
    debug("try to connect...");
    my $chan = ssl_connect($uw_config{server}, $uw_config{port},
                            \&close_channel);
    return unless $chan;

    delete $ev_watch{try_con};
    delete $ev_watch{wait_con};

    if ($chan->{pending}) {
        #debug("connection is pending, wating on socket");
        $chans{$chan} = $chan;
        $ev_watch{wait_con} = $ev_loop->io($chan->{conn},
                                        &EV::READ | &EV::WRITE,
                                        sub { connect_pending($chan) });
        return;
    }

    on_connect($chan, "at once");
}

sub connect_pending ($) {
    my ($chan) = @_;
    my $code = ssl_connected($chan);
    if ($code eq "pending") {
        debug("connection still pending...");
        return;
    }

    if ($code ne "ok") {
        debug("connection aborted");
        $srv_chan = $chan;
        reconnect();
        return;
    }

    delete $ev_watch{wait_con};
    on_connect($chan, "after wait");
}

sub on_connect ($$) {
    my ($chan, $msg) = @_;

    debug('successfully connected to server (%s)', $msg);
    $ev_watch{update}->set(0, $uw_config{update_interval});
    $chans{$chan} = $srv_chan = $chan;
    handle_next_job();
}

#
# reading and writing
#

sub srv_writing_done ($$$) {
    my ($chan, $success, $job) = @_;

    unless ($success) {
        unshift @jobs, $job;
        reconnect();
        return;
    }

    ssl_read_packet($srv_chan, \&srv_reading_done, $job);
}

sub srv_reading_done ($$$) {
    my ($chan, $reply, $job) = @_;

    unless (defined $reply) {
        unshift @jobs, $job;
        reconnect();
        return;        
    }

    debug('received reply %s', $reply);
    handle_next_job();
}

#
# cleanup
#

sub close_channel ($) {
    my ($chan) = @_;
    ssl_disconnect($chan);
    delete $chans{$chan};
    if ($srv_chan eq $chan) {
        undef $srv_chan;
        reconnect() unless $finished;
    }
}

sub cleanup () {
    $finished = 1;
    close_channel($_) for (values %chans);
    %chans = ();
    ssl_destroy_context();
    end_daemon();
}

END { cleanup(); }
main();

