#!/usr/bin/perl
#
# UserWatch
# Client daemon
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";
require "$Bin/uw-ssl.inc.pm";
require "$Bin/uw-cache.inc.pm";
require "$Bin/uw-groups.inc.pm";

use IO::Socket::UNIX;

#
# require: perl-IO-Handle-Record and perl-Class-Member
#
# you can obtain these modules from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/letter_p.group.html
#
use IO::Handle::Record; # for peercred

our ($config_file, $progname, %uw_config);
our ($ev_loop, %ev_watch, $ev_reload);
our (%local_users);
my  ($srv_chan, @jobs, $finished);
my  ($reconnect_pending, $reconnect_fast);

our %cache_backend = (
        );

##############################################
# typical operations
#

sub handle_unix_request ($$) {
    my ($chan, $req) = (@_);
    my (@arg) = split(/\s+/, $req);
    my $cmd = $arg[0];
    rescan_etc();

    if ($cmd eq "echo") {
        $req =~ s/^\s*\w+\s+//;
        return $req;
    } elsif ($cmd eq "update") {
        return $#arg != 0 ? "usage: update"
                    : update_active($chan);
    } elsif ($cmd eq "auth") {
        return $#arg != 2 ? "usage: auth user pass"
                    : user_auth($arg[1], $arg[2], $chan);
    } elsif ($cmd eq "groups") {
        return $#arg != 1 ? "usage: groups user"
                    : user_groups($arg[1], $chan);
    } elsif ($cmd eq "login") {
        return $#arg != 2 ? "usage: login user xdm|net|con|pty"
                    : user_login($arg[1], $arg[2], $chan);
    } elsif ($cmd eq "logout") {
        return $#arg != 2 ? "usage: logout user xdm|net|con|pty"
                    : user_logout($arg[1], $arg[2], $chan);
    } else {
        return "usage: echo|update|auth|groups|login|logout [args...]";
    }
}

#
# handle extra fields of the reply from server
#
sub handle_reply ($$$) {
    my ($job, $reply, $groups) = @_;
    if ($job->{info}) {
        info($job->{info} . ": " . $reply);
    }
    if ($groups && $uw_config{enable_gmirror}) {
        handle_groups($job, $groups);
    }
    if ($job->{cmd} eq "auth" && $job->{user}) {
        update_auth_cache($job->{user}, $job->{pass}, $reply);
    }
    if ($uw_config{enable_gmirror}) {
        gmirror_apply($job);
    }
}

sub update_active ($) {
    my ($chan) = @_;
    debug("update active");
    return "no connection" unless $srv_chan;

    my (@users) = get_active_users();
    my $all = join("|", map { join(",", @$_{qw[user method beg_time]}) } @users);
    my $opts = "";
    $opts .= "g" if $uw_config{enable_gmirror};
    my $req = join(":", $opts, get_ips(), $all);
    queue_job("update", $req, $chan);

    # return nothing so that channel will wait for server reply
    return;
}

sub user_auth ($$$) {
    my ($user, $pass, $chan) = @_;

    if (is_local_user($user)) {
        debug("$user: local user auth");
        return "local user auth";
    }

    my $req = "$user:$pass";
    if (check_auth_cache($user, $pass) == 0) {
        info("$user: user login: OK (cached)");
        queue_job("auth", $req, undef);
        return "success";
    }
    queue_job("auth", $req, $chan, info => "$user: auth",
                user => $user, pass => $pass);

    # return nothing so that channel will wait for server reply
    return;
}

sub user_groups ($$) {
    my ($user, $chan) = @_;
    if (is_local_user($user)) {
        debug("$user: local user groups");
        return "success";
    }

    queue_job("groups", $user, $chan, user => $user);

    # return nothing so that channel will wait for server reply
    return;
}

sub user_login ($$$) {
    my ($user, $method, $chan) = @_;
    if (is_local_user($user)) {
        debug("$user: local user login");
        return "success";
    }

    my $req = join(":", $user, $method, time, get_ips());
    queue_job("login", $req, $chan, info => "$user: login",
                user => $user, method => $method);

    # return nothing so that channel will wait for server reply
    return;
}

sub user_logout ($$$) {
    my ($user, $method, $chan) = @_;
    if (is_local_user($user)) {
        debug("$user: local user logout");
        return "local";
    }

    # maybe other such users still exist?
    for my $u (get_active_users()) {
        if ($u->{user} eq $user && $u->{method} eq $method) {
            debug("$user: more users exist with method $method");
            return "got more";
        }
    }

    my $req = join(":", $user, $method, time, get_ips());
    queue_job("logout", $req, $chan, info => "$user: logout",
                user => $user, method => $method);

    # return nothing so that channel will wait for server reply
    return;
}

#
# scan interfaces
#
sub get_ips () {
    my ($ips, $out);
    run_prog($uw_config{ifconfig}, \$out);
    for (split /\n/, $out) {
        next unless m"^\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w";
        next if $1 eq "127.0.0.1";
        $ips .= $1 . ",";
    }
    $ips =~ s/,$//;
    debug("ip list: $ips");
    return $ips;
}

##############################################
# job queue
#

sub queue_job ($$$$) {
    my ($cmd, $req, $chan, %job) = @_;
    $job{cmd} = $cmd;
    $job{req} = "$cmd:$req";
    $job{chan} = $chan;
    $job{source} = $chan ? $chan->{addr} : "none";
    push @jobs, \%job;
    handle_next_job();
}

sub handle_next_job () {
    unless (@jobs) {
        debug("next job: queue empty");
        return;
    }
    unless ($srv_chan) {
        debug("next job: no connection");
        return;
    }
    if ($srv_chan->{io_watch}) {
        debug("next job: another job running");
        return;
    }

    my $job = shift @jobs;
    debug("sending job %s from %s", $job->{req}, $job->{source});
    ssl_write_packet($srv_chan, $job->{req}, \&_srv_write_done, $job);
}

##############################################
# reconnections
#

sub reconnect () {
    $reconnect_pending = 1;
    cache_flush();

    # close previous server connection, if any
    if ($srv_chan) {
        debug("disconnect previous server connection");
        ev_close($srv_chan);
        undef $srv_chan;
    }

    # initiate new connection to server
    delete $ev_watch{try_con};
    delete $ev_watch{wait_con};
    my $interval = $uw_config{connect_interval};
    $ev_watch{try_con} = $ev_loop->timer(
                            ($reconnect_fast ? 0 : $interval), $interval,
                            \&connect_attempt);

    debug("reconnection started (fast:$reconnect_fast)...");
    $reconnect_pending = 0;
    $reconnect_fast = 0;
}

sub connect_attempt () {
    debug("try to connect...");
    my $chan = ssl_connect($uw_config{server}, $uw_config{port}, \&ev_close);
    return unless $chan;

    delete $ev_watch{try_con};
    delete $ev_watch{wait_con};

    if ($chan->{pending}) {
        ev_add_chan($chan, 'wait_con', &EV::READ | &EV::WRITE, \&connect_pending);
        return;
    }

    on_connect($chan);
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
    on_connect($chan);
}

sub _srv_disconnect ($) {
    my ($chan) = @_;
    ssl_disconnect($chan);
    undef $srv_chan;
    reconnect() if !$finished && !$reconnect_pending;
}

sub on_connect ($) {
    my ($chan) = @_;

    info("connected to server");
    # update user list immediately
    $ev_watch{update}->set(0, $uw_config{update_interval});

    # our special destructor will initiate immediate reconnection
    $chan->{destructor} = \&_srv_disconnect;
    ev_add_chan($srv_chan = $chan);
    # reconnection will start immediately after detected disconnect
    $reconnect_fast = 1;

    handle_next_job();
}

##############################################
# SSL reading and writing
#

sub _srv_write_done ($$$) {
    my ($chan, $success, $job) = @_;

    unless ($success) {
        debug("re-queue job from %s after failed write", $job->{source});
        unshift @jobs, $job;
        reconnect();
        return;
    }

    ssl_read_packet($srv_chan, \&_srv_read_done, $job);
}

sub _srv_read_done ($$$) {
    my ($chan, $reply, $job) = @_;

    unless (defined $reply) {
        debug("re-queue job from %s after failed read", $job->{source});
        unshift @jobs, $job;
        reconnect();
        return;
    }

    debug("%s: got reply \"%s\" for %s", $chan->{addr}, $reply, $job->{source});
    my ($reply, $groups) = split /:/, $reply;

    rescan_etc();
    if ($job->{chan}) {
        unix_write_reply($job->{chan}, $reply);
    }
    handle_reply($job, $reply, $groups);

    undef $job;
    handle_next_job();
}

##############################################
# Unix-domain sockets
#

sub unix_listen () {
    my $path = $uw_config{unix_socket};
    create_parent_dir($path);
    unlink($path);
    my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM,
                                    Local => $path, Listen => SOMAXCONN);
    fail("unix sock: $!") unless $sock;
    chmod(0666, $path);
    $sock->blocking(0) or fail("unix non-blocking: $!");
    my $s_chan = {
        type => 'accepting',
        destructor => \&unix_disconnect,
        pending => 1,
        ssl => undef,
        conn => $sock,
        addr => $path,
        unix => 1,
        path => $path
        };
    ev_add_chan($s_chan, 'u_accept', &EV::READ, \&unix_accept_pending);
    debug("unix listen on $path");
}

sub unix_accept_pending () {
    my ($s_chan) = @_;
    my $conn = $s_chan->{conn}->accept();
    unless ($conn) {
        debug("unix accept: $!");
        return;
    }

    # determine who is our client
    my ($pid, $euid, $egid) = $conn->peercred();
    my $prog = readlink("/proc/$pid/exe");
    my $addr = "$euid:$pid:$prog";

    my $c_chan = {
        type => 'accepted',
        destructor => \&unix_disconnect,
        pending => 0,
        ssl => undef,
        conn => $conn,
        unix => 1,
        addr => $addr
        };

    if ($euid != 0) {
        info("reject connection from pid:$pid euid:$euid prog:$prog");
        ev_close($c_chan);
        return;
    }

    # start reading
    $conn->blocking(0) or fail("unix client non-blocking: $!");
    init_timeouts($c_chan, \&ev_close);
    $c_chan->{r_buf} = "";
    init_transmission($c_chan, &EV::READ, \&_unix_read_pending);
    debug('accepted unix %s', $c_chan->{addr});
    return $c_chan;
}

sub _unix_read_pending ($) {
    my ($chan) = @_;

    fire_transmission($chan);
    my $len = $chan->{conn}->sysread($chan->{r_buf}, 1024, length($chan->{r_buf}));
    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        debug("%s: will read later", $chan->{addr});
        return;
    }

    if ($chan->{r_buf} !~ /\n/) {
        if ($len) {
            #debug("%s: read %s bytes", $chan->{addr}, defined($len) ? $len : "?");
            postpone_timeouts($chan);
        } else {
            info("%s: read failed: %s", $chan->{addr}, $!);
            ev_close($chan);
        }
        return;
    }

    end_transmission($chan);
    chomp($chan->{r_buf});
    #debug("received from %s: \"%s\"", $chan->{addr}, $chan->{r_buf});
    my $reply = handle_unix_request($chan, $chan->{r_buf});
    unix_write_reply($chan, $reply) if defined $reply;
}

sub unix_write_reply ($$) {
    my ($chan, $reply) = @_;
    $chan->{w_buf} = $reply . "\n";
    init_transmission($chan, &EV::WRITE, \&_unix_write_pending);
    fire_transmission($chan);
    debug("sending to %s: \"%s\"", $chan->{addr}, $reply);
}

sub _unix_write_pending ($) {
    my ($chan) = @_;

    my $len = $chan->{conn}->syswrite($chan->{w_buf});
    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        debug("%s: will write later", $chan->{addr});
        return;
    }

    #debug("%s: write %s bytes", $chan->{addr}, defined($len) ? $len : "?");
    unless ($len) {
        info("%s: write failed: %s", $chan->{addr}, $!);
        ev_close($chan);
        return;
    }

    substr($chan->{w_buf}, 0, $len, "");
    if (length($chan->{w_buf})) {
        postpone_timeouts($chan);
        return;
    }

    ev_close($chan);
}

sub unix_disconnect ($) {
    my ($chan) = @_;
    debug("close channel %s", $chan->{addr});
    ssl_disconnect($chan);
    if ($chan->{path}) {
        unlink($chan->{path});
        delete $chan->{path};
    }
}

##############################################
# main loop
#

sub main_loop () {
    read_config($config_file,
                # required parameters
                [ qw(
                    server
                )],
                # optional parameters
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    also_local syslog stdout debug stacktrace daemonize
                    connect_interval update_interval auth_cache_ttl
                    enable_gmirror gmirror_conf update_nscd nscd_pid_file
                )]);
    require_program("ifconfig");
    log_init();

    debug("setting up");
    ev_create_loop();

    gmirror_init()
        if ($uw_config{enable_gmirror} = $uw_config{enable_gmirror} ? 1 : 0);

    if (daemonize()) {
        # clone event loop in the child
        $ev_loop->loop_fork();
    }

    debug("post-fork setup");
    ssl_startup();
    ssl_create_context($uw_config{peer_pem}, $uw_config{ca_cert});
    unix_listen();
    $reconnect_fast = 1;
    reconnect();
    $ev_watch{update} = $ev_loop->timer(0, $uw_config{update_interval},
                                        sub { update_active(undef) });

    info("$progname started");
    $ev_loop->loop();
}

#
# cleanup
#

sub cleanup () {
    $finished = 1;
    ev_close_all();
    ev_remove_handlers();
    ssl_destroy_context();
    end_daemon();
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

