#!/usr/bin/perl
#
# UserWatch SSL client
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";
require "$Bin/uw-ssl.inc.pm";

#
# require: perl-User-Utmp
#
# you can obtain perl-User-Utmp RPM from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/perl-User-Utmp.html
#
use User::Utmp qw(:constants :utmpx);
use IO::Socket::UNIX;

our ($config_file, $progname, %uw_config);
our ($ev_loop, %ev_watch, $ev_reload);
my  ($srv_chan, @jobs, $finished, $reconnecting);
my  (%local_users, $passwd_modified_stamp);
my  ($unix_seqno);

my $ifconfig = "/sbin/ifconfig";

#
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

    my $addr = sprintf('unix_%04d', ++$unix_seqno);
    my $c_chan = {
        type => 'accepted',
        destructor => \&unix_disconnect,
        pending => 0,
        ssl => undef,
        conn => $conn,
        unix => 1,
        addr => $addr
        };

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
            debug("%s: read %s bytes",
                    $chan->{addr}, defined($len) ? $len : "?");
            postpone_timeouts($chan);
        } else {
            info("%s: read failed: %s", $chan->{addr}, $!);
            ev_close($chan);
        }
        return;
    }

    end_transmission($chan);
    chomp($chan->{r_buf});
    debug("received from %s: \"%s\"", $chan->{addr}, $chan->{r_buf});
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

    debug("%s: write %s bytes", $chan->{addr}, defined($len) ? $len : "?");
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

sub handle_unix_request ($$) {
    my ($chan, $req) = (@_);
    my (@arg) = split(/\s+/, $req);
    my $cmd = $arg[0];
    if ($cmd eq "echo") {
        $req =~ s/^\s*\w+\s+//;
        return $req;
    } elsif ($cmd eq "login") {
        return "usage: login XDM|RSH|CON user pass" if $#arg != 3;
        user_login($arg[1], $arg[2], $arg[3], undef, $chan);
    } elsif ($cmd eq "logout") {
        return "usage: logout XDM|RSH|CON user" if $#arg != 2;
        user_logout($arg[1], $arg[2], $chan);
    } elsif ($cmd eq "update") {
        update_active_users($chan);
    } else {
        return "usage: login|logout|update|echo [args...]";
    }
    return;
}

#
# scan interfaces
#
sub get_ip_list () {
    my @ip_list;
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

sub update_active_users ($) {
    my ($chan) = @_;
    debug("update active users");
    return unless $srv_chan;
    my $req = create_request("C", 1);
    queue_job($req, $chan);
}

sub user_login ($$$$$) {
    my ($method, $user, $pass, $uid, $chan) = @_;
    get_local_users();
    if (!$uw_config{also_local} && exists($local_users{$user})) {
        debug("$user: is local user");
        return "OK";
    }
    my $req = create_request("I", 0, {
                method => $method, user => $user, pass => $pass, uid => $uid
                });
    queue_job($req, $chan);
}

sub user_logout ($$$) {
    my ($method, $user, $chan) = @_;
    my $req = create_request("O", 0, {
                method => $method, user => $user, uid => 0
                });
    queue_job($req, $chan);
}

#
# main loop
#

sub main_loop () {
    read_config($config_file, [ qw(
                    server
                )],
                [ qw(
                    port ca_cert peer_pem idle_timeout rw_timeout
                    also_local syslog stdout debug stacktrace daemonize
                    connect_interval update_interval
                )]);
    fail("$config_file: server host undefined")
        unless $uw_config{server};
    fail("$ifconfig: executable not found") unless -x $ifconfig;
    log_init();

    debug("setting up");
    ev_create_loop();

    if (daemonize()) {
        # clone event loop in the child
        $ev_loop->loop_fork();
    }

    debug("post-fork setup");
    ssl_startup();
    ssl_create_context($uw_config{peer_pem}, $uw_config{ca_cert});
    unix_listen();
    reconnect(1);
    $ev_watch{update} = $ev_loop->timer(0, $uw_config{update_interval},
                                        sub { update_active_users(undef) });

    info("$progname started");
    $ev_loop->loop();
}

#
# job queue
#

sub queue_job ($$) {
    my ($req, $chan) = @_;
    push @jobs, {
        req => $req,
        chan => $chan,
        source => $chan ? $chan->{addr} : "none"
        };
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

#
# reconnections
#

sub reconnect (;$) {
    my ($now) = @_;
    $reconnecting = 1;

    # close previous server connection, if any
    if ($srv_chan) {
        debug("disconnect previous server connection");
        ev_close($srv_chan);
        undef $srv_chan;
    }

    # initiate new connection to server
    delete $ev_watch{try_con};
    delete $ev_watch{wait_con};
    $ev_watch{try_con} = $ev_loop->timer(
                            $now ? 0 : $uw_config{connect_interval},
                            $uw_config{connect_interval},
                            \&connect_attempt);

    $reconnecting = 0;
    debug("reconnection started (now:$now)...");
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

sub _srv_disconnect ($) {
    my ($chan) = @_;
    ssl_disconnect($chan);
    undef $srv_chan;
    reconnect() if !$finished && !$reconnecting;
}

sub on_connect ($$) {
    my ($chan, $msg) = @_;

    debug("%s: successfully connected to server", $msg);
    $ev_watch{update}->set(0, $uw_config{update_interval});

    $chan->{destructor} = \&_srv_disconnect;
    ev_add_chan($srv_chan = $chan);

    handle_next_job();
}

#
# reading and writing
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

    debug("received reply \"%s\" for %s", $reply, $job->{source});
    unix_write_reply($job->{chan}, $reply) if $job->{chan};

    handle_next_job();
}

#
# cleanup
#

sub cleanup () {
    $finished = 1;
    ev_close_all();
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


