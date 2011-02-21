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
my  ($srv_chan, $finished, @net_jobs, @fix_jobs, %utmp_fixes);
my  ($reconnect_pending, $reconnect_fast);

our %nss = (
            name => "nss",
            get_user_uid_grp    => \&nss_get_user_uid_grp,
            get_user_groups     => \&nss_get_user_groups,
        );


##############################################
# command handling
#

sub handle_unix_request ($$) {
    my ($chan, $req) = (@_);
    my (@arg) = split(/\s+/, $req);
    my $cmd = $arg[0];

    if ($uw_config{debug}) {
    	my $pkt = $req;
    	# hide password from log
    	$pkt =~ s/\s\S+$/ \*\*\*/ if $pkt =~ /^auth /;
    	debug("received \"%s\" from [%s]", $pkt, $chan->{addr});
    }

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
    } elsif ($cmd eq "login") {
        return $#arg != 2 ? "usage: login user sid"
                    : user_login($arg[1], $arg[2], $chan);
    } elsif ($cmd eq "logout") {
        return $#arg != 2 ? "usage: logout user sid"
                    : user_logout($arg[1], $arg[2], $chan);
    } else {
        return "usage: echo|update|auth|login|logout [args...] ;"
              ." SIDs: tty\@rhost xdm/N net/N con/N pty/N";
    }
}

sub handle_server_reply ($$$) {
    my ($job, $reply, $groups) = @_;
    my $cmd = $job->{cmd};
    rescan_etc();

    if ($job->{chan}) {
        unix_write_reply($job->{chan}, $reply);
    }
    if ($job->{info}) {
        info($job->{info} . ": " . $reply);
    }
    if ($groups && $uw_config{enable_gmirror} && !$uw_config{prefer_nss}) {
        if ($groups) {
            handle_groups($job, $groups);
        }
        if ($cmd eq "groups") {
            gmirror_apply($job);
        }
    }
    if ($cmd eq "auth" && $job->{user}) {
        update_auth_cache($job->{user}, $job->{pass}, $reply);
    }
}

##############################################
# typical operations
#

sub update_active ($) {
    my ($chan) = @_;
    debug("update active");
    cache_gc();
    remove_stale_fixes();
    return "no connection" unless $srv_chan;

    my $opts = $uw_config{enable_gmirror} && !$uw_config{prefer_nss} ? "g" : "-";
    my $req = join("|", $opts, pack_ips(), pack_utmp());
    my $job = make_job("update", $req, $chan);
    queue_net_job($job);

    if ($uw_config{enable_gmirror} && $uw_config{prefer_nss}) {
        gmirror_apply(undef);
    }

    # return nothing so that channel will wait for server reply
    return;
}

sub user_auth ($$$) {
    my ($user, $pass, $chan) = @_;

    if ($uw_config{authorize_permit}) {
        return "success";
    }

    if ($uw_config{prefer_nss}) {
        return "not implemented";
    }

    if (is_local_user($user)) {
        debug("$user: local user auth");
        return "local user auth";
    }

    my $req = "$user|$pass";
    if (check_auth_cache($user, $pass) == 0) {
        info("$user: user auth: success (cached)");
        queue_net_job(make_job("auth", $req, undef));
        return "success";
    }
    queue_net_job(make_job("auth", $req, $chan, info => "$user: auth",
                            user => $user, pass => $pass));

    # return nothing so that channel will wait for server reply
    return;
}

sub user_login ($$$) {
    my ($user, $sid, $chan) = @_;
    return "local login" if is_local_user($user);

    # Let PAM wait only if group mirroring depends on uw-server.
    # Otherwise, perform group mirroring if needed, and let PAM continue.
    my $wait = ($uw_config{enable_gmirror} && !$uw_config{prefer_nss});
    my $job = make_job("login", undef, $chan,
                        user => $user, sid => $sid, can_wait => $wait);
    my ($reply, $done) = logon_action($job);
    queue_fix_job($job) if !$done;
    gmirror_apply($job) if $uw_config{enable_gmirror} && !$wait;
    return $reply;
}

sub user_logout ($$$) {
    my ($user, $sid, $chan) = @_;
    return "local logout" if is_local_user($user);
    my $job = make_job("logout", undef, $chan,
                        user => $user, sid => $sid, can_wait => 0);
    my ($reply, $done) = logon_action($job);
    queue_fix_job($job) if !$done;
    gmirror_apply($job) if $uw_config{enable_gmirror};
    return "success";
}

#
# fix user login sid
#
sub logon_action ($) {
    my ($job) = @_;

    # determine pid of the login process
    if (defined($job->{chan}) && !defined($job->{pid})) {
        if ($job->{chan}{addr} =~ /^(\d+):(\d+):(.+)$/) {
            ($job->{euid}, $job->{pid}, $job->{prog}) = ($1, $2, $3);
        } else {
            ($job->{euid}, $job->{pid}, $job->{prog}) = ("", "", "");
        }
    }

    # fix the remote host part of sid
    my ($tty, $rhost) = split(/\@/, $job->{sid});
    if ($rhost eq "localhost" || $rhost eq "localhost.localdomain") {
        $rhost = "127.0.0.1";
    } elsif ($rhost && $rhost !~ /^\d+\.\d+\.\d+\.\d+$/) {
        my $ip = gethostbyname($rhost);
        if ($ip) {
            $rhost = join(".", unpack("C4", $ip));
        } else {
            info("$rhost: cannot determine ip");
            return ("invalid host", 1);
        }
    } elsif (!$rhost) {
        $rhost = "";
    }
    my $sid = $job->{sid} = $rhost ? "${tty}\@${rhost}" : $tty;

    # detect user login time and possibly fix tty
    my @utmp = scan_utmp();
    my ($cmd, $user, $pid) = ($job->{cmd}, $job->{user}, $job->{pid});
    my ($btime, $key);
    debug("utmp search: user:%s pid:%s tty:%s rhost:%s",
            $user, $pid, $tty, $rhost);
    for my $u (@utmp) {
        debug("utmp try: user:%s pid:%s tty:%s rhost:%s",
                $u->{user}, $u->{pid}, $u->{tty}, $u->{rhost});

        # maybe this combination is already fixed
        $key = "$u->{user}|$u->{sid}|$u->{pid}|$u->{btime}";
        if (exists $utmp_fixes{$key}) {
            ($u->{user}, $u->{sid}, $u->{pid}, $u->{btime})
                = split /\|/, $utmp_fixes{$key};
            debug("utmp fix: user:%s pid:%s tty:%s rhost:%s cmd:%s",
                    $u->{user}, $u->{pid}, $u->{tty}, $u->{rhost}, $cmd);
            # remove fix if logging out
            if ($cmd eq "logout") {
                debug("remove fix: $key");
                delete $utmp_fixes{$key};
            }
        }

        # simple comparison
        if ($u->{user} eq $user && $u->{tty} eq $tty && $u->{rhost} eq $rhost) {
            $btime = $u->{btime};
            last;
        }

        # /bin/su: check parent processes
        if ($job->{prog} eq "/bin/su" && $u->{user} eq "root"
                && $u->{tty} eq $tty && $u->{rhost} eq $rhost) {
            my $ppid = parent_pid($pid);
            $ppid = parent_pid($ppid) if $ppid && $u->{pid} != $ppid;
            if ($u->{pid} == $ppid) {
                # found!
                $btime = $u->{btime};
                $utmp_fixes{$key} = "$user|$sid|$pid|$btime";
                debug("add fix: %s ==> %s", $key, $utmp_fixes{$key});
                last;
            }
        }
    }

    # cannot find matching utmp record
    my $err;
    if (!$btime && ++ $job->{attemps} > 2) {
        info("$user $cmd: cannot find utmp record");
        $btime = time();
        $err = "utmp not found";
    }

    if ($btime) {
        # found user match in utmpx
        my $wait = $job->{can_wait};
        my $opts = $wait ? "g" : "-";
        $job->{info} = "$user: $cmd";
        $job->{req} = join("|", $cmd, $user, $sid, $btime, $opts,
                            pack_ips(), pack_utmp(@utmp));
        undef $job->{chan} unless $wait;
        queue_net_job($job);
        if ($err) {
            return ($err, 1);
        } else {
            return ($wait ? undef : "success", 1);
        }
    }

    debug("postpone utmp search: user:$user tty:$tty");
    my $wait = $job->{can_wait};
    return ($wait ? undef : "success", 0);
}

sub parent_pid ($) {
    my ($pid) = @_;
    my $line = read_file("/proc/$pid/stat");
    return ($line =~ /^\d+ \(\S+ \S+ (\d+) \S/) ? $1 : 0;
}

sub remove_stale_fixes () {
    my ($user, $sid, $btime, $pid1, $pid2);
    for my $key (keys %utmp_fixes) {
        ($user, $sid, $pid1, $btime) = split /\|/, $key;
        ($user, $sid, $pid2, $btime) = split /\|/, $utmp_fixes{$key};
        if (kill(0, $pid1) == 0 || kill(0, $pid2) == 0) {
            debug("remove stale fix: $key");
            delete $utmp_fixes{$key};
        }
    }
}

#
# scan interfaces
#
sub pack_ips () {
    my ($ips, $out);
    $ips = cache_get("host", "netif");
    return $ips if defined $ips;

    run_prog($uw_config{ifconfig}, \$out);
    for (split /\n/, $out) {
        next unless m"^\s+inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\w";
        next if $1 eq "127.0.0.1";
        $ips .= $1 . ",";
    }
    $ips =~ s/,$//;

    cache_put("host", "netif", $ips, $uw_config{netif_cache_ttl});
    debug("ip list: $ips");
    return $ips;
}

sub pack_utmp (@) {
    my (@utmp) = @_;
    @utmp = scan_utmp() unless @utmp;
    my @lines;
    for my $u (@utmp) {
        my ($user, $sid, $pid, $btime) = @$u{qw[user sid pid btime]};
        my $key = "$user|$sid|$pid|$btime";
        if (exists $utmp_fixes{$key}) {
            ($user, $sid, $pid, $btime) = split /\|/, $utmp_fixes{$key};
        }
        next if is_local_user($user);
        push @lines, join("!", $user, $sid, $btime);
    }
    return @lines ? join("~", @lines) : "-";
}

##############################################
# job queue
#

sub make_job ($$$%) {
    my ($cmd, $req, $chan, %job) = @_;
    $job{cmd} = $cmd;
    $job{req} = "$cmd|$req";
    $job{chan} = $chan;
    $job{source} = $chan ? $chan->{addr} : "none";
    return \%job;
}

sub queue_net_job ($) {
    my ($job) = @_;
    push @net_jobs, $job;
    handle_net_job();
    return $job;
}

sub handle_net_job () {
    if (!@net_jobs) {
        #debug("net queue empty");
        return;
    }
    if (!$srv_chan) {
        debug("postpone net job: no connection");
        return;
    }
    if ($srv_chan->{io_watch}) {
        debug("another net job running");
        return;
    }

    my $job = shift @net_jobs;
    if ($uw_config{debug}) {
    	my $req = $job->{req};
    	# hide password from log
    	$req =~ s/\|[^\|]*$/\|\*\*\*/ if $req =~ /^auth\|/;
    	debug("send request \"%s\" for [%s]", $req, $job->{source});
    }
    ssl_write_packet($srv_chan, $job->{req}, \&_srv_write_done, $job);
}

sub queue_fix_job ($) {
    my ($job) = @_;
    push @fix_jobs, $job;
    $ev_watch{fix}->start() if $#fix_jobs == 0;
}

sub handle_fix_job () {
    while ($#fix_jobs >= 0) {
        my $job = $fix_jobs[0];
        my ($reply, $done) = logon_action($job);
        return if !$done;
        if ($job->{can_wait} && $job->{chan} && defined($reply)) {
            unix_write_reply($job->{chan}, $reply);
        }
        shift @fix_jobs;
    }
    $ev_watch{fix}->stop() if $#fix_jobs < 0;
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

    handle_net_job();
}

##############################################
# SSL reading and writing
#

sub _srv_write_done ($$$) {
    my ($chan, $success, $job) = @_;

    unless ($success) {
        debug("re-queue job from \"%s\" after failed write", $job->{source});
        unshift @net_jobs, $job;
        reconnect();
        return;
    }

    ssl_read_packet($srv_chan, \&_srv_read_done, $job);
}

sub _srv_read_done ($$$) {
    my ($chan, $reply, $job) = @_;

    unless (defined $reply) {
        debug("re-queue job from \"%s\" after failed read", $job->{source});
        unshift @net_jobs, $job;
        reconnect();
        return;
    }

    debug("got reply \"%s\" for [%s]", $reply, $job->{source});
    my ($reply, $groups) = split /\|/, $reply;

    handle_server_reply($job, $reply, $groups);

    undef $job;
    handle_net_job();
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

    if ($euid != 0 && $prog ne "/bin/su") {
        info("reject connection from pid:$pid euid:$euid prog:$prog");
        ev_close($c_chan);
        return;
    }

    # start reading
    $conn->blocking(0) or fail("unix client non-blocking: $!");
    init_timeouts($c_chan, \&ev_close);
    $c_chan->{r_buf} = "";
    init_transmission($c_chan, &EV::READ, \&_unix_read_pending);
    debug("[%s] accepted", $c_chan->{addr});
    return $c_chan;
}

sub _unix_read_pending ($) {
    my ($chan) = @_;

    fire_transmission($chan);
    my $len = $chan->{conn}->sysread($chan->{r_buf}, 1024, length($chan->{r_buf}));
    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        debug("[%s] postpone read", $chan->{addr});
        return;
    }

    if ($chan->{r_buf} !~ /\n/) {
        if ($len) {
            #debug("%s: read %s bytes", $chan->{addr}, defined($len) ? $len : "?");
            postpone_timeouts($chan);
        } else {
            debug("[%s] read failed: %s", $chan->{addr}, $!);
            ev_close($chan);
        }
        return;
    }

    end_transmission($chan);
    chomp($chan->{r_buf});
    my $reply = handle_unix_request($chan, $chan->{r_buf});
    unix_write_reply($chan, $reply) if defined $reply;
}

sub unix_write_reply ($$) {
    my ($chan, $reply) = @_;
    $chan->{w_buf} = $reply . "\n";
    init_transmission($chan, &EV::WRITE, \&_unix_write_pending);
    fire_transmission($chan);
    debug("send \"%s\" to [%s]", $reply, $chan->{addr});
}

sub _unix_write_pending ($) {
    my ($chan) = @_;

    my $len = $chan->{conn}->syswrite($chan->{w_buf});
    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        debug("[%s] postpone write", $chan->{addr});
        return;
    }

    #debug("%s: write %s bytes", $chan->{addr}, defined($len) ? $len : "?");
    unless ($len) {
        debug("[%s] write failed: %s", $chan->{addr}, $!);
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
    debug("[%s] closed", $chan->{addr});
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
                    syslog stdout debug stacktrace daemonize
                    prefer_nss skip_local authorize_permit
                    uid_cache_ttl group_cache_ttl
                    connect_interval update_interval auth_cache_ttl
                    enable_gmirror gmirror_conf update_nscd nscd_pid_file
                    pam_debug
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

    my $fix_interval = $uw_config{utmp_cache_ttl};
    $fix_interval = 0 if !$fix_interval || $fix_interval < 0;
    $fix_interval += 1;
    $ev_watch{fix} = $ev_loop->timer_ns($fix_interval, $fix_interval,
                                        \&handle_fix_job);

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

