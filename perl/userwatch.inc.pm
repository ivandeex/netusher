#!/usr/bin/perl
#
# UserWatch common and SSL functions
# $Id$
#

use strict;

#
# require: perl-Net-SSLeay, perl-EV
#
use Carp;
use Errno;
use Fcntl;
use Socket;
use Net::SSLeay ();
use Net::SSLeay::Handle;
use Sys::Syslog;
use POSIX;
use EV;

our ($ev_loop, %ev_watch, $ssl_ctx, $in_parent);
my  ($pid_written);

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
        timeout         => 5,
        idle_timeout    => 240,
        # client parameters
        server          => undef,
        also_local      => 0,
        update_interval => 120,
        connect_interval => 5,
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
        ldap_user_base  => undef,
        ldap_attr_user  => 'uid',
        ldap_attr_uid   => 'uidNumber',
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
    my $msg = "[ fail] " . sprintf($fmt, @_);
    chomp $msg;
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
    my $msg = "[ info] " . sprintf($fmt, @_);
    syslog("notice", $msg) if $uw_config{syslog};
    printf("[%5d] %s\n", $$, $msg) if $uw_config{stdout};
}

sub debug ($@) {
    return unless $uw_config{debug};
    my $fmt = shift;
    my $msg = "[debug] " . sprintf($fmt, @_);
    syslog("info", $msg) if $uw_config{syslog};
    printf("[%5d] %s\n", $$, $msg) if $uw_config{stdout};    
}

##############################################
# Event loop
#

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

    chdir('/')                 or fail("can't chdir to /: $!");
    open(STDIN,  '</dev/null') or fail("can't read /dev/null: $!");
    open(STDOUT, '>/dev/null') or fail("can't write to /dev/null: $!");
    open(STDERR, '>/dev/null') or fail("can't write to /dev/null: $!");
    setsid()                   or fail("can't start a new session: $!");
    umask(022);
    $uw_config{stdout} = 0;

    $| = 1;
    if (open(my $pf, "> $pid_file")) {
        print $pf $$;
        close $pf;
    }
    $pid_written = 1;

    debug("daemonized");
    return $$;
}

sub end_daemon () {
    unless ($in_parent) {
        unlink($uw_config{pid_file}) if $pid_written;
        info("$progname finished");
    }
}

##############################################
# Safe wrappers around Net::SSLeay
#

#
# Somehow you have to guarantee that these are called just once. Alas,
# Net::SSLeay should've taken care of this with more "use"s, such as
# "use Net::SSLeay::load_error_strings;". At least by using this hack we
# cooperate with other callers in working around Net::SSLeay's deficiency.
#
sub ssl_startup () {

    Net::SSLeay::load_error_strings();
    eval 'no warnings "redefine"; sub Net::SSLeay::load_error_strings () {}';
    fail($@) if $@;

    Net::SSLeay::SSLeay_add_ssl_algorithms();
    eval 'no warnings "redefine"; sub Net::SSLeay::SSLeay_add_ssl_algorithms () {}';
    fail($@) if $@;

    #Net::SSLeay::ENGINE_load_builtin_engines();
    #eval 'no warnings "redefine"; sub Net::SSLeay::ENGINE_load_builtin_engines () {}';
    #fail($@) if $@;

    #Net::SSLeay::ENGINE_register_all_complete();
    #eval 'no warnings "redefine"; sub Net::SSLeay::ENGINE_register_all_complete () {}';
    #fail($@) if $@;

    Net::SSLeay::randomize();
    eval 'no warnings "redefine"; sub Net::SSLeay::randomize (;$$) {}';
    fail($@) if $@;

    $| = 1;
    if ($uw_config{debug} > 1) {
        $Net::SSLeay::trace = 3;
        Net::SSLeay::Handle->debug(1);
    }
}

#
# Net::SSLeay's error functions are terrible.
# These are a bit more programmable and readable.
#
sub ssl_get_error () {
    my $errors = "";
    my $errnos = [];
    while (my $errno = Net::SSLeay::ERR_get_error()) {
        push @$errnos, $errno;
        $errors .= Net::SSLeay::ERR_error_string($errno) . "\n";
    }
    return $errors, $errnos if wantarray;
    return $errors;
}

sub ssl_check_die ($;$) {
    my ($message, $non_fatal) = @_;
    my ($errors, $errnos) = ssl_get_error();
    return 0 unless @$errnos;
    if (!$non_fatal) {
       fail("${message}: ${errors}");
    }
    info("${message}: ${errors}");
    return -1;
}

sub ssl_sock_opts ($) {
    my ($conn) = @_;

    # No buffering
    my $f = select($conn); $| = 1; select $f;

    # Set O_NONBLOCK.
    my $v = fcntl($conn, F_GETFL, 0)
        or fail("fcntl F_GETFL: $!");  # 0 for error, 0e0 for 0.
    fcntl($conn, F_SETFL, $v | O_NONBLOCK)
        or fail("fcntl F_SETFL O_NONBLOCK: $!");  # 0 for error, 0e0 for 0.
}

#
# The CTX ("context") should be shared between many SSL connections. A CTX
# could apply to multiple listening sockets, or each listening socket could
# have its own CTX. Each CTX may represent only one local certificate.
#
sub ssl_create_context ($$) {
    my ($pem_path, $ca_path) = @_;

    $ssl_ctx = Net::SSLeay::CTX_new();
    ssl_check_die("SSL CTX_new");

    # OP_ALL enables all harmless work-arounds for buggy clients.
    Net::SSLeay::CTX_set_options($ssl_ctx, Net::SSLeay::OP_ALL());
    ssl_check_die("SSL CTX_set_options");

    # Modes:
    # 0x1: SSL_MODE_ENABLE_PARTIAL_WRITE
    # 0x2: SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    # 0x4: SSL_MODE_AUTO_RETRY
    # 0x8: SSL_MODE_NO_AUTO_CHAIN
    # 0x10: SSL_MODE_RELEASE_BUFFERS (ignored before OpenSSL v1.0.0)
    Net::SSLeay::CTX_set_mode($ssl_ctx, 0x11);
    ssl_check_die("SSL CTX_set_mode");

    if ($pem_path) {
        # Server and client can use PEM (cert+key) for secure connection
        $pem_path = "$config_root/$pem_path"
            unless $pem_path =~ m'^/';
        fail("$pem_path: pem certificate not found")
            unless -r $pem_path;

        # Load certificate. Avoid password prompt.
        Net::SSLeay::CTX_set_default_passwd_cb($ssl_ctx, sub { "" });
        ssl_check_die("SSL CTX_set_default_passwd_cb");

        Net::SSLeay::CTX_use_RSAPrivateKey_file($ssl_ctx, $pem_path,
                                                Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_RSAPrivateKey_file");

        Net::SSLeay::CTX_use_certificate_file($ssl_ctx, $pem_path,
                                                Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_certificate_file");
        debug("enable ssl pem: $pem_path");
    }

    if ($ca_path) {
        # Server and client can use CA certificate to check other side
        $ca_path = "$config_root/$ca_path"
            unless $ca_path =~ m'^/';
        fail("$ca_path: ca certificate not found")
            unless -r $ca_path;
        my ($ca_file, $ca_dir) = (-d $ca_path) ?
                                    (undef, $ca_path) : ($ca_path, undef);

        Net::SSLeay::CTX_load_verify_locations($ssl_ctx, $ca_file, $ca_dir);
        ssl_check_die("SSL CTX_load_verify_locations");
        debug("enable ca check file:$ca_file dir:$ca_dir");

        my $mode = &Net::SSLeay::VERIFY_PEER
                    | &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT
                    | &Net::SSLeay::VERIFY_CLIENT_ONCE;
        Net::SSLeay::CTX_set_verify($ssl_ctx, $mode, \&_ssl_cert_verify_cb);
        ssl_check_die("SSL CTX_set_verify");
    }
}

sub _ssl_cert_verify_cb {
    my ($ok, $x509_store_ctx) = @_;
    if ($uw_config{debug}) {
        my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx);
        my $subj = Net::SSLeay::X509_get_subject_name($cert);
        $subj = Net::SSLeay::X509_NAME_oneline($subj);
        my $cname = ($subj =~ m'/CN=([^/]+)/') ? $1 : $subj;
        debug("verification ok:$ok cname:$cname");
    }
    return $ok;
}

sub ssl_destroy_context () {
    Net::SSLeay::CTX_free($ssl_ctx) if $ssl_ctx;
    ssl_check_die("SSL CTX_free");
    undef $ssl_ctx;
}

#
# Each connection needs an SSL object,
# which is associated with the shared CTX.
#
sub ssl_create_ssl ($$) {
    my ($conn, $ctx) = @_;

    my $ssl = Net::SSLeay::new($ctx);
    ssl_check_die("SSL new");

    Net::SSLeay::set_fd($ssl, fileno($conn));
    ssl_check_die("SSL set_fd");

    return $ssl;
}

#
# Listen for client connections
#
sub ssl_listen ($) {
    my ($port) = @_;

    my $sock;
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or fail("socket: $!");
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1)
        or fail("setsockopt SOL_SOCKET, SO_REUSEADDR: $!");
    bind($sock, pack_sockaddr_in($port, INADDR_ANY))
        or fail("bind ${port}: $!");
    listen($sock, SOMAXCONN)
        or fail("listen ${port}: $!");

    ssl_sock_opts($sock);

    my $chan = {
        type => 'accepting',
        pending => 1,
        ssl => undef,
        conn => $sock,
        addr => ":$port",
        };

    return $chan;
}

#
# Accept another client connection
#
sub ssl_accept ($;$) {
    my ($s_chan, $idle_handler) = @_;

    my $paddr = accept(my $conn, $s_chan->{conn});
    unless ($paddr) {
        debug("accept: $!");
        return;
    }
    my ($port, $iaddr) = sockaddr_in($paddr);
    my $addr = join('.', unpack('C*', $iaddr)) . ':' . $port;

    my $c_chan = {
        type => 'accepted',
        pending => 0,
        conn => $conn,
        addr => $addr
        };

    ssl_sock_opts($c_chan->{conn});
    $c_chan->{ssl} = ssl_create_ssl($c_chan->{conn}, $ssl_ctx);
    Net::SSLeay::accept($c_chan->{ssl});
    ssl_check_die("SSL accept");

    set_idle_timeout($c_chan, $idle_handler);
    return $c_chan;
}

#
# Connecting to server
#
sub ssl_connect ($$;$) {
    my ($server, $port, $idle_handler) = @_;

    my $conn;
    socket($conn, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or fail("socket: $!");

    my $ip = gethostbyname($server)
        or fail("$server: host not found");
    my $conn_params = sockaddr_in($port, $ip);

    ssl_sock_opts($conn);

    my $ret = connect($conn, $conn_params);

    if ($ret) {
        debug("connect: success");
    } else {
        unless ($!{EINPROGRESS}) {
            info("$server: connection failed: $!");
            return;
        }
        debug("connection pending...");
    }

    my $chan = {
        type => 'connecting',
        pending => 1,
        ssl => undef,
        conn => $conn,
        addr => "$server:$port",
        server => $server,
        port => $port,
        conn_params => $conn_params,
        idle_handler => $idle_handler
        };

    ssl_connected($chan, 1) if $ret;
    return $chan;
}


sub ssl_connected ($;$) {
    my ($chan, $already_connected) = @_;

    unless ($already_connected) {
        my $ret = connect($chan->{conn}, $chan->{conn_params});
        unless ($ret) {
            return "pending" if $!{EINPROGRESS};
            info("%s: cannot connect: %s", $chan->{server}, $!);
            return "fail";
        }
        debug("client connection ready");
    }

    $chan->{type} = 'connected';
    $chan->{pending} = 0;

    $chan->{ssl} = ssl_create_ssl($chan->{conn}, $ssl_ctx);
    Net::SSLeay::connect($chan->{ssl});
    ssl_check_die("SSL connect");

    set_idle_timeout($chan, $chan->{idle_handler});
    return "ok";
}

#
# Idle timeout handling
#

sub set_idle_timeout ($$) {
    my ($chan, $idle_handler) = @_;

    if ($uw_config{idle_timeout} > 0 && $idle_handler) {
        $chan->{idle_timeout} = $uw_config{idle_timeout};
        $chan->{idle_handler} = $idle_handler;
        $chan->{idle_watch} = $ev_loop->timer(
                                    $chan->{idle_timeout}, 0,
                                    sub { _ssl_idle_handler($chan) });
    }
}

sub ssl_update_idle ($) {
    my ($chan) = @_;
    if ($chan->{idle_watch}) {
        $chan->{idle_watch}->set($chan->{idle_timeout}, 0);
    }
}

sub _ssl_idle_handler ($) {
    my ($chan) = @_;
    debug('idle disconnect of %s', $chan->{addr});
    my $handler = $chan->{idle_handler};
    &$handler($chan);
    delete $chan->{idle_watch};
    ssl_disconnect($chan);
}

#
# Detach and close connection
#

sub ssl_disconnect ($) {
    my ($chan) = @_;

    # Paired with closing connection.
    if ($chan->{ssl}) {
        Net::SSLeay::free($chan->{ssl});
        ssl_check_die("SSL free");
        delete $chan->{ssl};
    }
    if ($chan->{conn}) {
        shutdown($chan->{conn}, 2);
        close($chan->{conn});
        delete $chan->{conn}
    }
    delete $chan->{r_watch};
    delete $chan->{w_watch};
}

#
# Packet reading
#

sub ssl_read_packet () {
    my ($chan, $handler, $param) = @_;
    $chan->{r_handler} = $handler;
    $chan->{r_param} = $param;
    $chan->{r_head} = "";
    $chan->{r_body} = "";
    $chan->{r_what} = "r_head";
    $chan->{r_bytes} = 5;
    $chan->{r_first} = 1;
    $chan->{r_watch} = $ev_loop->io($chan->{conn}, &EV::READ,
                                    sub { _ssl_read_pending($chan) });
    #debug('wait for data from %s: watch:%s', $chan->{addr}, $chan->{r_watch});
}

sub _ssl_read_pending ($) {
    my ($chan) = @_;
    #debug("reading triggered");

    #
    # reset wait mode to read/write after first byte.
    # ssl might need re-negotiation etc
    #
    if ($chan->{r_first}) {
        #debug('switching to read/write: watch:%s', $chan->{r_watch});
        $chan->{r_watch}->events(&EV::READ | &EV::WRITE);
        $chan->{r_first} = 0;
    }

    #
    # 16384 is the maximum amount read() can return.
    # Larger values allocate memory that can't be unused
    # as part of the buffer passed to read().
    #
    my $bytes = $chan->{r_bytes};
    $bytes = 16384 if $bytes > 16384;

    #
    # Repeat read() until EAGAIN before select()ing for more. SSL may already be
    # holding the last packet in its buffer, so if we aren't careful to decode
    # everything that's pending we could block forever at select(). This would be
    # after SSL already read "\r\n\r\n" but before it decoded and returned it. As
    # documented, OpenSSL returns data from only one SSL record per call, but its
    # internal system call to read may gather more than one record. In short, a
    # socket may not become readable again after reading, but note that writing
    # doesn't have this problem since a socket will always become writable again
    # after writing.
    #
    my $buf = Net::SSLeay::read($chan->{ssl}, $bytes);
    ssl_check_die("SSL read", "non-fatal");

    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        #debug("will read later: again=%s intr=%s nobufs=%s", $!{EAGAIN}, $!{EINTR}, $!{ENOBUFS});
        return;
    }

    my $handler = $chan->{r_handler};
    unless (defined $buf) {
        info('read failed: %s', $!);
        delete $chan->{r_watch};
        &$handler($chan, undef, $chan->{r_param});
        return;
    }

    $bytes = length($buf);
    unless ($bytes) {
        debug("connection terminated");
        delete $chan->{r_watch};
        &$handler($chan, undef, $chan->{r_param});
        return;
    }

    $chan->{$chan->{r_what}} .= $buf;
    $chan->{r_bytes} -= $bytes;
    ssl_update_idle($chan);
    return if $chan->{r_bytes} > 0;

    if ($chan->{r_what} eq "r_body") {
        my $body = $chan->{r_body};
        if ($body =~ /\n$/) {
            chomp $body;
            debug("received: [$body]");
            delete $chan->{r_watch};
            &$handler($chan, $body, $chan->{r_param});
            return;
        }
        debug("bad request body [$body]");
        delete $chan->{r_watch};
        &$handler($chan, undef, $chan->{r_param});
        return;
    }
    
    # it's a header
    if ($chan->{r_head} =~ /^(\d{4}):$/) {
        $bytes = $1 - 5;
        if ($bytes > 0 && $bytes <= 8192) {
            debug("request header: [%s]", $chan->{r_head});
            $chan->{r_what} = "r_body";
            $chan->{r_body} = "";
            $chan->{r_bytes} = $bytes;
            return;
        }
    }

    debug("bad request header [%s]", $chan->{r_head});
    delete $chan->{r_watch};
    &$handler($chan, undef, $chan->{r_param});
    return;
}

#
# Packet writing
#

sub ssl_write_packet ($$$$) {
    my ($chan, $buf, $handler, $param) = @_;
    my $bytes = length($buf);
    fail("packet too long") if $bytes >= 8192;
    $bytes += 6;
    my $head = sprintf('%04d:', $bytes);
    debug("send packet:[${head}${buf}]");

    $chan->{w_handler} = $handler;
    $chan->{w_param} = $param;
    $chan->{w_buf} = $head . $buf . "\n";
    $chan->{w_watch} = $ev_loop->io($chan->{conn}, &EV::READ | &EV::WRITE,
                                    sub { _ssl_write_pending($chan) });
}

sub _ssl_write_pending ($) {
    my ($chan) = @_;

    my $total = length($chan->{w_buf});
    #debug('writing %s bytes', $total);
    my $bytes = Net::SSLeay::write($chan->{ssl}, $chan->{w_buf});
    ssl_check_die("SSL write");

    if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
        #debug("will write later: again=%s intr=%s nobufs=%s", $!{EAGAIN}, $!{EINTR}, $!{ENOBUFS});
        return;
    }

    my $handler = $chan->{w_handler};
    unless ($bytes) {
        info('write failed:%s', $!);
        delete $chan->{w_watch};
        &$handler($chan, 0, $chan->{w_param});
        return;
    }

    ssl_update_idle($chan);
    return if $bytes < 0;

    substr($chan->{w_buf}, 0, $bytes, "");
    $total -= $bytes;
    return if $total > 0;

    delete $chan->{w_watch};
    &$handler($chan, 1, $chan->{w_param});
    return;
}

##############################################
1;

