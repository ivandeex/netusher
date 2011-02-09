#!/usr/bin/perl
#
# UserWatch
# SSL functions
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

#
# require: perl-Net-SSLeay
#
use Errno;
use Fcntl;
use Socket;
use Net::SSLeay ();
use Net::SSLeay::Handle;
use Sys::Syslog;

our ($config_root, %uw_config);

##############################################
# Safe wrappers around Net::SSLeay
#

my ($ssl_ctx);

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

##############################################
# Listen for client connections
#

sub ssl_listen ($) {
    my ($port) = @_;

    my $sock;
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or fail("ssl_listen socket: $!");
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1)
        or fail("ssl_listen setsockopt SOL_SOCKET, SO_REUSEADDR: $!");
    bind($sock, pack_sockaddr_in($port, INADDR_ANY))
        or fail("ssl_listen bind ${port}: $!");
    listen($sock, SOMAXCONN)
        or fail("ssl_listen listen ${port}: $!");

    ssl_sock_opts($sock);

    my $chan = {
        type => 'accepting',
        destructor => \&ssl_disconnect,
        pending => 1,
        ssl => undef,
        conn => $sock,
        addr => ":$port",
        };

    return $chan;
}

sub ssl_accept ($;$) {
    my ($s_chan, $close_handler) = @_;

    my $paddr = accept(my $conn, $s_chan->{conn});
    unless ($paddr) {
        debug("ssl_accept accept: $!");
        return;
    }
    my ($port, $iaddr) = sockaddr_in($paddr);
    my $addr = join('.', unpack('C*', $iaddr)) . ':' . $port;

    my $c_chan = {
        type => 'accepted',
        destructor => \&ssl_disconnect,
        pending => 0,
        conn => $conn,
        addr => $addr
        };

    ssl_sock_opts($c_chan->{conn});
    $c_chan->{ssl} = ssl_create_ssl($c_chan->{conn}, $ssl_ctx);
    Net::SSLeay::accept($c_chan->{ssl});
    ssl_check_die("SSL accept");

    init_timeouts($c_chan, $close_handler);
    return $c_chan;
}

##############################################
# Connecting to server
#

sub ssl_connect ($$;$) {
    my ($server, $port, $close_handler) = @_;

    my $conn;
    socket($conn, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or fail("ssl_connect socket connect: $!");

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
        destructor => \&ssl_disconnect,
        pending => 1,
        ssl => undef,
        conn => $conn,
        addr => "$server:$port",
        server => $server,
        port => $port,
        conn_params => $conn_params,
        close_handler => $close_handler
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

    init_timeouts($chan, $chan->{close_handler});
    return "ok";
}

#
# Detach and close connection
#

sub ssl_disconnect ($) {
    my ($chan) = @_;

    end_transmission($chan);
    init_timeouts($chan, 0);

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
}

##############################################
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
    init_transmission($chan, &EV::READ, \&_ssl_read_pending);
}

sub _ssl_read_pending ($) {
    my ($chan) = @_;

    #
    # reset wait mode to read/write after first byte.
    # ssl might need re-negotiation etc
    #
    fire_transmission($chan, &EV::READ | &EV::WRITE);

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
        info("%s: read failed: %s", $chan->{addr}, $!);
        end_transmission($chan);
        &$handler($chan, undef, $chan->{r_param});
        return;
    }

    $bytes = length($buf);
    unless ($bytes) {
        info("%s: read terminated: %s", $chan->{addr}, $!);
        end_transmission($chan);
        &$handler($chan, undef, $chan->{r_param});
        return;
    }

    $chan->{$chan->{r_what}} .= $buf;
    $chan->{r_bytes} -= $bytes;
    postpone_timeouts($chan);
    return if $chan->{r_bytes} > 0;

    if ($chan->{r_what} eq "r_body") {
        my $body = $chan->{r_body};
        if ($body =~ /\n$/) {
            chomp $body;
            debug("%s: received \"%s\"", $chan->{addr}, $body);
            end_transmission($chan);
            &$handler($chan, $body, $chan->{r_param});
            return;
        }
        info("%s: bad request body \"%s\"", $chan->{addr}, $body);
        end_transmission($chan);
        &$handler($chan, undef, $chan->{r_param});
        return;
    }
    
    # it's a header
    if ($chan->{r_head} =~ /^(\d{4}):$/) {
        $bytes = $1 - 5;
        if ($bytes > 0 && $bytes <= 8192) {
            debug("%s: request header \"%s\"", $chan->{addr}, $chan->{r_head});
            $chan->{r_what} = "r_body";
            $chan->{r_body} = "";
            $chan->{r_bytes} = $bytes;
            return;
        }
    }

    info("%s: bad request header \"%s\"", $chan->{addr}, $chan->{r_head});
    end_transmission($chan);
    &$handler($chan, undef, $chan->{r_param});
    return;
}

##############################################
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
    init_transmission($chan, &EV::READ | &EV::WRITE, \&_ssl_write_pending);
    fire_transmission($chan);
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
        info("%s: write failed: %s", $chan->{addr}, $!);
        end_transmission($chan);
        &$handler($chan, 0, $chan->{w_param});
        return;
    }

    postpone_timeouts($chan);
    return if $bytes < 0;

    substr($chan->{w_buf}, 0, $bytes, "");
    $total -= $bytes;
    return if $total > 0;

    end_transmission($chan);
    &$handler($chan, 1, $chan->{w_param});
    return;
}

##############################################
1;

