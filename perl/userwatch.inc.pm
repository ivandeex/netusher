#!/usr/bin/perl
#
# UserWatch common and SSL functions
# $Id$
#

use strict;

use Errno;
use Fcntl;
use Net::SSLeay ();
use Net::SSLeay::Handle;
use Socket;

our $CFG_ROOT = '/etc/userwatch';
our $debug = 1;
our $blocking_ssl = 0;

##############################################
# Configuration file
#

our %uw_config = (
        server     => undef,
        port       => 7501,
        ca_cert    => "$CFG_ROOT/ca.crt",
        server_pem => "$CFG_ROOT/uwserver.pem",
        client_pem => "$CFG_ROOT/uwclient.pem",
        also_local => 0,
        debug      => 0,
        timeout    => 5,
    );

sub read_config ($) {
    my ($config) = @_;
    open (my $file, $config)
        or die "$config: configuration file not found\n";
    while (<$file>) {
        next if /^\s*$/ || /^\s*#/;
        if (/^\s*(\w+)\s*=\s*(\S+)\s*$/) {
            my ($param, $value) = ($1, $2);
            if (exists $uw_config{$param}) {
                if ($uw_config{$param} !~ /^\d+$/ || $value =~ /^\d+$/) {
                    $uw_config{$param} = $value;
                    next;
                }
            }
        }
        die "$config: configuration error in line $.\n";
    }
    close ($file);
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
    die $@ if $@;

    Net::SSLeay::SSLeay_add_ssl_algorithms();
    eval 'no warnings "redefine"; sub Net::SSLeay::SSLeay_add_ssl_algorithms () {}';
    die $@ if $@;

    #Net::SSLeay::ENGINE_load_builtin_engines();
    #eval 'no warnings "redefine"; sub Net::SSLeay::ENGINE_load_builtin_engines () {}';
    #die $@ if $@;

    #Net::SSLeay::ENGINE_register_all_complete();
    #eval 'no warnings "redefine"; sub Net::SSLeay::ENGINE_register_all_complete () {}';
    #die $@ if $@;

    Net::SSLeay::randomize();
    eval 'no warnings "redefine"; sub Net::SSLeay::randomize (;$$) {}';
    die $@ if $@;

    $| = 1;
    if ($debug > 1) {
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

sub ssl_check_die ($) {
    my ($message) = @_;
    my ($errors, $errnos) = ssl_get_error();
    die "${message}: ${errors}" if @$errnos;
    return;
}

sub ssl_sock_opts ($$) {
    my ($conn, $nobuf) = @_;

    if (!$blocking_ssl) {
        # Set FD_CLOEXEC.
        $_ = fcntl($conn, F_GETFD, 0)
            or die "fcntl: $!\n";
        fcntl($conn, F_SETFD, $_ | FD_CLOEXEC)
            or die "fnctl: $!\n";
    }

    if (1) {
        # No buffering
        $_ = select($conn); $| = 1; select $_;
    }

    if ($nobuf && !$blocking_ssl) {
        # Set O_NONBLOCK.
        $_ = fcntl($conn, F_GETFL, 0)
            or die "fcntl F_GETFL: $!\n";  # 0 for error, 0e0 for 0.
        fcntl($conn, F_SETFL, $_ | O_NONBLOCK)
            or die "fcntl F_SETFL O_NONBLOCK: $!\n";  # 0 for error, 0e0 for 0.
    }
}

#
# The CTX ("context") should be shared between many SSL connections. A CTX
# could apply to multiple listening sockets, or each listening socket could
# have its own CTX. Each CTX may represent only one local certificate.
#
sub ssl_create_context (;$) {
    my ($pem_path) = @_;

    my $ctx = Net::SSLeay::CTX_new();
    ssl_check_die("SSL CTX_new");

    # OP_ALL enables all harmless work-arounds for buggy clients.
    Net::SSLeay::CTX_set_options($ctx, Net::SSLeay::OP_ALL());
    ssl_check_die("SSL CTX_set_options");

    # Modes:
    # 0x1: SSL_MODE_ENABLE_PARTIAL_WRITE
    # 0x2: SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    # 0x4: SSL_MODE_AUTO_RETRY
    # 0x8: SSL_MODE_NO_AUTO_CHAIN
    # 0x10: SSL_MODE_RELEASE_BUFFERS (ignored before OpenSSL v1.0.0)
    Net::SSLeay::CTX_set_mode($ctx, 0x11);
    ssl_check_die("SSL CTX_set_mode");

    if ($pem_path) {
        $pem_path = "$CFG_ROOT/$pem_path"
            unless $pem_path =~ m'^/';
        die "$pem_path: pem certificate not found\n"
            unless -r $pem_path;

        # Load certificate. Avoid password prompt.
        Net::SSLeay::CTX_set_default_passwd_cb($ctx, sub { "" });
        ssl_check_die("SSL CTX_set_default_passwd_cb");

        Net::SSLeay::CTX_use_RSAPrivateKey_file($ctx, $pem_path, Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_RSAPrivateKey_file");

        Net::SSLeay::CTX_use_certificate_file($ctx, $pem_path, Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_certificate_file");
    }

    return $ctx;
}

sub ssl_free_context ($) {
    my ($ctx) = @_;
    Net::SSLeay::CTX_free($ctx);
    ssl_check_die("SSL CTX_free");
}

#
# Listen for client connections
#
sub ssl_listen ($) {
    my ($port) = @_;

    my $sock;
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or die("socket: $!\n");
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1)
        or die("setsockopt SOL_SOCKET, SO_REUSEADDR: $!\n");
    bind($sock, pack_sockaddr_in($port, INADDR_ANY))
        or die("bind ${port}: $!\n");
    listen($sock, SOMAXCONN)
        or die("listen ${port}: $!\n");

    ssl_sock_opts($sock, 0);

    return $sock;
}

#
# Accept another client connection
#
sub ssl_accept ($$) {
    my ($sock, $ctx) = @_;

    accept(my $conn, $sock)
        or die "accept: $!\n";

    ssl_sock_opts($conn, 1);

    # Each connection needs an SSL object,
    # which is associated with the shared CTX.
    my $ssl = Net::SSLeay::new($ctx);
    ssl_check_die("SSL new");

    Net::SSLeay::set_fd($ssl, fileno($conn));
    ssl_check_die("SSL set_fd");

    Net::SSLeay::accept($ssl);
    ssl_check_die("SSL accept");

    return ($ssl, $conn);
}

#
# Connect to server
#
sub ssl_connect ($$$) {
    my ($server, $port, $ctx) = @_;

    my $sock;
    socket($sock, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
        or die("socket: $!\n");

    my $ip = gethostbyname($server)
        or die("$server: host not found\n");
    my $conn_params = sockaddr_in($port, $ip);

    connect($sock, $conn_params)
        or die("$server: cannot connect: $!\n");

    ssl_sock_opts($sock, 1);

    # Each connection needs an SSL object,
    # which is associated with the shared CTX.
    my $ssl = Net::SSLeay::new($ctx);
    ssl_check_die("SSL new");

    Net::SSLeay::set_fd($ssl, fileno($sock));
    ssl_check_die("SSL set_fd");

    Net::SSLeay::connect($ssl);
    ssl_check_die("SSL connect");

    return ($ssl, $sock);
}

#
# Detach and close connection
#
sub ssl_detach ($$) {
    my ($ssl, $conn) = @_;

    # Paired with closing connection.
    Net::SSLeay::free($ssl);
    ssl_check_die("SSL free");
    close($conn);
}

#
# Safe reading and writing
#
sub ssl_read ($$$) {
    my ($ssl, $conn, $bytes) = @_;

    my $lines = "";
    my $timeout = $uw_config{timeout};
    print "read returned: " if $debug;

    while ($bytes > 0) {
        my $vec = "";
        vec($vec, fileno($conn), 1) = 1;
        my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
        $timeout = $timeleft if $timeleft;
        #print "{$nfound/$timeleft} " if $debug;

        # Repeat read() until EAGAIN before select()ing for more. SSL may already be
        # holding the last packet in its buffer, so if we aren't careful to decode
        # everything that's pending we could block forever at select(). This would be
        # after SSL already read "\r\n\r\n" but before it decoded and returned it. As
        # documented, OpenSSL returns data from only one SSL record per call, but its
        # internal system call to read may gather more than one record. In short, a
        # socket may not become readable again after reading, but note that writing
        # doesn't have this problem since a socket will always become writable again
        # after writing.

        while ($bytes > 0) {
            # 16384 is the maximum amount read() can return; larger values allocate memory
            # that can't be unused as part of the buffer passed to read().
            my $read_buf = Net::SSLeay::read($ssl, $bytes);
            ssl_check_die("SSL read");
            if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
                #print "[again], " if $debug;
                #print "." if $debug;
                next;                
            }
            die "read: $!\n" unless defined $read_buf;
            if (defined $read_buf) {
                print length($read_buf),", " if $debug;
                $lines .= $read_buf;
                $bytes -= length($read_buf);
            }
        }
    }

    print "\n" if $debug;
    print $lines if $debug;
    return $lines;
}

sub ssl_write ($$$) {
    my ($ssl, $conn, $write_buf) = @_;

    my $total = length($write_buf);
    print "write ($total) returned: " if $debug;
    my $timeout = $uw_config{timeout};

    while ($total > 0) {
        my $vec = "";
        vec($vec, fileno($conn), 1) = 1;
        my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
        $timeout = $timeleft if $timeleft;
        #print "{$nfound/$timeleft} " if $debug;

        my $bytes = Net::SSLeay::write($ssl, $write_buf);
        ssl_check_die("SSL write");
        if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
            #print "[again], " if $debug;
            #print "." if $debug;
            next;
        }
        die "write error: $!\n" unless $bytes;
        print $bytes,", " if $debug;
        if ($bytes > 0) {
            substr($write_buf, 0, $bytes, "");
            $total -= $bytes;
        }
    }

    print "\n" if $debug;
}

sub ssl_read_packet ($$) {
    my ($ssl, $conn) = @_;

    if ($blocking_ssl) {
        my $pkt = Net::SSLeay::ssl_read_until($ssl, "\n");
        return unless $pkt =~ /^\d{4}:/;
        $pkt = substr($pkt, 5, length($pkt) - 6);
        print "received: [$pkt]\n" if $debug;
        return $pkt;
    }

    my $hdr = ssl_read($ssl, $conn, 5);
    if ($hdr =~ /^(\d{4}):$/) {
        my $bytes = $1 - 5;
        if ($bytes > 0 && $bytes <= 8192) {
            print "request header: [$hdr]\n" if $debug;
            my $pkt = ssl_read($ssl, $conn, $bytes);
            if ($pkt =~ /\n$/) {
                chomp $pkt;
                print "received: [$pkt]\n" if $debug;
                return $pkt;
            }
            print "bad request body [$pkt]\n" if $debug;
            return;
        }
    }
    print "bad request header \"$hdr\"\n" if $debug;
    return;
}

sub ssl_write_packet ($$$) {
    my ($ssl, $conn, $pkt) = @_;
    die "packet too long\n" if length($pkt) >= 8192;
    my $hdr = sprintf('%04d:', length($pkt) + 6);
    print "send packet:[${hdr}${pkt}]\n" if $debug;
    if ($blocking_ssl) {
        Net::SSLeay::ssl_write_all($ssl, $hdr . $pkt . "\n");
    } else {
        ssl_write($ssl, $conn, $hdr . $pkt . "\n");
    }
}

##############################################
1;

