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

our $CFG_ROOT = '/etc/userwatch';

##############################################
# Configuration file
#

our %uw_config = (
        # common parameters
        port        => 7501,
        ca_cert     => "$CFG_ROOT/ca.crt",
        debug       => 0,
        syslog      => 1,
        stdout      => 0,
        timeout     => 5,
        # client parameters
        server      => undef,
        client_pem  => "$CFG_ROOT/uwclient.pem",
        also_local  => 0,
        # server parameters
        server_pem  => "$CFG_ROOT/uwserver.pem",
        mysql_host  => "localhost",
        mysql_port  => 3306,
        mysql_db    => undef,
        mysql_user  => undef,
        mysql_pass  => undef,
        vpn_net     => undef,
        ldap_uri        => undef,
        ldap_bind_dn    => undef,
        ldap_bind_pass  => undef,
        ldap_start_tls  => 0,
        ldap_user_base  => undef,
        ldap_attr_user  => 'uid',
        ldap_attr_uid   => 'uidNumber',
        cache_retention => 300,
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

sub fail ($@) {
    my $fmt = shift;
    my $msg = "[ fail] " . sprintf($fmt, @_);
    syslog("err", $msg) if $uw_config{syslog};
    confess($msg."\n");
}

sub info ($@) {
    my $fmt = shift;
    my $msg = "[ info] " . sprintf($fmt, @_);
    syslog("notice", $msg) if $uw_config{syslog};
    print($msg."\n") if $uw_config{stdout};
}

sub debug ($@) {
    return unless $uw_config{debug};
    my $fmt = shift;
    my $msg = "[debug] " . sprintf($fmt, @_);
    syslog("info", $msg) if $uw_config{syslog};
    print($msg."\n") if $uw_config{stdout};    
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

sub ssl_check_die ($) {
    my ($message) = @_;
    my ($errors, $errnos) = ssl_get_error();
    fail("${message}: ${errors}") if @$errnos;
    return;
}

sub ssl_sock_opts ($$) {
    my ($conn, $noblock) = @_;

    if (1) {
        # No buffering
        $_ = select($conn); $| = 1; select $_;
    }

    if ($noblock) {
        # Set O_NONBLOCK.
        $_ = fcntl($conn, F_GETFL, 0)
            or fail("fcntl F_GETFL: $!");  # 0 for error, 0e0 for 0.
        fcntl($conn, F_SETFL, $_ | O_NONBLOCK)
            or fail("fcntl F_SETFL O_NONBLOCK: $!");  # 0 for error, 0e0 for 0.
    }
}

#
# The CTX ("context") should be shared between many SSL connections. A CTX
# could apply to multiple listening sockets, or each listening socket could
# have its own CTX. Each CTX may represent only one local certificate.
#
sub ssl_create_context (;$$) {
    my ($pem_path, $ca_crt_path) = @_;

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
        # Server and client can use PEM (cert+key) for secure connection
        $pem_path = "$CFG_ROOT/$pem_path"
            unless $pem_path =~ m'^/';
        fail("$pem_path: pem certificate not found")
            unless -r $pem_path;

        # Load certificate. Avoid password prompt.
        Net::SSLeay::CTX_set_default_passwd_cb($ctx, sub { "" });
        ssl_check_die("SSL CTX_set_default_passwd_cb");

        Net::SSLeay::CTX_use_RSAPrivateKey_file($ctx, $pem_path, Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_RSAPrivateKey_file");

        Net::SSLeay::CTX_use_certificate_file($ctx, $pem_path, Net::SSLeay::FILETYPE_PEM());
        ssl_check_die("SSL CTX_use_certificate_file");
    }

    if ($ca_crt_path) {
        # Server and client can use CA certificate to check other side
        $ca_crt_path = "$CFG_ROOT/$ca_crt_path"
            unless $ca_crt_path =~ m'^/';
        fail("$ca_crt_path: ca certificate not found")
            unless -r $ca_crt_path;
        my ($ca_file, $ca_dir) = (-d $ca_crt_path) ?
                                    (undef, $ca_crt_path) : ($ca_crt_path, undef);

        Net::SSLeay::CTX_load_verify_locations($ctx, $ca_file, $ca_dir);
        ssl_check_die("SSL CTX_load_verify_locations");
        debug("enable verification file:$ca_file dir:$ca_dir");

        my $mode = &Net::SSLeay::VERIFY_PEER
                    | &Net::SSLeay::VERIFY_FAIL_IF_NO_PEER_CERT
                    | &Net::SSLeay::VERIFY_CLIENT_ONCE;
        Net::SSLeay::CTX_set_verify($ctx, $mode, \&ssl_cert_verify_cb);
        ssl_check_die("SSL CTX_set_verify");
    }

    return $ctx;
}

sub ssl_cert_verify_cb {
    my ($ok, $x509_store_ctx) = @_;
    if ($uw_config{debug}) {
        my $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($x509_store_ctx);
        my $subj = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($cert));
        my $cname = ($subj =~ m'/CN=([^/]+)/') ? $1 : $subj;
        debug("verification ok:$ok cname:$cname");
    }
    return $ok;
}

sub ssl_free_context ($) {
    my ($ctx) = @_;
    if (defined $ctx) {
        Net::SSLeay::CTX_free($ctx);
        ssl_check_die("SSL CTX_free");
    }
}

#
# Each connection needs an SSL object,
# which is associated with the shared CTX.
#
sub ssl_create_ssl ($$) {
    my ($ctx, $conn) = @_;

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

    ssl_sock_opts($sock, 1);

    return $sock;
}

#
# Accept another client connection
#
sub ssl_accept ($$) {
    my ($sock, $ctx) = @_;

    my $timeout = $uw_config{timeout};
    my $vec = "";
    vec($vec, fileno($sock), 1) = 1;
    my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
    return unless $nfound;

    my $from = accept(my $conn, $sock);
    unless ($from) {
        debug("accept: $!");
        return;
    }

    ssl_sock_opts($conn, 1);

    my $ssl = ssl_create_ssl($ctx, $conn);

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
        or fail("socket: $!");

    my $ip = gethostbyname($server)
        or fail("$server: host not found");
    my $conn_params = sockaddr_in($port, $ip);

    ssl_sock_opts($sock, 1);

    connect($sock, $conn_params);
    my $timeout = $uw_config{timeout};
    my $vec = "";
    vec($vec, fileno($sock), 1) = 1;
    my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
    if (!connect($sock, $conn_params)) {
        info("$server: cannot connect: $!");
        return;
    }
    debug("connected to server");

    ssl_sock_opts($sock, 1);

    my $ssl = ssl_create_ssl($ctx, $sock);

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
    if (defined $ssl) {
        Net::SSLeay::free($ssl);
        ssl_check_die("SSL free");
    }
    if (defined $conn) {
        shutdown($conn, 2);
        close($conn);
    }
}

#
# Safe reading and writing
#
sub ssl_read ($$$) {
    my ($ssl, $conn, $bytes) = @_;

    my $lines = "";
    my $timeout = $uw_config{timeout};
    #print "read returned: ";

    while ($bytes > 0) {
        my $vec = "";
        vec($vec, fileno($conn), 1) = 1;
        my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
        $timeout = $timeleft if $timeleft;
        #print "{$nfound/$timeleft} ";

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
                #print "[again], ";
                #print "!";
                next;                
            }
            fail("read failed: $!")
                unless defined $read_buf;
            if (defined $read_buf) {
                my $len = length($read_buf);
                if ($len == 0) {
                    debug("connection terminated");
                    return;
                }
                $lines .= $read_buf;
                $bytes -= $len;
            }
        }
    }

    #print "\n";
    return $lines;
}

sub ssl_write ($$$) {
    my ($ssl, $conn, $write_buf) = @_;

    my $total = length($write_buf);
    debug("write $total bytes");
    #print "write returned: ";
    my $timeout = $uw_config{timeout};

    while ($total > 0) {
        my $vec = "";
        vec($vec, fileno($conn), 1) = 1;
        my ($nfound, $timeleft) = select($vec, $vec, undef, $timeout);
        $timeout = $timeleft if $timeleft;
        #print "{$nfound/$timeleft} ";

        my $bytes = Net::SSLeay::write($ssl, $write_buf);
        ssl_check_die("SSL write");
        if ($!{EAGAIN} || $!{EINTR} || $!{ENOBUFS}) {
            #print "[again], ";
            #print "!";
            next;
        }
        fail("write error: $!") unless $bytes;
        #print $bytes > 0 ? $bytes.", " : ".";
        if ($bytes > 0) {
            substr($write_buf, 0, $bytes, "");
            $total -= $bytes;
        }
    }

    #print "\n";
}

sub ssl_read_packet ($$) {
    my ($ssl, $conn) = @_;

    my $hdr = ssl_read($ssl, $conn, 5);
    if ($hdr =~ /^(\d{4}):$/) {
        my $bytes = $1 - 5;
        if ($bytes > 0 && $bytes <= 8192) {
            debug("request header: [$hdr]");
            my $pkt = ssl_read($ssl, $conn, $bytes);
            if ($pkt =~ /\n$/) {
                chomp $pkt;
                debug("received: [$pkt]");
                return $pkt;
            }
            debug("bad request body [$pkt]");
            return;
        }
    }
    debug("bad request header \"$hdr\"");
    return;
}

sub ssl_write_packet ($$$) {
    my ($ssl, $conn, $pkt) = @_;
    fail("packet too long") if length($pkt) >= 8192;
    my $hdr = sprintf('%04d:', length($pkt) + 6);
    debug("send packet:[${hdr}${pkt}]");
    ssl_write($ssl, $conn, $hdr . $pkt . "\n");
}

##############################################
1;

