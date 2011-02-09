#!/usr/bin/perl
use strict;
use IO::Socket::UNIX qw( SOCK_STREAM );

my $path = "/var/run/userwatch/uwclient.sock";
my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path)
    or die("can't connect to server: $!\n");
my $cmd = $ARGV[0] || "test";
print $sock "$cmd\n";
chomp(my $line = <$sock>);
print "result: \"$line\"\n";
close($sock);

