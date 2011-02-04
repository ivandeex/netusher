#!/usr/bin/perl
#
# UserWatch SSL server
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/userwatch.inc.pm";

our ($CFG_ROOT, $debug, %uw_config);

sub main {
    my $config = "$CFG_ROOT/uwserver.conf";
    read_config($config);
    ssl_startup();
    my $ctx = ssl_create_context($uw_config{server_pem}, $uw_config{ca_cert});
    my $sock = ssl_listen($uw_config{port});
    while(1) {
        print "waiting for client...\n" if $debug;
        my ($ssl, $conn) = ssl_accept($sock, $ctx);
        my $ok = 0;
        my $req = ssl_read_packet($ssl, $conn);
        if (defined $req) {
            print "request ok\n";
            ssl_write_packet($ssl, $conn, "OK");
        }
        ssl_detach($ssl, $conn);
    }

    # Paired with closing listening socket.
    ssl_free_context($ctx);
    close($sock);
}

main();

