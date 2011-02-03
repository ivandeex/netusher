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
    my $ctx = ssl_create_context($uw_config{server_pem});
    my $sock = ssl_listen($uw_config{port});
    while(1) {
        my $conn = ssl_accept($sock);
        my $ssl = ssl_attach($ctx, $conn);
        my $request = ssl_read_until_cr($ssl, $conn);
        ssl_write($ssl, $conn, "0007OK\n");
        # Paired with closing connection.
        ssl_detach($ssl);
        close($conn);
    }

    # Paired with closing listening socket.
    ssl_free_context($ctx);
    close($sock);
}

main();

