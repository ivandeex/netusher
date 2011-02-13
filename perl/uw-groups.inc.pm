#!/usr/bin/perl
#
# UserWatch
# Local users and groups
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

our (%local_users);
my  ($passwd_modified_stamp);

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

##############################################
1;

