#!/usr/bin/perl
#
# UserWatch
# Various caches
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

our (%uw_config, %cache_backend);
my  (%user_cache);

#
# flush all caches
#
sub cache_flush () {
    %user_cache = ();
}

#
# return uidNumber for a user
#
sub get_user_uid ($) {
    my ($user) = @_;
    my ($uid, $msg);

    # try to fetch uid from cache
    my $stamp = time();
    if (exists($user_cache{$user})) {
        if ($stamp - $user_cache{$user}{stamp} < $uw_config{cache_retention}) {
            $uid = $user_cache{$user}{uid};
            debug("get_user_uid user:$user uid:$uid from:cache");
            return $uid;
        }
        delete $user_cache{$user};
    }

    ($uid, $msg) = &{$cache_backend{get_user_uid}}($user);
    if ($msg) {
        debug("get_user_uid user:$user uid:$uid error:$msg");
        return;
    }

    # update cache with defined or undefined uid
    $user_cache{$user}{uid} = $uid;
    $user_cache{$user}{stamp} = $stamp;
    debug("get_user_uid user:$user uid:$uid from:backend");
    return $uid;
}

##############################################
1;

