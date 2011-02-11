#!/usr/bin/perl
#
# UserWatch
# Various caches
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

use Digest::MD5 qw(md5_hex);

our (%uw_config, %cache_backend);
my  (%user_cache, %auth_cache);

#
# flush all caches
#
sub cache_flush () {
    %user_cache = ();
    %auth_cache = ();
}

#
# return uidNumber for a user (used by server)
#
sub get_user_uid ($) {
    my ($user) = @_;
    my ($uid, $msg);

    # try to fetch uid from cache
    my $ttl = $uw_config{uid_cache_ttl};
    if ($ttl > 0 && exists($user_cache{$user})) {
        if (monotonic_time() - $user_cache{$user}{stamp} < $ttl) {
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
    if ($ttl > 0) {
        $user_cache{$user}{uid} = $uid;
        $user_cache{$user}{stamp} = monotonic_time();
    }
    debug("get_user_uid user:$user uid:$uid from:backend");
    return $uid;
}

#
# user authentication caching (used by client)
#
sub check_auth_cache ($$$) {
    my ($user, $uid, $pass) = @_;

    my $ttl = $uw_config{auth_cache_ttl};
    return -1 if !$ttl || $ttl < 0;
    return -2 unless exists $auth_cache{$user};

    if (monotonic_time() - $auth_cache{$user}{stamp} >= $ttl) {
        delete $auth_cache{$user};
        return -3;
    }

    return -4 if $uid != $auth_cache{$user}{uid};
    return -5 if md5_hex($pass) ne $auth_cache{$user}{pass_md5};

    return 0;
}

sub update_auth_cache ($$$$) {
    my ($user, $uid, $pass, $result) = @_;

    my $ttl = $uw_config{auth_cache_ttl};
    return -1 if !$ttl || $ttl < 0;
    return -2 if $result ne "OK";

    $auth_cache{$user}{uid} = $uid;
    # store password as MD5 hash for security
    $auth_cache{$user}{pass_md5} = md5_hex($pass);
    $auth_cache{$user}{stamp} = monotonic_time();
    debug("cache user auth: user:$user uid:$uid pass:ok");
    return 0;
}

##############################################
1;

