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

#
# require: perl-User-getgrouplist
#
# you can obtain the modules from
# http://rpm.vitki.net/pub/centos/5/i386/repoview/letter_p.group.html
#
use User::getgrouplist;

our (%uw_config, %cache_backend, %local_groups);
my  (%uid_grp_cache, %group_cache, %auth_cache);

#
# flush all caches
#
sub cache_flush () {
    %uid_grp_cache = ();
    %group_cache = ();
    %auth_cache = ();
}

#
# return uidNumber for a user (used by server)
#
sub get_user_uid_grp ($$) {
    my ($user, $grp_ref) = @_;
    my ($uid, $grp, $msg);

    # try to fetch uid from cache
    my $ttl = $uw_config{uid_cache_ttl};
    if ($ttl > 0 && exists($uid_grp_cache{$user})) {
        if (monotonic_time() - $uid_grp_cache{$user}{stamp} < $ttl) {
            $uid = $uid_grp_cache{$user}{uid};
            $grp = $uid_grp_cache{$user}{grp};
            debug("get user:$user uid:$uid grp:$grp from:cache");
            $$grp_ref = $grp if defined $grp_ref;
            return $uid;
        }
        delete $uid_grp_cache{$user};
    }

    ($msg, $uid, $grp) = &{$cache_backend{get_user_uid_grp}}($user);
    if ($msg) {
        debug("get user:$user uid:$uid error:$msg");
        return;
    }

    # update cache with defined or undefined uid
    if ($ttl > 0) {
        $uid_grp_cache{$user}{uid} = $uid;
        $uid_grp_cache{$user}{grp} = $grp;
        $uid_grp_cache{$user}{stamp} = monotonic_time();
    }
    debug("get user:$user uid:$uid grp:$grp from:backend");
    $$grp_ref = $grp if defined $grp_ref;
    return $uid;
}

#
# return group list for a user (used by server)
#
sub get_user_groups ($) {
    my ($user) = @_;
    my ($msg, $groups);

    # try to fetch uid from cache
    my $ttl = $uw_config{group_cache_ttl};
    if ($ttl > 0 && exists($group_cache{$user})) {
        if (monotonic_time() - $group_cache{$user}{stamp} < $ttl) {
            $groups = $group_cache{$user}{groups};
            debug("get_user_groups user:%s from:cache groups:%s",
                    $user, join(",", @$groups));
            return ;
        }
        delete $group_cache{$user};
    }

    ($msg, $groups) = &{$cache_backend{get_user_groups}}($user);
    if ($msg) {
        debug("get_user_groups user:$user error:$msg");
        return;
    }

    # update cache with defined or undefined uid
    if ($ttl > 0) {
        $group_cache{$user}{groups} = $groups;
        $group_cache{$user}{stamp} = monotonic_time();
    }
    debug("get_user_groups user:%s from:backend groups:%s",
            $user, join(",", @$groups));
    return $groups;
}

#
# return groups for a set of users (user by server)
#
sub inquire_groups ($) {
    my ($users) = @_;

    # remove duplicates
    my %groups_map;
    $groups_map{$_->{user}} = 1 for (@$users);

    # skip local users and users with non-matching id
    for my $user (keys %groups_map) {
        my $grp;
        my $uid = get_user_uid_grp($user, \$grp);

        if (!$uid || is_local_user($user)) {
            debug("inquire_groups($user): skip local user");
            delete $groups_map{$user};
            next;
        }

        # sort and remove duplicates
        my %groups_set = ( $grp => 1 );
        my $groups_ref = get_user_groups($user);
        if ($groups_ref) {
            $groups_set{$_} = 1 for (@$groups_ref);
        }
        $groups_map{$user} = [ sort keys %groups_set ];
    }

    return \%groups_map;
}

#
# NSS queries (used by server):
# - uid/gid numbers for a user
# - list of groups for a user
#
sub nss_get_user_uid_grp ($) {
    my ($user) = @_;
    my ($name, $pass, $uid, $gid) = getpwnam($user);
    my ($msg, $grp);
    if ($name) {
        $grp = getgrgid($gid);
        $grp = $gid unless $grp;
    } else {
        $msg = "not found";
    }
    return ($msg, $uid, $grp);
}

sub nss_get_user_groups ($) {
    my ($user) = @_;
    my @all_groups = getgrouplist($user);
    my @global_groups;
    rescan_etc();
    for my $grp (@all_groups) {
        if ($grp =~ /^\d+$/) {
            $grp = getgrgid($grp);
            next unless $grp;
        }
        next if $local_groups{$grp};
        push @global_groups, $grp;
    }
    return (0, \@global_groups);
}

#
# user authentication caching (used by client)
#
sub check_auth_cache ($$) {
    my ($user, $pass) = @_;

    my $ttl = $uw_config{auth_cache_ttl};
    return -1 if !$ttl || $ttl < 0;
    return -2 unless exists $auth_cache{$user};

    if (monotonic_time() - $auth_cache{$user}{stamp} >= $ttl) {
        delete $auth_cache{$user};
        return -3;
    }

    return -4 if md5_hex($pass) ne $auth_cache{$user}{pass_md5};

    return 0;
}

sub update_auth_cache ($$$) {
    my ($user, $pass, $result) = @_;

    my $ttl = $uw_config{auth_cache_ttl};
    return -1 if !$ttl || $ttl < 0;
    return -2 if $result ne "OK";

    # store password as MD5 hash for security
    $auth_cache{$user}{pass_md5} = md5_hex($pass);
    $auth_cache{$user}{stamp} = monotonic_time();
    debug("cache user auth: user:$user pass:ok");
    return 0;
}

##############################################
1;

