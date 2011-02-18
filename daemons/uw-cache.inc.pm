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

our (%uw_config, %nss, %local_groups);
my  (%cache_pool);

#
# generic cache API.
#
sub cache_flush () {
    %cache_pool = ();
}

sub cache_put ($$$$) {
    my ($pool, $key, $value, $ttl) = @_;
    return if $ttl <= 0;
    $cache_pool{$pool}{$key} = [ monotonic_time() + $ttl, $value ];
}

sub cache_get ($$) {
    my ($pool, $key) = @_;
    my $item = $cache_pool{$pool}{$key};
    if ($item) {
        if (monotonic_time() - $item->[0] < 0) {
            return $item->[1];
        }
        delete $cache_pool{$pool}{$key};
    }
    return undef;
}

sub cache_gc () {
    my $now = monotonic_time();
    for my $pool (keys %cache_pool) {
        for my $key (keys %{ $cache_pool{$pool} }) {
            my $item = $cache_pool{$pool}{$key};
            if ($now - $item->[0] >= 0) {
                delete $cache_pool{$pool}{$key};
            }
        }
    }
}

#
# return uidNumber for a user (used by server and client)
#
sub get_user_uid_grp ($$) {
    my ($user, $grp_ref) = @_;
    my ($err, $uid, $grp);

    # try to fetch uid from cache
    my $item = cache_get("uid_grp", $user);
    if (defined $item) {
        ($uid, $grp) = @$item;
        debug("get user:$user from:cache uid:$uid grp:$grp");
        $$grp_ref = $grp if defined $grp_ref;
        return $uid;
    }

    ($err, $uid, $grp) = &{$nss{get_user_uid_grp}}($user);
    if ($err) {
        debug("get user:$user from:$nss{name} uid:- err:$err");
        return;
    }

    # update cache with (defined or even undefined) uid
    cache_put("uid_grp", $user, [ $uid, $grp ], $uw_config{uid_cache_ttl});
    debug("get user:$user from:$nss{name} uid:$uid grp:$grp");
    $$grp_ref = $grp if defined $grp_ref;
    return $uid;
}

#
# return group list for a user (used by server and client)
#
sub get_user_groups ($) {
    my ($user) = @_;
    my ($err, $groups);

    $groups = cache_get("groups", $user);
    if (defined $groups) {
        debug("get user:$user from:cache groups:" . join(",", @$groups));
        return $groups;
    }

    ($err, $groups) = &{$nss{get_user_groups}}($user);
    if ($err) {
        debug("get user:$user from:$nss{name} groups:- error:$err");
        return;
    }

    cache_put("groups", $user, $groups, $uw_config{group_cache_ttl});
    debug("get user:$user from:$nss{name} groups:" . join(",", @$groups));
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
    my ($err, $grp);
    if ($name) {
        $grp = getgrgid($gid);
        $grp = $gid unless $grp;
    } else {
        $err = "not found";
    }
    return ($err, $uid, $grp);
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
# User authentication caching (used by client).
# Note: password is stored as MD5 hash for sake of security.
#
sub check_auth_cache ($$) {
    my ($user, $pass) = @_;
    my $cached_md5 = cache_get("auth", $user);
    return -1 unless defined $cached_md5;
    return -2 if md5_hex($pass) ne $cached_md5;
    return 0;
}

sub update_auth_cache ($$$) {
    my ($user, $pass, $result) = @_;
    return -1 if $result ne "success";
    cache_put("auth", $user, md5_hex($pass), $uw_config{auth_cache_ttl});
    debug("caching auth: user:$user pass:\*\*\*");
    return 0;
}

##############################################
1;

