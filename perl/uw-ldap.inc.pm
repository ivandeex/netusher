#!/usr/bin/perl
#
# UserWatch
# LDAP stuff
# $Id$
#

use strict;
use FindBin qw($Bin);
require "$Bin/uw-common.inc.pm";

#
# require: perl-LDAP
#
use Net::LDAP;

our (%uw_config);

my  ($ldap, %uid_cache);

#
# connection to ldap for browsing
#
sub ldap_init () {
    ldap_close();
    my ($msg, $ldap_conn)
        = ldap_connect($uw_config{ldap_bind_dn}, undef,
                        $uw_config{ldap_bind_pass}, 0);
    $ldap = $ldap_conn unless $msg;
    # flush ldap cache at every re-connection
    %uid_cache = ();
    return $msg;
}

sub ldap_close () {
    if (defined $ldap) {
        eval { $ldap->unbind() };
        undef $ldap;
    }
}

#
# connection to ldap for browsing or to to check credentials
#
sub ldap_connect ($$$$) {
    my ($bind_dn, $user, $pass, $just_check) = @_;

    my $conn = Net::LDAP->new($uw_config{ldap_uri},
                                timeout => $uw_config{ldap_timeout},
                                version => 3)
        or return "ldap server down";

    if ($uw_config{ldap_start_tls}) {
        $conn->start_tls()
            or return "ldap tls failed";
    }

    if (!$bind_dn) {
        $bind_dn = sprintf('%s=%s,%s', $uw_config{ldap_attr_user},
                            $user, $uw_config{ldap_user_base});
    }
    my $res = $conn->bind($bind_dn, password => $pass);

    $conn->unbind() if $just_check;

    debug("ldap auth uri:%s tls:%s bind:%s pass:%s returns: %s",
            $uw_config{ldap_uri}, $uw_config{ldap_start_tls},
            $bind_dn, $pass, $res->error());
    return "invalid password" if $res->code();

    # success
    return (0, $conn);
}

#
# return ldap uidNumber for given user
#
sub ldap_get_uid ($) {
    my ($user) = @_;
    my ($uid, $res);

    # try to fetch uid from cache
    my $stamp = time();
    if (exists($uid_cache{$user})) {
        if ($stamp - $uid_cache{$user}{stamp} < $uw_config{cache_retention}) {
            $uid = $uid_cache{$user}{uid};
            debug("ldap get uid user:$user uid:$uid from cache");
            return $uid;
        }
        delete $uid_cache{$user};
    }

    # search for uid in ldap.
    # ldap server might have disconnected due to timeout.
    # if so, we try to re-connect and repeat the search.
    for (my $try = 1; $try <= 2; $try++) {
        if ($ldap) {
            $res = $ldap->search(
                    base => $uw_config{ldap_user_base},
                    filter => sprintf('(%s=%s)', $uw_config{ldap_attr_user}, $user),
                    scope => 'one', defer => 'never',
                    attrs => [ $uw_config{ldap_attr_uid} ]
                    );
        }
        if (!$ldap || $res->code() == 1) {
            # unexpected eof. try to reconnect
            debug("restoring ldap connection ($try)");
            undef $ldap;
            ldap_init();
            # a little delay
            select(undef, undef, undef, ($try - 1) * 0.100);
        } else {
            last;
        }
    }

    # fetch uid from ldap array
    unless ($res) {
        debug("ldap get uid user:$user server down");
        return;
    }
    if (!$res->code()) {
        my $entry = $res->pop_entry();
        if ($entry) {
            $uid  = $entry->get_value($uw_config{ldap_attr_uid});
        }
        # update cache with defined or undefined uid
        $uid_cache{$user}{uid} = $uid;
        $uid_cache{$user}{stamp} = $stamp;
    }

    debug("ldap_get_uid user:%s uid:%s message:%s", $user, $uid, $res->error());

    return $uid;
}

##############################################
1;

