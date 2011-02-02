#!/bin/sh
# update dynamic dns zone
# $Id: 02-any-vitki-dyndns.sh 107 2011-02-02 08:30:40Z vitki $
if [ -z "$RC_CLIENT" -o -z "$RC_IP" -o -z "$NS_SERVER" -o -z "$VPN_ZONE" ]; then
    echo "dyndns: missing parameter: client:$RC_CLIENT ip:$RC_IP ns:$NS_SERVER zone:$VPN_ZONE"
    exit 1
fi
HOST=$RC_CLIENT.$VPN_ZONE
(
    echo "server $NS_SERVER"
    echo "zone $VPN_ZONE"
    echo "update delete $HOST A"
    ( [ $RC_ACTION = up ] && echo "update add $HOST $RR_TIME A $RC_IP" )
    echo "send"
) > $RC_TMP_VAR
nsupdate $RC_TMP_VAR
echo "dyndns: $RC_ACTION $HOST [$RC_IP] status:$?"
