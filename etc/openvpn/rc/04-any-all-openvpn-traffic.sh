#!/bin/bash
#set -x

[ -z "$RC_ACTION" -o -z "$RC_CLIENT" ] && exit 1
[ -z "$DB_HOST" -o -z "$DB_DBASE" -o -z "$DB_USER" -o -z "$DB_PASS" ] && exit 1
[ -z "$STATUS_FILE" -o ! -r "$STATUS_FILE" ] && exit 1

NOW=$(date)
[ $RC_ACTION = down ] && RUNNING=0 || RUNNING=1

while read LINE; do
    IFS_BAK="$IFS"
    IFS=","
    read TAG CNAME REAL_IP_PORT VPN_IP RX_BYTES TX_BYTES STARTED STARTED_UNIX <<< "$LINE"
    read REAL_IP REAL_PORT <<< "${REAL_IP_PORT/:/,}"
    IFS="$IFS_BAK"

    [ x"$TAG" = x"CLIENT_LIST" ] || continue

    [ $RC_DEBUG = 1 ] && \
        echo "cname:$CNAME real_ip:$REAL_IP vpn_ip:$VPN_IP started:'$STARTED' now:'$NOW'"

    CNAME=${CNAME#client-}
    if [ $RC_ACTION = up -a $RC_CLIENT != all ]; then
        [ -z "$CNAME" -o x"$CNAME" = x"UNDEF" ] && CNAME=$RC_CLIENT
        [ -z "$VPN_IP" ] && VPN_IP=$ifconfig_pool_remote_ip
    fi
    [ $CNAME = $RC_CLIENT -o $RC_CLIENT = all ] || continue

    SQL="INSERT INTO uw_openvpn
        (beg_time,end_time,running,cname,
            real_ip,real_port,vpn_ip,rx_bytes,tx_bytes)
        VALUES (FROM_UNIXTIME($STARTED_UNIX),NOW(),$RUNNING,'$CNAME',
                '$REAL_IP',$REAL_PORT,'$VPN_IP',$RX_BYTES,$TX_BYTES)
        ON DUPLICATE KEY UPDATE
                end_time=NOW(), running=$RUNNING,
                vpn_ip='$VPN_IP', rx_bytes=$RX_BYTES, tx_bytes=$TX_BYTES;"
    #echo "$SQL"
    mysql -h$DB_HOST -u$DB_USER -p$DB_PASS $DB_DBASE <<< "$SQL"
done < $STATUS_FILE

