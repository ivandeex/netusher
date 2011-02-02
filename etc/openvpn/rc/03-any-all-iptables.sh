#!/bin/sh
[ $RC_ACTION = up ] && CMD=I || CMD=D
for CHAIN in $CHAINS; do
    iptables -$CMD $CHAIN -s $RC_IP -j ACCEPT
    echo "iptables: $RC_ACTION $CHAIN $RC_IP status:$?"
    iptables-save | egrep '^\-A '$CHAIN >> $RC_TMP_VAR
done
mv -f $RC_TMP_VAR $RC_VAR/iptables
