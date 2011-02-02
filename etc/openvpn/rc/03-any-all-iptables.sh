#!/bin/sh
# $Id$

case "$RC_ACTION" in
  up)   CMD=I ;;
  down) CMD=D ;;
  *)    exit 1 ;;
esac

for CHAIN in $CHAINS; do
    iptables -$CMD $CHAIN -s $RC_IP -j ACCEPT
    echo "iptables: $RC_ACTION $CHAIN $RC_IP status:$?"
    iptables-save | egrep '^\-A '$CHAIN >> $RC_TMP_VAR
done

mv -f $RC_TMP_VAR $RC_VAR/iptables
