#! /bin/bash
#
# userwatch        Start/Stop the userwatch daemon.
#
# chkconfig: 2345 90 60
# description: userwatch allows users to roam over the network \
#              and still be accountable
# processname: uwatchd
# config: /etc/uwatch.conf
# pidfile: /var/run/uwatchd.pid

RETVAL=0
prog="uwatchd"
UWATCHD=/usr/sbin/uwatchd
LOCK_FILE=/var/lock/subsys/uwatchd
PIDFILE=/var/run/uwatchd.pid

. /etc/init.d/functions

[ -f /etc/sysconfig/uwatchd ] && . /etc/sysconfig/uwatchd

prog="uwatchd"

start() {
	echo -n $"Starting $prog: "
	daemon $prog $OPTIONS && success || failure
	RETVAL=$?
	[ "$RETVAL" = 0 ] && touch $LOCK_FILE
	echo
}

stop() {
	echo -n $"Stopping $prog: "
	if [ -n "`pidfileofproc $UWATCHD`" ]; then
		killproc $UWATCHD
	else
		failure $"Stopping $prog"
	fi
	RETVAL=$?
	[ "$RETVAL" = 0 ] && rm -f $LOCK_FILE
	echo
}	

reload() {
	echo -n $"Reloading $prog: "
	if [ -n "`pidfileofproc $UWATCHD`" ]; then
		killproc $UWATCHD -HUP
	else
		failure $"Reloading $prog"
	fi
	RETVAL=$?
	echo
}	

case "$1" in
  start)
  	start
	;;
  stop)
  	stop
	;;
  restart)
	stop
  	start
	;;
  reload)
  	reload
	;;
  status)
	status $UWATCHD
	;;
  condrestart)
    if [ -f  $LOCK_FILE ]; then
        if [ "$RETVAL" = 0 ]; then
            stop
            sleep 3
            start
        fi
    fi
    ;;
  *)
	echo $"Usage: $0 {start|stop|status|reload|restart|condrestart}"
	RETVAL=3
esac
exit $RETVAL

