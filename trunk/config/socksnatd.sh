#!/bin/sh

PIDFILE=/var/run/socksnatd.pid

do_start()
{
	/usr/sbin/socksnatd -p $PIDFILE -d
}

do_stop()
{
	echo -n "Stopping the service... "
	if [ ! -f $PIDFILE ]; then
		echo "service not running, failed"
		return 1
	fi
	kill `cat $PIDFILE`
	echo "done"
}

case "$1" in
	start)
		do_start
		;;
	stop)
		do_stop
		;;
	reload|restart)
		do_stop
		do_start
		;;
	*)
		echo "Usage: $0 {start|stop|restart|reload}" >&2
		exit 1
		;;
esac
