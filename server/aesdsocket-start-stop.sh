#!/bin/sh

DAEMON=/usr/bin/aesdsocket
NAME=aesdsocket
PIDFILE=/var/run/$NAME.pid

case "$1" in
    start)
        echo "Starting $NAME"
        start-stop-daemon -S -q -b -m -p $PIDFILE --exec $DAEMON
        ;;
    stop)
        echo "Stopping $NAME"
        start-stop-daemon -K -q -p $PIDFILE -s TERM -R 5/KILL/5 --oknodo
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac

exit 0
