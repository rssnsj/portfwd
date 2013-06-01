#!/bin/sh

for F in /usr/local/lib/libsehijack.so /usr/lib/libsehijack.so; do
	[ -e "$F" ] && libfile="$F"
done

if [ -z "$libfile" ]; then
	echo "*** File libsehijack.so not found."
	exit 1
fi

case "$1" in
	*.*.*.*:*)
		hijack_addr="$1"
		shift 1
		LD_PRELOAD=./libsehijack.so LIBSEHIJACK_ADDR="$hijack_addr" "$@"
		;;
	*)
		echo "Usage: sehijack <hijacked_ip:hijacked_port> command ..."
		exit 1
		;;
esac

