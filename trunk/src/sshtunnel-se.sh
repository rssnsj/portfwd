#!/bin/sh

for F in `pwd`/libsehijack.so /usr/local/lib/libsehijack.so /usr/lib/libsehijack.so; do
	[ -e "$F" ] && { libfile="$F"; break; }
done

if [ -z "$libfile" ]; then
	echo "*** File libsehijack.so not found."
	exit 1
fi

# Address that 'ssh -D' listens on and is hijacked
tunnel_addr=xx.xx.xx.xx:7707

LD_PRELOAD=$libfile LIBSEHIJACK_ADDR="$tunnel_addr" ssh XXXX@127.0.0.1 -D $tunnel_addr -N -f

