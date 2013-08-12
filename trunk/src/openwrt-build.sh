#!/bin/sh

openwrt_root=~/openwrt-ar9331

[ -z "$1" ] || openwrt_root="$1"

for dir in $openwrt_root/staging_dir/toolchain-mips_*/bin; do
	[ -d "$dir" ] && { STAGING_DIR="$dir"; break; }
done
export STAGING_DIR

for dir in $openwrt_root/build_dir/target-mips_*/libevent-*-stable; do
	[ -d "$dir" ] && { libevent_dir="$dir"; break; }
done

set -x
make CROSS_COMPILE=$STAGING_DIR/mips-openwrt-linux- CFLAGS=-I$libevent_dir LDFLAGS=-L$libevent_dir/.libs

