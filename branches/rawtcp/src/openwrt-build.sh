#!/bin/sh -x
homedir=~
export STAGING_DIR=$homedir/backfire-db120/staging_dir/toolchain-mips_gcc-4.3.3+cs_uClibc-0.9.30.1/bin

make CROSS_COMPILE=$STAGING_DIR/mips-openwrt-linux- \
	CFLAGS=-I$homedir/backfire-db120/build_dir/target-mips_uClibc-0.9.30.1/libevent-2.0.16-stable \
	LDFLAGS=-L$homedir/backfire-db120/build_dir/target-mips_uClibc-0.9.30.1/libevent-2.0.16-stable/.libs

