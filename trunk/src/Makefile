CC = $(CROSS_COMPILE)gcc
ARCH ?= x86

socksnatd: socksnatd.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	mkdir -p /usr/local/bin
	cp -vf socksnatd /usr/local/bin/
	mkdir -p /lib/modules/$(shell uname -r)/kernel/misc
	depmod

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
	  -o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;
	rm -f socksnatd *.o

