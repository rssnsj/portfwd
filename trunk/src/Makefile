CC = $(CROSS_COMPILE)gcc
ARCH ?= x86

socksnatd: socksnatd.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: socksnatd
	mkdir -p /usr/local/bin
	cp -vf socksnatd /usr/local/bin/

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
	  -o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;
	rm -f socksnatd *.o

