CC = $(CROSS_COMPILE)gcc

KERNSRC ?= /lib/modules/$(shell uname -r)/build
ARCH ?= x86

all: socksnatd socksnat.ko

obj-m := socksnat.o

socksnat.ko: socksnat.c
	make -C $(KERNSRC) M=$(shell pwd) modules CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH)

socksnatd: socksnatd.o
	$(CC) -o $@ $^ -lpthread

%.o: %.c
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	- rmmod socksnat
	insmod socksnat.ko
	mkdir -p /usr/local/bin
	cp -vf socksnatd /usr/local/bin/
	mkdir -p /lib/modules/$(shell uname -r)/kernel/misc
	cp -vf socksnat.ko /lib/modules/$(shell uname -r)/kernel/misc/
	depmod

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
	  -o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;
	rm -f socksnatd *.o

