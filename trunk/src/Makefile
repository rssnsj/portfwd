all: socksnatd socksnat.ko

# Driver module

KERNSRC ?= /lib/modules/$(shell uname -r)/build

obj-m := socksnat.o

socksnat.ko: socksnat.c
	make -C $(KERNSRC) M=$(shell pwd) modules

socksnatd: socksnatd.o
	gcc -o $@ $^ -lpthread

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

install: all
	- rmmod socksnat
	insmod socksnat.ko
	cp -vf socksnatd /usr/local/bin/
	mkdir -p /lib/modules/$(shell uname -r)/kernel/misc
	cp -vf socksnat.ko /lib/modules/$(shell uname -r)/kernel/misc/
	depmod

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
	  -o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;
	rm -f socksnatd *.o

