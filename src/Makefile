# Driver module

KERNSRC ?= /lib/modules/$(shell uname -r)/build
CC      ?= gcc

obj-m := nf_nat_rule.o

nf_nat_rule.ko: nf_nat_rule.c
	make -C $(KERNSRC) M=$(shell pwd) modules

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
		-o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;
