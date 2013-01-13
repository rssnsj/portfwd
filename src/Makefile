all: socksnatd
	make -C netfilter

socksnatd: socksnatd.o
	gcc -o $@ $^ -lpthread

clean:
	rm -f socksnatd *.o

install: all
	make install -C netfilter
	cp -vf socksnatd /usr/local/bin/

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

