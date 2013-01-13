all: socksnatd
	make -C netfilter

socksnatd: socksnatd.o
	gcc -o $@ $^ -lpthread

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f socksnatd *.o

up:
	make up -C netfilter

