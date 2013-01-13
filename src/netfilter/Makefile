#
# Makefile for the netfilter modules on top of IPv4.
#

# objects for l3 independent conntrack
nf_conntrack_ipv4-objs :=  nf_conntrack_l3proto_ipv4.o nf_conntrack_proto_icmp.o nf_conntrack_l3proto_ipv4_compat.o
# nf_nat-objs := nf_nat_core.o nf_nat_helper.o nf_nat_proto_unknown.o nf_nat_proto_common.o nf_nat_proto_tcp.o nf_nat_proto_udp.o nf_nat_proto_icmp.o
# iptable_nat-objs := nf_nat_rule.o nf_nat_standalone.o

# connection tracking
obj-m += nf_conntrack_ipv4.o

# obj-m += nf_nat.o

# NAT helpers (nf_conntrack)
# obj-m += nf_nat_amanda.o
# obj-m += nf_nat_ftp.o
# obj-m += nf_nat_h323.o
# obj-m += nf_nat_irc.o
# obj-m += nf_nat_pptp.o
# obj-m += nf_nat_sip.o
# obj-m += nf_nat_snmp_basic.o
# obj-m += nf_nat_tftp.o

# NAT protocols (nf_nat)
# obj-m += nf_nat_proto_dccp.o
# obj-m += nf_nat_proto_gre.o
# obj-m += nf_nat_proto_udplite.o
# obj-m += nf_nat_proto_sctp.o

# generic IP tables 
# obj-m += ip_tables.o

# the three instances of ip_tables
# obj-m += iptable_filter.o
# obj-m += iptable_mangle.o
# obj-m += iptable_nat.o
# obj-m += iptable_raw.o

# matches
# obj-m += ipt_addrtype.o
# obj-m += ipt_ah.o
# obj-m += ipt_ecn.o
# obj-m += ipt_recent.o
# obj-m += ipt_ttl.o

# targets
# obj-m += ipt_CLUSTERIP.o
# obj-m += ipt_ECN.o
# obj-m += ipt_LOG.o
# obj-m += ipt_MASQUERADE.o
# obj-m += ipt_NETMAP.o
# obj-m += ipt_REDIRECT.o
# obj-m += ipt_REJECT.o
# obj-m += ipt_TTL.o
# obj-m += ipt_ULOG.o

# generic ARP tables
# obj-m += arp_tables.o
# obj-m += arpt_mangle.o

# just filtering instance of ARP tables for now
# obj-m += arptable_filter.o

# obj-m += ip_queue.o

KERNSRC ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNSRC) M=$(shell pwd) modules

clean:
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \
	  -o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;

up: all
	iptables -t nat -F
	- rmmod ipt_MASQUERADE
	- rmmod iptable_nat
	- rmmod nf_nat
	- rmmod nf_conntrack_ipv4
	insmod nf_conntrack_ipv4.ko
	iptables-restore < /etc/iptables.rules
	dmesg -c

