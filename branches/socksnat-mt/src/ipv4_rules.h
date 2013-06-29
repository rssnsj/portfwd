#ifndef __IPV4_RULES_H
#define __IPV4_RULES_H

#include "utils.h"

typedef unsigned long __rtype_t;

struct ipv4_rules
{
	__rtype_t ***map_table;
	unsigned long (*fn_get_edata)(const char *extra_str);
	void (*fn_show_edata)(unsigned long edata, char *buf);
	void (*fn_clear)(struct ipv4_rules *rules);
};

int ipv4_rules_add_netmask(struct ipv4_rules *rules, u32 net, u32 net_mask, unsigned long data);
int ipv4_rules_add_net(struct ipv4_rules *rules, u32 net, int net_bits, unsigned long data);
int ipv4_rules_add_range(struct ipv4_rules *rules, u32 low, u32 high, unsigned long data);
bool ipv4_rules_check(struct ipv4_rules *rules, u32 ip, unsigned long *edata);

int ipv4_rules_init(struct ipv4_rules *rules);
void ipv4_rules_purge(struct ipv4_rules *rules);

char *ipv4_rules_show_mem(struct ipv4_rules *rules, size_t *lenp);


#endif /* __IPV4_RULES_H */
