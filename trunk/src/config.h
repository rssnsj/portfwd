#ifndef __CONFIG_H
#define __CONFIG_H

#include "utils.h"

struct proxy_rule {
	u32 netaddr;
	u32 netmask;
	/* proxy_addr = 0 means no proxy to this network*/
	u32 proxy_addr;
	u16 proxy_port;
};

struct proxy_rule *lookup_proxy_by_ip(u32 ip);
void init_proxy_rules(void);

#endif /* __CONFIG_H */
