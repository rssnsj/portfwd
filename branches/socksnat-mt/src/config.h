#ifndef __CONFIG_H
#define __CONFIG_H

#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"

struct proxy_server {
	int socks_version;
	struct sockaddr_in server_sa;
};

struct proxy_server *get_socks_server_by_ip(u32 ip);
void init_proxy_rules_or_exit(void);

#endif /* __CONFIG_H */
