#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "config.h"

static const char *g_default_cfg_file = "/etc/socksnatd.conf";

#define MAX_PROXY_RULES 1024
static struct proxy_rule g_proxy_rules[MAX_PROXY_RULES];
static int g_proxy_rules_num = 0;

struct proxy_rule *lookup_proxy_by_ip(u32 ip)
{
	int i;
	struct proxy_rule *rule;
	
	for (i = 0; i < g_proxy_rules_num; i++) {
		rule = &g_proxy_rules[i];
		if ((ip & rule->netmask) == rule->netaddr)
			return rule;
	}
	return NULL;
}

/**
 * Load configs from file.
 * Process exits in case of any error.
 */
void init_proxy_rules(void)
{
	FILE *fp;
	char line[100];
	static size_t line_sz = sizeof(line);
	struct proxy_rule rule;
	
	if ((fp = fopen(g_default_cfg_file, "r")) == NULL) {
		fprintf(stderr, "Warning: Config file %s not found, "
			"use default proxy setting.\n", g_default_cfg_file);
		return;
	}
	
	while (!feof(fp)) {
		size_t line_len;
		char *ep;
		
		if (fgets(line, line_sz, fp) == NULL)
			continue;
		line_len = strlen(line);
		if (line_len <= 1)
			continue;
		if (line[0] == '#')
			continue;
		
		if ((ep = strchr(line, '='))) {
			/**
			 * In format:
			 *  10.255.0.0/24 = 127.0.0.1:1080
			 *  10.255.2.0/24 = none
			 */
			char *netp = line, *svrp = ep + 1;
			char s_net[20], s_mask[20], s_svrip[20];
			int svr_port, net_bits;
			
			memset(&rule, 0x0, sizeof(rule));
			*ep = '\0';
			while (*netp && __isspace(*netp)) netp++;
			while (*svrp && __isspace(*svrp)) svrp++;
			
			/* Parse network/mask pair */
			if (sscanf(netp, "%19[^/]/%19[^ \t]", s_net, s_mask) != 2) {
				fprintf(stderr, "*** Bad network/mask pair: %s.\n", netp);
				exit(1);
			}
			if (!is_ipv4_addr(s_net)) {
				fprintf(stderr, "*** Bad network/mask pair: %s.\n", netp);
				exit(1);
			} else {
				rule.netaddr = ipv4_stohl(s_net);
			}
			if (is_ipv4_addr(s_mask))
				rule.netmask = ipv4_stohl(s_mask);
			else if (sscanf(s_mask, "%d", &net_bits) == 1)
				rule.netmask = netbits_to_mask(net_bits);
			else {
				fprintf(stderr, "*** Invalid network/mask pair: %s.\n", netp);
				exit(1);
			}
			if ((rule.netaddr & rule.netmask) != rule.netaddr) {
				fprintf(stderr, "*** Invalid network/mask pair: %s.\n", netp);
				exit(1);
			}
			
			/* Parse proxy server part */
			if (strncmp(svrp, "none", 4) == 0) {
				rule.proxy_addr = 0;
				rule.proxy_port = 0;
			} else if (sscanf(svrp, "%19[^:]:%d", s_svrip, &svr_port) == 2) {
				rule.proxy_addr = ipv4_stohl(s_svrip);
				rule.proxy_port = (u16)svr_port;
			} else {
				fprintf(stderr, "*** Invalid proxy_addr:proxy_port pair: %s.\n", svrp);
				exit(1);
			}
			
			/* Check table size and add the rule */
			if (g_proxy_rules_num >= MAX_PROXY_RULES - 1) {
				fprintf(stderr, "*** Proxy rule items exceed limitation %d.\n", MAX_PROXY_RULES - 1);
				exit(1);
			}
			g_proxy_rules[g_proxy_rules_num++] = rule;
		}
	}
	fclose(fp);
}

