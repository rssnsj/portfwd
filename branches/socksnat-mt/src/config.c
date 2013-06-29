#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ipv4_rules.h"
#include "config.h"

static const char *g_default_cfg_file = "/etc/socksnatd.conf";

static void proxy_rule_show(unsigned long edata, char *buf)
{
	struct proxy_server *ps = (struct proxy_server *)edata;
	char s1[20];
	if (ps->server_sa.sin_addr.s_addr == 0 &&
		ps->server_sa.sin_port == 0) {
		sprintf(buf, "none");
	} else {
		sprintf(buf, "%s:%d",
			ipv4_hltos(ntohl(ps->server_sa.sin_addr.s_addr), s1),
			ntohs(ps->server_sa.sin_port));
	}
}

static struct ipv4_rules g_proxy_rules = {
	.map_table = NULL,
	.fn_show_edata = proxy_rule_show,
};

/* Table that stores SOCKS server address. */
static struct proxy_server *g_proxy_servers = NULL;
static int g_proxy_servers_sz = 0;   /* current table size */
static int g_proxy_servers_len = 0;  /* current used items */

/* Pseudo 'proxy_server' entry for "default = xxxx" rule. */
static struct proxy_server g_default_proxy;
static bool g_is_default_proxy_defined = false;

/**
 * insert_proxy_addr_or_get - search in 'g_proxy_servers',
 *  if not exists add a new one, and return its address.
 */
static struct proxy_server *insert_proxy_addr_or_get(u32 ip, u16 port)
{
	struct proxy_server *ps;
	int i;
	
	/* Find in table if this address already exists. */
	for (i = 0; i < g_proxy_servers_len; i++) {
		ps = &g_proxy_servers[i];
		if (ps->server_sa.sin_addr.s_addr == htonl(ip) &&
			ps->server_sa.sin_port == htons(port)) {
			return ps;
		}
	}
	
	/* When we need to add a new entry, check mem alloc first. */
	if (g_proxy_servers == NULL) {
		g_proxy_servers_sz = 10; /* the initial size */
		g_proxy_servers = (struct proxy_server *)
			malloc(sizeof(struct proxy_server) * g_proxy_servers_sz);
		if (g_proxy_servers == NULL) {
			fprintf(stderr, "*** malloc() failed: %s.\n", strerror(errno));
			exit(1);
		}
	} else if (g_proxy_servers_len >= g_proxy_servers_sz) {
		/* double the size */
		g_proxy_servers_sz *= 2;
		g_proxy_servers = (struct proxy_server *)realloc(g_proxy_servers,
				sizeof(struct proxy_server) * g_proxy_servers_sz);
		if (g_proxy_servers == NULL) {
			fprintf(stderr, "*** realloc() failed: %s.\n", strerror(errno));
			exit(1);
		}
	}
	ps = &g_proxy_servers[g_proxy_servers_len++];
	memset(ps, 0x0, sizeof(ps[0]));
	ps->socks_version = 5; /* FIXME: should get version from rule */
	ps->server_sa.sin_family = AF_INET;
	ps->server_sa.sin_addr.s_addr = htonl(ip);
	ps->server_sa.sin_port = htons(port);
	return ps;
}

/**
 * get_socks_server_by_ip - do fast table lookup to
 *  get a defined proxy rule.
 */
struct proxy_server *get_socks_server_by_ip(u32 ip)
{
	unsigned long ps_edata;
	
	if (ipv4_rules_check(&g_proxy_rules, ip, &ps_edata)) {
		return (struct proxy_server *)ps_edata;
	} else if (g_is_default_proxy_defined) {
		return &g_default_proxy;
	} else {
		return NULL;
	}
}

#ifdef DUMP_PROXY_RULES
static void dump_proxy_rules(void)
{
	size_t showlen;
	char *showstr;
	
	showstr = ipv4_rules_show_mem(&g_proxy_rules, &showlen);
	printf("%s", showstr);
	printf("Total proxy servers: %d\n", g_proxy_servers_len);
}
#endif

/**
 * Load configs from file.
 * Process exits in case of any error.
 */
void init_proxy_rules_or_exit(void)
{
	FILE *fp;
	char line[100];
	static size_t line_sz = sizeof(line);
	
	if ((fp = fopen(g_default_cfg_file, "r")) == NULL) {
		fprintf(stderr, "*** Config file %s not found.",
				g_default_cfg_file);
		exit(1);
	}
	
	ipv4_rules_init(&g_proxy_rules);
	
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
			char *netp = line, *proxyp = ep + 1;
			char s_proxy_ip[20];
			u32 proxy_ip = 0;
			int proxy_port = 0;
			
			*ep = '\0';
			while (*netp && __isspace(*netp)) netp++;
			while (*proxyp && __isspace(*proxyp)) proxyp++;
			
			/**
			 * Parse server address part first since the network/mask
			 *  part might be a "default".
			 */
			if (strncmp(proxyp, "none", 4) == 0) {
				proxy_ip = 0;
				proxy_port = 0;
			} else if (sscanf(proxyp, "%19[^:]:%d", s_proxy_ip, &proxy_port) == 2) {
				proxy_ip = ipv4_stohl(s_proxy_ip);
				proxy_port = (u16)proxy_port;
			} else {
				fprintf(stderr, "*** Invalid proxy_ip:proxy_port pair: %s.\n", proxyp);
				exit(1);
			}
			
			if (strncmp(netp, "default", 7) == 0) {
				g_default_proxy.socks_version = 5; /* FIXME: should get version from rule */
				g_default_proxy.server_sa.sin_family = AF_INET;
				g_default_proxy.server_sa.sin_addr.s_addr = htonl(proxy_ip);
				g_default_proxy.server_sa.sin_port = htons(proxy_port);
				g_is_default_proxy_defined = true;
			} else {
				char s_net[20], s_mask[20], s_start[20], s_end[20];

				/* Destination network part */
				if (sscanf(netp, "%19[^/]/%19[^ \t]", s_net, s_mask) == 2) {
					u32 netaddr = 0, netmask = 0;
					int net_bits = 0;
					
					/* network/mask or network/bits */
					if (!is_ipv4_addr(s_net)) {
						fprintf(stderr, "*** Bad network/mask pair: %s.\n", netp);
						exit(1);
					}
					/* network/bits */
					netaddr = ipv4_stohl(s_net);
					if (is_ipv4_addr(s_mask)) {
						netmask = ipv4_stohl(s_mask);
						ipv4_rules_add_netmask(&g_proxy_rules, netaddr, netmask,
							(unsigned long)insert_proxy_addr_or_get(proxy_ip, proxy_port));
					} else if (sscanf(s_mask, "%d", &net_bits) == 1) {
						ipv4_rules_add_net(&g_proxy_rules, netaddr, net_bits,
							(unsigned long)insert_proxy_addr_or_get(proxy_ip, proxy_port));
					} else {
						fprintf(stderr, "*** Invalid network/mask pair: %s.\n", netp);
						exit(1);
					}
				} else if (sscanf(netp, "%19[^-]-%19[^ \t]", s_start, s_end) == 2) {
					u32 start, end;
					
					if (!is_ipv4_addr(s_start) || !is_ipv4_addr(s_end)) {
						fprintf(stderr, "*** Invalid start-end format: %s.\n", netp);
						exit(1);
					}
					start = ipv4_stohl(s_start);
					end = ipv4_stohl(s_end);
					ipv4_rules_add_range(&g_proxy_rules, start, end,
						(unsigned long)insert_proxy_addr_or_get(proxy_ip, proxy_port));
				} else {
					fprintf(stderr, "*** Bad network range description: %s.\n", netp);
					exit(1);
				}
			}
		} else {
			fprintf(stderr, "*** Ignored unrecognized config line: %s", line);
		}
	}
	fclose(fp);
	
#ifdef DUMP_PROXY_RULES
	dump_proxy_rules();
#endif
}

