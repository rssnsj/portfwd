#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#ifdef __linux__
	#include <sys/epoll.h>
#else
	#define ERESTART 700
	#include "no-epoll.h"
#endif

typedef int bool;
#define true 1
#define false 0

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

struct sockaddr_inx {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

#define port_of_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		(s)->in6.sin6_port : (s)->in.sin_port)
#define addr_of_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		(void *)&(s)->in6.sin6_addr : (void *)&(s)->in.sin_addr)
#define sizeof_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		sizeof((s)->in6) : sizeof((s)->in))

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#include <stddef.h>

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     /*prefetch(pos->member.next),*/ &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static struct sockaddr_inx g_src_addr;
static struct sockaddr_inx g_dst_addr;
static const char *g_pidfile;

#define CONN_TBL_HASH_SIZE  (1 < 8)
static struct list_head conn_tbl_hbase[CONN_TBL_HASH_SIZE];
static unsigned conn_tbl_len;
static unsigned proxy_conn_timeo = 60;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int do_daemonize(void)
{
	int rc;
	
	if ((rc = fork()) < 0) {
		fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
		return rc;
	} else if (rc > 0) {
		/* In parent process */
		exit(0);
	} else {
		/* In child process */
		int fd;
		setsid();
		fd = open("/dev/null", O_RDONLY);
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
		chdir("/tmp");
	}
	return 0;
}

static void write_pidfile(const char *filepath)
{
	FILE *fp;
	if (!(fp = fopen(filepath, "w"))) {
		fprintf(stderr, "*** fopen(%s): %s\n", filepath, strerror(errno));
		exit(1);
	}
	fprintf(fp, "%d\n", (int)getpid());
	fclose(fp);
}

static void set_nonblock(int sockfd)
{
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK);
}

static int get_sockaddr_inx_pair(const char *pair, struct sockaddr_inx *sa)
{
	struct addrinfo hints, *result;
	char host[51] = "", s_port[20] = "";
	int port = 0, rc;

	if (sscanf(pair, "[%50[^]]]:%d", host, &port) == 2) {
		/* Quoted IP and port: [10.0.0.1]:10000 */
	} else if (sscanf(pair, "%50[^:]:%d", host, &port) == 2) {
		/* Regular IP and port: 10.0.0.1:10000 */
	} else {
		/**
		 * A single port number, usually for local IPv4 listen address.
		 * e.g., "10000" stands for "0.0.0.0:10000"
		 */
		const char *sp;
		for (sp = pair; *sp; sp++) {
			if (!(*sp >= '0' && *sp <= '9'))
				return -EINVAL;
		}
		sscanf(pair, "%d", &port);
		strcpy(host, "0.0.0.0");
	}
	sprintf(s_port, "%d", port);
	if (port <= 0 || port > 65535)
		return -EINVAL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if ((rc = getaddrinfo(host, s_port, &hints, &result)))
		return -EAGAIN;

	/* Get the first resolution. */
	memcpy(sa, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 0;
}

static bool is_sockaddr_inx_equal(struct sockaddr_inx *sa1, struct sockaddr_inx *sa2)
{
	if (sa1->sa.sa_family != sa2->sa.sa_family)
		return false;

	if (sa1->sa.sa_family == AF_INET) {
		if (sa1->in.sin_addr.s_addr != sa2->in.sin_addr.s_addr)
			return false;
		if (sa1->in.sin_port != sa2->in.sin_port)
			return false;
		return true;
	} else if (sa1->sa.sa_family == AF_INET6) {
		if (memcmp(&sa1->in6.sin6_addr, &sa2->in6.sin6_addr, sizeof(sa2->in6.sin6_addr)))
			return false;
		if (sa1->in6.sin6_port != sa2->in6.sin6_port)
			return false;
		return true;
	}

	return true;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
	struct list_head list;
	time_t last_active;
	struct sockaddr_inx cli_addr;  /* <-- key */
	int svr_sock;
};

static unsigned int proxy_conn_hash(struct sockaddr_inx *sa)
{
	unsigned int hash = 0;

	if (sa->sa.sa_family == AF_INET) {
		hash = ntohl(sa->in.sin_addr.s_addr) + ntohs(sa->in.sin_port);
	} else if (sa->sa.sa_family == AF_INET6) {
		int i;
		for (i = 0; i < 4; i++)
			hash += ((uint32_t *)&sa->in6.sin6_addr)[i];
		hash += ntohs(sa->in6.sin6_port);
	}

	return hash;
}

static struct proxy_conn *proxy_conn_get_or_create(
		struct sockaddr_inx *cli_addr, int epfd)
{
	struct list_head *chain = &conn_tbl_hbase[
		proxy_conn_hash(cli_addr) & (CONN_TBL_HASH_SIZE - 1)];
	struct proxy_conn *conn;
	int svr_sock = -1;
	struct epoll_event ev;
	char s_addr[50] = "";

	list_for_each_entry (conn, chain, list) {
		if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
			conn->last_active = time(NULL);
			return conn;
		}
	}

	/* ------------------------------------------ */
	/* Establish the server-side connection */
	if ((svr_sock = socket(g_dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "*** socket(svr_sock): %s", strerror(errno));
		goto err;
	}
	/* Connect to real server. */
	if (connect(svr_sock, (struct sockaddr *)&g_dst_addr,
			sizeof_sockaddr(&g_dst_addr)) != 0) {
		/* Error occurs, drop the session. */
		syslog(LOG_WARNING, "Connection failed: %s", strerror(errno));
		goto err;
	}
	set_nonblock(svr_sock);

	/* Allocate session data for the connection */
	if ((conn = malloc(sizeof(*conn))) == NULL) {
		syslog(LOG_ERR, "*** malloc(conn): %s", strerror(errno));
		goto err;
	}
	memset(conn, 0x0, sizeof(*conn));
	conn->svr_sock = svr_sock;
	conn->cli_addr = *cli_addr;

	ev.data.ptr = conn;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
	/* ------------------------------------------ */

	list_add_tail(&conn->list, chain);
	conn_tbl_len++;

	inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr),
			s_addr, sizeof(s_addr));
	syslog(LOG_INFO, "New connection %s:%d [%u]",
			s_addr, ntohs(port_of_sockaddr(cli_addr)), conn_tbl_len);

	conn->last_active = time(NULL);
	return conn;

err:
	if (svr_sock >= 0)
		close(svr_sock);
	return NULL;
}

/**
 * Close both sockets of the connection and remove it
 * from the current ready list.
 */
static void release_proxy_conn(struct proxy_conn *conn, int epfd)
{
	list_del(&conn->list);
	conn_tbl_len--;
	epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
	close(conn->svr_sock);
	free(conn);
}

static void proxy_conn_walk_continue(unsigned walk_max, int epfd)
{
	static unsigned bucket_index = 0;
	unsigned __bucket_index = bucket_index;
	unsigned walk_count = 0;
	time_t current_ts = time(NULL);

	if (walk_max > conn_tbl_len)
		walk_max = conn_tbl_len;
	if (walk_max == 0)
		return;

	do {
		struct proxy_conn *conn, *__conn;
		list_for_each_entry_safe (conn, __conn, &conn_tbl_hbase[bucket_index], list) {
			if ((unsigned)(current_ts - conn->last_active) > proxy_conn_timeo) {
				struct sockaddr_inx addr = conn->cli_addr;
				char s_addr[50] = "";
				release_proxy_conn(conn, epfd);
				inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr),
						s_addr, sizeof(s_addr));
				syslog(LOG_INFO, "Recycled %s:%d [%u]",
						s_addr, ntohs(port_of_sockaddr(&addr)), conn_tbl_len);
			}
			walk_count++;
		}
		bucket_index = (bucket_index + 1) & (CONN_TBL_HASH_SIZE - 1);
	} while (walk_count < walk_max && bucket_index != __bucket_index);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("Userspace UDP proxy.\n");
	printf("Usage:\n");
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d] [-o]\n", argv[0]);
	printf("Options:\n");
	printf("  -t <seconds>    proxy session timeout (default: %u)\n", proxy_conn_timeo);
	printf("  -d              run in background\n");
	printf("  -o              accept IPv6 connections only for IPv6 listener\n");
	printf("  -p <pidfile>    write PID to file\n");
}

int main(int argc, char *argv[])
{
	int opt, b_true = 1, lsn_sock, epfd, i;
	bool is_daemon = false, is_v6only = false;
	struct epoll_event ev, events[100];
	char buffer[1024 * 64], s_addr1[50] = "", s_addr2[50] = "";
	time_t last_check;

	while ((opt = getopt(argc, argv, "t:dhop:")) != -1) {
		switch (opt) {
		case 't':
			proxy_conn_timeo = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			is_daemon = true;
			break;
		case 'h':
			show_help(argc, argv);
			exit(0);
			break;
		case 'o':
			is_v6only = true;
			break;
		case 'p':
			g_pidfile = optarg;
			break;
		case '?':
			exit(1);
		}
	}

	if (optind > argc - 2) {
		show_help(argc, argv);
		exit(1);
	}

	/* Resolve source address */
	if (get_sockaddr_inx_pair(argv[optind], &g_src_addr) < 0) {
		fprintf(stderr, "*** Invalid source address '%s'.\n", argv[optind]);
		exit(1);
	}
	optind++;

	/* Resolve destination addresse */
	if (get_sockaddr_inx_pair(argv[optind], &g_dst_addr) < 0) {
		fprintf(stderr, "*** Invalid destination address '%s'.\n", argv[optind]);
		exit(1);
	}
	optind++;

	openlog("udpfwd", LOG_PERROR|LOG_NDELAY, LOG_USER);

	lsn_sock = socket(g_src_addr.sa.sa_family, SOCK_DGRAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket(): %s.\n", strerror(errno));
		exit(1);
	}
	if (g_src_addr.sa.sa_family == AF_INET6 && is_v6only)
		setsockopt(lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_true, sizeof(b_true));
	if (bind(lsn_sock, (struct sockaddr *)&g_src_addr,
			sizeof_sockaddr(&g_src_addr)) < 0) {
		fprintf(stderr, "*** bind(): %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(lsn_sock);

	inet_ntop(g_src_addr.sa.sa_family, addr_of_sockaddr(&g_src_addr),
			s_addr1, sizeof(s_addr1));
	inet_ntop(g_dst_addr.sa.sa_family, addr_of_sockaddr(&g_dst_addr),
			s_addr2, sizeof(s_addr2));
	syslog(LOG_INFO, "UDP proxy [%s]:%d -> [%s]:%d",
			s_addr1, ntohs(port_of_sockaddr(&g_src_addr)),
			s_addr2, ntohs(port_of_sockaddr(&g_dst_addr)));

	/* Create epoll table. */
	if ((epfd = epoll_create(2048)) < 0) {
		syslog(LOG_ERR, "epoll_create(): %s", strerror(errno));
		exit(1);
	}

	if (is_daemon)
		do_daemonize();
	if (g_pidfile)
		write_pidfile(g_pidfile);

	signal(SIGPIPE, SIG_IGN);

	/* Initialize the connection table */
	for (i = 0; i < CONN_TBL_HASH_SIZE; i++)
		INIT_LIST_HEAD(&conn_tbl_hbase[i]);
	conn_tbl_len = 0;

	last_check = time(NULL);

	/* epoll loop */
	ev.data.ptr = NULL;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, lsn_sock, &ev);

	for (;;) {
		int nfds;
		time_t current_ts = time(NULL);

		/* Timeout check and recycle */
		if ((unsigned)(current_ts - last_check) >= 2) {
			proxy_conn_walk_continue(200, epfd);
			last_check = current_ts;
		}

		nfds = epoll_wait(epfd, events, countof(events), 1000 * 2);
		if (nfds == 0)
			continue;
		if (nfds < 0) {
			if (errno == EINTR || errno == ERESTART)
				continue;
			syslog(LOG_ERR, "*** epoll_wait(): %s", strerror(errno));
			exit(1);
		}

		for (i = 0; i < nfds; i++) {
			struct epoll_event *evp = &events[i];
			struct proxy_conn *conn;
			int r;

			if (evp->data.ptr == NULL) {
				/* Data from client */
				struct sockaddr_inx cli_addr;
				socklen_t cli_alen = sizeof(cli_addr);
				if ((r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0,
						(struct sockaddr *)&cli_addr, &cli_alen)) <= 0)
					continue;
				if (!(conn = proxy_conn_get_or_create(&cli_addr, epfd)))
					continue;
				(void)send(conn->svr_sock, buffer, r, 0);
			} else {
				/* Data from server */
				conn = (struct proxy_conn *)evp->data.ptr;
				if ((r = recv(conn->svr_sock, buffer, sizeof(buffer), 0)) <= 0) {
					/* Close the session. */
					release_proxy_conn(conn, epfd);
					continue;
				}
				(void)sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
						sizeof_sockaddr(&conn->cli_addr));
			}
		}
	}

	return 0;
}

