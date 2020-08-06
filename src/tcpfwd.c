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

#ifdef __linux__
	#include <sys/epoll.h>
	#include <linux/netfilter_ipv4.h>
#else
	#define ERESTART 700
	#include "no-epoll.h"
#endif

typedef int bool;
#define true 1
#define false 0

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

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

static struct sockaddr_inx g_src_addr;
static struct sockaddr_inx g_dst_addr;
static bool g_base_addr_mode = false;
static const char *g_pidfile;

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
	hints.ai_socktype = SOCK_STREAM;
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

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Status indicators of proxy sessions */
enum conn_state {
	S_INVALID,
	S_SERVER_CONNECTING,
	S_SERVER_CONNECTED,
	S_FORWARDING,
	S_CLOSING,
};

enum ev_magic {
	EV_MAGIC_LISTENER = 0x1010,
	EV_MAGIC_CLIENT   = 0x2020,
	EV_MAGIC_SERVER   = 0x3030,
};

struct buffer_info {
	char data[4096];
	unsigned rpos;
	unsigned dlen;
};

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
	int cli_sock;
	int svr_sock;

	/**
	 * The two fields are used when an epoll event occurs,
	 * to know on which socket fd it is triggered client
	 * or server.
	 * ev.data.ptr = &ct.magic_client;
	 */
	int magic_client;
	int magic_server;
	unsigned short state;

	/* Remember the session addresses */
	struct sockaddr_inx cli_addr;
	struct sockaddr_inx svr_addr;

	/* Buffers for both direction */
	struct buffer_info request;
	struct buffer_info response;
};

static inline struct proxy_conn *alloc_proxy_conn(void)
{
	struct proxy_conn *conn;

	if (!(conn = malloc(sizeof(*conn))))
		return NULL;
	memset(conn, 0x0, sizeof(*conn));

	conn->cli_sock = -1;
	conn->svr_sock = -1;
	conn->magic_client = EV_MAGIC_CLIENT;
	conn->magic_server = EV_MAGIC_SERVER;
	conn->state = S_INVALID;

	return conn;
}

/**
 * Close both sockets of the connection and remove it
 *  from the current ready list.
 */
static void release_proxy_conn(struct proxy_conn *conn,
		struct epoll_event *pending_evs, int pending_fds, int epfd)
{
	int i;

	/**
	 * Clear possible fd events that might belong to current
	 *  connection. The event must be cleared or an invalid
	 *  pointer might be accessed.
	 */
	for (i = 0; i < pending_fds; i++) {
		struct epoll_event *ev = &pending_evs[i];
		if (ev->data.ptr == &conn->magic_client ||
			ev->data.ptr == &conn->magic_server) {
			ev->data.ptr = NULL;
			break;
		}
	}

	if (epfd >= 0) {
		if (conn->cli_sock >= 0) {
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL);
			close(conn->cli_sock);
		}
		if (conn->svr_sock >= 0) {
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
			close(conn->svr_sock);
		}
	}

	free(conn);
}

static void init_new_conn_epoll_fds(struct proxy_conn *conn, int epfd)
{
	struct epoll_event ev_cli, ev_svr;

	ev_cli.events = EPOLLIN;
	ev_cli.data.ptr = &conn->magic_client;

	ev_svr.events = EPOLLIN;
	ev_svr.data.ptr = &conn->magic_server;

	epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &ev_cli);
	epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev_svr);
}

/**
 * Add or activate the epoll fds according to the status of
 *  'conn'. Different conn->state and buffer status will
 *  affect the polling behaviors.
 */
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd)
{
	struct epoll_event ev_cli, ev_svr;
	
	ev_cli.events = 0;
	ev_cli.data.ptr = &conn->magic_client;

	ev_svr.events = 0;
	ev_svr.data.ptr = &conn->magic_server;

	switch(conn->state) {
		case S_FORWARDING:
			/* Connection established, data forwarding in progress. */
			if (conn->request.dlen < sizeof(conn->request.data))
				ev_cli.events |= EPOLLIN;
			if (conn->response.dlen < sizeof(conn->response.data))
				ev_svr.events |= EPOLLIN;
			if (conn->request.rpos < conn->request.dlen)
				ev_svr.events |= EPOLLOUT;
			if (conn->response.rpos < conn->response.dlen)
				ev_cli.events |= EPOLLOUT;
			break;
		case S_SERVER_CONNECTING:
			/* Wait for the server connection to establish. */
			if (conn->request.dlen < sizeof(conn->request.data))
				ev_cli.events |= EPOLLIN; /* for detecting client close */
			ev_svr.events |= EPOLLOUT;
			break;
	}

	/* Reset epoll status */
	epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev_cli);
	epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev_svr);
}

static int handle_accept_new_connection(int sockfd, struct proxy_conn **conn_p)
{
	int cli_sock, svr_sock;
	struct sockaddr_inx cli_addr;
	socklen_t cli_alen = sizeof(cli_addr);
	struct proxy_conn *conn = NULL;
	char s_addr1[50] = "", s_addr2[50] = "";

	cli_sock = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_alen);
	if (cli_sock < 0) {
		/* FIXME: error indicated, need to exit? */
		syslog(LOG_ERR, "*** accept(): %s", strerror(errno));
		goto err;
	}

	/* Client calls in, allocate session data for it. */
	if (!(conn = alloc_proxy_conn())) {
		syslog(LOG_ERR, "*** alloc_proxy_conn(): %s", strerror(errno));
		close(cli_sock);
		goto err;
	}
	conn->cli_sock = cli_sock;
	set_nonblock(conn->cli_sock);

	conn->cli_addr = cli_addr;

	/* Calculate address of the real server */
	conn->svr_addr = g_dst_addr;
#ifdef __linux__
	if (g_base_addr_mode) {
		struct sockaddr_inx loc_addr, orig_dst;
		socklen_t loc_alen = sizeof(loc_addr), orig_alen = sizeof(orig_dst);
		int port_offset = 0;
		uint32_t *addr_pos = NULL; /* big-endian data */

		memset(&loc_addr, 0x0, sizeof(loc_addr));
		memset(&orig_dst, 0x0, sizeof(orig_dst));
		if (getsockname(conn->cli_sock, (struct sockaddr *)&loc_addr, &loc_alen)) {
			syslog(LOG_ERR, "*** getsockname(): %s.", strerror(errno));
			goto err;
		}
		if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_alen)) {
			syslog(LOG_ERR, "*** getsockopt(SO_ORIGINAL_DST): %s.", strerror(errno));
			goto err;
		}

		if (conn->svr_addr.sa.sa_family == AF_INET) {
			addr_pos = (uint32_t *)&conn->svr_addr.in.sin_addr;
		} else {
			addr_pos = (uint32_t *)&conn->svr_addr.in6.sin6_addr.s6_addr32[3];
		}
		port_offset = (int)(ntohs(port_of_sockaddr(&orig_dst)) - ntohs(port_of_sockaddr(&loc_addr)));

		*addr_pos = htonl(ntohl(*addr_pos) + port_offset);
	}
#endif

	inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
			s_addr1, sizeof(s_addr1));
	inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
			s_addr2, sizeof(s_addr2));
	syslog(LOG_INFO, "New connection [%s]:%d -> [%s]:%d",
			s_addr1, ntohs(port_of_sockaddr(&conn->cli_addr)),
			s_addr2, ntohs(port_of_sockaddr(&conn->svr_addr)));

	/* Initiate the connection to server right now. */
	if ((svr_sock = socket(g_dst_addr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "*** socket(svr_sock): %s", strerror(errno));
		goto err;
	}
	conn->svr_sock = svr_sock;
	set_nonblock(conn->svr_sock);

	if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
			sizeof_sockaddr(&conn->svr_addr)) == 0) {
		/* Connected, prepare for data forwarding. */
		conn->state = S_SERVER_CONNECTED;
		*conn_p = conn;
		return 0;
	} else if (errno == EINPROGRESS) {
		/* OK, poll for the connection to complete or fail */
		conn->state = S_SERVER_CONNECTING;
		*conn_p = conn;
		return -EAGAIN;
	} else {
		/* Error occurs, drop the session. */
		syslog(LOG_WARNING, "Connection to [%s]:%d failed: %s",
				s_addr2, ntohs(port_of_sockaddr(&conn->svr_addr)),
				strerror(errno));
		goto err;
	}

err:
	/**
	 * 'conn' has only been used among this function,
	 * so don't need the caller to release anything
	 */
	if (conn)
		release_proxy_conn(conn, NULL, 0, -1);
	*conn_p = NULL;
	return 0;
}

static int handle_server_connecting(struct proxy_conn *conn, int efd)
{
	char s_addr[50] = "";

	if (efd == conn->svr_sock) {
		/* The connection has established or failed. */
		int err = 0;
		socklen_t errlen = sizeof(err);

		if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err) {
			inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
					s_addr, sizeof(s_addr));
			syslog(LOG_WARNING, "Connection to [%s]:%d failed: %s",
					s_addr, ntohs(port_of_sockaddr(&conn->svr_addr)),
					strerror(err ? err : errno));
			conn->state = S_CLOSING;
			return 0;
		}

		/* Connected, preparing for data forwarding. */
		conn->state = S_SERVER_CONNECTED;
		return 0;
	} else {
		/* Received data early before server connection is OK */
		struct buffer_info *rxb = &conn->request;
		int rc;

		if ((rc = recv(efd , rxb->data + rxb->dlen,
				sizeof(rxb->data) - rxb->dlen, 0)) <= 0) {
			inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
					s_addr, sizeof(s_addr));
			syslog(LOG_INFO, "Connection [%s]:%d closed during server handshake",
					s_addr, ntohs(port_of_sockaddr(&conn->cli_addr)));
			conn->state = S_CLOSING;
			return 0;
		}
		rxb->dlen += rc;

		return -EAGAIN;
	}
}

static int handle_server_connected(struct proxy_conn *conn, int efd)
{
	conn->state = S_FORWARDING;
	return -EAGAIN;
}

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd,
		struct epoll_event *ev)
{
	struct buffer_info *rxb, *txb;
	int noefd, rc;
	char s_addr[50] = "";

	if (efd == conn->cli_sock) {
		rxb = &conn->request;
		txb = &conn->response;
		noefd = conn->svr_sock;
	} else {
		rxb = &conn->response;
		txb = &conn->request;
		noefd = conn->cli_sock;
	}

	if (ev->events & EPOLLIN) {
		if ((rc = recv(efd , rxb->data + rxb->dlen,
				sizeof(rxb->data) - rxb->dlen, 0)) <= 0)
			goto err;
		rxb->dlen += rc;
		/* Try if we can send it out */
		if ((rc = send(noefd, rxb->data + rxb->rpos, rxb->dlen - rxb->rpos, 0)) > 0) {
			rxb->rpos += rc;
			/* Buffer consumed, empty it */
			if (rxb->rpos >= rxb->dlen)
				rxb->rpos = rxb->dlen = 0;
		}
	}

	if (ev->events & EPOLLOUT) {
		if ((rc = send(efd, txb->data + txb->rpos, txb->dlen - txb->rpos, 0)) <= 0)
			goto err;
		txb->rpos += rc;
		/* Buffer consumed, empty it */
		if (txb->rpos >= txb->dlen)
			txb->rpos = txb->dlen = 0;
	}

	/* I/O not ready, handle in next event. */
	return -EAGAIN;

err:
	inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr), s_addr, sizeof(s_addr));
	syslog(LOG_INFO, "Connection [%s]:%d closed", s_addr, ntohs(port_of_sockaddr(&conn->cli_addr)));
	conn->state = S_CLOSING;
	return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("Userspace TCP proxy.\n");
	printf("Usage:\n");
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d] [-o] [-b]\n", argv[0]);
	printf("Options:\n");
	printf("  -d              run in background\n");
	printf("  -o              accept IPv6 connections only for IPv6 listener\n");
	printf("  -b              base address to port mapping mode\n");
	printf("  -p <pidfile>    write PID to file\n");
}

int main(int argc, char *argv[])
{
	int opt, b_true = 1, lsn_sock, epfd;
	bool is_daemon = false, is_v6only = false;
	struct epoll_event ev, events[100];
	int ev_magic_listener = EV_MAGIC_LISTENER;
	char s_addr1[50] = "", s_addr2[50] = "";

	while ((opt = getopt(argc, argv, "dhobp:")) != -1) {
		switch (opt) {
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
		case 'b':
			g_base_addr_mode = true;
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

	openlog("tcpfwd", LOG_PERROR|LOG_NDELAY, LOG_USER);

	lsn_sock = socket(g_src_addr.sa.sa_family, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket(): %s.\n", strerror(errno));
		exit(1);
	}
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_true, sizeof(b_true));
	if (g_src_addr.sa.sa_family == AF_INET6 && is_v6only)
		setsockopt(lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_true, sizeof(b_true));
	if (bind(lsn_sock, (struct sockaddr *)&g_src_addr,
			sizeof_sockaddr(&g_src_addr)) < 0) {
		fprintf(stderr, "*** bind(): %s.\n", strerror(errno));
		exit(1);
	}
	if (listen(lsn_sock, 100) < 0) {
		fprintf(stderr, "*** listen(): %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(lsn_sock);

	inet_ntop(g_src_addr.sa.sa_family, addr_of_sockaddr(&g_src_addr),
			s_addr1, sizeof(s_addr1));
	inet_ntop(g_dst_addr.sa.sa_family, addr_of_sockaddr(&g_dst_addr),
			s_addr2, sizeof(s_addr2));
	syslog(LOG_INFO, "TCP proxy [%s]:%d -> [%s]:%d",
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

	/* epoll loop */
	ev.data.ptr = &ev_magic_listener;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, lsn_sock, &ev);

	for (;;) {
		int nfds, i;

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
			int *evptr = (int *)evp->data.ptr, efd = -1;
			struct proxy_conn *conn;
			int io_state = 0;

			/* 'evptr = NULL' indicates the socket is closed. */
			if (evptr == NULL)
				continue;

			if (*evptr == EV_MAGIC_LISTENER) {
				/* A new connection */
				conn = NULL;
				io_state = handle_accept_new_connection(lsn_sock, &conn);
				if (!conn)
					continue;
				init_new_conn_epoll_fds(conn, epfd);
			} else if (*evptr == EV_MAGIC_CLIENT) {
				conn = container_of(evptr, struct proxy_conn, magic_client);
				efd = conn->cli_sock;
			} else if (*evptr == EV_MAGIC_SERVER) {
				conn = container_of(evptr, struct proxy_conn, magic_server);
				efd = conn->svr_sock;
			} else {
				assert(*evptr == EV_MAGIC_CLIENT || *evptr == EV_MAGIC_SERVER);
			}

			/**
			 * NOTICE:
			 * - io_state = 0: no pending I/O, state machine can move forward
			 * - io_state = -EAGAIN: has pending I/O, should wait for further events
			 * - conn->state = S_CLOSING: connection must be closed at once
			 */
			while (conn->state != S_CLOSING && io_state == 0) {
				switch (conn->state) {
				case S_FORWARDING:
					io_state = handle_forwarding(conn, efd, epfd, evp);
					break;
				case S_SERVER_CONNECTING:
					io_state = handle_server_connecting(conn, efd);
					break;
				case S_SERVER_CONNECTED:
					io_state = handle_server_connected(conn, efd);
					break;
				default:
					syslog(LOG_ERR, "*** Undefined state: %d", conn->state);
					conn->state = S_CLOSING;
					io_state = 0;
				}
			}

			if (conn->state == S_CLOSING) {
				release_proxy_conn(conn, events + i + 1, nfds - 1 - i, epfd);
			} else {
				set_conn_epoll_fds(conn, epfd);
			}
		}
	}

	return 0;
}

