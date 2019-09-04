#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <assert.h>
#ifdef __linux__
	#include <sys/epoll.h>
#else
	#define ERESTART 700
	#include "ps_epoll.h"
#endif
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef __linux__
	#include <linux/netfilter_ipv4.h>
#endif

typedef int bool;
#define true  1
#define false 0

struct sockaddr_inx {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

#define port_of_sockaddr(s) ((s)->sa.sa_family == AF_INET6 ? (s)->in6.sin6_port : (s)->in.sin_port)
#define addr_of_sockaddr(s) ((s)->sa.sa_family == AF_INET6 ? (void *)&(s)->in6.sin6_addr : (void *)&(s)->in.sin_addr)
#define sizeof_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? sizeof((s)->in6) : sizeof((s)->in))

static struct sockaddr_inx g_src_sockaddr;
static struct sockaddr_inx g_dst_sockaddr;
static socklen_t g_src_addrlen;
static socklen_t g_dst_addrlen;
static bool g_base_addr_mode = false;

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

static int set_nonblock(int sfd)
{
	if (fcntl(sfd, F_SETFL,
		fcntl(sfd, F_GETFD, 0) | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

static void write_pidfile(const char *filepath)
{
	FILE *fp;
	if (!(fp = fopen(filepath, "w"))) {
		fprintf(stderr, "*** fopen() failed: %s\n", strerror(errno));
		exit(1);
	}
	fprintf(fp, "%d\n", (int)getpid());
	fclose(fp);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define EPOLL_TABLE_SIZE 2048
#define MAX_POLL_EVENTS 100

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

/* Statues indicators of proxy sessions. */
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

	/* To know if the fds are already added to epoll */
	bool client_in_ep;
	bool server_in_ep;

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
	conn->client_in_ep = false;
	conn->server_in_ep = false;

	return conn;
}

/**
 * Close both sockets of the connection and remove it
 *  from the current ready list.
 */
static inline void release_proxy_conn(struct proxy_conn *conn,
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
			if (conn->request.dlen) {
				ev_svr.events |= EPOLLOUT;
			} else {
				ev_cli.events |= EPOLLIN;
			}
			if (conn->response.dlen) {
				ev_cli.events |= EPOLLOUT;
			} else {
				ev_svr.events |= EPOLLIN;
			}
			break;
		case S_SERVER_CONNECTING:
			/* Wait for the server connection to establish. */
			ev_cli.events |= EPOLLIN;  /* for detecting client close */
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
		fprintf(stderr, "*** accept(): %s\n", strerror(errno));
		goto err;
	}

	/* Client calls in, allocate session data for it. */
	if (!(conn = alloc_proxy_conn())) {
		fprintf(stderr, "*** malloc(struct proxy_conn): %s\n", strerror(errno));
		close(cli_sock);
		goto err;
	}
	conn->cli_sock = cli_sock;
	set_nonblock(conn->cli_sock);
	conn->cli_addr = cli_addr;

	/* Calculate address of the real server */
	conn->svr_addr = g_dst_sockaddr;
#ifdef __linux__
	if (g_base_addr_mode) {
		if (conn->svr_addr.sa.sa_family == AF_INET) {
			struct sockaddr_in *svr_addr = (struct sockaddr_in *)&conn->svr_addr;
			struct sockaddr_in loc_addr, orig_dst;
			socklen_t loc_alen = sizeof(loc_addr), orig_alen = sizeof(orig_dst);
			int port_offset = 0;

			memset(&loc_addr, 0x0, sizeof(loc_addr));
			memset(&orig_dst, 0x0, sizeof(orig_dst));

			if (getsockname(conn->cli_sock, (struct sockaddr *)&loc_addr, &loc_alen)) {
				fprintf(stderr, "*** getsockname(): %s.\n", strerror(errno));
				goto err;
			}
			if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_alen)) {
				fprintf(stderr, "*** getsockopt(SO_ORIGINAL_DST): %s.\n", strerror(errno));
				goto err;
			}

			port_offset = (int)(ntohs(orig_dst.sin_port) - ntohs(loc_addr.sin_port));
			svr_addr->sin_addr.s_addr = htonl(ntohl(svr_addr->sin_addr.s_addr) + port_offset);
		} else {
			fprintf(stderr, "*** No IPv6 support for base address/port mapping mode.\n");
		}
	}
#endif

	inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
			s_addr1, sizeof(s_addr1));
	inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
			s_addr2, sizeof(s_addr2));
	printf("New connection [%s]:%d -> [%s]:%d\n",
			s_addr1, ntohs(port_of_sockaddr(&conn->cli_addr)),
			s_addr2, ntohs(port_of_sockaddr(&conn->svr_addr)));

	/* Initiate the connection to server right now. */
	if ((svr_sock = socket(g_dst_sockaddr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "*** socket(svr_sock): %s\n", strerror(errno));
		goto err;
	}
	conn->svr_sock = svr_sock;
	set_nonblock(conn->svr_sock);

	if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
			g_dst_addrlen) == 0) {
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
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
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

static int handle_server_connecting(struct proxy_conn *conn)
{
	/* The connection has established or failed. */
	int err = 0;
	socklen_t errlen = sizeof(err);
	
	if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		conn->state = S_CLOSING;
		return 0;
	}
	if (err != 0) {
		fprintf(stderr, "*** Connection failed: %s\n", strerror(err));
		conn->state = S_CLOSING;
		return 0;
	}
	/* Connected, preparing for data forwarding. */
	conn->state = S_SERVER_CONNECTED;
	return 0;
}

static int handle_server_connected(struct proxy_conn *conn)
{
	conn->state = S_FORWARDING;
	return -EAGAIN;
}

static int handle_forwarding(struct proxy_conn *conn, int epfd, struct epoll_event *ev)
{
	int *evptr = (int *)ev->data.ptr;
	struct buffer_info *rxb, *txb;
	int efd, rc;
	char s_addr[50] = "";

	if (*evptr == EV_MAGIC_CLIENT) {
		efd = conn->cli_sock;
		rxb = &conn->request;
		txb = &conn->response;
	} else {
		efd = conn->svr_sock;
		rxb = &conn->response;
		txb = &conn->request;
	}

	if (ev->events & EPOLLIN) {
		if ((rc = recv(efd , rxb->data, sizeof(rxb->data), 0)) <= 0)
			goto err;
		rxb->dlen = rc;
	}

	if (ev->events & EPOLLOUT) {
		if ((rc = send(efd, txb->data + txb->rpos, txb->dlen - txb->rpos, 0)) <= 0)
			goto err;
		txb->rpos += rc;
		if (txb->rpos >= txb->dlen)
			txb->rpos = txb->dlen = 0;
	}

	/* I/O not ready, handle in next event. */
	return -EAGAIN;

err:
	inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr), s_addr, sizeof(s_addr));
	printf("Connection [%s]:%d closed\n", s_addr, ntohs(port_of_sockaddr(&conn->cli_addr)));
	conn->state = S_CLOSING;
	return 0;
}

static int get_sockaddr_v4v6(const char *node, int port,
		int socktype, int *family, struct sockaddr_inx *addr,
		socklen_t *addrlen)
{
	struct addrinfo hints, *result;
	char s_port[12];
	int rc;

	sprintf(s_port, "%d", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = *family;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	
	if ((rc = getaddrinfo(node, s_port, &hints, &result))) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		return -1;
	}
	
	/* Get the first resolved address */
	*family = result->ai_family;
	*addrlen = result->ai_addrlen;
	memcpy(addr, result->ai_addr, result->ai_addrlen);
	freeaddrinfo(result);
	return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("Userspace TCP proxy.\n");
	printf("Usage:\n");
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d] [-o] [-f6.4] [-b]\n", argv[0]);
	printf("Options:\n");
	printf("  -d              run in background\n");
	printf("  -o              accept IPv6 connections only for IPv6 listener\n");
	printf("  -b              base address to port mapping mode\n");
	printf("  -f X.Y          allow address families for source|destination\n");
	printf("  -p <pidfile>    write PID to file\n");
}

int main(int argc, char *argv[])
{
	int lsn_sock;
	int src_family = AF_UNSPEC, dst_family = AF_UNSPEC;
	int b_sockopt = 1, opt;
	bool is_daemon = false, is_v6only = false;
	const char *pidfile = NULL;
	char s_src_host[50], s_dst_host[50], s_af1[10], s_af2[10];
	int src_port, dst_port;
	int rc, epfd, af1 = 0, af2 = 0;
	struct epoll_event ev, events[MAX_POLL_EVENTS];
	size_t events_sz = MAX_POLL_EVENTS;
	int ev_magic_listener = EV_MAGIC_LISTENER;

	while ((opt = getopt(argc, argv, "dhobf:p:")) != -1) {
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
			pidfile = optarg;
			break;
		case 'f':
			rc = sscanf(optarg, "%5[^.].%5s", s_af1, s_af2);
			if (rc == 2) {
				sscanf(s_af1, "%d", &af1);
				sscanf(s_af2, "%d", &af2);
			} else {
				fprintf(stderr, "*** Invalid address families: %s\n", optarg);
				exit(1);
			}
			if (af1 == 4) {
				src_family = AF_INET;
			} else if (af1 == 6) {
				src_family = AF_INET6;
			}
			if (af2 == 4) {
				dst_family = AF_INET;
			} else if (af2 == 6) {
				dst_family = AF_INET6;
			}
			break;
		case '?':
			exit(1);
		}
	}

	if (optind > argc - 2) {
		show_help(argc, argv);
		exit(1);
	}

	/* Parse source address. */
	if (sscanf(argv[optind], "[%40[^]]]:%d", s_src_host,
		&src_port) == 2) {
	} else if (sscanf(argv[optind], "%40[^:]:%d", s_src_host,
		&src_port) == 2) {
	} else if (sscanf(argv[optind], "%d", &src_port) == 1) {
		strcpy(s_src_host, "0.0.0.0");
	} else {
		fprintf(stderr, "*** Invalid source address '%s'.\n",
				argv[optind]);
		exit(1);
	}
	optind++;

	/* Parse destination address. */
	if (sscanf(argv[optind], "[%40[^]]]:%d", s_dst_host,
		&dst_port) == 2) {
	} else if (sscanf(argv[optind], "%40[^:]:%d", s_dst_host,
		&dst_port) == 2) {
	} else {
		fprintf(stderr, "*** Invalid destination address '%s'.\n",
				argv[optind]);
		exit(1);
	}

	/* Resolve the addresses */
	if (get_sockaddr_v4v6(s_src_host, src_port, SOCK_STREAM,
		&src_family, &g_src_sockaddr, &g_src_addrlen)) {
		fprintf(stderr, "*** Invalid source address.\n");
		exit(1);
	}
	if (get_sockaddr_v4v6(s_dst_host, dst_port, SOCK_STREAM,
		&dst_family, &g_dst_sockaddr, &g_dst_addrlen)) {
		fprintf(stderr, "*** Invalid destination address.\n");
		exit(1);
	}
	
	lsn_sock = socket(g_src_sockaddr.sa.sa_family, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}

	b_sockopt = 1;
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_sockopt, sizeof(b_sockopt));

	if (g_src_sockaddr.sa.sa_family == AF_INET6 && is_v6only) {
		b_sockopt = 1;
		setsockopt(lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_sockopt, sizeof(b_sockopt));
	}
	
	if (bind(lsn_sock, (struct sockaddr *)&g_src_sockaddr, g_src_addrlen) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}

	if (listen(lsn_sock, 100) < 0) {
		fprintf(stderr, "*** listen() failed: %s.\n", strerror(errno));
		exit(1);
	}

	set_nonblock(lsn_sock);
	
	printf("TCP proxy %s:%d -> %s:%d started \n",
		   s_src_host, src_port, s_dst_host, dst_port);

	/* Create epoll table. */
	if ((epfd = epoll_create(EPOLL_TABLE_SIZE)) < 0) {
		fprintf(stderr, "*** epoll_create() failed: %s\n",
				strerror(errno));
		exit(1);
	}

	/* Run in background. */
	if (is_daemon)
		do_daemonize();

	if (pidfile)
		write_pidfile(pidfile);

	/**
	 * Ignore PIPE signal, which is triggered when send() to
	 *  a half-closed socket which causes process to abort.
	 */
	signal(SIGPIPE, SIG_IGN);

	/* epoll loop */
	ev.data.ptr = &ev_magic_listener;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, lsn_sock, &ev);

	for (;;) {
		int nfds, i;
		
		nfds = epoll_wait(epfd, events, events_sz, 1000 * 2);
		if (nfds == 0)
			continue;
		if (nfds < 0) {
			if (errno == EINTR || errno == ERESTART)
				continue;
			fprintf(stderr, "*** epoll_wait(): %s\n", strerror(errno));
			exit(1);
		}
		
		for (i = 0; i < nfds; i++) {
			struct epoll_event *evp = &events[i];
			int *evptr = (int *)evp->data.ptr;
			struct proxy_conn *conn;
			int io_state = 0;
			
			if (evptr == NULL) {
				/* 'evptr = NULL' indicates the socket is closed. */
				continue;
			} else if (*evptr == EV_MAGIC_LISTENER) {
				/* A new connection */
				conn = NULL;
				io_state = handle_accept_new_connection(lsn_sock, &conn);
				if (!conn)
					continue;
				init_new_conn_epoll_fds(conn, epfd);
			} else if (*evptr == EV_MAGIC_CLIENT) {
				conn = container_of(evptr, struct proxy_conn, magic_client);
			} else if (*evptr == EV_MAGIC_SERVER) {
				conn = container_of(evptr, struct proxy_conn, magic_server);
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
					io_state = handle_forwarding(conn, epfd, evp);
					break;
				case S_SERVER_CONNECTING:
					io_state = handle_server_connecting(conn);
					break;
				case S_SERVER_CONNECTED:
					io_state = handle_server_connected(conn);
					break;
				default:
					fprintf(stderr, "*** Undefined state: %d\n", conn->state);
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

