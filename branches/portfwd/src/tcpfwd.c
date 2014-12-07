#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef int bool;
#define true  1
#define false 0

//static unsigned int   g_source_ip   = 0;
//static unsigned short g_source_port = 0;
//static unsigned int   g_dest_ip     = 0;
//static unsigned short g_dest_port   = 0;

static struct sockaddr_storage g_src_sockaddr;
static struct sockaddr_storage g_dst_sockaddr;
static socklen_t g_src_addrlen;
static socklen_t g_dst_addrlen;

static char *sockaddr_to_print(const void *addr,
		char *host, int *port)
{
	const union __sa_union {
		struct sockaddr_storage ss;
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
	} *sa = addr;
	
	if (sa->ss.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sa->sa4.sin_addr, host, 16);
		*port = ntohs(sa->sa4.sin_port);
	} else if (sa->ss.ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &sa->sa6.sin6_addr, host, 40);
		*port = ntohs(sa->sa6.sin6_port);
	} else {
		return NULL;
	}
	return host;
}

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
	EV_MAGIC_CLIENT = 0x2010,
	EV_MAGIC_SERVER = 0x3020,
};

struct buffer_info {
	char *buf;
	unsigned rpos;
	unsigned dlen;
	unsigned size;
};

#define REQ_BUFFER_SIZE 8192
#define RSP_BUFFER_SIZE 8192

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
	int cli_sock;
	int svr_sock;

	/**
	 * The two fields are used when an epoll event occur,
	 *  to know on which socket fd it is triggered,
	 *  client or server.
	 *  ev.data.ptr = &ct.ev_client;
	 */
	int ev_client;
	int ev_server;
	unsigned short state;

	/* Memorize the session addresses. */
	struct sockaddr_storage cli_addr;
	struct sockaddr_storage svr_addr;

	/* To know if the fds are already added to epoll. */
	bool client_in_ep;
	bool server_in_ep;

	/* Buffers for both direction. */
	struct buffer_info request;
	struct buffer_info response;
};

/**
 * Get 'conn' structure by passing the ev.data.ptr
 * @ptr: cannot be NULL and must be either EV_MAGIC_CLIENT
 *  or EV_MAGIC_SERVER.
 */
static inline struct proxy_conn *get_conn_by_evptr(int *evptr)
{
	if (*evptr == EV_MAGIC_CLIENT)
		return container_of(evptr, struct proxy_conn, ev_client);
	else if (*evptr == EV_MAGIC_SERVER)
		return container_of(evptr, struct proxy_conn, ev_server);
	else
		assert(*evptr == EV_MAGIC_CLIENT || *evptr == EV_MAGIC_SERVER);
	return NULL;
}

static inline struct proxy_conn *alloc_proxy_conn(void)
{
	struct proxy_conn *conn;

	if (!(conn = malloc(sizeof(*conn))))
		return NULL;
	memset(conn, 0x0, sizeof(*conn));
	conn->cli_sock = -1;
	conn->svr_sock = -1;
	conn->ev_client = EV_MAGIC_CLIENT;
	conn->ev_server = EV_MAGIC_SERVER;
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
		struct epoll_event *pending_evs, int pending_fds)
{
	int i;
	struct epoll_event *ev;
	
	/**
	 * Clear possible fd events that might belong to current
	 *  connection. The event must be cleared or an invalid
	 *  pointer might be accessed.
	 */
	if (conn->client_in_ep || conn->server_in_ep) {
		for (i = 0; i < pending_fds; i++) {
			ev = &pending_evs[i];
			if (ev->data.ptr == &conn->ev_client ||
				ev->data.ptr == &conn->ev_server) {
				ev->data.ptr = NULL;
				break;
			}
		}
	}
	
	if (conn->cli_sock >= 0)
		close(conn->cli_sock);
	if (conn->svr_sock >= 0)
		close(conn->svr_sock);
	
	if (conn->request.buf)
		free(conn->request.buf);
	if (conn->response.buf)
		free(conn->response.buf);
	
	free(conn);
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
	ev_svr.events = 0;
	
	switch(conn->state) {
		case S_FORWARDING:
			/* Connection established, data forwarding in progress. */
			if (!conn->request.dlen && !conn->response.dlen) {
				ev_cli.events = EPOLLIN;
				ev_svr.events = EPOLLIN;
			} else if (conn->request.dlen && !conn->response.dlen) {
				ev_svr.events = EPOLLIN | EPOLLOUT;
			} else if (!conn->request.dlen && conn->response.dlen) {
				ev_cli.events = EPOLLIN | EPOLLOUT;
			} else {
				ev_cli.events = EPOLLOUT;
				ev_svr.events = EPOLLOUT;
			}
			break;
		case S_SERVER_CONNECTING:
			/* Wait for the server connection to establish. */
			ev_svr.events = EPOLLOUT;
			break;
	}
	
	if (ev_cli.events) {
		ev_cli.data.ptr = &conn->ev_client;
		if (conn->client_in_ep)
			epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev_cli); /* FIXME: result */
		else
			epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &ev_cli);
		conn->client_in_ep = true;
	} else {
		if (conn->client_in_ep)
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL);
		conn->client_in_ep = false;
	}
	
	if (ev_svr.events) {
		ev_svr.data.ptr = &conn->ev_server;
		if (conn->server_in_ep)
			epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev_svr);
		else
			epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev_svr);
		conn->server_in_ep = true;
	} else {
		if (conn->server_in_ep)
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
		conn->server_in_ep = false;
	}
}

static struct proxy_conn *accept_and_connect(int lsn_sock, int *error)
{
	int cli_sock, svr_sock;
	struct sockaddr_storage cli_addr;
	socklen_t cli_alen = sizeof(cli_addr);
	struct proxy_conn *conn;
	char s1[44] = ""; int n1 = 0;

	cli_sock = accept(lsn_sock, (struct sockaddr *)&cli_addr, &cli_alen);
	if (cli_sock < 0) {
		/* FIXME: error indicated, need to exit? */
		fprintf(stderr, "*** accept() failed: %s\n", strerror(errno));
		return NULL;
	}
	
	/* Client calls in, allocate session data for it. */
	if (!(conn = alloc_proxy_conn())) {
		fprintf(stderr, "*** malloc(struct proxy_conn) error: %s\n",
				strerror(errno));
		close(cli_sock);
		return NULL;
	}
	conn->cli_sock = cli_sock;
	set_nonblock(conn->cli_sock);
	conn->cli_addr = cli_addr;
	
	/* Initiate the connection to server right now. */
	if ((svr_sock = socket(g_dst_sockaddr.ss_family, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "*** socket(svr_sock) error: %s\n", strerror(errno));
		/**
		 * 'conn' has only been used among this function,
		 *  so don't need the caller to release anything.
		 */
		release_proxy_conn(conn, NULL, 0);
		return NULL;
	}
	conn->svr_sock = svr_sock;
	set_nonblock(conn->svr_sock);
	
	/* Connect to real server. */
	conn->svr_addr = g_dst_sockaddr;

	sockaddr_to_print(&conn->cli_addr, s1, &n1);
	printf("-- Client [%s]:%d entered\n", s1, n1);
	
	if ((connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
		g_dst_addrlen)) == 0) {
		/* Connected, prepare for data forwarding. */
		conn->state = S_SERVER_CONNECTED;
		*error = 0;
		return conn;
	} else if (errno == EINPROGRESS) {
		/**
		 * OK, the request does not fail right now, so wait
		 *  for it completes.
		 */
		conn->state = S_SERVER_CONNECTING;
		*error = EINPROGRESS;
		return conn;
	} else {
		/* Error occurs, drop the session. */
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		release_proxy_conn(conn, NULL, 0);
		return NULL;
	}
}

static int server_connecting(struct proxy_conn *conn)
{
	/* The connection has established or failed. */
	int err = 0;
	socklen_t errlen = sizeof(err);
	
	if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err,
		&errlen) < 0) {
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		conn->state = S_CLOSING;
		return ECONNABORTED;
	}
	if (err != 0) {
		fprintf(stderr, "*** Connection failed: %s\n", strerror(err));
		conn->state = S_CLOSING;
		return ECONNABORTED;
	}
	/* Connected, preparing for data forwarding. */
	conn->state = S_SERVER_CONNECTED;
	return 0;
}

static int server_connected(struct proxy_conn *conn)
{
	/* Allocate both buffers. */
	conn->request.size = REQ_BUFFER_SIZE;
	conn->response.size = RSP_BUFFER_SIZE;
	conn->request.buf = (char *)malloc(conn->request.size);
	conn->response.buf = (char *)malloc(conn->response.size);
	if (!conn->request.buf || !conn->response.buf) {
		fprintf(stderr, "*** Failed to allocate either request "
				"or response buffers.\n");
		conn->state = S_CLOSING;
		return ECONNABORTED;
	}
	
	if (0) {
		/* FIXME: SOCKS request. */
	} else {
		/* Direct access. */
		conn->state = S_FORWARDING;
	}
	return EWOULDBLOCK;
}

static int forward_data(struct proxy_conn *conn, int epfd,
		struct epoll_event *ev)
{
	int *evptr = (int *)ev->data.ptr;
	struct buffer_info *rxb, *txb;
	int efd, rc;
	
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
		if ((rc = recv(efd , rxb->buf, rxb->size, 0)) <= 0) {
			char s1[44] = ""; int n1 = 0;
			sockaddr_to_print(&conn->cli_addr, s1, &n1);
			printf("-- Client [%s]:%d exits\n", s1, n1);
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
		rxb->dlen = (unsigned)rc;
	}
	
	if (ev->events & EPOLLOUT) {
		if ((rc = send(efd, txb->buf + txb->rpos,
			txb->dlen - txb->rpos, 0)) <= 0) {
			char s1[44] = ""; int n1 = 0;
			sockaddr_to_print(&conn->cli_addr, s1, &n1);
			printf("-- Client [%s]:%d exits\n", s1, n1);
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
		txb->rpos += rc;
		if (txb->rpos >= txb->dlen)
			txb->rpos = txb->dlen = 0;
	}
	
	return EWOULDBLOCK;
}

static int get_sockaddr_v4v6(const char *node, int port,
		int socktype, int *family, struct sockaddr_storage *addr,
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
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d] [-o] [-f6.4]\n", argv[0]);
	printf("Options:\n");
	printf("  -d              run in background\n");
	printf("  -o              accept IPv6 connections only for IPv6 listener\n");
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

	while ((opt = getopt(argc, argv, "dhof:p:")) != -1) {
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
	} else if (sscanf(argv[optind], "%19[^:]:%d", s_dst_host,
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
	
	lsn_sock = socket(g_src_sockaddr.ss_family, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}

	b_sockopt = 1;
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_sockopt, sizeof(b_sockopt));

	if (g_src_sockaddr.ss_family == AF_INET6 && is_v6only) {
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
			fprintf(stderr, "*** epoll_wait() error: %s\n", strerror(errno));
			exit(1);
		}
		
		for (i = 0; i < nfds; i++) {
			struct epoll_event *evp = &events[i];
			int *evptr = (int *)evp->data.ptr;
			struct proxy_conn *conn;
			int rc = 0;
			
			/* NULL evp->data.ptr indicates this socket is closed. */
			if (evptr == NULL)
				continue;
			
			if (*evptr == EV_MAGIC_LISTENER) {
				/* A new connection calls in. */
				rc = -1;
				if (!(conn = accept_and_connect(lsn_sock, &rc)))
					continue;
			} else {
				conn = get_conn_by_evptr(evptr);
			}
			
			/**
			 * 1. rc == 0 means I/O completes, can be treated in current epoll cycle;
			 *    rc != 0 means I/O inprogress, cannot be treated in this cycle.
			 * 2. If conn->state == S_CLOSING, close it.
			 */
			while (rc == 0 && conn->state != S_CLOSING) {
				switch (conn->state) {
				case S_FORWARDING:
					rc = forward_data(conn, epfd, evp);
					break;
				case S_SERVER_CONNECTING:
					rc = server_connecting(conn);
					break;
				case S_SERVER_CONNECTED:
					rc = server_connected(conn);
					break;
				default:
					fprintf(stderr, "*** Undefined state: %d\n", conn->state);
					conn->state = S_CLOSING;
					rc = ECONNABORTED;
				}
			}
			if (conn->state == S_CLOSING) {
				release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
			} else {
				set_conn_epoll_fds(conn, epfd);
			}
		}
	}

	return 0;
}

