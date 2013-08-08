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
#include <linux/netfilter_ipv4.h>

#include "utils.h"
#include "config.h"

static unsigned int   g_tcp_proxy_ip   = 0;
static unsigned short g_tcp_proxy_port = 7070;

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

enum proxy_type {
	PROXY_NONE,
	PROXY_SOCKS4,
	PROXY_SOCKS5,
};

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define EPOLL_TABLE_SIZE 2048
#define MAX_POLL_EVENTS 100

/* Statues indicators of proxy sessions. */
enum conn_state {
	S_INVALID,
	S_SERVER_CONNECTING,
	S_SERVER_CONNECTED,
	S_SERVER_SENDING,
	S_SERVER_RECEIVING,
	S_SENTV4REQ,
	S_GOTV4REQ,
	S_SENTV5METHOD,
	S_GOTV5METHOD,
	S_SENTV5CONNECT,
	S_GOTV5CONNECT,
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
	 * The two fields are used when an epoll event occurs,
	 *  to know on which socket fd it is triggered,
	 *  client or server.
	 *  ev.data.ptr = &conn.ev_client;
	 */
	int ev_client;
	int ev_server;
	unsigned short state;
	unsigned short next_state;
	unsigned short proxy_type;

	/* Memorize the session addresses. */
	struct sockaddr_in cli_addr;
	struct sockaddr_in orig_dst;

	/* To know if the fds are already added to epoll. */
	bool client_in_ep;
	bool server_in_ep;

	/* Buffers for both direction. */
	struct buffer_info request;
	struct buffer_info response;
};

/* Choose conn->request.buf to use in SOCKS handshakes. */
#define hsbuf(conn) ((conn)->request)

/**
 * Get 'conn' structure by passing the ev.data.ptr
 * @ptr: cannot be NULL and must be either EV_MAGIC_CLIENT
 *  or EV_MAGIC_SERVER.
 */
static inline struct proxy_conn *conn_of_evptr(int *evptr)
{
	if (*evptr == EV_MAGIC_CLIENT)
		return container_of(evptr, struct proxy_conn, ev_client);
	else if (*evptr == EV_MAGIC_SERVER)
		return container_of(evptr, struct proxy_conn, ev_server);
	else
		assert(*evptr == EV_MAGIC_CLIENT || *evptr == EV_MAGIC_SERVER);
	return NULL;
}

static inline void rewind_conn_buffers(struct proxy_conn *conn)
{
	conn->request.rpos = conn->request.dlen = 0;
	conn->response.rpos = conn->response.dlen = 0;
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
 *  'conn'. Different conn->state and buffer status result in
 *  different poll behaviors.
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
		case S_SERVER_SENDING:
			ev_svr.events = EPOLLOUT;
			break;
		case S_SERVER_RECEIVING:
			ev_svr.events = EPOLLIN;
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
	struct sockaddr_in cli_addr, orig_dst, svr_addr;
	socklen_t cli_alen = sizeof(cli_addr),
			orig_alen = sizeof(orig_dst);
	struct proxy_conn *conn;
	struct proxy_server *ps;
	char s1[20], s2[20];

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
	
	/* Get the original dest address before DNAT translation. */
	if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST,
		(struct sockaddr_in *)&orig_dst, &orig_alen)) {
		fprintf(stderr, "*** getsockopt(SO_ORIGINAL_DST) failed: %s.\n",
				strerror(errno));
		release_proxy_conn(conn, NULL, 0);
		return NULL;
	}
	conn->orig_dst = orig_dst;
	/**
	 * FIXME: Check if destination address equals the
	 *  listening address. Refuse the operation if so.
	 */
	
	printf("-- Client %s:%d -> %s:%d in, ",
			strcpy(s1, inet_ntoa(conn->cli_addr.sin_addr)),
			ntohs(conn->cli_addr.sin_port),
			strcpy(s2, inet_ntoa(conn->orig_dst.sin_addr)),
			ntohs(conn->orig_dst.sin_port));
	
	/* Select a proxy server to connect to the real server. */
	ps = get_socks_server_by_ip(ntohl(orig_dst.sin_addr.s_addr));
	if (!ps) {
		/* No matching rule, use local network. */
		conn->proxy_type = PROXY_NONE;
		svr_addr = orig_dst;
		printf("no proxy\n");
	} else if (ps->server_sa.sin_addr.s_addr == 0 &&
			ps->server_sa.sin_port == 0) {
		/* Explicitly defined 'none', use local network. */
		conn->proxy_type = PROXY_NONE;
		svr_addr = orig_dst;
		printf("no proxy\n");
	} else {
		/* Use SOCKS5 proxy. */
		conn->proxy_type = PROXY_SOCKS5;
		svr_addr = ps->server_sa;
		printf("proxy %s:%d\n", inet_ntoa(svr_addr.sin_addr),
			ntohs(svr_addr.sin_port));
	}
	
	/* Initiate the connection to server right now. */
	if ((svr_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "*** socket(svr_sock) error: %s\n",
				strerror(errno));
		/**
		 * 'conn' has only been used among this function,
		 *  so don't need the caller to release anything.
		 */
		release_proxy_conn(conn, NULL, 0);
		return NULL;
	}
	conn->svr_sock = svr_sock;
	set_nonblock(conn->svr_sock);
	
	/* Connect to server. */
	if ((connect(conn->svr_sock, (struct sockaddr *)&svr_addr,
		sizeof(svr_addr))) == 0) {
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

static int send_socksv5_method(struct proxy_conn *conn)
{
	char verstring[] = { 0x05,    /* Version 5 SOCKS */
						 0x01,    /* Number of Methods     */
						 0x00,    /* Null Auth       */
						/*0x02*/ };  /* User/Pass Auth  */
	memcpy(hsbuf(conn).buf, verstring, sizeof(verstring));
	hsbuf(conn).dlen = sizeof(verstring);
	hsbuf(conn).rpos = 0;
	conn->state = S_SERVER_SENDING;
	conn->next_state = S_SENTV5METHOD;
	/* Assume I/O ready now, try to send in the same epoll cycle. */
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
	
	if (conn->proxy_type == PROXY_NONE) {
		/* Direct access, the next state is FORWARDING. */
		conn->state = S_FORWARDING;
		return EWOULDBLOCK;
	} else if (conn->proxy_type == PROXY_SOCKS5) {
		return send_socksv5_method(conn);
	} else if (conn->proxy_type == PROXY_SOCKS4) {
		/* FIXME: Implement it */
		conn->state = S_CLOSING;
		return EINVAL;
	} else {
		fprintf(stderr, "*** Unknown proxy type: %u\n", conn->proxy_type);
		conn->state = S_CLOSING;
		return EINVAL;
	}
}

static int server_send_buffer(struct proxy_conn *conn)
{
	int rc = 0;
	
	for (;;) {
		rc = send(conn->svr_sock, hsbuf(conn).buf + hsbuf(conn).rpos,
				  hsbuf(conn).dlen - hsbuf(conn).rpos, 0);
		if (rc > 0) {
			hsbuf(conn).rpos += rc;
			if (hsbuf(conn).rpos >= hsbuf(conn).dlen) {
				/* Sent the full buffer, return */
				conn->state = conn->next_state;
				return 0;
			}
			/* Continue to try */
		} else if (rc == 0) {
			fprintf(stderr, "*** [%s] Connection closed unexpectedly.\n",
					__FUNCTION__);
			conn->state = S_CLOSING;
			return ECONNABORTED;
		} else if (errno == EWOULDBLOCK && errno == EAGAIN) {
			/* I/O not ready, handle in next event. */
			return errno;
		} else {
			fprintf(stderr, "*** [%s] Unexpected error: %s\n",
					__FUNCTION__, strerror(errno));
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
	}
	
	/* Won't reach here */
	return -1;
}

static int server_recv_buffer(struct proxy_conn *conn)
{
	int rc = 0;

	for (;;) {
		rc = recv(conn->svr_sock, hsbuf(conn).buf + hsbuf(conn).rpos,
				  hsbuf(conn).dlen - hsbuf(conn).rpos, 0);
		if (rc > 0) {
			hsbuf(conn).rpos += rc;
			if (hsbuf(conn).rpos >= hsbuf(conn).dlen) {
				/* Received the full size, return */
				conn->state = conn->next_state;
				return 0;
			}
			/* Continue to try */
		} else if (rc == 0) {
			fprintf(stderr, "*** [%s] Connection closed unexpectedly.\n",
					__FUNCTION__);
			conn->state = S_CLOSING;
			return ECONNABORTED;
		} else if (errno == EWOULDBLOCK && errno == EAGAIN) {
			/* I/O not ready, handle in next event. */
			return errno;
		} else {
			fprintf(stderr, "*** [%s] Unexpected error: %s\n",
					__FUNCTION__, strerror(errno));
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
	}
	
	/* Won't reach here */
	return -1;
}

static int read_socksv5_method(struct proxy_conn *conn)
{
	char constring[] = { 0x05,    /* Version 5 SOCKS */
						 0x01,    /* Connect request */
						 0x00,    /* Reserved        */
						 0x01 };  /* IP Version 4    */
	
	if ((unsigned char)hsbuf(conn).buf[1] == 0xff) {
		fprintf(stderr, "*** SOCKS5 method negotiation failed.\n");
		conn->state = S_CLOSING;
		return ECONNREFUSED;
	}
	
	/* OK, send the CONNECT request. */
	memcpy(hsbuf(conn).buf, constring, sizeof(constring));
	hsbuf(conn).dlen = sizeof(constring);
	memcpy(hsbuf(conn).buf + hsbuf(conn).dlen,
			&conn->orig_dst.sin_addr.s_addr, 4);
	hsbuf(conn).dlen += 4;
	memcpy(hsbuf(conn).buf + hsbuf(conn).dlen,
			&conn->orig_dst.sin_port, 2);
	hsbuf(conn).dlen += 2;
	hsbuf(conn).rpos = 0;
	/* Total: 10 bytes */
	
	conn->state = S_SERVER_SENDING;
	conn->next_state = S_SENTV5CONNECT;
	return 0;
}

static int read_socksv5_connect(struct proxy_conn *conn)
{
	if ((unsigned char)hsbuf(conn).buf[1] != 0x00) {
		fprintf(stderr, "*** SOCKS V5 connect failed: ");
		conn->state = S_CLOSING;
		switch ((unsigned char)hsbuf(conn).buf[1]) {
			case 1:
				fprintf(stderr, "General SOCKS server failure\n");
				return ECONNABORTED;
			case 2:
				fprintf(stderr, "Connection denied by rule\n");
				return ECONNABORTED;
			case 3:
				fprintf(stderr, "Network unreachable\n");
				return ENETUNREACH;
			case 4:
				fprintf(stderr, "Host unreachable\n");
				return EHOSTUNREACH;
			case 5:
				fprintf(stderr, "Connection refused\n");
				return ECONNREFUSED;
			case 6: 
				fprintf(stderr, "TTL Expired\n");
				return ETIMEDOUT;
			case 7:
				fprintf(stderr, "Command not supported\n");
				return ECONNABORTED;
			case 8:
				fprintf(stderr, "Address type not supported\n");
				return ECONNABORTED;
			default:
				fprintf(stderr, "Unknown error\n");
				return ECONNABORTED;
		}
	}
	
	rewind_conn_buffers(conn);
	conn->state = S_FORWARDING;
	return EWOULDBLOCK;
}

static int forward_data(struct proxy_conn *conn, struct epoll_event *ev)
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
			printf("-- Client %s:%d exits\n", inet_ntoa(conn->cli_addr.sin_addr),
				ntohs(conn->cli_addr.sin_port));
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
		rxb->dlen = (unsigned)rc;
	}
	
	if (ev->events & EPOLLOUT) {
		if ((rc = send(efd, txb->buf + txb->rpos,
			txb->dlen - txb->rpos, 0)) <= 0) {
			printf("-- Client %s:%d exits\n", inet_ntoa(conn->cli_addr.sin_addr),
				ntohs(conn->cli_addr.sin_port));
			conn->state = S_CLOSING;
			return ECONNABORTED;
		}
		txb->rpos += rc;
		if (txb->rpos >= txb->dlen)
			txb->rpos = txb->dlen = 0;
	}
	
	return EWOULDBLOCK;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("IP-to-SOCKS transforming gateway service.\n");
	printf("Usage:\n");
	printf("  %s [-s socks_ip:socks_port] [-d] [-z]\n", argv[0]);
	printf("Options:\n");
	printf("  -l [local_ip:]port          TCP proxy listening address, default: 0.0.0.0:7070\n");
	printf("  -d                          run in background\n");
}

int main(int argc, char *argv[])
{
	int lsn_sock;
	struct sockaddr_in lsn_addr;
	int b_reuse = 1;
	int opt;
	bool is_daemon = false;
	struct rlimit rlim;
	int epfd;
	struct epoll_event ev, events[MAX_POLL_EVENTS];
	size_t events_sz = MAX_POLL_EVENTS;
	int ev_magic_listener = EV_MAGIC_LISTENER;

	while ((opt = getopt(argc, argv, "l:dh")) != -1) {
		switch (opt) {
		case 'l': {
				char s_lsn_ip[20];
				int lsn_port;
				if (sscanf(optarg, "%19[^:]:%d", s_lsn_ip,
					&lsn_port) == 2) {
					g_tcp_proxy_ip = ntohl(inet_addr(s_lsn_ip));
					g_tcp_proxy_port = lsn_port;
				} else if (sscanf(optarg, "%d", &lsn_port) == 1) {
					g_tcp_proxy_port = (unsigned short)lsn_port;
				} else {
					fprintf(stderr, "*** Invalid argument for '-l'.\n");
					show_help(argc, argv);
					exit(1);
				}
				break;
			}
		case 'd':
			is_daemon = true;
			break;
		case 'h':
			show_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	/* Load proxy rules defined in config file. */
	init_proxy_rules_or_exit();

	/* Enlarge the file descriptor limination. */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		if (rlim.rlim_max < 20480) {
			rlim.rlim_cur = rlim.rlim_max = 20480;
			setrlimit(RLIMIT_NOFILE, &rlim);
		}
	}

	lsn_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_reuse, sizeof(b_reuse));

	memset(&lsn_addr, 0x0, sizeof(lsn_addr));
	lsn_addr.sin_family = AF_INET;
	lsn_addr.sin_addr.s_addr = htonl(g_tcp_proxy_ip);
	lsn_addr.sin_port = htons(g_tcp_proxy_port);
	if (bind(lsn_sock, (struct sockaddr *)&lsn_addr,
		sizeof(lsn_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}

	if (listen(lsn_sock, 100) < 0) {
		fprintf(stderr, "*** listen() failed: %s.\n", strerror(errno));
		exit(1);
	}

	set_nonblock(lsn_sock);
	
	printf("Transparent proxy service started on %s:%d\n",
		   inet_ntoa(lsn_addr.sin_addr), ntohs(lsn_addr.sin_port));

	/* Create epoll table. */
	if ((epfd = epoll_create(EPOLL_TABLE_SIZE)) < 0) {
		fprintf(stderr, "*** epoll_create() failed: %s\n",
				strerror(errno));
		exit(1);
	}

	/* Run in background. */
	if (is_daemon)
		do_daemonize();

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
			if (errno == EINTR)
				continue;
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
				conn = conn_of_evptr(evptr);
			}
			
			/**
			 * 1. rc == 0 means I/O completes, can be treated in current epoll cycle;
			 *    rc != 0 means I/O inprogress, cannot be treated in this cycle.
			 * 2. If conn->state == S_CLOSING, close it.
			 */
			while (rc == 0 && conn->state != S_CLOSING) {
				switch (conn->state) {
					case S_FORWARDING:
						rc = forward_data(conn, evp);
						break;
					case S_SERVER_CONNECTING:
						rc = server_connecting(conn);
						break;
					case S_SERVER_CONNECTED:
						rc = server_connected(conn);
						break;
					case S_SERVER_SENDING:
						rc = server_send_buffer(conn);
						break;
					case S_SERVER_RECEIVING:
						rc = server_recv_buffer(conn);
						break;
					case S_SENTV5METHOD:
						hsbuf(conn).dlen = 2;
						hsbuf(conn).rpos = 0;
						conn->state = S_SERVER_RECEIVING;
						conn->next_state = S_GOTV5METHOD;
						break;
					case S_GOTV5METHOD:
						rc = read_socksv5_method(conn);
						break;
					case S_SENTV5CONNECT:
						hsbuf(conn).dlen = 10;
						hsbuf(conn).rpos = 0;
						conn->state = S_SERVER_RECEIVING;
						conn->next_state = S_GOTV5CONNECT;
						break;
					case S_GOTV5CONNECT:
						rc = read_socksv5_connect(conn);
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

