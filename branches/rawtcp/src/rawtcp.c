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

typedef int bool;
#define true  1
#define false 0

static unsigned int   g_source_ip   = 0;
static unsigned short g_source_port = 0;
static unsigned int   g_dest_ip     = 0;
static unsigned short g_dest_port   = 0;

static int do_daemonize(void)
{
	int ret;
	
	if ((ret = fork()) < 0) {
		fprintf(stderr, "*** fork() error: %s.", strerror(errno));
		return ret;
	} else if (ret > 0) {
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

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

/* Statues indicators of proxy sessions. */
enum ct_state {
	CT_SERVER_CONNECTING,
	CT_SERVER_CONNECTED,
};

enum ev_magic {
	EV_MAGIC_LISTENER = 0x1010,
	EV_MAGIC_CLIENT = 0x2010,
	EV_MAGIC_SERVER = 0x3020,
};

struct buffer_info {
	unsigned rpos;
	unsigned dlen;
	char buf[4096];
};

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
	struct sockaddr_in cli_addr;
	struct sockaddr_in svr_addr;

	/* To know if the fds are already added to epoll. */
	bool client_in_ep;
	bool server_in_ep;

	/* Buffers for both direction. */
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
	conn->ev_client = EV_MAGIC_CLIENT;
	conn->ev_server = EV_MAGIC_SERVER;
	conn->state = -1;
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
	
	for (i = 0; i < pending_fds; i++) {
		ev = &pending_evs[i];
		if (ev->data.ptr == &conn->ev_client ||
			ev->data.ptr == &conn->ev_server) {
			ev->data.ptr = NULL;
			break;
		}
	}
	
	if (conn->cli_sock >= 0)
		close(conn->cli_sock);
	if (conn->svr_sock >= 0)
		close(conn->svr_sock);
	free(conn);
}

/**
 * Add or activate the epoll fds according to the status of
 *  'conn'. Different conn->state and buffer status will
 *  affect the polling behaviors.
 */
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd)
{
	struct epoll_event ev;
	
	switch(conn->state) {
		case CT_SERVER_CONNECTING:
			/* Wait for the server connection to complete. */
			ev.data.ptr = &conn->ev_server;
			ev.events = EPOLLOUT;
			if (conn->server_in_ep)
				epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev); /* FIXME: result */
			else
				epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
			conn->server_in_ep = true;
			break;
		case CT_SERVER_CONNECTED:
			/* Connection established, data forwarding in progress. */
			if (!conn->request.dlen && !conn->response.dlen) {
				ev.data.ptr = &conn->ev_client;
				ev.events = EPOLLIN;
				if (conn->client_in_ep)
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev);
				else
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &ev);
				conn->client_in_ep = true;
				
				ev.data.ptr = &conn->ev_server;
				ev.events = EPOLLIN;
				if (conn->server_in_ep)
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev);
				else
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
				conn->server_in_ep = true;
			} else if (conn->request.dlen && !conn->response.dlen) {
				ev.data.ptr = &conn->ev_server;
				ev.events = EPOLLIN | EPOLLOUT;
				if (conn->server_in_ep) {
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev);
				} else {
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
					conn->server_in_ep = true;
				}
				
				if (conn->client_in_ep) {
					epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL);
					conn->client_in_ep = false;
				}
			} else if (!conn->request.dlen && conn->response.dlen) {
				ev.data.ptr = &conn->ev_client;
				ev.events = EPOLLIN | EPOLLOUT;
				if (conn->client_in_ep) {
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev);
				} else {
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &ev);
					conn->client_in_ep = true;
				}
				
				if (conn->server_in_ep) {
					epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
					conn->server_in_ep = false;
				}
			} else {
				ev.data.ptr = &conn->ev_client;
				ev.events = EPOLLOUT;
				if (conn->client_in_ep)
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev);
				else
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &ev);
				conn->client_in_ep = true;
				
				ev.data.ptr = &conn->ev_server;
				ev.events = EPOLLOUT;
				if (conn->server_in_ep)
					epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev);
				else
					epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
				conn->server_in_ep = true;
			}
			break;
	}
}

static void do_new_client_in(int lsn_sock, int epfd)
{
	int cli_sock;
	struct sockaddr_in cli_addr;
	socklen_t cli_alen = sizeof(cli_addr);
	struct proxy_conn *conn;

	cli_sock = accept(lsn_sock, (struct sockaddr *)&cli_addr, &cli_alen);
	if (cli_sock < 0) {
		/* FIXME: error indicated, need to exit? */
		fprintf(stderr, "*** accept() failed: %s\n", strerror(errno));
		return;
	}
	/* Client calls in, allocate session data for it. */
	if (!(conn = alloc_proxy_conn())) {
		fprintf(stderr, "*** malloc(struct proxy_conn) error: %s\n",
				strerror(errno));
		close(cli_sock);
		return;
	}
	conn->cli_sock = cli_sock;
	conn->cli_addr = cli_addr;
	
	/* Initiate the connection to server right now. */
	if ((conn->svr_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "*** socket(svr_sock) error: %s\n",
				strerror(errno));
		release_proxy_conn(conn, NULL, 0);
		return;
	}
	set_nonblock(conn->svr_sock);
	
	/* Connect to server. */
	memset(&conn->svr_addr, 0x0, sizeof(conn->svr_addr));
	conn->svr_addr.sin_family = AF_INET;
	conn->svr_addr.sin_addr.s_addr = htonl(g_dest_ip);
	conn->svr_addr.sin_port = htons(g_dest_port);

	printf("-- Client %s:%d calls in\n", inet_ntoa(conn->cli_addr.sin_addr),
		ntohs(conn->cli_addr.sin_port));
	
	if ((connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
		sizeof(conn->svr_addr))) == 0) {
		/* Connected, prepare for data forwarding. */
		conn->state = CT_SERVER_CONNECTED;
		set_conn_epoll_fds(conn, epfd);
	} else if (errno == EINPROGRESS) {
		/**
		 * OK, the request does not fail right now, so wait
		 *  for it completes.
		 */
		conn->state = CT_SERVER_CONNECTING;
		set_conn_epoll_fds(conn, epfd);
	} else {
		/* Error occurs, drop the session. */
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		release_proxy_conn(conn, NULL, 0);
	}
}

static void do_server_connected(struct proxy_conn *conn, int epfd)
{
	/* The connection has established or failed. */
	int err = 0;
	socklen_t errlen = sizeof(err);
	
	if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err,
		&errlen) == 0) {
		/* Connected, prepare for data forwarding. */
		if (err == 0) {
			conn->state = CT_SERVER_CONNECTED;
			set_conn_epoll_fds(conn, epfd);
		} else {
			fprintf(stderr, "*** Connection failed: %s\n", strerror(err));
			release_proxy_conn(conn, NULL, 0);
		}
	} else {
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		release_proxy_conn(conn, NULL, 0);
	}
}

static void do_forward_data(struct proxy_conn *conn, int epfd,
		struct epoll_event *ev, struct epoll_event *pending_evs,
		int pending_fds)
{
	int *evptr = (int *)ev->data.ptr;
	struct buffer_info *rxb, *txb;
	int efd, ret;
	
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
		if ((ret = recv(efd , rxb->buf, sizeof(rxb->buf), 0)) <= 0) {
			release_proxy_conn(conn, pending_evs, pending_fds);
			printf("-- Client %s:%d exits\n", inet_ntoa(conn->cli_addr.sin_addr),
				ntohs(conn->cli_addr.sin_port));
			return;
		}
		rxb->dlen = (unsigned)ret;
	}
	
	if (ev->events & EPOLLOUT) {
		if ((ret = send(efd, txb->buf + txb->rpos,
			txb->dlen - txb->rpos, 0)) <= 0) {
			release_proxy_conn(conn, pending_evs, pending_fds);
			printf("-- Client %s:%d exits\n", inet_ntoa(conn->cli_addr.sin_addr),
				ntohs(conn->cli_addr.sin_port));
			return;
		}
		txb->rpos += ret;
		if (txb->rpos >= txb->dlen)
			txb->rpos = txb->dlen = 0;
	}
	
	set_conn_epoll_fds(conn, epfd);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("Userspace TCP proxy.\n");
	printf("Usage:\n");
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d]\n", argv[0]);
	printf("Options:\n");
	printf("  -d                run in background\n");
}

int main(int argc, char *argv[])
{
	int lsn_sock;
	int ev_magic_listener = EV_MAGIC_LISTENER;
	struct sockaddr_in lsn_addr;
	int b_reuse = 1;
	int opt;
	bool is_daemon = false;
	char s_lsn_ip[20], s_dst_ip[20];
	int lsn_port, dst_port;
	int epfd;
#define EPOLL_TABLE_SIZE 2048
#define MAX_POLL_EVENTS 100
	struct epoll_event ev, events[MAX_POLL_EVENTS];
	size_t events_sz = MAX_POLL_EVENTS;

	while ((opt = getopt(argc, argv, "dh")) != -1) {
		switch (opt) {
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

	if (optind > argc - 2) {
		show_help(argc, argv);
		exit(1);
	}

	/* Parse source address. */
	if (sscanf(argv[optind], "%19[^:]:%d", s_lsn_ip,
		&lsn_port) == 2) {
		g_source_ip = ntohl(inet_addr(s_lsn_ip));
		g_source_port = lsn_port;
	} else if (sscanf(argv[optind], "%d", &lsn_port) == 1) {
		g_source_port = (unsigned short)lsn_port;
	} else {
		fprintf(stderr, "*** Invalid source address '%s'.\n",
				argv[optind]);
		show_help(argc, argv);
		exit(1);
	}
	optind++;

	/* Parse destination address. */
	if (sscanf(argv[optind], "%19[^:]:%d", s_dst_ip,
		&dst_port) != 2) {
		fprintf(stderr, "*** Invalid destination address '%s'.\n",
				argv[optind]);
		show_help(argc, argv);
		exit(1);
	}
	g_dest_ip = ntohl(inet_addr(s_dst_ip));
	g_dest_port = (unsigned short)dst_port;

	/* Enlarge the file descriptor limination. */
	//if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
	//	if (rlim.rlim_max < 20480) {
	//		rlim.rlim_cur = rlim.rlim_max = 20480;
	//		setrlimit(RLIMIT_NOFILE, &rlim);
	//	}
	//}

	lsn_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.", strerror(errno));
		exit(1);
	}
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_reuse, sizeof(b_reuse));

	memset(&lsn_addr, 0x0, sizeof(lsn_addr));
	lsn_addr.sin_family = AF_INET;
	lsn_addr.sin_addr.s_addr = htonl(g_source_ip);
	lsn_addr.sin_port = htons(g_source_port);

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
	
	printf("TCP proxy %s:%d -> %s:%d started, \n",
		   s_lsn_ip, lsn_port, s_dst_ip, dst_port);

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
	 * Ignore PIPE signal, which is triggered by 'send'
	 *  and will cause the process exit.
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
			
			/* NULL evp->data.ptr indicates this socket is closed. */
			if (evptr == NULL)
				continue;
			
			if (*evptr == EV_MAGIC_LISTENER) {
				/* A new connection calls in. */
				do_new_client_in(lsn_sock, epfd);
				continue;
			}
			
			if (*evptr == EV_MAGIC_CLIENT) {
				conn = container_of(evptr, struct proxy_conn, ev_client);
			} else if (*evptr == EV_MAGIC_SERVER) {
				conn = container_of(evptr, struct proxy_conn, ev_server);
			} else {
				assert(*evptr == EV_MAGIC_CLIENT || *evptr == EV_MAGIC_SERVER);
			}
			
			switch (conn->state) {
				case CT_SERVER_CONNECTING:
					do_server_connected(conn, epfd);
					break;
				case CT_SERVER_CONNECTED:
					do_forward_data(conn, epfd, evp, events + i + 1, nfds - 1 - i);
					break;
				default:
					fprintf(stderr, "*** Undefined state: %d\n", conn->state);
					release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
					break;
			}
		}
	}
	
	return 0;
}

