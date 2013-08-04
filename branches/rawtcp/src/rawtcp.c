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

/* Define each phase during a connection. */
enum ct_state {
	CT_CLIENT_CONNECTED,
	CT_SERVER_CONNECTING,
	CT_SERVER_CONNECTED,
};

enum ev_magic {
	EV_MAGIC_LISTENER = 0x1010,
	EV_MAGIC_CLIENT = 0x2010,
	EV_MAGIC_SERVER = 0x3020,
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

	/* To know if the fds are already added to epoll. */
	bool client_in_ep;
	bool server_in_ep;
	
	unsigned req_rpos;
	unsigned rsp_rpos;
	unsigned req_dlen;
	unsigned rsp_dlen;
	char req_buf[4096];
	char rsp_buf[4096];
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
		if (!conn->req_dlen && !conn->rsp_dlen) {
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
		} else if (conn->req_dlen && !conn->rsp_dlen) {
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
		} else if (!conn->req_dlen && conn->rsp_dlen) {
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
	int epfd, nfds;
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
		int i;
		
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
			
			/* NULL evp->data.ptr indicates this socket is closed. */
			if (evptr == NULL)
				continue;
			
			if (*evptr == EV_MAGIC_LISTENER) {
				/**
				 * We passed NULL to ev.data, so NULL indicates
				 * the listening socket.
				 */
				int cli_sock;
				struct sockaddr_in cli_addr, svr_addr;
				socklen_t cli_alen = sizeof(cli_addr);
				struct proxy_conn *conn;
				
				do {
					cli_sock = accept(lsn_sock, (struct sockaddr *)&cli_addr, &cli_alen);
					if (cli_sock < 0) {
						/* FIXME: error indicated, need to exit? */
						break;
					}
					/* Client calls in, allocate session data for it. */
					if (!(conn = alloc_proxy_conn())) {
						fprintf(stderr, "*** malloc(struct proxy_conn) error: %s\n",
								strerror(errno));
						close(cli_sock);
						break;
					}
					conn->cli_sock = cli_sock;
					
					/* Initiate the connection to server right now. */
					if ((conn->svr_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
						fprintf(stderr, "*** socket(svr_sock) error: %s\n",
								strerror(errno));
						release_proxy_conn(conn, NULL, 0);
						break;
					}
					set_nonblock(conn->svr_sock);
					/* Connect to server. */
					memset(&svr_addr, 0x0, sizeof(svr_addr));
					svr_addr.sin_family = AF_INET;
					svr_addr.sin_addr.s_addr = htonl(g_dest_ip);
					svr_addr.sin_port = htons(g_dest_port);
					if ((connect(conn->svr_sock, (struct sockaddr *)&svr_addr,
						sizeof(svr_addr))) == 0) {
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
				} while(0);
				
			} else if (*evptr == EV_MAGIC_SERVER) {
				struct proxy_conn *conn =
					container_of(evptr, struct proxy_conn, ev_server);
				int ret;
				
				switch (conn->state) {
				case CT_SERVER_CONNECTED:
					if (evp->events & EPOLLIN) {
						if ((ret = recv(conn->svr_sock, conn->rsp_buf,
							sizeof(conn->rsp_buf), 0)) <= 0) {
							release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
							break;
						}
						conn->rsp_dlen = (unsigned)ret;
					}
					if (evp->events & EPOLLOUT) {
						if ((ret = send(conn->svr_sock, conn->req_buf + conn->req_rpos,
							conn->req_dlen - conn->req_rpos, 0)) <= 0) {
							release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
							break;
						}
						conn->req_rpos += ret;
						if (conn->req_rpos >= conn->req_dlen)
							conn->req_rpos = conn->req_dlen = 0;
					}
					set_conn_epoll_fds(conn, epfd);
					break;
				case CT_SERVER_CONNECTING: {
						/* The connection has established or failed. */
						int error = 0;
						socklen_t errlen = sizeof(error);
						
						if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR,
							&error, &errlen) == 0) {
							/* Connected, prepare for data forwarding. */
							if (error == 0) {
								conn->state = CT_SERVER_CONNECTED;
								set_conn_epoll_fds(conn, epfd);
							} else {
								fprintf(stderr, "*** Connection failed: %s\n", strerror(error));
								release_proxy_conn(conn, NULL, 0);
								break;
							}
						} else {
							fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
							release_proxy_conn(conn, NULL, 0);
							break;
						}
					}
					break;
				}
			} else if (*evptr == EV_MAGIC_CLIENT) {
				struct proxy_conn *conn =
					container_of(evptr, struct proxy_conn, ev_client);
				int ret;
				
				do {
					if (evp->events & EPOLLIN) {
						if ((ret = recv(conn->cli_sock, conn->req_buf,
							sizeof(conn->req_buf), 0)) <= 0) {
							release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
							break;
						}
						conn->req_dlen = (unsigned)ret;
					}
					if (evp->events & EPOLLOUT) {
						if ((ret = send(conn->cli_sock, conn->rsp_buf + conn->rsp_rpos,
							conn->rsp_dlen - conn->rsp_rpos, 0)) <= 0) {
							release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
							break;
						}
						conn->rsp_rpos += ret;
						if (conn->rsp_rpos >= conn->rsp_dlen)
							conn->rsp_rpos = conn->rsp_dlen = 0;
					}
					set_conn_epoll_fds(conn, epfd);
				} while(0);
				
			} else {
				fprintf(stderr, "*** [%s:%d] Bug: Undefined epoll event: %d.\n",
						__FUNCTION__, __LINE__, *evptr);
				abort();
			}
		} /* for (i = 0; i < nfds; i++) ... */
		
	}
	
	return 0;
}

