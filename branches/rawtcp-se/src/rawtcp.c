#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int bool;
#define true  1
#define false 0

/* Functions for encrypted transmission. */

static unsigned char enc_factor = 0xaf; /* one-byte passcode. */

static inline void bytes_enc(void *buf, size_t len)
{
	unsigned char *ebuf = (unsigned char *)buf;
	for (; len; len--)
		*(ebuf++) ^= enc_factor;
}
static inline void bytes_dec(void *buf, size_t len)
{
	unsigned char *ebuf = (unsigned char *)buf;
	for (; len; len--)
		*(ebuf++) ^= enc_factor;
}

static ssize_t se_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t ret;
	ret = recv(fd, buf, len, flags);
	if (ret > 0)
		bytes_dec(buf, ret);
	return ret;
}
ssize_t se_send_rwbuf(int fd, void *buf, size_t len, int flags)
{
	bytes_enc(buf, len);
	return send(fd, buf, len, flags);
}
/* ****************************************** */

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

static void *conn_thread(void *arg)
{
	int cli_sock = (int)(long)arg;
	int svr_sock;
	struct sockaddr_in cli_addr, dst_addr;
	socklen_t cli_alen = sizeof(cli_addr);
	fd_set rset, wset;
	int maxfd;
	char req_buf[1024 * 4], rsp_buf[1024 * 4];
	const size_t req_buf_sz = sizeof(req_buf),
				 rsp_buf_sz = sizeof(rsp_buf);
	size_t req_dlen = 0, rsp_dlen = 0,
		   req_rpos = 0, rsp_rpos = 0;
	int ret;

	/* Get current session addresses. */
	if (getpeername(cli_sock, (struct sockaddr *)&cli_addr,
		&cli_alen) < 0) {
		fprintf(stderr, "*** getpeername() failed: %s.\n",
				strerror(errno));
		goto out1;
	}
	printf("-- Client %s:%d entered.\n",
		   inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

	/* Connect to real target address. */
	svr_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (svr_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		goto out1;
	}

	memset(&dst_addr, 0x0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = htonl(g_dest_ip);
	dst_addr.sin_port = htons(g_dest_port);

	ret = connect(svr_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	if ( ret < 0) {
		fprintf(stderr, "*** Connection to '%s:%d' failed: %s.\n",
				inet_ntoa(dst_addr.sin_addr), ntohs(dst_addr.sin_port),
				strerror(errno));
		goto out2;
	}

	/* Set non-blocking. */
	if (set_nonblock(cli_sock) < 0) {
		fprintf(stderr, "*** set_nonblock(cli_sock) failed: %s.",
				strerror(errno));
		goto out2;
	}
	if (set_nonblock(svr_sock) < 0) {
		fprintf(stderr, "*** set_nonblock(svr_sock) failed: %s.",
				strerror(errno));
		goto out2;
	}

	for (;;) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		maxfd = 0;

		if (!req_dlen && !rsp_dlen) {
			FD_SET(cli_sock, &rset);
			FD_SET(svr_sock, &rset);
			maxfd = svr_sock > cli_sock ? svr_sock : cli_sock;
		} else if (req_dlen && !rsp_dlen) {
			FD_SET(svr_sock, &rset);
			FD_SET(svr_sock, &wset);
			maxfd = svr_sock;
		} else if (!req_dlen && rsp_dlen) {
			FD_SET(cli_sock, &rset);
			FD_SET(cli_sock, &wset);
			maxfd = cli_sock;
		} else {
			FD_SET(cli_sock, &wset);
			FD_SET(svr_sock, &wset);
			maxfd = svr_sock > cli_sock ? svr_sock : cli_sock;
		}

		ret = select(maxfd + 1, &rset, &wset, NULL, NULL);
		if (ret < 0) {
			break;
		} else if (ret == 0) {
			break;
		}

		if (FD_ISSET(svr_sock, &wset)) {
			if ((ret = se_send_rwbuf(svr_sock, req_buf + req_rpos, req_dlen - req_rpos, 0)) <= 0) {
				break;
			}
			req_rpos += ret;
			if (req_rpos >= req_dlen) {
				req_dlen = req_rpos = 0;
			}
		}

		if (FD_ISSET(svr_sock, &rset)) {
			if ((rsp_dlen = se_recv(svr_sock, rsp_buf, rsp_buf_sz, 0)) <= 0) {
				break;
			}
		}

		if (FD_ISSET(cli_sock, &rset)) {
			if ((req_dlen = recv(cli_sock, req_buf, req_buf_sz, 0)) <= 0) {
				break;
			}
		}

		if (FD_ISSET(cli_sock, &wset)) {
			if ((ret = send(cli_sock, rsp_buf + rsp_rpos, rsp_dlen - rsp_rpos, 0)) <= 0) {
				break;
			}
			rsp_rpos += ret;
			if (rsp_rpos >= req_dlen) {
				rsp_dlen = rsp_rpos = 0;
			}
		}
	}

	printf("-- Client %s:%d exited.\n",
		inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

out2:
	close(svr_sock);
out1:
	close(cli_sock);
	return NULL;
}

static void show_help(int argc, char *argv[])
{
	printf("TCP proxy with simple encryption.\n");
	printf("Usage:\n");
	printf("  %s <local_ip:local_port> <dest_ip:dest_port> [-d]\n", argv[0]);
	printf("Options:\n");
	printf("  -d                run in background\n");
}

int main(int argc, char *argv[])
{
	int lsn_sock, cli_sock;
	struct sockaddr_in lsn_addr;
	int b_reuse = 1;
	int opt;
	bool is_daemon = false;
	char s_lsn_ip[20], s_dst_ip[20];
	int lsn_port, dst_port;

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

	if (optind >= argc) {
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

	printf("TCP proxy %s:%d -> %s:%d started, server connection encrypted (cypher:0x%02x)\n",
		   s_lsn_ip, lsn_port, s_dst_ip, dst_port, enc_factor);

	/* Run in background. */
	if (is_daemon)
		do_daemonize();

	/**
	 * Ignore PIPE signal, which is triggered by 'send'
	 *  and will cause the process exit.
	 */
	signal(SIGPIPE, SIG_IGN);

	/* Loop for incoming proxy connections. */
	for (;;) {
		struct sockaddr_in cli_addr;
		socklen_t cli_alen = sizeof(cli_addr);
		pthread_t conn_pth;

		cli_sock = accept(lsn_sock, (struct sockaddr *)&cli_addr,
						  &cli_alen);
		if (cli_sock < 0)
			continue;

		/* Process the connection in new thread. */
		if (pthread_create(&conn_pth, NULL, conn_thread,
			(void *)(long)cli_sock) == 0)
			pthread_detach(conn_pth);
	}

	return 0;
}

