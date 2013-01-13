#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CT_GET_ORIG_BY_DNATED _IOR('I', 'G', int)

typedef u_int32_t __be32;
typedef u_int16_t __be16;
typedef u_int8_t  __u8;
typedef int bool;
#define true  1
#define false 0

struct ct_query_req {
	__u8   l4proto;
	struct __ct_dnated_addr {
		__be32 sip;
		__be32 dip;
		__be16 sport;
		__be16 dport;
	} dnated;
	struct __ct_orig_addr {
		__be32 sip;
		__be32 dip;
		__be16 sport;
		__be16 dport;
	} orig;
};

static const unsigned short g_tcp_proxy_port = 7070;
static const unsigned int g_tcp_proxy_ip = 0;
static int g_ct_fd = -1;

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
		umask(0);
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
	struct sockaddr_in loc_addr, cli_addr, svr_addr;
	int loc_alen = sizeof(loc_addr),
		cli_alen = sizeof(cli_addr);
	struct ct_query_req ct_req;

	fd_set rset, wset;
	int maxfd;
	char req_buf[1024 * 4], rsp_buf[1024 * 4];
	const size_t req_buf_sz = sizeof(req_buf),
				 rsp_buf_sz = sizeof(rsp_buf);
	size_t req_dlen = 0, rsp_dlen = 0,
		   req_rpos = 0, rsp_rpos = 0;
	int ret;

	/* Get current session addresses. */
	if (getsockname(cli_sock, (struct sockaddr *)&loc_addr,
		&loc_alen) < 0) {
		fprintf(stderr, "*** getsockname() failed: %s.\n",
				strerror(errno));
		goto out1;
	}
	if (getpeername(cli_sock, (struct sockaddr *)&cli_addr,
		&cli_alen) < 0) {
		fprintf(stderr, "*** getpeername() failed: %s.\n",
				strerror(errno));
		goto out1;
	}

	printf("-- Client %s:%d entered.\n",
		inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

	/* Query in kernel to get the original target IP & port. */
	memset(&ct_req, 0x0, sizeof(ct_req));
	ct_req.l4proto = IPPROTO_TCP;
	ct_req.dnated.sip = cli_addr.sin_addr.s_addr;
	ct_req.dnated.dip = loc_addr.sin_addr.s_addr;
	ct_req.dnated.sport = cli_addr.sin_port;
	ct_req.dnated.dport = loc_addr.sin_port;

	if (ioctl(g_ct_fd, CT_GET_ORIG_BY_DNATED, &ct_req) < 0) {
		fprintf(stderr, "*** Cannot find conntrack for connection: %s.\n",
				strerror(errno));
		goto out1;
	}

	/* Connect to real target address. */
	svr_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (svr_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		goto out1;
	}

	memset(&svr_addr, 0x0, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = ct_req.orig.dip;
	svr_addr.sin_port = ct_req.orig.dport;

	if (connect(svr_sock, (struct sockaddr *)&svr_addr,
		sizeof(svr_addr)) < 0) {
		fprintf(stderr, "*** Failed to connect to server '%s:%d': %s.\n",
				inet_ntoa(svr_addr.sin_addr), ntohs(svr_addr.sin_port),
				strerror(errno));
		goto out2;
	}
	
	/* Set non-blocking. */
	if (set_nonblock(cli_sock) < 0) {
		fprintf(stderr, "*** set_nonblock(cli_sock) failed: %s.");
		goto out2;
	}
	if (set_nonblock(svr_sock) < 0) {
		fprintf(stderr, "*** set_nonblock(svr_sock) failed: %s.");
		goto out2;
	}

	for (;;) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		maxfd = 0;

		if (req_dlen == 0) {
			FD_SET(cli_sock, &rset);
		} else {
			FD_SET(svr_sock, &wset);
		}

		if (rsp_dlen == 0) {
			FD_SET(svr_sock, &rset);
		} else {
			FD_SET(cli_sock, &wset);
		}

		maxfd = svr_sock > cli_sock ? svr_sock : cli_sock;

		ret = select(maxfd + 1, &rset, &wset, NULL, NULL);
		if (ret < 0) {
			break;
		} else if (ret == 0) {
			break;
		}

		if (FD_ISSET(svr_sock, &wset)) {
			if ((ret = send(svr_sock, req_buf + req_rpos, req_dlen - req_rpos, 0)) <= 0) {
				break;
			}
			req_rpos += ret;
			if (req_rpos >= req_dlen) {
				req_dlen = req_rpos = 0;
			}
		}

		if (FD_ISSET(svr_sock, &rset)) {
			if ((rsp_dlen = recv(svr_sock, rsp_buf, rsp_buf_sz, 0)) <= 0) {
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

out2:
	close(svr_sock);
out1:
	close(cli_sock);
	return NULL;
}


int main(int argc, char *argv[])
{
	int lsn_sock, cli_sock;
	struct sockaddr_in lsn_addr;
	int  b_reuse = 1;
	int opt;
	bool is_daemon = false;
	bool under_tsocks = false;

	while ((opt = getopt(argc, argv, "dz")) != -1) {
		switch (opt) {
		case 'd':
			is_daemon = true;
			break;
		case 'z':
			under_tsocks = true;
			break;
		case '?':
			exit(1);
		}
	}

	/* Program should work together with 'tsocks'. */
	if (!under_tsocks) {
		char **nargv;
		nargv = (char **)malloc((sizeof(char *) * argc + 3));
		nargv[0] = "tsocks";
		memcpy(&nargv[1], argv, sizeof(char *) * argc);
		nargv[argc + 1] = "-z";
		nargv[argc + 2] = NULL;
		execvp("tsocks", nargv);
		fprintf(stderr, "*** Failed to run 'tsocks', please "
				"check if it has been correctly installed.\n"
				"*** Error reason: %s.\n", strerror(errno));
		exit(127);
	}

	g_ct_fd = open("/proc/ip_conntrack_query", O_RDONLY);
	if (g_ct_fd < 0) {
		fprintf(stderr, "*** Failed to open 'ip_conntrack_query': %s.\n",
			strerror(errno));
		exit(1);
	}

	lsn_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (lsn_sock < 0) {
		fprintf(stderr, "*** socket() failed: %s.", strerror(errno));
		exit(1);
	}
	setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_reuse, sizeof(b_reuse));

	memset(&lsn_addr, 0x0, sizeof(lsn_addr));
	lsn_addr.sin_family = AF_INET;
	lsn_addr.sin_port = htons(g_tcp_proxy_port);
	lsn_addr.sin_addr.s_addr = htonl(0);
	if (bind(lsn_sock, (struct sockaddr *)&lsn_addr,
		sizeof(lsn_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}

	if (listen(lsn_sock, 100) < 0) {
		fprintf(stderr, "*** listen() failed: %s.\n", strerror(errno));
		exit(1);
	}

	printf("SOCKS Proxy NAT started, listening %s:%d.\n",
			inet_ntoa(lsn_addr.sin_addr),
			ntohs(lsn_addr.sin_port));
	
	/* Work as a daemon process. */
	if (is_daemon)
		do_daemonize();

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
		if (pthread_create(&conn_pth, NULL, conn_thread, (void *)(long)cli_sock) == 0)
			pthread_detach(conn_pth);
	}

	return 0;
}

