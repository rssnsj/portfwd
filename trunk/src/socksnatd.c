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
#include <sys/resource.h>
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

static unsigned int   g_tcp_proxy_ip   = 0;
static unsigned short g_tcp_proxy_port = 7070;

static unsigned int   g_socks_svr_ip   = 0x7f000001;  /* 127.0.0.1 */
static unsigned short g_socks_svr_port = 1080;
static int            g_socks_version  = 5;

static int            g_recv_timeout   = 10; 
static bool           g_enable_socks   = true;

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


#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

/**
 * x_recv_n - wrapper of 'recv', wait until the specified
 *  length of data was received.
 */
static int x_recv_n(int sockfd, void *buff, int len, int flags,
					int timeo_sec)
{
	char *buf = (char *)buff;
	fd_set rset;
	int ret;
	int rlen;
	struct timeval tv;

	for (rlen = 0; rlen < len; ) {
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		if (timeo_sec) {
			tv.tv_sec = timeo_sec;
			tv.tv_usec = 0;
			ret = select(sockfd + 1, &rset, NULL, NULL, &tv);
		} else {
			ret = select(sockfd + 1, &rset, NULL, NULL, NULL);
		}
		if (ret < 0) {
			return -1;
		} else if (ret == 0) {
			return -1;
		}
		if (FD_ISSET(sockfd, &rset)) {
			ret = recv(sockfd, buf + rlen, len - rlen, flags);
			if (ret <= 0)
				return -1;
			rlen += ret;
		}
	}
	return rlen;
}

/**
 * x_send_n - wrapper of 'send'.
 */
static int x_send_n(int sockfd, void *buff, int len, int flags)
{
	return send(sockfd, (const char *)buff, len, flags);
}


/**
 * socks_connect - connect to real server over SOCKS proxy.
 * parameters:
 *  @sfd: socket descriptor
 *  @svr_addr: IPv4 address of real server
 *  @svr_alen: address length
 * return value: compatible with 'connect()'.
 */
static int socks_connect(int sfd, const struct sockaddr *svr_addr,
						 socklen_t svr_alen)
{
	struct sockaddr_in ss_svr_addr;
	const struct sockaddr_in *svr_sa =
			(const struct sockaddr_in *)svr_addr;
	unsigned char buf[1024];
	int ret;
	
	/* We only support IPv4, refuse other protocol types. */
	if (svr_sa->sin_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}
	
	/* Connect to SOCKS server. */
	memset(&ss_svr_addr, 0x0, sizeof(ss_svr_addr));
	ss_svr_addr.sin_family = AF_INET;
	ss_svr_addr.sin_addr.s_addr = htonl(g_socks_svr_ip);
	ss_svr_addr.sin_port = htons(g_socks_svr_port);
	
	ret = connect(sfd, (struct sockaddr *)&ss_svr_addr, sizeof(ss_svr_addr));
	if (ret < 0) {
		return ret;
	}
	
	if (g_socks_version == 5) {
		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		if (x_send_n(sfd, buf, 3, 0) != 3) {
			fprintf(stderr, "*** [%s:%d] x_send_n() failed.\n",
					__FUNCTION__, __LINE__);
			errno = ECONNREFUSED;
			return -1;
		}
		/* Receive and check the response. */
		if (x_recv_n(sfd, buf, 2, 0, g_recv_timeout) != 2) {
			fprintf(stderr, "*** [%s:%d] x_recv_n() failed.\n",
					__FUNCTION__, __LINE__);
		}
		if (buf[1] == SOCKS_NOMETHOD) {
			fprintf(stderr, "*** Authentication method negotiation failed.\n");
			errno = ECONNREFUSED;
			return -1;
		}
		
		/* Conduct the 'connect' request. */
		buf[0] = SOCKS_V5;
		buf[1] = SOCKS_CONNECT;
		buf[2] = 0;
		buf[3] = SOCKS_IPV4;
		memcpy(buf + 4, &svr_sa->sin_addr, 4);
		memcpy(buf + 8, &svr_sa->sin_port, 2);
		/* FIXME: data length is 10. */
		if (x_send_n(sfd, buf, 10, 0) != 10) {
			//fprintf(stderr, "*** [%s:%d] x_send_n() failed.\n",
			//		__FUNCTION__, __LINE__);
			errno = ECONNREFUSED;
			return -1;
		}
		if (x_recv_n(sfd, buf, 4, 0, g_recv_timeout) != 4) {
			//fprintf(stderr, "*** [%s:%d] x_recv_n() failed.\n",
			//		__FUNCTION__, __LINE__);
			errno = ECONNREFUSED;
			return -1;
		}
		if (buf[1] != 0) {
			fprintf(stderr, "*** Connection failed, SOCKS error %d.\n", buf[1]);
			errno = ECONNREFUSED;
			return -1;
		}
		switch (buf[3]) {
		case SOCKS_IPV4:
			if (x_recv_n(sfd, buf + 4, 6, 0, g_recv_timeout) != 6) {
				errno = ECONNREFUSED;
				return -1;
			}
			break;
		case SOCKS_IPV6:
			if (x_recv_n(sfd, buf + 4, 18, 0, g_recv_timeout) != 6) {
				errno = ECONNREFUSED;
				return -1;
			}
			break;
		default:
			fprintf(stderr, "*** Unsupported address type '%d' from server.\n", buf[3]);
			errno = ECONNREFUSED;
			return -1;
		}
	} else if (g_socks_version == 4) {
		
	} else {
		fprintf(stderr, "*** Unsupported SOCKS version '%d'.\n", g_socks_version);
		errno = EINVAL;
		return -1;
	}
	
	/* OK, now the connection is ready for send() & recv(). */
	return 0;
}


static void *conn_thread(void *arg)
{
	int cli_sock = (int)(long)arg;
	int svr_sock;
	struct sockaddr_in loc_addr, cli_addr, svr_addr;
	socklen_t loc_alen = sizeof(loc_addr),
			  cli_alen = sizeof(cli_addr);
	struct ct_query_req ct_req;
	fd_set rset, wset;
	int maxfd;
	char req_buf[1024 * 4], rsp_buf[1024 * 4];
	const size_t req_buf_sz = sizeof(req_buf),
				 rsp_buf_sz = sizeof(rsp_buf);
	size_t req_dlen = 0, rsp_dlen = 0,
		   req_rpos = 0, rsp_rpos = 0;
	/* dotted addresses for displaying */
	char s_src_addr[20], s_dst_addr[20];
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

	strcpy(s_src_addr, inet_ntoa(cli_addr.sin_addr));
	strcpy(s_dst_addr, inet_ntoa(*(struct in_addr *)&ct_req.orig.dip));

	printf("-- Client %s:%d entered, to %s:%d.\n",
		s_src_addr, ntohs(cli_addr.sin_port),
		s_dst_addr, ntohs(ct_req.orig.dport));

	/*
	 * Drop connections whose original target address is same
	 *  as the translated one.
	 */
	if (ct_req.dnated.dip == ct_req.orig.dip &&
		ct_req.dnated.dport == ct_req.orig.dport) {
		fprintf(stderr, "*** The requested address may cause loop, drop it.\n");
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

	if (g_enable_socks) {
		ret = socks_connect(svr_sock, (struct sockaddr *)&svr_addr,
							sizeof(svr_addr));
	} else {
		ret = connect(svr_sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr));
	}
	if ( ret < 0) {
		fprintf(stderr, "*** Connection to '%s:%d' failed: %s.\n",
				inet_ntoa(svr_addr.sin_addr), ntohs(svr_addr.sin_port),
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
	printf("IP-to-SOCKS transforming gateway service.\n");
	printf("Usage:\n");
	printf("  %s [-s socks_ip:socks_port] [-d] [-z]\n", argv[0]);
	printf("Options:\n");
	printf("  -s socks_ip:socks_port      -- specify SOCKS server address, default: 127.0.0.1:7070\n");
	printf("  -d                          -- run at background\n");
	printf("  -z                          -- do not use SOCKS, just proxy\n");
}

int main(int argc, char *argv[])
{
	int lsn_sock, cli_sock;
	struct sockaddr_in lsn_addr;
	int b_reuse = 1;
	int opt;
	bool is_daemon = false;
	struct rlimit rlim;

	while ((opt = getopt(argc, argv, "s:dzh")) != -1) {
		switch (opt) {
		case 's': {
			char s_socks_host[40];
			int socks_port;
			if (sscanf(optarg, "%39[^:]:%d", s_socks_host,
				&socks_port) != 2) {
				fprintf(stderr, "*** Invalid argument for '-s'.\n\n");
				show_help(argc, argv);
				exit(1);
			}
			g_socks_svr_ip = ntohl(inet_addr(s_socks_host));
			g_socks_svr_port = socks_port;
			break;
		}
		case 'd':
			is_daemon = true;
			break;
		case 'z':
			g_enable_socks = false;
			break;
		case 'h':
			show_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	/* Enlarge the file descriptor limination. */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		if (rlim.rlim_max < 20480) {
			rlim.rlim_cur = rlim.rlim_max = 20480;
			setrlimit(RLIMIT_NOFILE, &rlim);
		}
	}
	
	g_ct_fd = open("/proc/socksnat_conntrack", O_RDONLY);
	if (g_ct_fd < 0) {
		fprintf(stderr, "*** Failed to open '/proc/socksnat_conntrack': %s.\n",
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

