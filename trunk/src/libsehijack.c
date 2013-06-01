#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>

#include "utils.h"

/* Original system functions. */

static int (*real_connect)(int sockfd, const struct sockaddr *serv_addr,
						   socklen_t addrlen);
static int (*real_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static ssize_t (*real_send)(int s, const void *buf, size_t len, int flags);
static ssize_t (*real_recv)(int s, void *buf, size_t len, int flags);
static ssize_t (*real_write)(int fd, const void *buf, size_t count);
static ssize_t (*real_read)(int fd, void *buf, size_t count);
static int (*real_close)(int fd);

/**
 * Each socket will be checked with this address to mark
 *  if it needs to be hijacketed.
 *  This address is got from environment variable:
 *  LIBSEHIJACK_ADDR=<socks_ip>:<socks_port>
 */
static u32 hijacked_ip = 0;
static u16 hijacked_port = 0;

/* Socket hijacking status list. */
#define MAX_FDS_STATUS  (1024 * 64)
static char fds_status[MAX_FDS_STATUS];
enum __hijack_status {
	FD_STATUS_NONE,
	FD_STATUS_HIJACKED,
};
static inline bool is_fd_hijacked(int fd)
{
	return (fd < MAX_FDS_STATUS &&
		fds_status[fd] == FD_STATUS_HIJACKED);
}

static inline void byte_enc(void *buf, size_t len)
{
	unsigned char *ebuf = (unsigned char *)buf;
	for (; len; ebuf--) {
		*(ebuf++) ^= 0xaf;
		len--;
	}
}

static inline void byte_dec(void *buf, size_t len)
{
	unsigned char *ebuf = (unsigned char *)buf;
	for (; len; ebuf--) {
		*(ebuf++) ^= 0xaf;
		len--;
	}
}

int connect(int sockfd, const struct sockaddr *serv_addr,
			socklen_t addrlen)
{
	int ret;

	ret = real_connect(sockfd, serv_addr, addrlen);
	/* Only when real 'connect' succeeds we check the address */
	if (ret != 0)
		return ret;

	if (sockfd >= MAX_FDS_STATUS) {
		fprintf(stderr, "*** libsehijack.so: sockfd(%d) exceeds "
				"our limitation(%d), won't track it.\n",
				sockfd, MAX_FDS_STATUS);
		return ret;
	}

	/* Check and select a hijacking type */
	if (serv_addr->sa_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)serv_addr;
		if (ntohl(addr->sin_addr.s_addr) == hijacked_ip &&
			ntohs(addr->sin_port) == hijacked_port) {
			fds_status[sockfd] = FD_STATUS_HIJACKED;
		} else {
			fds_status[sockfd] = FD_STATUS_NONE;
		}
	} else {
		fds_status[sockfd] = FD_STATUS_NONE;
	}

	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int newfd;

	newfd = real_accept(sockfd, addr, addrlen);
	if (newfd < 0)
		return newfd;

	if (sockfd >= MAX_FDS_STATUS) {
		fprintf(stderr, "*** libsehijack.so: sockfd(%d) exceeds "
				"our limitation(%d), won't track it.\n",
				sockfd, MAX_FDS_STATUS);
		return newfd;
	}

	/* Check and select a hijacking type */
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in myaddr;
		socklen_t myaddr_len = sizeof(myaddr);

		if (getsockname(newfd, (struct sockaddr *)&myaddr, &myaddr_len) < 0) {
			fprintf(stderr, "*** libsehijack.so: getsockname() failed: %s.\n",
					strerror(errno));
			fds_status[newfd] = FD_STATUS_NONE;
			return newfd;
		}
		if (ntohl(myaddr.sin_addr.s_addr) == hijacked_ip &&
			ntohs(myaddr.sin_port) == hijacked_port) {
			fds_status[newfd] = FD_STATUS_HIJACKED;
		} else {
			fds_status[newfd] = FD_STATUS_NONE;
		}
	} else {
		fds_status[newfd] = FD_STATUS_NONE;
	}

	return newfd;
}

int close(int fd)
{
	if (fd < MAX_FDS_STATUS)
		fds_status[fd] = FD_STATUS_NONE;
	return real_close(fd);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	if (is_fd_hijacked(fd)) {
		char *ebuf;
		ssize_t ret;

		if ((ebuf = (char *)malloc(len)) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(ebuf, buf, len);
		byte_enc(ebuf, len);
		ret = real_send(fd, ebuf, len, flags);
		free(ebuf);
		return ret;

	} else {
		return real_send(fd, buf, len, flags);
	}
}

ssize_t write(int fd, const void *buf, size_t len)
{
	if (is_fd_hijacked(fd)) {
		char *ebuf;
		ssize_t ret;

		if ((ebuf = (char *)malloc(len)) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(ebuf, buf, len);
		byte_enc(ebuf, len);
		ret = real_write(fd, ebuf, len);
		free(ebuf);
		return ret;

	} else {
		return real_write(fd, buf, len);
	}
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	if (is_fd_hijacked(fd)) {
		ssize_t ret;
		ret = real_recv(fd, buf, len, flags);
		if (ret > 0) {
			byte_dec(buf, ret);
		}
		return ret;
	} else {
		return real_recv(fd, buf, len, flags);
	}
}

ssize_t read(int fd, void *buf, size_t len)
{
	if (is_fd_hijacked(fd)) {
		ssize_t ret;
		ret = real_read(fd, buf, len);
		if (ret > 0) {
			byte_dec(buf, ret);
		}
		return ret;
	} else {
		return real_read(fd, buf, len);
	}
}

void _init(void) {
	const char *hijack_env;
	int i;

	real_connect = (void *)dlsym(RTLD_NEXT, "connect");
	real_accept = (void *)dlsym(RTLD_NEXT, "accept");
	real_close = (void *)dlsym(RTLD_NEXT, "close");
	real_send = (void *)dlsym(RTLD_NEXT, "send");
	real_recv = (void *)dlsym(RTLD_NEXT, "recv");
	real_write = (void *)dlsym(RTLD_NEXT, "write");
	real_read = (void *)dlsym(RTLD_NEXT, "read");

	for (i = 0; i < MAX_FDS_STATUS; i++)
		fds_status[i] = FD_STATUS_NONE;

	if ((hijack_env = getenv("LIBSEHIJACK_ADDR"))) {
		char s_ip[20];
		int port;

		if (sscanf(hijack_env, "%19[^:]:%d", s_ip, &port) == 2) {
			hijacked_ip = ipv4_stohl(s_ip);
			hijacked_port = (u16)port;
		} else {
			fprintf(stderr, "*** libsehijack.so: Invalid format "
					"LIBSEHIJACK_ADDR=%s\n", hijack_env);
		}
		printf("libsehijack.so: Connections with %s:%d will be encoded.\n",
			   s_ip, port);
	}
}
