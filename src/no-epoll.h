#ifndef __NO_EPOLL_H
#define __NO_EPOLL_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <time.h>

/* NOTICE: To make sure being included once in a single program. */
int build_error_on_linking = 0;

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events; /* epoll events */
	epoll_data_t data; /* user data variable */
};


#define EPOLLIN  0x001
#define EPOLLOUT 0x004

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

struct pseudo_epoll_handle {
	int allocated;
	fd_set rset;
	fd_set wset;
	int max_fd;
	struct epoll_event events[FD_SETSIZE];
};

#define PSEUDO_EPOLL_LIST_SIZE  4
static struct pseudo_epoll_handle pseudo_epolls[PSEUDO_EPOLL_LIST_SIZE];

static int epoll_create(int size)
{
	int i;

	for (i = 0; i < PSEUDO_EPOLL_LIST_SIZE; i++) {
		struct pseudo_epoll_handle *eh = &pseudo_epolls[i];
		if (!eh->allocated) {
			eh->allocated = 1;
			FD_ZERO(&eh->rset);
			FD_ZERO(&eh->wset);
			eh->max_fd = -1;
			return i;
		}
	}

	return -EINVAL;
}

static int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	struct pseudo_epoll_handle *eh = &pseudo_epolls[epfd];

	assert(fd < FD_SETSIZE);

	switch (op) {
	case EPOLL_CTL_ADD:
	case EPOLL_CTL_MOD:
		assert((event->events & ~(EPOLLIN | EPOLLOUT)) == 0);
		FD_CLR(fd, &eh->rset);
		FD_CLR(fd, &eh->wset);
		if ((event->events & EPOLLIN))
			FD_SET(fd, &eh->rset);
		if ((event->events & EPOLLOUT))
			FD_SET(fd, &eh->wset);
		if (event->events && fd > eh->max_fd)
			eh->max_fd = fd;
		eh->events[fd] = *event;
		break;
	case EPOLL_CTL_DEL:
		FD_CLR(fd, &eh->rset);
		FD_CLR(fd, &eh->wset);
		if (eh->max_fd == fd) {
			while (!FD_ISSET(eh->max_fd, &eh->rset) && ! FD_ISSET(eh->max_fd, &eh->wset))
				eh->max_fd--;
		}
		break;
	default:
		fprintf(stderr, "*** Unsupported operation: %d\n", op);
		abort();
	}

	return 0;
}

static int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	struct pseudo_epoll_handle *eh = &pseudo_epolls[epfd];
	fd_set rset, wset;
	struct timeval timeo;
	int nr_events = 0, nfds, fd;

	/* Remove closed fds from the poll list. */
	for (fd = 0; fd <= eh->max_fd; fd++) {
		if (fcntl(fd, F_GETFL) < 0 && errno == EBADF) {
			FD_CLR(fd, &eh->rset);
			FD_CLR(fd, &eh->wset);
			if (eh->max_fd == fd) {
				while (!FD_ISSET(eh->max_fd, &eh->rset) && ! FD_ISSET(eh->max_fd, &eh->wset))
					eh->max_fd--;
			}
		}
	}

	rset = eh->rset;
	wset = eh->wset;

	if (timeout >= 0) {
		timeo.tv_sec = timeout / 1000;
		timeo.tv_usec = (timeout % 1000) * 1000;
		nfds = select(eh->max_fd + 1, &rset, &wset, NULL, &timeo);
	} else {
		nfds = select(eh->max_fd + 1, &rset, &wset, NULL, NULL);
	}

	if (nfds <= 0)
		return nfds;

	/* Copy all popped events to result. */
	for (fd = 0; fd <= eh->max_fd; fd++) {
		uint32_t evs = 0;
		if (FD_ISSET(fd, &rset))
			evs |= EPOLLIN;
		if (FD_ISSET(fd, &wset))
			evs |= EPOLLOUT;
		if (evs) {
			events[nr_events] = eh->events[fd];
			events[nr_events].events = evs;
			if (++nr_events >= maxevents)
				break;
		}
	}

	return nr_events;
}

#endif /* __NO_EPOLL_H */
