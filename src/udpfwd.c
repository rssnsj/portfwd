#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#ifdef __linux__
	#include <sys/epoll.h>
#else
	#define ERESTART 700
	#include "no-epoll.h"
#endif

typedef int bool;
#define true 1
#define false 0

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

struct sockaddr_inx {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

#define port_of_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		(s)->in6.sin6_port : (s)->in.sin_port)
#define addr_of_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		(void *)&(s)->in6.sin6_addr : (void *)&(s)->in.sin_addr)
#define sizeof_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? \
		sizeof((s)->in6) : sizeof((s)->in))

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#include <sys/types.h>
#include <stddef.h>

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

/* ------------------------------------------------------- */
static inline void init_list_entry(struct list_head *entry)
{
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}
static inline int list_entry_orphan(struct list_head *entry)
{
	return entry->next == LIST_POISON1;
}
/* ------------------------------------------------------- */

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     /*prefetch(pos->member.next),*/ &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Vector hash entry (for caches). */
struct h_cache {
	struct list_head list;
	struct h_bucket *bucket;
	struct h_table *table;
	struct list_head idle_list;
	/* Time for the latest `h_entry_put()` operation. */
	time_t last_put;
	int refs;
};

struct h_bucket {
	struct list_head chain;
};

enum __h_table_type {
	H_TABLE_TYPE_CACHE,
};

struct h_table {
	int table_type;
	union {
		struct h_operations *ops;
	};
	struct h_bucket *base;
	bool      static_base;
	size_t    size;
	size_t    max_len;
	size_t    len;
	long      timeo;
	struct list_head idle_queue;
};

/* Hash table operation collections. */
struct h_operations {
	unsigned int (*hash)(void *key);
	int   (*comp_key)(struct h_cache *he, void *key);
	void  (*release)(struct h_cache *he);
	char *(*build_line)(struct h_cache *he);
	int   (*operate_cmd)(struct h_table *ht, const char *cmd);
};

/* Exported operations. */

static inline int h_table_len(struct h_table *ht)
{
	return ht->len;
}

static inline size_t h_table_len_inc(struct h_table *ht)
{
	size_t len = ++ht->len;
	return len;
}

static inline size_t h_table_len_dec(struct h_table *ht)
{
	size_t len = --ht->len;
	return len;
}

static struct h_cache *__h_cache_try_get(struct h_table *ht, void *key,
		struct h_cache *(*create)(struct h_table *, void *),
		void (*modify)(struct h_cache *, void *) )
{
	struct h_bucket *b = &ht->base[ht->ops->hash(key) & (ht->size - 1)];
	struct h_cache *he;
	
	list_for_each_entry(he, &b->chain, list) {
		if (ht->ops->comp_key(he, key) == 0) {
			/* Pop-up from idle queue when reference leaves 0. */
			if (++he->refs == 1) {
				if (!list_entry_orphan(&he->idle_list))
					list_del(&he->idle_list);
			}
			/* Invoke the call back to do modifications. */
			if (modify)
				modify(he, key);
			return he;
		}
	}
	
	/* Not found, try to create a new entry. */
	if (create == NULL) {
		return NULL;
	}
	
	/* If the table is full, try to recycle idle entries. */
	if (h_table_len(ht) >= ht->max_len) {
		fprintf(stderr, "-- ht->len: %d, ht->max_len: %d\n", (int)ht->len, (int)ht->max_len);
		return NULL;
	}
	
	if ((he = create(ht, key)) == NULL) {
		return NULL;
	}
	/* Initialize the base class. */
	he->bucket = b;
	he->table = ht;
	init_list_entry(&he->list);
	//init_timer(&he->timer);
	init_list_entry(&he->idle_list);
	he->last_put = 0;
	he->refs = 1;
	list_add(&he->list, &b->chain);
	
	h_table_len_inc(ht);
	
	return he;
}

static inline struct h_cache *h_entry_try_get(struct h_table *ht, void *key,
		struct h_cache *(*create)(struct h_table *, void *),
		void (*modify)(struct h_cache *, void *) )
{
	return __h_cache_try_get(ht, key, create, modify);
}

static void h_entry_put(struct h_cache *he)
{
	struct h_table *ht = he->table;
	
	if (--he->refs == 0) {
		/* Push unused entry to TAIL of the idle queue. */
		if (list_entry_orphan(&he->idle_list)) {
			/* Timer will check this to determine when it should be removed. */
			he->last_put = time(NULL);
			list_add_tail(&he->idle_list, &ht->idle_queue);
		} else {
			fprintf(stderr, "%s(): entry(0x%08lx) is already in idle queue!\n",
				__FUNCTION__, (unsigned long)he);
		}
	}
}

static int h_table_clear(struct h_table *ht)
{
	int count = 0;
	struct h_cache *he;
	
	while (!list_empty(&ht->idle_queue)) {
		he = list_first_entry(&ht->idle_queue, struct h_cache, idle_list);

		list_del(&he->idle_list);
		list_del(&he->list);

		ht->ops->release(he);
		h_table_len_dec(ht);

		count++;
	}

	return count;
}

static int h_table_release(struct h_table *ht)
{
	size_t ht_len = ht->len;
	
	if (ht->base) {
		if (h_table_clear(ht) != ht_len)
			return -EFAULT;
		if (!ht->static_base)
			free(ht->base);
		ht->base = NULL;
	}
	ht->size = 0;
	
	return 0;
}

static void __h_table_timeo_check(struct h_table *ht)
{
	struct h_cache *he;

	while (!list_empty(&ht->idle_queue)) {
		he = list_first_entry(&ht->idle_queue, struct h_cache, idle_list);

		if ((time(NULL) - he->last_put <= ht->timeo) &&
			(h_table_len(ht) < ht->max_len * 9 / 10) )
			break;

		list_del(&he->idle_list);
		list_del(&he->list);

		ht->ops->release(he);
		h_table_len_dec(ht);
	} /* while(!list_empty(&ht->idle_queue)) */
	
	printf("-- Live entries: %d\n", (int)ht->len);
}

/*
 * h_table_create: Initialize a new hash table.
 * Parameters: 
 *  @ht: `h_table` structure, already allocated or static,
 *  @base: optional argument, used for large sized hash table,
 *  @size: hash size,
 *  @max_len: maximum entries,
 *  @timeo: idle timeout secs.,
 *  @ops: operation collections for hash table.
 * return value:
*   0 for success, <0 for error codes, use `errno` standards.
 */
static int __h_table_create(struct h_table *ht, enum __h_table_type table_type,
		struct h_bucket *base, size_t size, size_t max_len, long timeo,
		struct h_operations *ops)
{
	struct h_bucket *b;
	size_t __size;
	int i;
	
	memset(ht, 0x0, sizeof(ht[0]));
	
	for (__size = size - 1, i = 0; __size; __size >>= 1, i++);
	__size = (1UL << i);
	if (size != __size) {
		fprintf(stderr, "%s() Warning: size '%lu' is accepted as '%lu'.\n",
			__FUNCTION__, (unsigned long)size, (unsigned long)__size);
		size = __size;
	}
	
	if (base) {
		ht->base = base;
		ht->static_base = true;
	} else {
		if ((ht->base = (struct h_bucket *)malloc(sizeof(struct h_bucket) * size)) == NULL)
			return -ENOMEM;
		ht->static_base = false;
	}
	
	for (i = 0; i < size; i++) {
		b = &ht->base[i];
		INIT_LIST_HEAD(&b->chain);
	}
	ht->size  = size;
	ht->max_len = max_len;
	ht->timeo = timeo;
	ht->ops   = ops;
	ht->len   = 0;
	
	/* Initialization for idle queue. */
	INIT_LIST_HEAD(&ht->idle_queue);

	switch (table_type) {
	case H_TABLE_TYPE_CACHE:
		ht->table_type = table_type;
		break;
	default:
		fprintf(stderr, "Invalid table type %d.\n", table_type);
		return -EINVAL;
	}

	return 0;
}

static inline int h_table_create(struct h_table *ht,
		struct h_bucket *base, size_t size, size_t max_len, long timeo,
		struct h_operations *ops)
{
	return __h_table_create(ht, H_TABLE_TYPE_CACHE, base, size, max_len, timeo, ops);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static struct sockaddr_inx g_src_addr;
static struct sockaddr_inx g_dst_addr;
static const char *g_pidfile;
static struct h_table g_conn_tbl;
static int g_lsn_sock = -1;
static int g_epfd = -1;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

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

static void write_pidfile(const char *filepath)
{
	FILE *fp;
	if (!(fp = fopen(filepath, "w"))) {
		fprintf(stderr, "*** fopen(%s): %s\n", filepath, strerror(errno));
		exit(1);
	}
	fprintf(fp, "%d\n", (int)getpid());
	fclose(fp);
}

static void set_nonblock(int sockfd)
{
	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK);
}

static int get_sockaddr_inx_pair(const char *pair, struct sockaddr_inx *sa)
{
	struct addrinfo hints, *result;
	char host[51] = "", s_port[20] = "";
	int port = 0, rc;

	if (sscanf(pair, "[%50[^]]]:%d", host, &port) == 2) {
		/* Quoted IP and port: [10.0.0.1]:10000 */
	} else if (sscanf(pair, "%50[^:]:%d", host, &port) == 2) {
		/* Regular IP and port: 10.0.0.1:10000 */
	} else {
		/**
		 * A single port number, usually for local IPv4 listen address.
		 * e.g., "10000" stands for "0.0.0.0:10000"
		 */
		const char *sp;
		for (sp = pair; *sp; sp++) {
			if (!(*sp >= '0' && *sp <= '9'))
				return -EINVAL;
		}
		sscanf(pair, "%d", &port);
		strcpy(host, "0.0.0.0");
	}
	sprintf(s_port, "%d", port);
	if (port <= 0 || port > 65535)
		return -EINVAL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if ((rc = getaddrinfo(host, s_port, &hints, &result)))
		return -EAGAIN;

	/* Get the first resolution. */
	memcpy(sa, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
	struct h_cache h_cache;
	time_t last_active;
	int svr_sock;
	/* Remember the session addresses */
	struct sockaddr_inx cli_addr;
	struct sockaddr_inx svr_addr;
};

static inline void release_proxy_conn(struct proxy_conn *conn,
		struct epoll_event *pending_evs, int pending_fds);
static inline struct proxy_conn *alloc_proxy_conn(void);
static struct proxy_conn *new_connection(int lsn_sock, int epfd,
		struct sockaddr_inx *cli_addr, int *error);

static unsigned int proxy_conn_hash_fn(void *key)
{
	struct sockaddr_inx *sa = key;
	unsigned int hash = 0;
	
	if (sa->sa.sa_family == AF_INET) {
		hash = ntohl(sa->in.sin_addr.s_addr) +
			ntohs(sa->in.sin_port);
	} else if (sa->sa.sa_family == AF_INET6) {
		int i;
		for (i = 0; i < 4; i++)
			hash += ((uint32_t *)&sa->in6.sin6_addr)[i];
		hash += ntohs(sa->in6.sin6_port);
	}
	
	return hash;
}

static int proxy_conn_key_cmp_fn(struct h_cache *he, void *key)
{
	struct proxy_conn *conn = container_of(he, struct proxy_conn, h_cache);
	struct sockaddr_inx *sa = key, *k = &conn->cli_addr;

	if (sa->sa.sa_family != k->sa.sa_family)
		return 1;
	
	if (sa->sa.sa_family == AF_INET) {
		if (sa->in.sin_addr.s_addr != k->in.sin_addr.s_addr)
			return 1;
		if (sa->in.sin_port != k->in.sin_port)
			return 1;
		return 0;
	} else if (sa->sa.sa_family == AF_INET6) {
		if (memcmp(&sa->in6.sin6_addr, &k->in6.sin6_addr, sizeof(k->in6.sin6_addr)))
			return 1;
		if (sa->in6.sin6_port != k->in6.sin6_port)
			return 1;
		return 0;
	}
	
	return 0;
}

static void proxy_conn_release_fn(struct h_cache *he)
{
	struct proxy_conn *conn = container_of(he, struct proxy_conn, h_cache);
	release_proxy_conn(conn, NULL, 0);
}

static struct h_operations proxy_conn_hops = {
	.hash        = proxy_conn_hash_fn,
	.comp_key    = proxy_conn_key_cmp_fn,
	.release     = proxy_conn_release_fn,
};

static struct h_cache *__proxy_conn_create_fn(struct h_table *ht, void *key)
{
	struct sockaddr_inx *cli_addr = key;
	struct proxy_conn *conn;
	int rc;

	if (!(conn = new_connection(g_lsn_sock, g_epfd, cli_addr, &rc)))
		return NULL;

	return &conn->h_cache;
}

static void __proxy_conn_modify_fn(struct h_cache *he, void *key)
{
	struct proxy_conn *conn = container_of(he, struct proxy_conn, h_cache);
	conn->last_active = time(NULL);
}


/**
 * Get 'conn' structure by passing the ev.data.ptr
 * @ptr: cannot be NULL and must be either EV_MAGIC_CLIENT
 *  or EV_MAGIC_SERVER.
 */
static inline struct proxy_conn *get_conn_by_evptr(int *evptr)
{
	return (struct proxy_conn *)evptr;
}

static inline struct proxy_conn *alloc_proxy_conn(void)
{
	struct proxy_conn *conn;

	if (!(conn = malloc(sizeof(*conn))))
		return NULL;
	memset(conn, 0x0, sizeof(*conn));

	conn->svr_sock = -1;
	conn->last_active = time(NULL);

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

	/**
	 * Clear possible fd events that might belong to current
	 *  connection. The event must be cleared or an invalid
	 *  pointer might be accessed.
	 */
	for (i = 0; i < pending_fds; i++) {
		struct epoll_event *ev = &pending_evs[i];
		if (ev->data.ptr == conn) {
			ev->data.ptr = NULL;
			break;
		}
	}

	if (conn->svr_sock >= 0)
		close(conn->svr_sock);

	free(conn);
}

static struct proxy_conn *new_connection(int lsn_sock, int epfd,
		struct sockaddr_inx *cli_addr, int *error)
{
	struct proxy_conn *conn;
	int svr_sock;

	/* Client calls in, allocate session data for it. */
	if (!(conn = alloc_proxy_conn())) {
		fprintf(stderr, "*** malloc(struct proxy_conn) error: %s\n",
				strerror(errno));
		return NULL;
	}
	conn->cli_addr = *cli_addr;
	
	/* Initiate the connection to server right now. */
	if ((svr_sock = socket(g_dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
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
	conn->svr_addr = g_dst_addr;

	if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
			sizeof_sockaddr(&conn->svr_addr)) == 0) {
		/* Connected, prepare for data forwarding. */
		struct epoll_event ev;
		ev.data.ptr = conn;
		ev.events = EPOLLIN;
		epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev);
		*error = 0;
		return conn;
	} else {
		/* Error occurs, drop the session. */
		fprintf(stderr, "*** Connection failed: %s\n", strerror(errno));
		release_proxy_conn(conn, NULL, 0);
		return NULL;
	}
}

static struct proxy_conn *get_conn_by_cli_addr(struct sockaddr_inx *cli_addr)
{
	struct h_cache *he;
	
	if (!(he = h_entry_try_get(&g_conn_tbl, cli_addr, __proxy_conn_create_fn,
		__proxy_conn_modify_fn)))
		return NULL;
	/* Single threaded, don't have to hold it. */
	h_entry_put(he);
	
	return container_of(he, struct proxy_conn, h_cache);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
	printf("User space UDP proxy.\n");
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
	int opt, b_true = 1, rc;
	bool is_daemon = false, is_v6only = false;
	struct epoll_event ev, events[100];
	char buffer[1024 * 64];
	time_t last_check, __last_check;
	char s_addr1[50] = "", s_addr2[50] = "";

	while ((opt = getopt(argc, argv, "dhop:")) != -1) {
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
			g_pidfile = optarg;
			break;
		case '?':
			exit(1);
		}
	}

	if (optind > argc - 2) {
		show_help(argc, argv);
		exit(1);
	}

	/* Resolve source address */
	if (get_sockaddr_inx_pair(argv[optind], &g_src_addr) < 0) {
		fprintf(stderr, "*** Invalid source address '%s'.\n", argv[optind]);
		exit(1);
	}
	optind++;

	/* Resolve destination addresse */
	if (get_sockaddr_inx_pair(argv[optind], &g_dst_addr) < 0) {
		fprintf(stderr, "*** Invalid destination address '%s'.\n", argv[optind]);
		exit(1);
	}
	optind++;

	openlog("udpfwd", LOG_PID|LOG_PERROR|LOG_NDELAY, LOG_USER);

	g_lsn_sock = socket(g_src_addr.sa.sa_family, SOCK_DGRAM, 0);
	if (g_lsn_sock < 0) {
		fprintf(stderr, "*** socket(): %s.\n", strerror(errno));
		exit(1);
	}
	if (g_src_addr.sa.sa_family == AF_INET6 && is_v6only)
		setsockopt(g_lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_true, sizeof(b_true));
	if (bind(g_lsn_sock, (struct sockaddr *)&g_src_addr,
			sizeof_sockaddr(&g_src_addr)) < 0) {
		fprintf(stderr, "*** bind(): %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(g_lsn_sock);

	inet_ntop(g_src_addr.sa.sa_family, addr_of_sockaddr(&g_src_addr),
			s_addr1, sizeof(s_addr1));
	inet_ntop(g_dst_addr.sa.sa_family, addr_of_sockaddr(&g_dst_addr),
			s_addr2, sizeof(s_addr2));
	syslog(LOG_INFO, "UDP proxy %s:%d -> %s:%d \n",
			s_addr1, ntohs(port_of_sockaddr(&g_src_addr)),
			s_addr2, ntohs(port_of_sockaddr(&g_dst_addr)));

	/* Create epoll table. */
	if ((g_epfd = epoll_create(2048)) < 0) {
		syslog(LOG_ERR, "epoll_create(): %s\n", strerror(errno));
		exit(1);
	}

	/* Run in background. */
	if (is_daemon)
		do_daemonize();

	if (g_pidfile)
		write_pidfile(g_pidfile);

	/* Create session hash table. */
	rc = h_table_create(&g_conn_tbl, NULL, 512, 2048, 60, &proxy_conn_hops);
	if (rc < 0) {
		fprintf(stderr, "*** h_table_create() failed.\n");
		exit(1);
	}

	/**
	 * Ignore PIPE signal, which is triggered when send() to
	 * a half-closed socket which causes process to abort
	 */
	signal(SIGPIPE, SIG_IGN);

	/* epoll loop */
	ev.data.ptr = &g_lsn_sock;
	ev.events = EPOLLIN;
	epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_lsn_sock, &ev);

	last_check = time(NULL);

	for (;;) {
		int nfds, i;

		/* Timeout check and recycle */
		__last_check = time(NULL);
		if (__last_check >= last_check + 2) {
			__h_table_timeo_check(&g_conn_tbl);
			last_check = __last_check;
		}

		nfds = epoll_wait(g_epfd, events, countof(events), 1000 * 1);
		if (nfds == 0)
			continue;
		if (nfds < 0) {
			if (errno == EINTR || errno == ERESTART)
				continue;
			syslog(LOG_ERR, "*** epoll_wait(): %s\n", strerror(errno));
			exit(1);
		}

		for (i = 0; i < nfds; i++) {
			struct epoll_event *evp = &events[i];
			int *evptr = (int *)evp->data.ptr;
			struct proxy_conn *conn;
			int rlen;
			
			if (evptr == NULL) {
				/* 'evptr = NULL' indicates the socket is closed. */
				continue;
			} else if (evptr == &g_lsn_sock) {
				/* Data from client. */
				struct sockaddr_inx cli_addr;
				socklen_t cli_alen = sizeof(cli_addr);
				if ((rlen = recvfrom(g_lsn_sock, buffer, sizeof(buffer), 0,
						(struct sockaddr *)&cli_addr, &cli_alen)) <= 0)
					continue;
				if (!(conn = get_conn_by_cli_addr(&cli_addr)))
					continue;
				send(conn->svr_sock, buffer, (size_t)rlen, 0);
				/* FIXME: Need to care 'rc'? */
			} else {
				/* Data from server. */
				conn = get_conn_by_evptr(evptr);
				if ((rlen = recv(conn->svr_sock, buffer, sizeof(buffer), 0))
					<= 0) {
					/* Close the session. */
					release_proxy_conn(conn, events + i + 1, nfds - 1 - i);
					continue;
				}
				sendto(g_lsn_sock, buffer, rlen, 0, (struct sockaddr *)&conn->cli_addr,
						sizeof_sockaddr(&conn->cli_addr));
				/* FIXME: Need to care 'rc'? */
			}
		}
	}

	h_table_release(&g_conn_tbl);

	return 0;
}

