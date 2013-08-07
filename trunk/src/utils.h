#ifndef __UTILS_H
#define __UTILS_H

typedef int bool;
#define true  1
#define false 0

typedef u_int16_t u16;
typedef u_int32_t u32;

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

static inline bool __isspace(char c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

static inline bool is_ipv4_addr(const char *s)
{
	int u[4];
	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4)
		return true;
	else
		return false;
}

static inline char *ipv4_hltos(u32 u, char *s)
{
	static char ss[20];
	if(!s) s = ss;
	sprintf(s, "%d.%d.%d.%d",
		(int)((u >> 24) & 0xff),
		(int)((u >> 16) & 0xff),
		(int)((u >> 8) & 0xff),
		(int)(u & 0xff) );
	return s;
}

static inline u32 ipv4_stohl(const char *s)
{
	int u[4];
	if(sscanf(s, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) == 4)
	{
		return  (((u32)u[0] & 0xff) << 24) |
				(((u32)u[1] & 0xff) << 16) |
				(((u32)u[2] & 0xff) << 8) |
				(((u32)u[3] & 0xff));
	}
	else
		return 0xffffffff;
}

static inline u32 netbits_to_mask(int bits)
{
	if (bits == 0)
		return 0x00000000;
	else
		return ~(((u32)1 << (32 - bits)) - 1);
}

#endif /* __UTILS_H */
