#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>

#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>

#define CT_GET_ORIG_BY_DNATED _IOR('I', 'G', int)

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

static int socksnat_ct_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int socksnat_ct_release(struct inode *inode, struct file *file)
{
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
static int socksnat_ct_ioctl(struct inode *inode, struct file *file,
							 unsigned int cmd, unsigned long arg)
#else
static long socksnat_ct_ioctl(struct file *file, unsigned int cmd,
							  unsigned long arg)
#endif

{
	switch (cmd) {
	case CT_GET_ORIG_BY_DNATED: {
			struct ct_query_req req;
			struct nf_conntrack_tuple tuple, *orig;
			struct nf_conntrack_tuple_hash *h;
			struct nf_conn *ct;

			if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
				return -EFAULT;

			/* Find 'nf_conn' by translated address. */
			memset(&tuple, 0x0, sizeof(tuple));
			tuple.src.l3num = PF_INET;
			tuple.src.u3.ip = req.dnated.dip;
			tuple.dst.u3.ip = req.dnated.sip;
			tuple.src.u.tcp.port = req.dnated.dport;
			tuple.dst.u.tcp.port = req.dnated.sport;
			tuple.dst.protonum = req.l4proto;
			tuple.dst.dir = IP_CT_DIR_REPLY;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
			h = nf_conntrack_find_get(&tuple);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
			h = nf_conntrack_find_get(&init_net, &tuple);
#else
			h = nf_conntrack_find_get(&init_net, 0, &tuple);
#endif
			if (h == NULL)
				return -EINVAL;
			ct = nf_ct_tuplehash_to_ctrack(h);
			
			/* Fill addresses in request structure to return. */
			orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
			req.orig.sip = orig->src.u3.ip;
			req.orig.dip = orig->dst.u3.ip;
			req.orig.sport = orig->src.u.tcp.port;
			req.orig.dport = orig->dst.u.tcp.port;
			if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
				nf_ct_put(ct);
				return -EFAULT;
			}

			nf_ct_put(ct);
			return 0;
			break;
		}
	}
	return -EINVAL;
}

static const struct file_operations socksnat_ct_fops = {
	.owner   = THIS_MODULE,
	.open    = socksnat_ct_open,
	.release = socksnat_ct_release,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	.ioctl   = socksnat_ct_ioctl,
#else
	.unlocked_ioctl = socksnat_ct_ioctl,
#endif
};

int __init socksnat_init(void)
{
	proc_create_data("socksnat_conntrack", 0444, NULL,
					 &socksnat_ct_fops, &init_net);
	return 0;
}

void __exit socksnat_exit(void)
{
	remove_proc_entry("socksnat_conntrack", NULL);
}

module_init(socksnat_init);
module_exit(socksnat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianying Liu <rssn@163.com>");
MODULE_DESCRIPTION("Connection track query extension for SOCKS NAT");
MODULE_VERSION("0.1.0");
