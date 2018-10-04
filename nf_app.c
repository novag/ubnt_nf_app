#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/slab.h>		// kmalloc
#include <linux/vmalloc.h>	// vmalloc

#include <asm/atomic.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/netfilter/nf_conntrack.h>

#ifdef CONFIG_COMPAT
#include <asm/compat.h>
#endif

#include "flow.h"

#define FWMOD_NAME "ubnt_nf_app"

static int export_enabled = 1;

static struct nf_hook_ops forward_hook_ops;

static struct proc_dir_entry *nf_dpi_proc_dir;

static uint32_t
forward_hook(uint32_t hooknum, struct sk_buff *skb,
	     const struct net_device *in_dev,
	     const struct net_device *out_dev, int (*okfn) (struct sk_buff *))
{
	uint32_t verdict = NF_ACCEPT;

	if (skb == NULL) {
		goto error;
	}

	update_flow(skb);

error:
	return verdict;
}

int is_export_enabled(void)
{
	return export_enabled;
}

static int export_show(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", export_enabled);
	return 0;
}

static int export_open(struct inode *inode, struct file *file)
{
	return single_open(file, export_show, NULL);
}

static ssize_t export_write(struct file *file, const char __user * input,
			    size_t size, loff_t * ofs)
{
	char buffer[255];
	int val = 0;
	int rc;

	if (copy_from_user(buffer, input, size))
		return -EFAULT;

	buffer[size] = 0;

	rc = sscanf(buffer, "%d", &val);
	if (rc != 1)
		return -1;

	if (val < 0 || val > 1)
		return -1;

	export_enabled = val;

	return size;
}

static const struct file_operations export_file_ops = {
	.owner = THIS_MODULE,
	.open = export_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = export_write,
};

static int __init nf_app_init(void)
{
	pr_debug("Register forward hook");

	nf_dpi_proc_dir = proc_mkdir("nf_dpi", NULL);
	if (!nf_dpi_proc_dir) {
		pr_err("Failed to create nf_dpi proc directory\n");
		return -ENOMEM;
	}

	if (!proc_create("export", 0644, nf_dpi_proc_dir, &export_file_ops))
		return -ENOMEM;

	flow_init(nf_dpi_proc_dir);

	memset(&forward_hook_ops, 0, sizeof(forward_hook_ops));
	forward_hook_ops.hooknum = NF_INET_FORWARD;
	forward_hook_ops.pf = PF_INET;
	forward_hook_ops.priority = NF_IP_PRI_FIRST;
	forward_hook_ops.hook = (nf_hookfn *) forward_hook;

	if (nf_register_hook(&forward_hook_ops) != 0) {
		return -1;
	}

	return 0;
}

static void __exit nf_app_exit(void)
{
	pr_debug("Unregister forward hook");

	nf_unregister_hook(&forward_hook_ops);

	flow_exit(nf_dpi_proc_dir);

	remove_proc_entry("export", nf_dpi_proc_dir);
	remove_proc_entry("nf_dpi", NULL);
}

module_init(nf_app_init);
module_exit(nf_app_exit);
