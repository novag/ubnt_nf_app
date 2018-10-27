#include <linux/vmalloc.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>

#include "nf_app.h"
#include "dpi_engine.h"
#include "flow.h"
#include "skb_access.h"
#include "export.h"

#define FLOW_COUNTERS
#define DPI

static flow_bucket_t *gbl_flow_cache;

#define FLOW_HASH_BITS 6

static DECLARE_HASHTABLE(app_hash, FLOW_HASH_BITS);
static DEFINE_RWLOCK(app_hash_rwlock);

static int dpi_enabled = 1;

static int decode_tcp(struct sk_buff *skb)
{
	skb_set_transport_header(skb, 0);
	return 0;
}

static int decode_udp(struct sk_buff *skb)
{
	skb_set_transport_header(skb, 0);
	return 0;
}

static int decode_ipv4(struct sk_buff *skb)
{
	unsigned int ip_head_len = 0;
	unsigned char flags = 0;
	unsigned int fragment;
	int ret = -1;

	if (unlikely(skb->len < 20 || SKB_IP_IHL(skb) < 5)) {
		pr_debug("skb->len %d have some error\n", skb->len);
		return ret;
	}
	if (unlikely(skb->len < (SKB_IP_IHL(skb) << 2))) {
		pr_debug("skb->len %d < ip header\n", skb->len);
		return ret;
	}

	ip_head_len = (unsigned int)(SKB_IP_IHL(skb) << 2);
	flags = (unsigned char)((ntohs(SKB_IP_FRAG_OFF(skb)) & 0xe000) >> 13);
	fragment = (unsigned int)(ntohs(SKB_IP_FRAG_OFF(skb)) & IP_OFFMASK);

	skb_pull(skb, ip_head_len);

	/* fragment */
	if ((flags & IP_FLAG_MF) || fragment) {
		goto __done;
	}

	switch (SKB_IP_PRO(skb)) {
	case IPPROTO_TCP:
		ret = decode_tcp(skb);
		break;
	case IPPROTO_UDP:
		ret = decode_udp(skb);
		break;
	default:
		break;
	}

__done:
	skb_push(skb, ip_head_len);
	return ret;
}

static int decode_ipv6(struct sk_buff *skb)
{
	int ret = -1;

	return ret;
}

static int parse_skb(struct sk_buff *skb)
{
	int ret = 0;

	if (unlikely(!skb)) {
		pr_debug("skb is NULL\n");
		return -1;
	}

	if (skb_is_nonlinear(skb)) {
		if (0 != skb_linearize(skb)) {
			pr_debug("linearize skb failed\n");
			return -1;
		}
	}

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		ret = decode_ipv4(skb);
		break;
	case ETH_P_IPV6:
		ret = decode_ipv6(skb);
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

static int check_ct(struct sk_buff *skb, flow_t * entry)
{
	struct nf_conn *ct;
	struct nf_conntrack_tuple *tuple_o, *tuple_r;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);

	if (ct == NULL)
		return 0;

	if (ctinfo == IP_CT_NEW) {
		entry->orig = 1;
		return 0;
	}

	entry->orig = 0;
	tuple_o = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	if (!tuple_o)
		return 0;
	tuple_r = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	if (!tuple_r)
		return 0;

	if (ctinfo == IP_CT_IS_REPLY && entry->daddr != tuple_o->dst.u3.ip) {
		entry->nat = 1;
	}

	if (entry->daddr == tuple_o->dst.u3.ip) {
		// original
		entry->tx_saddr = tuple_r->dst.u3.ip;
		entry->tx_daddr = tuple_r->src.u3.ip;
		entry->tx_sport = tuple_r->dst.u.udp.port;
		entry->tx_dport = tuple_r->src.u.udp.port;
		return 1;
	}
	// reply
	entry->tx_saddr = tuple_r->dst.u3.ip;
	entry->tx_daddr = tuple_o->src.u3.ip;
        entry->tx_sport = tuple_r->dst.u.udp.port;
        entry->tx_dport = tuple_r->src.u.udp.port;


	return 1;
}

static int nf_flush_cache(void)
{
	int i, j;
	flow_t *entry;
	flow_bucket_t *bucket;
	int old_val;

	old_val = dpi_enabled;
	dpi_enabled = 0;
	for (i = 0; i < FLOW_BUCKETS; i++) {
		bucket = &gbl_flow_cache[i];
		for (j = 0; j < ENTRIES_PER_BUCKET; j++) {
			entry = &bucket->entry[j];
			entry->timestamp = 0xffffffff;
		}
	}
	dpi_enabled = old_val;
	return 0;
}

static flow_t *find_entry(struct sk_buff *skb)
{
	flow_t *entry;
	flow_bucket_t *bucket;
	uint16_t sport, dport;
	uint16_t eth_type;
	uint8_t proto = -1;
	uint32_t hash_key, lru_timestamp;
	struct iphdr *ip;
	struct timeval tv;
	struct neighbour *neigh;
	int i, bucket_idx, free_entry, lru;

	eth_type = ntohs(skb->protocol);

	if (ETH_P_IP == eth_type) {
		ip = SKB_IP(skb);
		proto = ip->protocol;
	} else {
		return NULL;
	}

	if (IPPROTO_TCP == proto) {
		sport = ntohs(SKB_TCP_SPORT(skb));
		dport = ntohs(SKB_TCP_DPORT(skb));
	} else if (IPPROTO_UDP == proto) {
		sport = ntohs(SKB_UDP_SPORT(skb));
		dport = ntohs(SKB_UDP_DPORT(skb));
	} else if (IPPROTO_ICMP == proto) {
		sport = SKB_ICMP_TYPE(skb);
		dport = SKB_ICMP_CODE(skb);
	} else {
		sport = dport = -1;
	}

	hash_key = HASH_KEY((uint32_t) ip->saddr, (uint32_t) ip->daddr,
			    sport, dport, proto);
	do_gettimeofday(&tv);

	bucket_idx = hash_key & FLOW_BUCKETS_MASK;
	if (bucket_idx >= FLOW_BUCKETS) {
		printk("Error: bucket_idx = %d\n", bucket_idx);
		return NULL;
	}
	bucket = &gbl_flow_cache[bucket_idx];
	free_entry = -1;
	lru = -1;
	lru_timestamp = 0xffffffff;
	for (i = 0; i < ENTRIES_PER_BUCKET; i++) {
		entry = &bucket->entry[i];
		if (entry->timestamp == 0xffffffff) {
			free_entry = i;
			continue;
		}
		if (entry->timestamp > tv.tv_sec + FLOW_TIMEOUT) {
			free_entry = i;
			continue;
		}
		if (entry->timestamp < lru_timestamp) {
			lru = i;
			lru_timestamp = entry->timestamp;
		}

		if (entry->proto != proto)
			continue;

		if ((entry->saddr == (uint32_t) ip->saddr) &&
		    (entry->daddr == (uint32_t) ip->daddr) &&
		    (entry->sport == sport) && (entry->dport == dport)) {
			goto found;
		}
	}

	// not found
	if (free_entry != -1) {
		if (free_entry >= ENTRIES_PER_BUCKET) {
			printk("Error free entry = %d\n", free_entry);
			return NULL;
		}
		entry = &bucket->entry[free_entry];
	} else {
		if (lru >= ENTRIES_PER_BUCKET) {
			printk("Error lru entry = %d\n", lru);
			return NULL;
		}
		entry = &bucket->entry[lru];
	}

	memset(entry, 0, sizeof(flow_t));
	entry->saddr = ip->saddr;
	entry->daddr = ip->daddr;
	entry->sport = sport;
	entry->dport = dport;
	entry->proto = proto;

	strncpy(entry->ifname, skb->dev->name, 16);

found:
	if (entry->tx_saddr == 0) {
		check_ct(skb, entry);
	}
	entry->timestamp = tv.tv_sec;

	if (entry->mac_addr[0] == 0 && entry->mac_addr[1] == 0 &&
		entry->mac_addr[2] == 0 && entry->mac_addr[3] == 0 &&
		entry->mac_addr[4] == 0 && entry->mac_addr[5] == 0) {
		if (!dev_is_mac_header_xmit(skb->dev)) {
			neigh = dst_neigh_lookup(skb_dst(skb), &SKB_IP(skb)->daddr);
			if (neigh == NULL) {
				printk("Error: ARP entry not found\n");
				memcpy(entry->mac_addr, SKB_ETH(skb)->h_source, ETH_ALEN);
			} else {
				memcpy(entry->mac_addr, neigh->ha, ETH_ALEN);
				neigh_release(neigh);
			}
		} else {
			memcpy(entry->mac_addr, SKB_ETH(skb)->h_source, ETH_ALEN);
		}
	}

	return entry;
}

static int anything_to_export(int bucket_idx)
{
	flow_t *entry;
	flow_bucket_t *bucket;
	int i;
	struct timeval tv;

	do_gettimeofday(&tv);
	if (bucket_idx >= FLOW_BUCKETS) {
		return 0;
	}
	bucket = &gbl_flow_cache[bucket_idx];
	for (i = 0; i < ENTRIES_PER_BUCKET; i++) {
		entry = &bucket->entry[i];
		if (entry->timestamp == 0xffffffff) {
			continue;
		}
		if (entry->timestamp < tv.tv_sec + FLOW_TIMEOUT) {
			return 1;
			continue;
		}
	}
	return 0;
}

#define CAT_MARK_SHIFT 18
#define CAT_MARK_MASK 0x7c0000
#define APP_MARK_SHIFT 13
#define APP_MARK_MASK 0x3e000

uint32_t is_app_int(uint8_t cat, uint16_t app)
{
	app_int_t *entry;
	uint32_t ret = 0;
	uint32_t cat_mark = 0, app_mark = 0;

	read_lock(&app_hash_rwlock);
	hash_for_each_possible(app_hash, entry, hnode, cat) {
		if (entry->cat == cat) {
			if (entry->app == 0) {
				cat_mark = entry->mark;
			}
			if (entry->app == app) {
				app_mark = entry->mark >> 16;
			}
		}
	}
	read_unlock(&app_hash_rwlock);

	if (cat_mark != 0) {
		ret = cat_mark << CAT_MARK_SHIFT;
	}
	if (app_mark != 0) {
		ret |= (app_mark << APP_MARK_SHIFT);
	}

	return ret;
}

EXPORT_SYMBOL(is_app_int);

static int update_entry(struct sk_buff *skb, flow_t * entry)
{
	tdts_pkt_parameter_t pkt_param;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	uint32_t mark;
	struct sk_buff *skb2;
	struct iphdr *ip;
	struct udphdr *udp;

	atomic_inc(&entry->count.packets);
	atomic_add(skb->len, &entry->count.bytes);

	if (!dpi_enabled)
		return 0;

	if (entry->dpi_final || entry->dpi_nomore || entry->dpi_noint) {
		ct = nf_ct_get(skb, &ctinfo);
		if (ct == NULL)
			return 0;
		if (ct->mark & (CAT_MARK_MASK | APP_MARK_MASK)) {
			skb->mark |= (ct->mark &
				      (CAT_MARK_MASK | APP_MARK_MASK));
		}
		return 0;
	}

	if (entry->dpi_calls > MAX_DPI_CALLS)
	     return 0;

	if (entry->tx_daddr != 0 && entry->daddr != entry->tx_daddr) {
		skb2 = skb_copy(skb, GFP_ATOMIC);
		if (!skb2) {
			if (printk_ratelimit()) {
				printk("skb_copy failed\n");
			}
			return 0;
		}
		ip = SKB_IP(skb2);
		ip->saddr = entry->tx_saddr;
		ip->daddr = entry->tx_daddr;
		if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
			udp = SKB_UDP_HEAD_ADDR(skb2);
			udp->source = entry->tx_sport;
			udp->dest = entry->tx_dport;
		}
		tdts_init_pkt_parameter(&pkt_param, SW_APP, 0);
		tdts_set_pkt_parameter_l3_ip(&pkt_param, skb2->data, skb2->len);
		if (tdts_shell_dpi_l3_data(skb2, &pkt_param) < 0) {
			kfree_skb(skb2);
			pr_debug("dpi error\n");
			return -1;
		}
		kfree_skb(skb2);
	} else {
		tdts_init_pkt_parameter(&pkt_param, SW_APP, 0);
		tdts_set_pkt_parameter_l3_ip(&pkt_param, skb->data, skb->len);
		if (tdts_shell_dpi_l3_data(skb, &pkt_param) < 0) {
			pr_debug("dpi error\n");
			return -1;
		}
	}
        skb->cvm_reserved |= SKB_CVM_RESERVED_15;
	entry->dpi_calls++;

	if (tdts_check_pkt_parameter_res(&pkt_param, TDTS_RES_TYPE_APPID)) {
		entry->dpi_cat =
		    TDTS_PKT_PARAMETER_RES_APPID_CAT_ID(&pkt_param);
		entry->dpi_app =
		    TDTS_PKT_PARAMETER_RES_APPID_APP_ID(&pkt_param);
		if (TDTS_PKT_PARAMETER_RES_APPID_CHECK_FINAL(&pkt_param)) {
			entry->dpi_final = 1;
		}
		if (TDTS_PKT_PARAMETER_RES_APPID_CHECK_NOMORE(&pkt_param)) {
			entry->dpi_nomore = 1;
		}
		if (TDTS_PKT_PARAMETER_RES_APPID_CHECK_NOINT(&pkt_param)) {
			entry->dpi_noint = 1;
		}
		if (entry->dpi_final || entry->dpi_nomore) {
			mark = is_app_int(entry->dpi_cat, entry->dpi_app);
			if (mark == 0) {
				return 0;
			}
			skb->mark |= mark;
			ct = nf_ct_get(skb, &ctinfo);
			if (ct == NULL) {
				return 0;
			}
			ct->mark |= mark;
			nf_conntrack_event_cache(IPCT_MARK, ct);
		}
	}

	return 0;
}

int update_flow(struct sk_buff *skb)
{

	flow_t *entry;

        if (skb->cvm_reserved >> SKB_DPI_SHIFT) {
            return -1;
        }

	if (parse_skb(skb) < 0) {
		return -1;
	}

	entry = find_entry(skb);
	if (entry == NULL) {
		return -1;
	}

	update_entry(skb, entry);

	return 0;
}

/*********** export **************/

static void flow_export_it(flow_t * entry, export_flow_t * f)
{
	if (entry->tx_saddr == 0)
		return;

	if (entry->orig || entry->nat == 0) {
		f->saddr = entry->saddr;
		f->daddr = entry->daddr;
		f->tx_saddr = entry->tx_saddr;
		f->tx_daddr = entry->tx_daddr;
		f->tx_ports = (entry->sport << 16 | entry->dport);
	} else {
		f->saddr = entry->saddr;
		f->daddr = entry->tx_saddr;
		f->tx_saddr = entry->saddr;
		f->tx_daddr = entry->tx_daddr;
		f->tx_ports = (entry->tx_dport << 16 | entry->tx_sport);
	}

	f->sport = entry->sport;
	f->dport = entry->dport;

#ifdef FLOW_COUNTERS
	f->packets = atomic_xchg(&entry->count.packets, 0);
	f->bytes = atomic_xchg(&entry->count.bytes, 0);
#endif
	f->proto = entry->proto;
	f->tx_proto = entry->proto;
#ifdef DPI
	f->dpi_final = entry->dpi_final;
	f->dpi_cat = entry->dpi_cat;
	f->dpi_app = entry->dpi_app;
#endif

	memcpy(f->mac_addr, entry->mac_addr, 6);
	strncpy(f->ifname, entry->ifname, 16);

	f->magic = EXPORT_MAGIC;
}

static uint64_t export_count;

static void *flow_export_seq_start(struct seq_file *s, loff_t * pos)
{
	loff_t *spos;

        if (*pos >= FLOW_BUCKETS) {
                return NULL;
        }
	spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
	if (!spos)
		return NULL;
	if (*pos == 0) {
		export_count = 0;
	} 
        *spos = *pos;
	return spos;
}

static void *flow_export_seq_next(struct seq_file *s, void *v, loff_t * pos)
{
	loff_t *spos = (loff_t *) v;
	*pos = ++(*spos);

	while ((!anything_to_export((int)*pos)) && (*pos + 1 < FLOW_BUCKETS)) {
		*pos = ++(*spos);
	}
	if (*pos >= FLOW_BUCKETS) {
		*pos = 0;
		return NULL;
	}
	return spos;
}

static void flow_export_seq_stop(struct seq_file *s, void *v)
{
	if (!v) {
		return;
	}
	kfree(v);
}

static int flow_export_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos = (loff_t *) v;
	flow_bucket_t *bucket;
	flow_t *entry;
	export_flow_t f[ENTRIES_PER_BUCKET], *fp;
	int i;
	struct timeval tv;

	if (*spos >= FLOW_BUCKETS) {
		return -1;
	}

	if (!is_export_enabled()) {
		return -1;
	}

	do_gettimeofday(&tv);

        memset(&f[0], 0, sizeof(f));
        bucket = &gbl_flow_cache[*spos];
        for (i = 0; i < ENTRIES_PER_BUCKET; i++) {
                entry = &bucket->entry[i];
                if (entry->timestamp > tv.tv_sec + FLOW_TIMEOUT)
                        continue;
                if (atomic_read(&entry->count.packets) != 0) {
                        flow_export_it(entry, &f[i]);
                }
        }
        for (i = 0; i < ENTRIES_PER_BUCKET; i++) {
                fp = &f[i];
                if (fp->magic == EXPORT_MAGIC) {
                        seq_putc(s, 'A');
                        seq_write(s, fp, sizeof(export_flow_t));
                        export_count++;
            }
        }

	if (*spos == (FLOW_BUCKETS - 1)) {
		seq_putc(s, 'B');
		seq_write(s, &export_count, sizeof(uint64_t));
	}

	return 0;
}

static struct seq_operations flow_export_seq_ops = {
	.start = flow_export_seq_start,
	.next = flow_export_seq_next,
	.stop = flow_export_seq_stop,
	.show = flow_export_seq_show
};

static int flow_export_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &flow_export_seq_ops);
}

static struct file_operations flow_export_file_ops = {
	.owner = THIS_MODULE,
	.open = flow_export_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/********* add/delete app of interest ***************************/

static int app_int_show(struct seq_file *s, void *v)
{
	int bucket;
	app_int_t *entry;

	read_lock(&app_hash_rwlock);
	hash_for_each(app_hash, bucket, entry, hnode) {
		seq_printf(s, "%d %d %d\n", entry->mark, entry->cat,
			   entry->app);
	}
	read_unlock(&app_hash_rwlock);

	return 0;
}

static int app_int_open(struct inode *inode, struct file *file)
{
	return single_open(file, app_int_show, NULL);
}

static void flush_app_hash(void)
{
	int bucket;
	app_int_t *entry;

	write_lock(&app_hash_rwlock);
	hash_for_each(app_hash, bucket, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	write_unlock(&app_hash_rwlock);
}

enum PROC_CMD {
	PROC_FLUSH = 0,
	PROC_ADD,
	PROC_DEL,
};

static ssize_t app_int_write(struct file *file, const char __user * input,
			     size_t size, loff_t * ofs)
{
	char buffer[255];
	uint32_t cmd, mark, cat, app;
	int rc;
	app_int_t *entry = NULL;
	int bucket;
	bool found = false;

	if (copy_from_user(buffer, input, size))
		return -EFAULT;

	buffer[size] = 0;

	cmd = mark = cat = app = 0;
	rc = sscanf(buffer, "%d %d %d %d", &cmd, &mark, &cat, &app);
	if (rc <= 0)
		return -1;

	rc = size;
	switch (cmd) {
	case PROC_FLUSH:	/* flush */
		flush_app_hash();
		return rc;
	case PROC_ADD:		/* add - mark cat app */
	case PROC_DEL:		/* del - mark */
		break;
	default:
		return -1;
	}

	if (cat > 0xff)
		return -1;
	if (app > 0xffff)
		return -1;

	write_lock(&app_hash_rwlock);
	hash_for_each(app_hash, bucket, entry, hnode) {
		if (entry->mark == mark) {
			if (cmd == PROC_DEL) {
				found = true;
				hash_del(&entry->hnode);
				kfree(entry);
			} else if (cmd == PROC_ADD && app == 0) {
				rc = -1;
				goto done;
			}
		}
	}

	if (cmd == PROC_DEL) {
		if (!found) {
			rc = -1;
		}
		goto done;
	}

	entry = kmalloc(sizeof(app_int_t), GFP_ATOMIC);
	if (!entry) {
		rc = -1;
		goto done;
	}

	entry->mark = mark;
	entry->cat = (uint8_t) (cat & 0x7f);
	entry->app = (uint16_t) app;
	INIT_HLIST_NODE(&entry->hnode);

	hash_add(app_hash, &entry->hnode, entry->cat);
done:
	write_unlock(&app_hash_rwlock);

	return rc;
}

static const struct file_operations app_int_file_ops = {
	.owner = THIS_MODULE,
	.open = app_int_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = app_int_write,
};

static int dpi_show(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", dpi_enabled);
	return 0;
}

static int dpi_open(struct inode *inode, struct file *file)
{
	return single_open(file, dpi_show, NULL);
}

static ssize_t dpi_write(struct file *file, const char __user * input,
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

	dpi_enabled = val;

	return size;
}

static const struct file_operations dpi_file_ops = {
	.owner = THIS_MODULE,
	.open = dpi_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = dpi_write,
};

static int nf_cache_show(struct seq_file *s, void *v)
{
	return -1;
}

static int nf_cache_open(struct inode *inode, struct file *file)
{
	return single_open(file, nf_cache_show, NULL);
}

static ssize_t nf_cache_write(struct file *file, const char __user * input,
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

	if (val != 0)
		return -1;

	nf_flush_cache();

	return size;
}

static const struct file_operations nf_cache_file_ops = {
	.owner = THIS_MODULE,
	.open = nf_cache_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = nf_cache_write,
};

int flow_init(struct proc_dir_entry *nf_dpi_proc_dir)
{
	size_t size;
	int i, j;
	flow_bucket_t *bucket;
	flow_t *flow;

	if (!proc_create("flows", 0600, nf_dpi_proc_dir, &flow_export_file_ops))
		return -ENOMEM;

	if (!proc_create("app_int", 0666, nf_dpi_proc_dir, &app_int_file_ops))
		return -ENOMEM;

	if (!proc_create("dpi", 0644, nf_dpi_proc_dir, &dpi_file_ops))
		return -ENOMEM;

	if (!proc_create("cache", 0600, nf_dpi_proc_dir, &nf_cache_file_ops))
		return -ENOMEM;

	size = sizeof(flow_bucket_t) * FLOW_BUCKETS;
	gbl_flow_cache = (flow_bucket_t *) vmalloc(size);
	if (!gbl_flow_cache) {
		pr_err("Failed to alloc %zd memory for flow cache\n", size);
		return -ENOMEM;
	}

	for (i = 0; i < FLOW_BUCKETS; i++) {
		bucket = &gbl_flow_cache[i];
		for (j = 0; j < ENTRIES_PER_BUCKET; j++) {
			flow = &bucket->entry[j];
			memset(flow, 0, sizeof(flow_t));
			flow->timestamp = 0xffffffff;
		}
	}

	hash_init(app_hash);

	return 0;
}

void flow_exit(struct proc_dir_entry *nf_dpi_proc_dir)
{
	if (gbl_flow_cache) {
		vfree((void *)gbl_flow_cache);
	}

	flush_app_hash();

	remove_proc_entry("flows", nf_dpi_proc_dir);
	remove_proc_entry("app_int", nf_dpi_proc_dir);
	remove_proc_entry("dpi", nf_dpi_proc_dir);
	remove_proc_entry("cache", nf_dpi_proc_dir);
}
