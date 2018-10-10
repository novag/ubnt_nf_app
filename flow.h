#ifndef UBNT_NF_APP_FLOW_H_
#define UBNT_NF_APP_FLOW_H_

#include <linux/hashtable.h>

typedef struct {
	atomic_t packets;
	atomic_t bytes;
} counters_t;

/*
 * Ideally the flow_t data structure should be 32 bytes so that 4
 * entries could fit in a bucket and the bucket would take up 1 cache
 * line, but we need the tx_saddr and tx_daddr.  Optimize later.
 *
 * Now that the size is 42 bytes we only get 2 entries per bucket.
 * Might be able to reduce timestamp to 2 bytes and that would give
 * one extra entry.  But given that the export scans the whole table
 * it might not help much.
 */

typedef struct {
	// word0
	uint32_t saddr;
	uint32_t daddr;
	// word1
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
	uint8_t dpi_final:1;
	uint8_t dpi_nomore:1;
	uint8_t dpi_noint:1;
	uint8_t orig:1;
	uint8_t nat:1;
	uint8_t dpi_pad:3;
	uint16_t dpi_app;
	// word2
	counters_t count;
	// word3
	uint32_t timestamp;
	uint8_t dpi_cat;
	uint8_t dpi_calls;
	uint16_t tx_sport;
	// word4
	uint32_t tx_saddr;
	uint32_t tx_daddr;
	// word5
	uint16_t tx_dport;
	unsigned char mac_addr[6];
	// word6
	char ifname[16];

} flow_t;

#define FLOW_BUCKETS         8192
#define FLOW_BUCKETS_MASK    (FLOW_BUCKETS - 1)
#define CACHE_LINE_SIZE      128
#define ENTRIES_PER_BUCKET   ((CACHE_LINE_SIZE/sizeof(flow_t)))

#define FLOW_TIMEOUT         30

#define MAX_DPI_CALLS        100

typedef struct {
	flow_t entry[ENTRIES_PER_BUCKET];
} flow_bucket_t;

typedef struct {
	uint32_t mark;
	uint8_t cat;
	uint16_t app;
	struct hlist_node hnode;
} app_int_t;

#define IP_FLAG_UF 0x04
#define IP_FLAG_DF 0x02
#define IP_FLAG_MF 0x01
#define IP_OFFMASK 0x1fff

#define HASH_KEY(__sip, __dip, __sport, __dport, __proto)	\
	((__sip ^ __dip ^ __sport ^ __dport ^ __proto))

extern int flow_init(struct proc_dir_entry *nf_dpi_proc_dir);
extern void flow_exit(struct proc_dir_entry *nf_dpi_proc_dir);
extern int update_flow(struct sk_buff *skb);

#endif /* UBNT_NF_APP_FLOW_H_ */
