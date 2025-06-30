// SPDX-License-Identifier: GPL-2.0-or-later
/* A network driver using virtio.
 *
 * Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 */
//#define DEBUG
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/dim.h>
#include <net/route.h>
#include <net/xdp.h>
#include <net/net_failover.h>
#include <net/xdp_sock_drv.h>

/* skip virtio_check_driver_offered_feature check for force_xdp  */
#define virtio_has_feature __virtio_test_bit

#define u64_stats_fetch_begin u64_stats_fetch_begin_irq
#define u64_stats_fetch_retry u64_stats_fetch_retry_irq

static int napi_weight = NAPI_POLL_WEIGHT;
module_param(napi_weight, int, 0444);

static int xsk_check_timeout = 100;
static int xsk_num_max       = 1024;
static int xsk_num_percent   = 80;
static int xsk_budget        = 64;

module_param(xsk_check_timeout, int, 0644);
module_param(xsk_num_max,       int, 0644);
module_param(xsk_num_percent,   int, 0644);
module_param(xsk_budget,        int, 0644);

static bool csum = true, gso = true, napi_tx = true, force_xdp;
static bool lro;
module_param(csum, bool, 0444);
module_param(gso, bool, 0444);
module_param(napi_tx, bool, 0644);
module_param(force_xdp, bool, 0644);
module_param(lro, bool, 0644);

/* 7 days are long enough by default. */
static unsigned int cvq_timeout = 7 * 24 * 3600 * 1000;
module_param(cvq_timeout, uint, 0644);

#define VIRTNET_DIM_TUNE_TRAFFIC 1
#define VIRTNET_DIM_NEVENTS 128

/* FIXME: MTU in config. */
#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

#define VIRTNET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
#define VIRTIO_XDP_HEADROOM 256

/* Separating two types of XDP xmit */
#define VIRTIO_XDP_TX		BIT(0)
#define VIRTIO_XDP_REDIR	BIT(1)

#define VIRTIO_XDP_FLAG	BIT(0)

/* RX packet size EWMA. The average packet size is used to determine the packet
 * buffer size when refilling RX rings. As the entire RX ring may be refilled
 * at once, the weight is chosen so that the EWMA will be insensitive to short-
 * term, transient changes in packet size.
 */
DECLARE_EWMA(pkt_len, 0, 64)

#define VIRTNET_DRIVER_VERSION "1.0.0"

static const unsigned long guest_offloads[] = {
	VIRTIO_NET_F_GUEST_TSO4,
	VIRTIO_NET_F_GUEST_TSO6,
	VIRTIO_NET_F_GUEST_ECN,
	VIRTIO_NET_F_GUEST_UFO,
	VIRTIO_NET_F_GUEST_CSUM,
	VIRTIO_NET_F_GUEST_USO4,
	VIRTIO_NET_F_GUEST_USO6
};

#define GUEST_OFFLOAD_GRO_HW_MASK ((1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
				(1ULL << VIRTIO_NET_F_GUEST_TSO6) | \
				(1ULL << VIRTIO_NET_F_GUEST_ECN)  | \
				(1ULL << VIRTIO_NET_F_GUEST_UFO)  | \
				(1ULL << VIRTIO_NET_F_GUEST_USO4) | \
				(1ULL << VIRTIO_NET_F_GUEST_USO6))

struct virtnet_stat_desc {
	char desc[ETH_GSTRING_LEN];
	size_t offset;
};

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t xdp_tx;
	u64_stats_t xdp_tx_drops;
	u64_stats_t kicks;
	u64_stats_t tx_timeouts;
	u64_stats_t xsk_wakeup;
	u64_stats_t xsk_wakeup_recycle;
	u64_stats_t xsk_run;
	u64_stats_t xsk_devfull;
	u64_stats_t xsk_timer;
	u64_stats_t xsk_timer_run;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t drops;
	u64_stats_t xdp_packets;
	u64_stats_t xdp_tx;
	u64_stats_t xdp_redirects;
	u64_stats_t xdp_drops;
	u64_stats_t kicks;
};

enum {
	XDP_TYPE_XSK,
	XDP_TYPE_TX,
};

struct virtnet_xdp_type {
	int offset:24;
	unsigned type:8;
};

struct virtnet_xsk_hdr {
	struct virtnet_xdp_type type;
	struct virtio_net_hdr_mrg_rxbuf hdr;
	u32 len;
};

#define VIRTNET_XSK_TXNAPI_RUNNING 0

#define VIRTNET_SQ_STAT(name, m) {name, offsetof(struct virtnet_sq_stats, m)}
#define VIRTNET_RQ_STAT(name, m) {name, offsetof(struct virtnet_rq_stats, m)}

static const struct virtnet_stat_desc virtnet_sq_stats_desc[] = {
	VIRTNET_SQ_STAT("packets",            packets),
	VIRTNET_SQ_STAT("bytes",              bytes),
	VIRTNET_SQ_STAT("xdp_tx",             xdp_tx),
	VIRTNET_SQ_STAT("xdp_tx_drops",       xdp_tx_drops),
	VIRTNET_SQ_STAT("kicks",              kicks),
	VIRTNET_SQ_STAT("tx_timeouts",        tx_timeouts),
	VIRTNET_SQ_STAT("xsk_wakeup",         xsk_wakeup),
	VIRTNET_SQ_STAT("xsk_wakeup_recycle", xsk_wakeup_recycle),
	VIRTNET_SQ_STAT("xsk_run",            xsk_run),
	VIRTNET_SQ_STAT("xsk_devfull",        xsk_devfull),
	VIRTNET_SQ_STAT("xsk_timer",          xsk_timer),
	VIRTNET_SQ_STAT("xsk_timer_run",      xsk_timer_run),
};

static const struct virtnet_stat_desc virtnet_rq_stats_desc[] = {
	VIRTNET_RQ_STAT("packets",       packets),
	VIRTNET_RQ_STAT("bytes",         bytes),
	VIRTNET_RQ_STAT("drops",         drops),
	VIRTNET_RQ_STAT("xdp_packets",   xdp_packets),
	VIRTNET_RQ_STAT("xdp_tx",        xdp_tx),
	VIRTNET_RQ_STAT("xdp_redirects", xdp_redirects),
	VIRTNET_RQ_STAT("xdp_drops",     xdp_drops),
	VIRTNET_RQ_STAT("kicks",         kicks),
};

#define VIRTNET_STATS_DESC_CQ(name) \
	{#name, offsetof(struct virtio_net_stats_cvq, name)}

#define VIRTNET_STATS_DESC_RX(class, name) \
	{#name, offsetof(struct virtio_net_stats_rx_ ## class, rx_ ## name)}

#define VIRTNET_STATS_DESC_TX(class, name) \
	{#name, offsetof(struct virtio_net_stats_tx_ ## class, tx_ ## name)}

static const struct virtnet_stat_desc virtnet_stats_cvq_desc[] = {
	VIRTNET_STATS_DESC_CQ(command_num),
	VIRTNET_STATS_DESC_CQ(ok_num),
};

static const struct virtnet_stat_desc virtnet_stats_rx_basic_desc[] = {
	VIRTNET_STATS_DESC_RX(basic, packets),
	VIRTNET_STATS_DESC_RX(basic, bytes),

	VIRTNET_STATS_DESC_RX(basic, notifications),
	VIRTNET_STATS_DESC_RX(basic, interrupts),

	VIRTNET_STATS_DESC_RX(basic, drops),
	VIRTNET_STATS_DESC_RX(basic, drop_overruns),
};

static const struct virtnet_stat_desc virtnet_stats_tx_basic_desc[] = {
	VIRTNET_STATS_DESC_TX(basic, packets),
	VIRTNET_STATS_DESC_TX(basic, bytes),

	VIRTNET_STATS_DESC_TX(basic, notifications),
	VIRTNET_STATS_DESC_TX(basic, interrupts),

	VIRTNET_STATS_DESC_TX(basic, drops),
	VIRTNET_STATS_DESC_TX(basic, drop_malformed),
};

static const struct virtnet_stat_desc virtnet_stats_rx_csum_desc[] = {
	VIRTNET_STATS_DESC_RX(csum, csum_valid),
	VIRTNET_STATS_DESC_RX(csum, csum_none),
	VIRTNET_STATS_DESC_RX(csum, csum_bad),
	VIRTNET_STATS_DESC_RX(csum, needs_csum),
};

static const struct virtnet_stat_desc virtnet_stats_tx_csum_desc[] = {
	VIRTNET_STATS_DESC_TX(csum, csum_none),
	VIRTNET_STATS_DESC_TX(csum, needs_csum),
};

static const struct virtnet_stat_desc virtnet_stats_rx_gso_desc[] = {
	VIRTNET_STATS_DESC_RX(gso, gso_packets),
	VIRTNET_STATS_DESC_RX(gso, gso_bytes),
	VIRTNET_STATS_DESC_RX(gso, gso_packets_coalesced),
	VIRTNET_STATS_DESC_RX(gso, gso_bytes_coalesced),
};

static const struct virtnet_stat_desc virtnet_stats_tx_gso_desc[] = {
	VIRTNET_STATS_DESC_TX(gso, gso_packets),
	VIRTNET_STATS_DESC_TX(gso, gso_bytes),
	VIRTNET_STATS_DESC_TX(gso, gso_segments),
	VIRTNET_STATS_DESC_TX(gso, gso_segments_bytes),

	VIRTNET_STATS_DESC_TX(gso, gso_packets_noseg),
	VIRTNET_STATS_DESC_TX(gso, gso_bytes_noseg),
};

static const struct virtnet_stat_desc virtnet_stats_rx_speed_desc[] = {
	VIRTNET_STATS_DESC_RX(speed, ratelimit_packets),
	VIRTNET_STATS_DESC_RX(speed, ratelimit_bytes),
};

static const struct virtnet_stat_desc virtnet_stats_tx_speed_desc[] = {
	VIRTNET_STATS_DESC_TX(speed, ratelimit_packets),
	VIRTNET_STATS_DESC_TX(speed, ratelimit_bytes),
};

#define VIRTNET_Q_TYPE_RX 0
#define VIRTNET_Q_TYPE_TX 1
#define VIRTNET_Q_TYPE_CQ 2

struct virtnet_interrupt_coalesce {
	u32 max_packets;
	u32 max_usecs;
};

struct virtnet_coal_node {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
	struct virtio_net_ctrl_coal_vq coal_vqs;
	struct list_head list;
};

/* Internal representation of a send virtqueue */
struct send_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* TX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of the send queue: output.$index */
	char name[40];

	struct virtnet_sq_stats stats;

	struct virtnet_interrupt_coalesce intr_coal;

	struct napi_struct napi;

	struct {
		struct xsk_buff_pool   __rcu *pool;
		struct virtnet_xsk_hdr __rcu *hdr;

		struct page **pgs;
		u64           npgs;

		unsigned long          state;
		u64                    hdr_con;
		u64                    hdr_pro;
		u64                    hdr_n;
		struct xdp_desc        last_desc;
		bool                   wait_slot;
		/* tx interrupt issues
		 *   1. that may be lost
		 *   2. that too slow, 200/s or delay 10ms
		 *
		 * timer for:
		 * 1. recycle the desc.(no check for performance, see below)
		 * 2. check the nic ring is avali. when nic ring is full
		 *
		 * Here, the regular check is performed for dev full. The
		 * application layer must ensure that the number of cq is
		 * sufficient, otherwise there may be insufficient cq in use.
		 *
		 */
		struct hrtimer          timer;
	} xsk;

	/* Record whether sq is in reset state. */
	bool reset;
};

/* Internal representation of a receive virtqueue */
struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* The number of rx notifications */
	u16 calls;

	/* Is dynamic interrupt moderation enabled? */
	bool dim_enabled;

	/* Dynamic Interrupt Moderation */
	struct dim dim;

	u32 packets_in_napi;

	struct virtnet_interrupt_coalesce intr_coal;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[40];

	struct xdp_rxq_info xdp_rxq;
};

/* This structure can contain rss message with maximum settings for indirection table and keysize
 * Note, that default structure that describes RSS configuration virtio_net_rss_config
 * contains same info but can't handle table values.
 * In any case, structure would be passed to virtio hw through sg_buf split by parts
 * because table sizes may be differ according to the device configuration.
 */
#define VIRTIO_NET_RSS_MAX_KEY_SIZE     40
struct virtio_net_ctrl_rss {
	u32 hash_types;
	u16 indirection_table_mask;
	u16 unclassified_queue;
	u16 hash_cfg_reserved; /* for HASH_CONFIG (see virtio_net_hash_config for details) */
	u16 max_tx_vq;
	u8 hash_key_length;
	u8 key[VIRTIO_NET_RSS_MAX_KEY_SIZE];

	u16 *indirection_table;
};

/* Control VQ buffers: protected by the rtnl lock */
struct control_buf {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* xdp_queue_pairs may be 0, when xdp is already loaded. So add this. */
	bool xdp_enabled;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Host supports rss and/or hash report */
	bool has_rss;
	bool has_rss_hash_report;
	u8 rss_key_size;
	u16 rss_indir_table_size;
	u32 rss_hash_types_supported;
	u32 rss_hash_types_saved;
	struct virtio_net_ctrl_rss rss;

	/* Has control virtqueue */
	bool has_cvq;

	/* Lock to protect the control VQ */
	struct mutex cvq_lock;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for delayed refilling if we run low on memory. */
	struct delayed_work refill;

	/* Is delayed refill enabled? */
	bool refill_enabled;

	/* The lock to synchronize the access to refill_enabled */
	spinlock_t refill_lock;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Work struct for setting rx mode */
	struct work_struct rx_mode_work;

	/* OK to queue work setting RX mode? */
	bool rx_mode_work_enabled;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	/* Is rx dynamic interrupt moderation enabled? */
	bool rx_dim_enabled;

	/* Interrupt coalescing settings */
	struct virtnet_interrupt_coalesce intr_coal_tx;
	struct virtnet_interrupt_coalesce intr_coal_rx;

	/* Used by dim cmds for concurrent delivery */
	int dim_cmd_nums;
	struct delayed_work get_cvq;

	/* OK to queue work getting cvq response? */
	bool get_cvq_work_enabled;

	/* Free nodes for dim filled by rx_dim_work. */
	struct mutex coal_free_lock;
	struct list_head coal_free_list;

	unsigned long guest_offloads;
	unsigned long guest_offloads_capable;

	/* failover when STANDBY feature enabled */
	struct failover *failover;

	u64 device_stats_cap;
};

struct padded_vnet_hdr {
	struct virtio_net_hdr_v1_hash hdr;
	/*
	 * hdr is in a separate sg buffer, and data sg buffer shares same page
	 * with this header sg. This padding makes next sg 16 byte aligned
	 * after the header.
	 */
	char padding[12];
};

static void __free_old_xmit_ptr(struct send_queue *sq, bool in_napi,
				bool xsk_wakeup,
				unsigned int *_packets, unsigned int *_bytes);
static void free_old_xmit_skbs(struct send_queue *sq, bool in_napi);
static int virtnet_xsk_run(struct send_queue *sq,
			   struct xsk_buff_pool *pool, int budget);
static void virtnet_rq_free_unused_buf(struct virtqueue *vq, void *buf);
static void virtnet_sq_free_unused_buf(struct virtqueue *vq, void *buf);

static int rss_indirection_table_alloc(struct virtio_net_ctrl_rss *rss, u16 indir_table_size)
{
	if (!indir_table_size) {
		rss->indirection_table = NULL;
		return 0;
	}

	rss->indirection_table = kmalloc_array(indir_table_size, sizeof(u16), GFP_KERNEL);
	if (!rss->indirection_table)
		return -ENOMEM;

	return 0;
}

static void rss_indirection_table_free(struct virtio_net_ctrl_rss *rss)
{
	kfree(rss->indirection_table);
}

static bool is_xdp_frame(void *ptr)
{
	return (unsigned long)ptr & VIRTIO_XDP_FLAG;
}

static void *xdp_to_ptr(struct virtnet_xdp_type *ptr)
{
	return (void *)((unsigned long)ptr | VIRTIO_XDP_FLAG);
}

static struct virtnet_xdp_type *ptr_to_xtype(void *ptr)
{
	return (struct virtnet_xdp_type *)((unsigned long)ptr & ~VIRTIO_XDP_FLAG);
}

static void *xtype_got_ptr(struct virtnet_xdp_type *xdptype)
{
	return (char *)xdptype + xdptype->offset;
}

/* Converting between virtqueue no. and kernel tx/rx queue no.
 * 0:rx0 1:tx0 2:rx1 3:tx1 ... 2N:rxN 2N+1:txN 2N+2:cvq
 */
static int vq2txq(struct virtqueue *vq)
{
	return (vq->index - 1) / 2;
}

static int txq2vq(int txq)
{
	return txq * 2 + 1;
}

static int vq2rxq(struct virtqueue *vq)
{
	return vq->index / 2;
}

static int rxq2vq(int rxq)
{
	return rxq * 2;
}

static int vq_type(struct virtnet_info *vi, int qid)
{
	if (qid == vi->max_queue_pairs * 2)
		return VIRTNET_Q_TYPE_CQ;

	if (qid % 2)
		return VIRTNET_Q_TYPE_TX;

	return VIRTNET_Q_TYPE_RX;
}

static inline struct virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(struct sk_buff *skb)
{
	return (struct virtio_net_hdr_mrg_rxbuf *)skb->cb;
}

/*
 * private is used to chain pages for big packets, put the whole
 * most recent used list in the beginning for reuse
 */
static void give_pages(struct receive_queue *rq, struct page *page)
{
	struct page *end;

	/* Find end of list, sew whole thing into vi->rq.pages. */
	for (end = page; end->private; end = (struct page *)end->private);
	end->private = (unsigned long)rq->pages;
	rq->pages = page;
}

static struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask)
{
	struct page *p = rq->pages;

	if (p) {
		rq->pages = (struct page *)p->private;
		/* clear private here, it is used to chain pages */
		p->private = 0;
	} else
		p = alloc_page(gfp_mask);
	return p;
}

static void enable_delayed_refill(struct virtnet_info *vi)
{
	spin_lock_bh(&vi->refill_lock);
	vi->refill_enabled = true;
	spin_unlock_bh(&vi->refill_lock);
}

static void disable_delayed_refill(struct virtnet_info *vi)
{
	spin_lock_bh(&vi->refill_lock);
	vi->refill_enabled = false;
	spin_unlock_bh(&vi->refill_lock);
}

static void enable_rx_mode_work(struct virtnet_info *vi)
{
	rtnl_lock();
	vi->rx_mode_work_enabled = true;
	rtnl_unlock();
}

static void disable_rx_mode_work(struct virtnet_info *vi)
{
	rtnl_lock();
	vi->rx_mode_work_enabled = false;
	rtnl_unlock();
}

static void virtqueue_napi_schedule(struct napi_struct *napi,
				    struct virtqueue *vq)
{
	if (napi_schedule_prep(napi)) {
		virtqueue_disable_cb(vq);
		__napi_schedule(napi);
	}
}

static bool virtqueue_napi_complete(struct napi_struct *napi,
				    struct virtqueue *vq, int processed)
{
	int opaque;

	opaque = virtqueue_enable_cb_prepare(vq);
	if (napi_complete_done(napi, processed)) {
		if (unlikely(virtqueue_poll(vq, opaque)))
			virtqueue_napi_schedule(napi, vq);
		else
			return true;
	} else {
		virtqueue_disable_cb(vq);
	}

	return false;
}

static void skb_xmit_done(struct virtqueue *vq)
{
	struct virtnet_info *vi = vq->vdev->priv;
	struct napi_struct *napi = &vi->sq[vq2txq(vq)].napi;

	/* Suppress further interrupts. */
	virtqueue_disable_cb(vq);

	if (napi->weight)
		virtqueue_napi_schedule(napi, vq);
	else
		/* We were probably waiting for more output buffers. */
		netif_wake_subqueue(vi->dev, vq2txq(vq));
}

static void virtnet_sq_stop_check(struct send_queue *sq, bool in_napi)
{
	struct virtnet_info *vi = sq->vq->vdev->priv;
	struct net_device *dev = vi->dev;
	int qnum = sq - vi->sq;

	/* If running out of space, stop queue to avoid getting packets that we
	 * are then unable to transmit.
	 * An alternative would be to force queuing layer to requeue the skb by
	 * returning NETDEV_TX_BUSY. However, NETDEV_TX_BUSY should not be
	 * returned in a normal path of operation: it means that driver is not
	 * maintaining the TX queue stop/start state properly, and causes
	 * the stack to do a non-trivial amount of useless work.
	 * Since most packets only take 1 or 2 ring slots, stopping the queue
	 * early means 16 slots are typically wasted.
	 */

	if (sq->vq->num_free < 2 + MAX_SKB_FRAGS) {
		netif_stop_subqueue(dev, qnum);
		if (sq->napi.weight) {
			if (unlikely(!virtqueue_enable_cb_delayed(sq->vq)))
				virtqueue_napi_schedule(&sq->napi, sq->vq);
		} else if (unlikely(!virtqueue_enable_cb_delayed(sq->vq))) {
			/* More just got used, free them then recheck. */
			free_old_xmit_skbs(sq, in_napi);
			if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS) {
				netif_start_subqueue(dev, qnum);
				virtqueue_disable_cb(sq->vq);
			}
		}
	}
}

#define MRG_CTX_HEADER_SHIFT 22
static void *mergeable_len_to_ctx(unsigned int truesize,
				  unsigned int headroom)
{
	return (void *)(unsigned long)((headroom << MRG_CTX_HEADER_SHIFT) | truesize);
}

static unsigned int mergeable_ctx_to_headroom(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx >> MRG_CTX_HEADER_SHIFT;
}

static unsigned int mergeable_ctx_to_truesize(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}

static int check_mergeable_len(struct net_device *dev, void *mrg_ctx,
			       unsigned int len)
{
	unsigned int headroom, tailroom, room, truesize;

	truesize = mergeable_ctx_to_truesize(mrg_ctx);
	headroom = mergeable_ctx_to_headroom(mrg_ctx);
	tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	room = SKB_DATA_ALIGN(headroom + tailroom);

	if (len > truesize - room) {
		pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
			 dev->name, len, (unsigned long)(truesize - room));
		dev->stats.rx_length_errors++;
		return -1;
	}

	return 0;
}

/* Called from bottom half context */
static struct sk_buff *page_to_skb(struct virtnet_info *vi,
				   struct receive_queue *rq,
				   struct page *page, unsigned int offset,
				   unsigned int len, unsigned int truesize,
				   bool hdr_valid, unsigned int metasize,
				   unsigned int headroom)
{
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	unsigned int copy, hdr_len, hdr_padded_len;
	struct page *page_to_free = NULL;
	int tailroom, shinfo_size;
	char *p, *hdr_p, *buf;

	p = page_address(page) + offset;
	hdr_p = p;

	hdr_len = vi->hdr_len;
	if (vi->mergeable_rx_bufs)
		hdr_padded_len = hdr_len;
	else
		hdr_padded_len = sizeof(struct padded_vnet_hdr);

	/* If headroom is not 0, there is an offset between the beginning of the
	 * data and the allocated space, otherwise the data and the allocated
	 * space are aligned.
	 *
	 * Buffers with headroom use PAGE_SIZE as alloc size, see
	 * add_recvbuf_mergeable() + get_mergeable_buf_len()
	 */
	truesize = headroom ? PAGE_SIZE : truesize;
	tailroom = truesize - len - headroom - (hdr_padded_len - hdr_len);
	buf = p - headroom;

	len -= hdr_len;
	offset += hdr_padded_len;
	p += hdr_padded_len;

	shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	/* copy small packet so we can reuse these pages */
	if (!NET_IP_ALIGN && len > GOOD_COPY_LEN && tailroom >= shinfo_size) {
		skb = build_skb(buf, truesize);
		if (unlikely(!skb))
			return NULL;

		skb_reserve(skb, p - buf);
		skb_put(skb, len);

		page = (struct page *)page->private;
		if (page)
			give_pages(rq, page);
		goto ok;
	}

	/* copy small packet so we can reuse these pages for small data */
	skb = napi_alloc_skb(&rq->napi, GOOD_COPY_LEN);
	if (unlikely(!skb))
		return NULL;

	/* Copy all frame if it fits skb->head, otherwise
	 * we let virtio_net_hdr_to_skb() and GRO pull headers as needed.
	 */
	if (len <= skb_tailroom(skb))
		copy = len;
	else
		copy = ETH_HLEN + metasize;
	skb_put_data(skb, p, copy);

	len -= copy;
	offset += copy;

	if (vi->mergeable_rx_bufs) {
		if (len)
			skb_add_rx_frag(skb, 0, page, offset, len, truesize);
		else
			page_to_free = page;
		goto ok;
	}

	/*
	 * Verify that we can indeed put this data into a skb.
	 * This is here to handle cases when the device erroneously
	 * tries to receive more than is possible. This is usually
	 * the case of a broken device.
	 */
	if (unlikely(len > MAX_SKB_FRAGS * PAGE_SIZE)) {
		net_dbg_ratelimited("%s: too much data\n", skb->dev->name);
		dev_kfree_skb(skb);
		return NULL;
	}
	BUG_ON(offset >= PAGE_SIZE);
	while (len) {
		unsigned int frag_size = min((unsigned)PAGE_SIZE - offset, len);
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page, offset,
				frag_size, truesize);
		len -= frag_size;
		page = (struct page *)page->private;
		offset = 0;
	}

	if (page)
		give_pages(rq, page);

ok:
	/* hdr_valid means no XDP, so we can copy the vnet header */
	if (hdr_valid) {
		hdr = skb_vnet_hdr(skb);
		memcpy(hdr, hdr_p, hdr_len);
	}
	if (page_to_free)
		put_page(page_to_free);

	if (metasize) {
		__skb_pull(skb, metasize);
		skb_metadata_set(skb, metasize);
	}

	return skb;
}

static int __virtnet_xdp_xmit_one(struct virtnet_info *vi,
				   struct send_queue *sq,
				   struct xdp_frame *xdpf)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	struct virtnet_xdp_type *xdptype;
	int err;

	if (unlikely(xdpf->headroom < vi->hdr_len + sizeof(*xdptype)))
		return -EOVERFLOW;

	xdptype = (struct virtnet_xdp_type *)(xdpf + 1);
	xdptype->offset = (char *)xdpf - (char *)xdptype;
	xdptype->type = XDP_TYPE_TX;

	/* Make room for virtqueue hdr (also change xdpf->headroom?) */
	xdpf->data -= vi->hdr_len;
	/* Zero header and leave csum up to XDP layers */
	hdr = xdpf->data;
	memset(hdr, 0, vi->hdr_len);
	xdpf->len   += vi->hdr_len;

	sg_init_one(sq->sg, xdpf->data, xdpf->len);

	err = virtqueue_add_outbuf(sq->vq, sq->sg, 1, xdp_to_ptr(xdptype),
				   GFP_ATOMIC);
	if (unlikely(err))
		return -ENOSPC; /* Caller handle free/refcnt */

	return 0;
}

/* when vi->curr_queue_pairs > nr_cpu_ids, the txq/sq is only used for xdp tx on
 * the current cpu, so it does not need to be locked.
 *
 * Here we use marco instead of inline functions because we have to deal with
 * three issues at the same time: 1. the choice of sq. 2. judge and execute the
 * lock/unlock of txq 3. make sparse happy. It is difficult for two inline
 * functions to perfectly solve these three problems at the same time.
 */
#define virtnet_xdp_get_sq(vi) ({                                       \
	struct netdev_queue *txq;                                       \
	typeof(vi) v = (vi);                                            \
	unsigned int qp;                                                \
									\
	if (v->curr_queue_pairs > nr_cpu_ids) {                         \
		qp = v->curr_queue_pairs - v->xdp_queue_pairs;          \
		qp += smp_processor_id();                               \
		txq = netdev_get_tx_queue(v->dev, qp);                  \
		__netif_tx_acquire(txq);                                \
	} else {                                                        \
		qp = smp_processor_id() % v->curr_queue_pairs;          \
		txq = netdev_get_tx_queue(v->dev, qp);                  \
		__netif_tx_lock(txq, raw_smp_processor_id());           \
	}                                                               \
	v->sq + qp;                                                     \
})

#define virtnet_xdp_put_sq(vi, q) {                                     \
	struct netdev_queue *txq;                                       \
	typeof(vi) v = (vi);                                            \
									\
	txq = netdev_get_tx_queue(v->dev, (q) - v->sq);                 \
	if (v->curr_queue_pairs > nr_cpu_ids)                           \
		__netif_tx_release(txq);                                \
	else                                                            \
		__netif_tx_unlock(txq);                                 \
}

static int virtnet_xdp_xmit(struct net_device *dev,
			    int n, struct xdp_frame **frames, u32 flags)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct receive_queue *rq = vi->rq;
	struct bpf_prog *xdp_prog;
	struct send_queue *sq;
	int packets = 0;
	int bytes = 0;
	int drops = 0;
	int kicks = 0;
	int ret, err;
	int i;

	/* Only allow ndo_xdp_xmit if XDP is loaded on dev, as this
	 * indicate XDP resources have been successfully allocated.
	 */
	xdp_prog = rcu_access_pointer(rq->xdp_prog);
	if (!xdp_prog)
		return -ENXIO;

	sq = virtnet_xdp_get_sq(vi);

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK)) {
		ret = -EINVAL;
		drops = n;
		goto out;
	}

	__free_old_xmit_ptr(sq, false, true, &packets, &bytes);

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];

		err = __virtnet_xdp_xmit_one(vi, sq, xdpf);
		if (err) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
		}
	}
	ret = n - drops;

	if (flags & XDP_XMIT_FLUSH) {
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq))
			kicks = 1;
	}
out:
	u64_stats_update_begin(&sq->stats.syncp);
	u64_stats_add(&sq->stats.bytes, bytes);
	u64_stats_add(&sq->stats.packets, packets);
	u64_stats_add(&sq->stats.xdp_tx, n);
	u64_stats_add(&sq->stats.xdp_tx_drops, drops);
	u64_stats_add(&sq->stats.kicks, kicks);
	u64_stats_update_end(&sq->stats.syncp);

	virtnet_xdp_put_sq(vi, sq);
	return ret;
}

static unsigned int virtnet_get_headroom(struct virtnet_info *vi)
{
	return vi->xdp_enabled ? VIRTIO_XDP_HEADROOM : 0;
}

/* We copy the packet for XDP in the following cases:
 *
 * 1) Packet is scattered across multiple rx buffers.
 * 2) Headroom space is insufficient.
 *
 * This is inefficient but it's a temporary condition that
 * we hit right after XDP is enabled and until queue is refilled
 * with large buffers with sufficient headroom - so it should affect
 * at most queue size packets.
 * Afterwards, the conditions to enable
 * XDP should preclude the underlying device from sending packets
 * across multiple buffers (num_buf > 1), and we make sure buffers
 * have enough headroom.
 */
static struct page *xdp_linearize_page(struct net_device *dev,
				       struct receive_queue *rq,
				       u16 *num_buf,
				       struct page *p,
				       int offset,
				       int page_off,
				       unsigned int *len)
{
	int tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct page *page;

	if (page_off + *len + tailroom > PAGE_SIZE)
		return NULL;

	page = alloc_page(GFP_ATOMIC);
	if (!page)
		return NULL;

	memcpy(page_address(page) + page_off, page_address(p) + offset, *len);
	page_off += *len;

	/* Only mergeable mode can go inside this while loop. In small mode,
	 * *num_buf == 1, so it cannot go inside.
	 */
	while (--*num_buf) {
		unsigned int buflen;
		void *buf;
		void *ctx;
		int off;

		buf = virtqueue_get_buf_ctx(rq->vq, &buflen, &ctx);
		if (unlikely(!buf))
			goto err_buf;

		p = virt_to_head_page(buf);
		off = buf - page_address(p);

		if (check_mergeable_len(dev, ctx, buflen)) {
			put_page(p);
			goto err_buf;
		}

		/* guard against a misconfigured or uncooperative backend that
		 * is sending packet larger than the MTU.
		 */
		if ((page_off + buflen + tailroom) > PAGE_SIZE) {
			put_page(p);
			goto err_buf;
		}

		memcpy(page_address(page) + page_off,
		       page_address(p) + off, buflen);
		page_off += buflen;
		put_page(p);
	}

	/* Headroom does not contribute to packet length */
	*len = page_off - VIRTIO_XDP_HEADROOM;
	return page;
err_buf:
	__free_pages(page, 0);
	return NULL;
}

static struct sk_buff *receive_small(struct net_device *dev,
				     struct virtnet_info *vi,
				     struct receive_queue *rq,
				     void *buf, void *ctx,
				     unsigned int len,
				     unsigned int *xdp_xmit,
				     struct virtnet_rq_stats *stats)
{
	struct sk_buff *skb;
	struct bpf_prog *xdp_prog;
	unsigned int xdp_headroom = (unsigned long)ctx;
	unsigned int header_offset = VIRTNET_RX_PAD + xdp_headroom;
	unsigned int headroom = vi->hdr_len + header_offset;
	unsigned int buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
			      SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct page *page = virt_to_head_page(buf);
	unsigned int delta = 0;
	struct page *xdp_page;
	int err;
	unsigned int metasize = 0;

	len -= vi->hdr_len;
	u64_stats_add(&stats->bytes, len);

	if (unlikely(len > GOOD_PACKET_LEN)) {
		pr_debug("%s: rx error: len %u exceeds max size %d\n",
			 dev->name, len, GOOD_PACKET_LEN);
		dev->stats.rx_length_errors++;
		goto err_len;
	}
	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct virtio_net_hdr_mrg_rxbuf *hdr = buf + header_offset;
		struct xdp_frame *xdpf;
		struct xdp_buff xdp;
		void *orig_data;
		u32 act;

		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* Partially checksummed packets must be dropped. */
		if (unlikely(hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
			goto err_xdp;

		if (unlikely(xdp_headroom < virtnet_get_headroom(vi))) {
			int offset = buf - page_address(page) + header_offset;
			unsigned int tlen = len + vi->hdr_len;
			u16 num_buf = 1;

			xdp_headroom = virtnet_get_headroom(vi);
			header_offset = VIRTNET_RX_PAD + xdp_headroom;
			headroom = vi->hdr_len + header_offset;
			buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
				 SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
			xdp_page = xdp_linearize_page(dev, rq, &num_buf, page,
						      offset, header_offset,
						      &tlen);
			if (!xdp_page)
				goto err_xdp;

			buf = page_address(xdp_page);
			put_page(page);
			page = xdp_page;
		}

		xdp.data_hard_start = buf + VIRTNET_RX_PAD + vi->hdr_len;
		xdp.data = xdp.data_hard_start + xdp_headroom;
		xdp.data_end = xdp.data + len;
		xdp.data_meta = xdp.data;
		xdp.rxq = &rq->xdp_rxq;
		xdp.frame_sz = buflen;
		orig_data = xdp.data;
		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		u64_stats_inc(&stats->xdp_packets);

		switch (act) {
		case XDP_PASS:
			/* Recalculate length in case bpf program changed it */
			delta = orig_data - xdp.data;
			len = xdp.data_end - xdp.data;
			metasize = xdp.data - xdp.data_meta;
			break;
		case XDP_TX:
			u64_stats_inc(&stats->xdp_tx);
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf))
				goto err_xdp;
			err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
			if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			u64_stats_inc(&stats->xdp_redirects);
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err)
				goto err_xdp;
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
		case XDP_DROP:
			goto err_xdp;
		}
	}
	rcu_read_unlock();

	skb = build_skb(buf, buflen);
	if (!skb) {
		put_page(page);
		goto err;
	}
	skb_reserve(skb, headroom - delta);
	skb_put(skb, len);
	if (!xdp_prog) {
		buf += header_offset;
		memcpy(skb_vnet_hdr(skb), buf, vi->hdr_len);
	} /* keep zeroed vnet hdr since XDP is loaded */

	if (metasize)
		skb_metadata_set(skb, metasize);

err:
	return skb;

err_xdp:
	rcu_read_unlock();
	u64_stats_inc(&stats->xdp_drops);
err_len:
	u64_stats_inc(&stats->drops);
	put_page(page);
xdp_xmit:
	return NULL;
}

static struct sk_buff *receive_big(struct net_device *dev,
				   struct virtnet_info *vi,
				   struct receive_queue *rq,
				   void *buf,
				   unsigned int len,
				   struct virtnet_rq_stats *stats)
{
	struct page *page = buf;
	struct sk_buff *skb =
		page_to_skb(vi, rq, page, 0, len, PAGE_SIZE, true, 0, 0);

	u64_stats_add(&stats->bytes, len - vi->hdr_len);
	if (unlikely(!skb))
		goto err;

	return skb;

err:
	u64_stats_inc(&stats->drops);
	give_pages(rq, page);
	return NULL;
}

static struct sk_buff *receive_mergeable(struct net_device *dev,
					 struct virtnet_info *vi,
					 struct receive_queue *rq,
					 void *buf,
					 void *ctx,
					 unsigned int len,
					 unsigned int *xdp_xmit,
					 struct virtnet_rq_stats *stats)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = buf;
	u16 num_buf = virtio16_to_cpu(vi->vdev, hdr->num_buffers);
	struct page *page = virt_to_head_page(buf);
	int offset = buf - page_address(page);
	struct sk_buff *head_skb, *curr_skb;
	struct bpf_prog *xdp_prog;
	unsigned int truesize = mergeable_ctx_to_truesize(ctx);
	unsigned int headroom = mergeable_ctx_to_headroom(ctx);
	unsigned int metasize = 0;
	unsigned int frame_sz;
	int err;

	head_skb = NULL;
	u64_stats_add(&stats->bytes, len - vi->hdr_len);

	if (unlikely(len > truesize)) {
		pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
			 dev->name, len, (unsigned long)ctx);
		dev->stats.rx_length_errors++;
		goto err_skb;
	}
	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct xdp_frame *xdpf;
		struct page *xdp_page;
		struct xdp_buff xdp;
		void *data;
		u32 act;

		/* Transient failure which in theory could occur if
		 * in-flight packets from before XDP was enabled reach
		 * the receive path after XDP is loaded.
		 */
		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* Partially checksummed packets must be dropped. */
		if (unlikely(hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
			goto err_xdp;

		/* Buffers with headroom use PAGE_SIZE as alloc size,
		 * see add_recvbuf_mergeable() + get_mergeable_buf_len()
		 */
		frame_sz = headroom ? PAGE_SIZE : truesize;

		/* This happens when rx buffer size is underestimated
		 * or headroom is not enough because of the buffer
		 * was refilled before XDP is set. This should only
		 * happen for the first several packets, so we don't
		 * care much about its performance.
		 */
		if (unlikely(num_buf > 1 ||
			     headroom < virtnet_get_headroom(vi))) {
			/* linearize data for XDP */
			xdp_page = xdp_linearize_page(dev, rq, &num_buf,
						      page, offset,
						      VIRTIO_XDP_HEADROOM,
						      &len);
			frame_sz = PAGE_SIZE;

			if (!xdp_page)
				goto err_xdp;
			offset = VIRTIO_XDP_HEADROOM;
		} else {
			xdp_page = page;
		}

		/* Allow consuming headroom but reserve enough space to push
		 * the descriptor on if we get an XDP_TX return code.
		 */
		data = page_address(xdp_page) + offset;
		xdp.data_hard_start = data - VIRTIO_XDP_HEADROOM + vi->hdr_len;
		xdp.data = data + vi->hdr_len;
		xdp.data_end = xdp.data + (len - vi->hdr_len);
		xdp.data_meta = xdp.data;
		xdp.rxq = &rq->xdp_rxq;
		xdp.frame_sz = frame_sz - vi->hdr_len;

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		u64_stats_inc(&stats->xdp_packets);

		switch (act) {
		case XDP_PASS:
			metasize = xdp.data - xdp.data_meta;

			/* recalculate offset to account for any header
			 * adjustments and minus the metasize to copy the
			 * metadata in page_to_skb(). Note other cases do not
			 * build an skb and avoid using offset
			 */
			offset = xdp.data - page_address(xdp_page) -
				 vi->hdr_len - metasize;

			/* recalculate len if xdp.data, xdp.data_end or
			 * xdp.data_meta were adjusted
			 */
			len = xdp.data_end - xdp.data + vi->hdr_len + metasize;
			/* We can only create skb based on xdp_page. */
			if (unlikely(xdp_page != page)) {
				rcu_read_unlock();
				put_page(page);
				head_skb = page_to_skb(vi, rq, xdp_page, offset,
						       len, PAGE_SIZE, false,
						       metasize,
						       VIRTIO_XDP_HEADROOM);
				return head_skb;
			}
			break;
		case XDP_TX:
			u64_stats_inc(&stats->xdp_tx);
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf))
				goto err_xdp;
			err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
			if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			u64_stats_inc(&stats->xdp_redirects);
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_DROP:
			if (unlikely(xdp_page != page))
				__free_pages(xdp_page, 0);
			goto err_xdp;
		}
	}
	rcu_read_unlock();

	head_skb = page_to_skb(vi, rq, page, offset, len, truesize, !xdp_prog,
			       metasize, headroom);
	curr_skb = head_skb;

	if (unlikely(!curr_skb))
		goto err_skb;
	while (--num_buf) {
		int num_skb_frags;

		buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers out of %d missing\n",
				 dev->name, num_buf,
				 virtio16_to_cpu(vi->vdev,
						 hdr->num_buffers));
			dev->stats.rx_length_errors++;
			goto err_buf;
		}

		u64_stats_add(&stats->bytes, len);
		page = virt_to_head_page(buf);

		truesize = mergeable_ctx_to_truesize(ctx);
		if (unlikely(len > truesize)) {
			pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
				 dev->name, len, (unsigned long)ctx);
			dev->stats.rx_length_errors++;
			goto err_skb;
		}

		num_skb_frags = skb_shinfo(curr_skb)->nr_frags;
		if (unlikely(num_skb_frags == MAX_SKB_FRAGS)) {
			struct sk_buff *nskb = alloc_skb(0, GFP_ATOMIC);

			if (unlikely(!nskb))
				goto err_skb;
			if (curr_skb == head_skb)
				skb_shinfo(curr_skb)->frag_list = nskb;
			else
				curr_skb->next = nskb;
			curr_skb = nskb;
			head_skb->truesize += nskb->truesize;
			num_skb_frags = 0;
		}
		if (curr_skb != head_skb) {
			head_skb->data_len += len;
			head_skb->len += len;
			head_skb->truesize += truesize;
		}
		offset = buf - page_address(page);
		if (skb_can_coalesce(curr_skb, num_skb_frags, page, offset)) {
			put_page(page);
			skb_coalesce_rx_frag(curr_skb, num_skb_frags - 1,
					     len, truesize);
		} else {
			skb_add_rx_frag(curr_skb, num_skb_frags, page,
					offset, len, truesize);
		}
	}

	ewma_pkt_len_add(&rq->mrg_avg_pkt_len, head_skb->len);
	return head_skb;

err_xdp:
	rcu_read_unlock();
	u64_stats_inc(&stats->xdp_drops);
err_skb:
	put_page(page);
	while (num_buf-- > 1) {
		buf = virtqueue_get_buf(rq->vq, &len);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers missing\n",
				 dev->name, num_buf);
			dev->stats.rx_length_errors++;
			break;
		}
		u64_stats_add(&stats->bytes, len);
		page = virt_to_head_page(buf);
		put_page(page);
	}
err_buf:
	u64_stats_inc(&stats->drops);
	dev_kfree_skb(head_skb);
xdp_xmit:
	return NULL;
}

static void virtio_skb_set_hash(const struct virtio_net_hdr_v1_hash *hdr_hash,
				struct sk_buff *skb)
{
	enum pkt_hash_types rss_hash_type;

	if (!hdr_hash || !skb)
		return;

	switch (__le16_to_cpu(hdr_hash->hash_report)) {
	case VIRTIO_NET_HASH_REPORT_TCPv4:
	case VIRTIO_NET_HASH_REPORT_UDPv4:
	case VIRTIO_NET_HASH_REPORT_TCPv6:
	case VIRTIO_NET_HASH_REPORT_UDPv6:
	case VIRTIO_NET_HASH_REPORT_TCPv6_EX:
	case VIRTIO_NET_HASH_REPORT_UDPv6_EX:
		rss_hash_type = PKT_HASH_TYPE_L4;
		break;
	case VIRTIO_NET_HASH_REPORT_IPv4:
	case VIRTIO_NET_HASH_REPORT_IPv6:
	case VIRTIO_NET_HASH_REPORT_IPv6_EX:
		rss_hash_type = PKT_HASH_TYPE_L3;
		break;
	case VIRTIO_NET_HASH_REPORT_NONE:
	default:
		rss_hash_type = PKT_HASH_TYPE_NONE;
	}
	skb_set_hash(skb, __le32_to_cpu(hdr_hash->hash_value), rss_hash_type);
}

static void receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
			void *buf, unsigned int len, void **ctx,
			unsigned int *xdp_xmit,
			struct virtnet_rq_stats *stats)
{
	struct net_device *dev = vi->dev;
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	u8 flags;

	if (unlikely(len < vi->hdr_len + ETH_HLEN)) {
		pr_debug("%s: short packet %i\n", dev->name, len);
		dev->stats.rx_length_errors++;
		if (vi->mergeable_rx_bufs) {
			put_page(virt_to_head_page(buf));
		} else if (vi->big_packets) {
			give_pages(rq, buf);
		} else {
			put_page(virt_to_head_page(buf));
		}
		return;
	}

	/* XDP invalidates virtio-net-hdr. Save flags in advance to
	 * determine checksum information before submitting it to netdev.
	 */

	if (vi->mergeable_rx_bufs) {
		flags = ((struct virtio_net_hdr_mrg_rxbuf *)buf)->hdr.flags;
		skb = receive_mergeable(dev, vi, rq, buf, ctx, len, xdp_xmit,
					stats);
	} else if (vi->big_packets) {
		void *p = page_address((struct page *)buf);
		flags = ((struct virtio_net_hdr_mrg_rxbuf *)p)->hdr.flags;
		skb = receive_big(dev, vi, rq, buf, len, stats);
	} else {
		void *p;
		p = buf + VIRTNET_RX_PAD + (unsigned long)ctx;
		flags = ((struct virtio_net_hdr_mrg_rxbuf *)p)->hdr.flags;
		skb = receive_small(dev, vi, rq, buf, ctx, len, xdp_xmit, stats);
	}

	if (unlikely(!skb))
		return;

	hdr = skb_vnet_hdr(skb);
	if (dev->features & NETIF_F_RXHASH && vi->has_rss_hash_report)
		virtio_skb_set_hash((const struct virtio_net_hdr_v1_hash *)hdr, skb);

	if (flags & VIRTIO_NET_HDR_F_DATA_VALID)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (virtio_net_hdr_to_skb(skb, &hdr->hdr,
				  virtio_is_little_endian(vi->vdev))) {
		net_warn_ratelimited("%s: bad gso: type: %u, size: %u\n",
				     dev->name, hdr->hdr.gso_type,
				     hdr->hdr.gso_size);
		goto frame_err;
	}

	skb_record_rx_queue(skb, vq2rxq(rq->vq));
	skb->protocol = eth_type_trans(skb, dev);
	pr_debug("Receiving skb proto 0x%04x len %i type %i\n",
		 ntohs(skb->protocol), skb->len, skb->pkt_type);

	napi_gro_receive(&rq->napi, skb);
	return;

frame_err:
	dev->stats.rx_frame_errors++;
	dev_kfree_skb(skb);
}

/* Unlike mergeable buffers, all buffers are allocated to the
 * same size, except for the headroom. For this reason we do
 * not need to use  mergeable_len_to_ctx here - it is enough
 * to store the headroom as the context ignoring the truesize.
 */
static int add_recvbuf_small(struct virtnet_info *vi, struct receive_queue *rq,
			     gfp_t gfp)
{
	struct page_frag *alloc_frag = &rq->alloc_frag;
	char *buf;
	unsigned int xdp_headroom = virtnet_get_headroom(vi);
	void *ctx = (void *)(unsigned long)xdp_headroom;
	int len = vi->hdr_len + VIRTNET_RX_PAD + GOOD_PACKET_LEN + xdp_headroom;
	int err;

	len = SKB_DATA_ALIGN(len) +
	      SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	if (unlikely(!skb_page_frag_refill(len, alloc_frag, gfp)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	get_page(alloc_frag->page);
	alloc_frag->offset += len;
	sg_init_one(rq->sg, buf + VIRTNET_RX_PAD + xdp_headroom,
		    vi->hdr_len + GOOD_PACKET_LEN);
	err = virtqueue_add_inbuf_ctx(rq->vq, rq->sg, 1, buf, ctx, gfp);
	if (err < 0)
		put_page(virt_to_head_page(buf));
	return err;
}

static int add_recvbuf_big(struct virtnet_info *vi, struct receive_queue *rq,
			   gfp_t gfp)
{
	struct page *first, *list = NULL;
	char *p;
	int i, err, offset;

	sg_init_table(rq->sg, MAX_SKB_FRAGS + 2);

	/* page in rq->sg[MAX_SKB_FRAGS + 1] is list tail */
	for (i = MAX_SKB_FRAGS + 1; i > 1; --i) {
		first = get_a_page(rq, gfp);
		if (!first) {
			if (list)
				give_pages(rq, list);
			return -ENOMEM;
		}
		sg_set_buf(&rq->sg[i], page_address(first), PAGE_SIZE);

		/* chain new page in list head to match sg */
		first->private = (unsigned long)list;
		list = first;
	}

	first = get_a_page(rq, gfp);
	if (!first) {
		give_pages(rq, list);
		return -ENOMEM;
	}
	p = page_address(first);

	/* rq->sg[0], rq->sg[1] share the same page */
	/* a separated rq->sg[0] for header - required in case !any_header_sg */
	sg_set_buf(&rq->sg[0], p, vi->hdr_len);

	/* rq->sg[1] for data packet, from offset */
	offset = sizeof(struct padded_vnet_hdr);
	sg_set_buf(&rq->sg[1], p + offset, PAGE_SIZE - offset);

	/* chain first in list head */
	first->private = (unsigned long)list;
	err = virtqueue_add_inbuf(rq->vq, rq->sg, MAX_SKB_FRAGS + 2,
				  first, gfp);
	if (err < 0)
		give_pages(rq, first);

	return err;
}

static unsigned int get_mergeable_buf_len(struct receive_queue *rq,
					  struct ewma_pkt_len *avg_pkt_len,
					  unsigned int room)
{
	struct virtnet_info *vi = rq->vq->vdev->priv;
	const size_t hdr_len = vi->hdr_len;
	unsigned int len;

	if (room)
		return PAGE_SIZE - room;

	len = hdr_len +	clamp_t(unsigned int, ewma_pkt_len_read(avg_pkt_len),
				rq->min_buf_len, PAGE_SIZE - hdr_len);

	return ALIGN(len, L1_CACHE_BYTES);
}

static int add_recvbuf_mergeable(struct virtnet_info *vi,
				 struct receive_queue *rq, gfp_t gfp)
{
	struct page_frag *alloc_frag = &rq->alloc_frag;
	unsigned int headroom = virtnet_get_headroom(vi);
	unsigned int tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	unsigned int room = SKB_DATA_ALIGN(headroom + tailroom);
	char *buf;
	void *ctx;
	int err;
	unsigned int len, hole;

	/* Extra tailroom is needed to satisfy XDP's assumption. This
	 * means rx frags coalescing won't work, but consider we've
	 * disabled GSO for XDP, it won't be a big issue.
	 */
	len = get_mergeable_buf_len(rq, &rq->mrg_avg_pkt_len, room);
	if (unlikely(!skb_page_frag_refill(len + room, alloc_frag, gfp)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	buf += headroom; /* advance address leaving hole at front of pkt */
	get_page(alloc_frag->page);
	alloc_frag->offset += len + room;
	hole = alloc_frag->size - alloc_frag->offset;
	if (hole < len + room) {
		/* To avoid internal fragmentation, if there is very likely not
		 * enough space for another buffer, add the remaining space to
		 * the current buffer.
		 */
		len += hole;
		alloc_frag->offset += hole;
	}

	sg_init_one(rq->sg, buf, len);
	ctx = mergeable_len_to_ctx(len, headroom);
	err = virtqueue_add_inbuf_ctx(rq->vq, rq->sg, 1, buf, ctx, gfp);
	if (err < 0)
		put_page(virt_to_head_page(buf));

	return err;
}

/*
 * Returns false if we couldn't fill entirely (OOM).
 *
 * Normally run in the receive path, but can also be run from ndo_open
 * before we're receiving packets, or from refill_work which is
 * careful to disable receiving (using napi_disable).
 */
static bool try_fill_recv(struct virtnet_info *vi, struct receive_queue *rq,
			  gfp_t gfp)
{
	int err;
	bool oom;

	do {
		if (vi->mergeable_rx_bufs)
			err = add_recvbuf_mergeable(vi, rq, gfp);
		else if (vi->big_packets)
			err = add_recvbuf_big(vi, rq, gfp);
		else
			err = add_recvbuf_small(vi, rq, gfp);

		oom = err == -ENOMEM;
		if (err)
			break;
	} while (rq->vq->num_free);
	if (virtqueue_kick_prepare(rq->vq) && virtqueue_notify(rq->vq)) {
		unsigned long flags;

		flags = u64_stats_update_begin_irqsave(&rq->stats.syncp);
		u64_stats_inc(&rq->stats.kicks);
		u64_stats_update_end_irqrestore(&rq->stats.syncp, flags);
	}

	return !oom;
}

static void virtnet_process_dim_cmd(struct virtnet_info *vi, void *res)
{
	struct virtnet_coal_node *node;
	u16 qnum;

	node = (struct virtnet_coal_node *)res;
	qnum = le16_to_cpu(node->coal_vqs.vqn) / 2;

	vi->rq[qnum].intr_coal.max_usecs =
		le32_to_cpu(node->coal_vqs.coal.max_usecs);
	vi->rq[qnum].intr_coal.max_packets =
		le32_to_cpu(node->coal_vqs.coal.max_packets);
	vi->rq[qnum].dim.state = DIM_START_MEASURE;

	mutex_lock(&vi->coal_free_lock);
	list_add(&node->list, &vi->coal_free_list);
	mutex_unlock(&vi->coal_free_lock);

	vi->dim_cmd_nums--;
}

static int virtnet_cvq_wait_timeout(struct virtnet_info *vi,
				    unsigned long time_end)
{
	if (time_after_eq(jiffies, time_end)) {
		netdev_warn(vi->dev,
			    "Timeout occurs when waiting the CVQ "
			    "request, break the virtio device.\n");
		virtio_break_device(vi->vdev);
		return true;
	}

	return false;
}

/**
 * virtnet_cvq_response - get the response for filled ctrlq requests
 * @poll: keep polling ctrlq when a NULL buffer is obtained.
 * @dim_oneshot: process a dim cmd then exit, excluding user commands.
 *
 * Note that user commands must be processed synchronously
 *  (poll = true, dim_oneshot = false).
 */
static int virtnet_cvq_response(struct virtnet_info *vi,
				bool poll,
				bool dim_oneshot)
{
	unsigned long time_end = jiffies + msecs_to_jiffies(cvq_timeout);
	unsigned tmp;
	void *res;

	while (true) {
		res = virtqueue_get_buf(vi->cvq, &tmp);
		if (virtqueue_is_broken(vi->cvq)) {
			dev_warn(&vi->dev->dev, "Control vq is broken.\n");
			return -EIO;
		}

		if (!res) {
			if (!poll)
				return 0;

			cpu_relax();
			if (virtnet_cvq_wait_timeout(vi, time_end))
				return -EBUSY;
			continue;
		}

		/* this does not occur inside the process of waiting dim */
		if (res == ((void *)vi))
			return 0;

		virtnet_process_dim_cmd(vi, res);
		/* When it is a user command, we must wait until the
		 * processing result is processed synchronously.
		 */
		if (dim_oneshot)
			return 0;
	}
}

static void enable_get_cvq_work(struct virtnet_info *vi)
{
	rtnl_lock();
	vi->get_cvq_work_enabled = true;
	rtnl_unlock();
}

static void disable_get_cvq_work(struct virtnet_info *vi)
{
	rtnl_lock();
	vi->get_cvq_work_enabled = false;
	rtnl_unlock();
}

static void __virtnet_add_dim_command(struct virtnet_info *vi,
				      struct virtnet_coal_node *ctrl)
{
	struct scatterlist *sgs[4], hdr, stat, out;
	unsigned int out_num = 0;
	int ret;

	BUG_ON(!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ));

	ctrl->hdr.class = VIRTIO_NET_CTRL_NOTF_COAL;
	ctrl->hdr.cmd = VIRTIO_NET_CTRL_NOTF_COAL_VQ_SET;

	sg_init_one(&hdr, &ctrl->hdr, sizeof(ctrl->hdr));
	sgs[out_num++] = &hdr;

	sg_init_one(&out, &ctrl->coal_vqs, sizeof(ctrl->coal_vqs));
	sgs[out_num++] = &out;

	ctrl->status = VIRTIO_NET_OK;
	sg_init_one(&stat, &ctrl->status, sizeof(ctrl->status));
	sgs[out_num] = &stat;

	BUG_ON(out_num + 1 > ARRAY_SIZE(sgs));
	ret = virtqueue_add_sgs(vi->cvq, sgs, out_num, 1, ctrl, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		ret = virtnet_cvq_response(vi, true, true);
		if (ret)
			goto err_ret;

		ret = virtqueue_add_sgs(vi->cvq, sgs, out_num, 1, ctrl, GFP_ATOMIC);
	}

err_ret:
	if (ret < 0) {
		mutex_lock(&vi->coal_free_lock);
		list_add(&ctrl->list, &vi->coal_free_list);
		mutex_unlock(&vi->coal_free_lock);
		return;
	}

	virtqueue_kick(vi->cvq);
	vi->dim_cmd_nums++;
	if (vi->dim_cmd_nums && vi->get_cvq_work_enabled)
		schedule_delayed_work(&vi->get_cvq, 1);
}

static void virtnet_add_dim_command(struct virtnet_info *vi,
				    struct virtnet_coal_node *ctrl)
{
	mutex_lock(&vi->cvq_lock);
	__virtnet_add_dim_command(vi, ctrl);
	mutex_unlock(&vi->cvq_lock);
}

static void virtnet_get_cvq_work(struct work_struct *work)
{
	struct virtnet_info *vi =
		container_of(work, struct virtnet_info, get_cvq.work);

	mutex_lock(&vi->cvq_lock);

	if (virtnet_cvq_response(vi, false, false))
		goto out;

	if (vi->dim_cmd_nums && vi->get_cvq_work_enabled)
		schedule_delayed_work(&vi->get_cvq, 1);

out:
	mutex_unlock(&vi->cvq_lock);
}

static void skb_recv_done(struct virtqueue *rvq)
{
	struct virtnet_info *vi = rvq->vdev->priv;
	struct receive_queue *rq = &vi->rq[vq2rxq(rvq)];

	rq->calls++;
	virtqueue_napi_schedule(&rq->napi, rvq);
}

static void virtnet_napi_enable(struct virtqueue *vq, struct napi_struct *napi)
{
	napi_enable(napi);

	/* If all buffers were filled by other side before we napi_enabled, we
	 * won't get another interrupt, so process any outstanding packets now.
	 * Call local_bh_enable after to trigger softIRQ processing.
	 */
	local_bh_disable();
	virtqueue_napi_schedule(napi, vq);
	local_bh_enable();
}

static void virtnet_napi_tx_enable(struct virtnet_info *vi,
				   struct virtqueue *vq,
				   struct napi_struct *napi)
{
	if (!napi->weight)
		return;

	/* Tx napi touches cachelines on the cpu handling tx interrupts. Only
	 * enable the feature if this is likely affine with the transmit path.
	 */
	if (!vi->affinity_hint_set) {
		napi->weight = 0;
		return;
	}

	return virtnet_napi_enable(vq, napi);
}

static void virtnet_napi_tx_disable(struct napi_struct *napi)
{
	if (napi->weight)
		napi_disable(napi);
}

static void refill_work(struct work_struct *work)
{
	struct virtnet_info *vi =
		container_of(work, struct virtnet_info, refill.work);
	bool still_empty;
	int i;

	for (i = 0; i < vi->curr_queue_pairs; i++) {
		struct receive_queue *rq = &vi->rq[i];

		napi_disable(&rq->napi);
		still_empty = !try_fill_recv(vi, rq, GFP_KERNEL);
		virtnet_napi_enable(rq->vq, &rq->napi);

		/* In theory, this can happen: if we don't get any buffers in
		 * we will *never* try to fill again.
		 */
		if (still_empty)
			schedule_delayed_work(&vi->refill, HZ/2);
	}
}

static int virtnet_receive(struct receive_queue *rq, int budget,
			   unsigned int *xdp_xmit)
{
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct virtnet_rq_stats stats = {};
	unsigned int len;
	int packets = 0;
	void *buf;
	int i;

	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		void *ctx;

		while (packets < budget &&
		       (buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx))) {
			receive_buf(vi, rq, buf, len, ctx, xdp_xmit, &stats);
			packets++;
		}
	} else {
		while (packets < budget &&
		       (buf = virtqueue_get_buf(rq->vq, &len)) != NULL) {
			receive_buf(vi, rq, buf, len, NULL, xdp_xmit, &stats);
			packets++;
		}
	}

	if (rq->vq->num_free > min((unsigned int)budget, virtqueue_get_vring_size(rq->vq)) / 2) {
		if (!try_fill_recv(vi, rq, GFP_ATOMIC)) {
			spin_lock(&vi->refill_lock);
			if (vi->refill_enabled)
				schedule_delayed_work(&vi->refill, 0);
			spin_unlock(&vi->refill_lock);
		}
	}

	u64_stats_set(&stats.packets, packets);
	u64_stats_update_begin(&rq->stats.syncp);
	for (i = 0; i < ARRAY_SIZE(virtnet_rq_stats_desc); i++) {
		size_t offset = virtnet_rq_stats_desc[i].offset;
		u64_stats_t *item, *src;

		item = (u64_stats_t *)((u8 *)&rq->stats + offset);
		src = (u64_stats_t *)((u8 *)&stats + offset);
		u64_stats_add(item, u64_stats_read(src));
	}
	u64_stats_update_end(&rq->stats.syncp);

	return packets;
}

static void virt_xsk_complete(struct send_queue *sq, u32 num, bool xsk_wakeup)
{
	struct xsk_buff_pool *pool;
	int n;

	rcu_read_lock();

	WRITE_ONCE(sq->xsk.hdr_pro, sq->xsk.hdr_pro + num);

	pool = rcu_dereference(sq->xsk.pool);
	if (!pool) {
		if (sq->xsk.hdr_pro - sq->xsk.hdr_con == sq->xsk.hdr_n) {
			struct virtnet_xsk_hdr *hdr = NULL;

			hdr = rcu_replace_pointer(sq->xsk.hdr, hdr, true);
			xsk_pool_unpin_pages(sq->xsk.pgs, sq->xsk.npgs);
			kfree(hdr);
		}
		rcu_read_unlock();
		return;
	}

	xsk_tx_completed(sq->xsk.pool, num);

	rcu_read_unlock();

	if (!xsk_wakeup || !sq->xsk.wait_slot)
		return;

	n = sq->xsk.hdr_pro - sq->xsk.hdr_con;

	if (n > sq->xsk.hdr_n / 2) {
		sq->xsk.wait_slot = false;
		virtqueue_napi_schedule(&sq->napi, sq->vq);
		u64_stats_update_begin(&sq->stats.syncp);
		u64_stats_add(&sq->stats.xsk_wakeup_recycle, 1);
		u64_stats_update_end(&sq->stats.syncp);
	}
}

static void __free_old_xmit_ptr(struct send_queue *sq, bool in_napi,
				bool xsk_wakeup,
				unsigned int *_packets, unsigned int *_bytes)
{
	unsigned int packets = 0;
	unsigned int bytes = 0;
	unsigned int len;
	u64 xsknum = 0;
	struct virtnet_xdp_type *xtype;
	struct xdp_frame        *frame;
	struct virtnet_xsk_hdr  *xskhdr;
	struct sk_buff          *skb;
	void                    *ptr;

	while ((ptr = virtqueue_get_buf(sq->vq, &len)) != NULL) {
		if (likely(!is_xdp_frame(ptr))) {
			skb = ptr;

			pr_debug("Sent skb %p\n", skb);

			bytes += skb->len;
			napi_consume_skb(skb, in_napi);
		} else {
			xtype = ptr_to_xtype(ptr);

			if (xtype->type == XDP_TYPE_XSK) {
				xskhdr = (struct virtnet_xsk_hdr *)xtype;
				bytes += xskhdr->len;
				xsknum += 1;
			} else {
				frame = xtype_got_ptr(xtype);
				xdp_return_frame(frame);
				bytes += frame->len;
			}
		}
		packets++;
	}

	if (xsknum)
		virt_xsk_complete(sq, xsknum, xsk_wakeup);

	*_packets = packets;
	*_bytes = bytes;
}

static void free_old_xmit_skbs(struct send_queue *sq, bool in_napi)
{
	unsigned int packets = 0;
	unsigned int bytes = 0;

	__free_old_xmit_ptr(sq, in_napi, true, &packets, &bytes);

	/* Avoid overhead when no packets have been processed
	 * happens when called speculatively from start_xmit.
	 */
	if (!packets)
		return;

	u64_stats_update_begin(&sq->stats.syncp);
	u64_stats_add(&sq->stats.bytes, bytes);
	u64_stats_add(&sq->stats.packets, packets);
	u64_stats_update_end(&sq->stats.syncp);
}

static bool is_xdp_raw_buffer_queue(struct virtnet_info *vi, int q)
{
	if (q < (vi->curr_queue_pairs - vi->xdp_queue_pairs))
		return false;
	else if (q < vi->curr_queue_pairs)
		return true;
	else
		return false;
}

static void virtnet_poll_cleantx(struct receive_queue *rq)
{
	struct virtnet_info *vi = rq->vq->vdev->priv;
	unsigned int index = vq2rxq(rq->vq);
	struct send_queue *sq = &vi->sq[index];
	struct netdev_queue *txq = netdev_get_tx_queue(vi->dev, index);

	if (!sq->napi.weight || is_xdp_raw_buffer_queue(vi, index))
		return;

	if (__netif_tx_trylock(txq)) {
		if (sq->reset) {
			__netif_tx_unlock(txq);
			return;
		}

		do {
			virtqueue_disable_cb(sq->vq);
			free_old_xmit_skbs(sq, true);
		} while (unlikely(!virtqueue_enable_cb_delayed(sq->vq)));

		if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS)
			netif_tx_wake_queue(txq);

		__netif_tx_unlock(txq);
	}
}

static void virtnet_rx_dim_update(struct virtnet_info *vi, struct receive_queue *rq)
{
	struct dim_sample cur_sample = {};

	if (!rq->packets_in_napi)
		return;

	u64_stats_update_begin(&rq->stats.syncp);
	dim_update_sample(rq->calls,
			  u64_stats_read(&rq->stats.packets),
			  u64_stats_read(&rq->stats.bytes),
			  &cur_sample);
	u64_stats_update_end(&rq->stats.syncp);

	net_dim_tune(&rq->dim, cur_sample, VIRTNET_DIM_NEVENTS,
		     VIRTNET_DIM_TUNE_TRAFFIC);
	rq->packets_in_napi = 0;
}

static int virtnet_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq =
		container_of(napi, struct receive_queue, napi);
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct send_queue *sq;
	unsigned int received;
	unsigned int xdp_xmit = 0;
	bool napi_complete;

	virtnet_poll_cleantx(rq);

	received = virtnet_receive(rq, budget, &xdp_xmit);
	rq->packets_in_napi += received;

	if (xdp_xmit & VIRTIO_XDP_REDIR)
		xdp_do_flush();

	/* Out of packets? */
	if (received < budget) {
		napi_complete = virtqueue_napi_complete(napi, rq->vq, received);
		if (napi_complete && rq->dim_enabled)
			virtnet_rx_dim_update(vi, rq);
	}

	if (xdp_xmit & VIRTIO_XDP_TX) {
		sq = virtnet_xdp_get_sq(vi);
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			u64_stats_inc(&sq->stats.kicks);
			u64_stats_update_end(&sq->stats.syncp);
		}
		virtnet_xdp_put_sq(vi, sq);
	}

	return received;
}

static int virtnet_open(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int i, err;

	enable_delayed_refill(vi);

	for (i = 0; i < vi->max_queue_pairs; i++) {
		if (i < vi->curr_queue_pairs)
			/* Make sure we have some buffers: if oom use wq. */
			if (!try_fill_recv(vi, &vi->rq[i], GFP_KERNEL))
				schedule_delayed_work(&vi->refill, 0);

		err = xdp_rxq_info_reg(&vi->rq[i].xdp_rxq, dev, i);
		if (err < 0)
			return err;

		err = xdp_rxq_info_reg_mem_model(&vi->rq[i].xdp_rxq,
						 MEM_TYPE_PAGE_SHARED, NULL);
		if (err < 0) {
			xdp_rxq_info_unreg(&vi->rq[i].xdp_rxq);
			return err;
		}

		virtnet_napi_enable(vi->rq[i].vq, &vi->rq[i].napi);
		virtnet_napi_tx_enable(vi, vi->sq[i].vq, &vi->sq[i].napi);
	}

	return 0;
}

static int virtnet_poll_tx(struct napi_struct *napi, int budget)
{
	struct send_queue *sq = container_of(napi, struct send_queue, napi);
	struct virtnet_info *vi = sq->vq->vdev->priv;
	unsigned int index = vq2txq(sq->vq);
	struct xsk_buff_pool *pool;
	struct netdev_queue *txq;
	int work = 0;
	int opaque;
	bool done;

	if (unlikely(is_xdp_raw_buffer_queue(vi, index))) {
		/* We don't need to enable cb for XDP */
		napi_complete_done(napi, 0);
		return 0;
	}

	txq = netdev_get_tx_queue(vi->dev, index);
	__netif_tx_lock(txq, raw_smp_processor_id());
	virtqueue_disable_cb(sq->vq);

	rcu_read_lock();

	pool = rcu_dereference(sq->xsk.pool);
	if (pool)
		work = virtnet_xsk_run(sq, pool, budget);
	else
		free_old_xmit_skbs(sq, true);

	rcu_read_unlock();

	if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS)
		netif_tx_wake_queue(txq);

	if (work >= budget) {
		__netif_tx_unlock(txq);
		return work;
	}

	opaque = virtqueue_enable_cb_prepare(sq->vq);

	done = napi_complete_done(napi, 0);

	if (!done)
		virtqueue_disable_cb(sq->vq);

	__netif_tx_unlock(txq);

	if (done) {
		if (unlikely(virtqueue_poll(sq->vq, opaque))) {
			if (napi_schedule_prep(napi)) {
				__netif_tx_lock(txq, raw_smp_processor_id());
				virtqueue_disable_cb(sq->vq);
				__netif_tx_unlock(txq);
				__napi_schedule(napi);
			}
		}
	}

	return 0;
}

static int xmit_skb(struct send_queue *sq, struct sk_buff *skb)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	const unsigned char *dest = ((struct ethhdr *)skb->data)->h_dest;
	struct virtnet_info *vi = sq->vq->vdev->priv;
	int num_sg;
	unsigned hdr_len = vi->hdr_len;
	bool can_push;

	pr_debug("%s: xmit %p %pM\n", vi->dev->name, skb, dest);

	can_push = vi->any_header_sg &&
		!((unsigned long)skb->data & (__alignof__(*hdr) - 1)) &&
		!skb_header_cloned(skb) && skb_headroom(skb) >= hdr_len;
	/* Even if we can, don't push here yet as this would skew
	 * csum_start offset below. */
	if (can_push)
		hdr = (struct virtio_net_hdr_mrg_rxbuf *)(skb->data - hdr_len);
	else
		hdr = skb_vnet_hdr(skb);

	if (virtio_net_hdr_from_skb(skb, &hdr->hdr,
				    virtio_is_little_endian(vi->vdev), false,
				    0))
		return -EPROTO;

	if (vi->mergeable_rx_bufs)
		hdr->num_buffers = 0;

	sg_init_table(sq->sg, skb_shinfo(skb)->nr_frags + (can_push ? 1 : 2));
	if (can_push) {
		__skb_push(skb, hdr_len);
		num_sg = skb_to_sgvec(skb, sq->sg, 0, skb->len);
		if (unlikely(num_sg < 0))
			return num_sg;
		/* Pull header back to avoid skew in tx bytes calculations. */
		__skb_pull(skb, hdr_len);
	} else {
		sg_set_buf(sq->sg, hdr, hdr_len);
		num_sg = skb_to_sgvec(skb, sq->sg + 1, 0, skb->len);
		if (unlikely(num_sg < 0))
			return num_sg;
		num_sg++;
	}
	return virtqueue_add_outbuf(sq->vq, sq->sg, num_sg, skb, GFP_ATOMIC);
}

static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int qnum = skb_get_queue_mapping(skb);
	struct send_queue *sq = &vi->sq[qnum];
	int err;
	struct netdev_queue *txq = netdev_get_tx_queue(dev, qnum);
	bool kick = !netdev_xmit_more();
	bool use_napi = sq->napi.weight;

	/* Free up any pending old buffers before queueing new ones. */
	do {
		if (use_napi)
			virtqueue_disable_cb(sq->vq);

		free_old_xmit_skbs(sq, false);

	} while (use_napi && kick &&
	       unlikely(!virtqueue_enable_cb_delayed(sq->vq)));

	/* timestamp packet in software */
	skb_tx_timestamp(skb);

	/* Try to transmit */
	err = xmit_skb(sq, skb);

	/* This should not happen! */
	if (unlikely(err)) {
		dev->stats.tx_fifo_errors++;
		if (net_ratelimit())
			dev_warn(&dev->dev,
				 "Unexpected TXQ (%d) queue failure: %d\n",
				 qnum, err);
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* Don't wait up for transmitted skbs to be freed. */
	if (!use_napi) {
		skb_orphan(skb);
		nf_reset_ct(skb);
	}

	virtnet_sq_stop_check(sq, false);

	if (kick || netif_xmit_stopped(txq)) {
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			u64_stats_inc(&sq->stats.kicks);
			u64_stats_update_end(&sq->stats.syncp);
		}
	}

	return NETDEV_TX_OK;
}

static void virtnet_cancel_dim(struct virtnet_info *vi, struct dim *dim)
{
	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return;
	net_dim_work_cancel(dim);
}

static int virtnet_rx_resize(struct virtnet_info *vi,
			     struct receive_queue *rq, u32 ring_num)
{
	bool running = netif_running(vi->dev);
	int err, qindex;

	qindex = rq - vi->rq;

	if (running) {
		napi_disable(&rq->napi);
		virtnet_cancel_dim(vi, &rq->dim);
	}

	err = virtqueue_resize(rq->vq, ring_num, virtnet_rq_free_unused_buf);
	if (err)
		netdev_err(vi->dev, "resize rx fail: rx queue index: %d err: %d\n", qindex, err);

	if (!try_fill_recv(vi, rq, GFP_KERNEL))
		schedule_delayed_work(&vi->refill, 0);

	if (running)
		virtnet_napi_enable(rq->vq, &rq->napi);
	return err;
}

static int virtnet_tx_resize(struct virtnet_info *vi,
			     struct send_queue *sq, u32 ring_num)
{
	bool running = netif_running(vi->dev);
	struct netdev_queue *txq;
	int err, qindex;

	qindex = sq - vi->sq;

	if (running)
		virtnet_napi_tx_disable(&sq->napi);

	txq = netdev_get_tx_queue(vi->dev, qindex);

	/* 1. wait all ximt complete
	 * 2. fix the race of netif_stop_subqueue() vs netif_start_subqueue()
	 */
	__netif_tx_lock_bh(txq);

	/* Prevent rx poll from accessing sq. */
	sq->reset = true;

	/* Prevent the upper layer from trying to send packets. */
	netif_stop_subqueue(vi->dev, qindex);

	__netif_tx_unlock_bh(txq);

	err = virtqueue_resize(sq->vq, ring_num, virtnet_sq_free_unused_buf);
	if (err)
		netdev_err(vi->dev, "resize tx fail: tx queue index: %d err: %d\n", qindex, err);

	__netif_tx_lock_bh(txq);
	sq->reset = false;
	netif_tx_wake_queue(txq);
	__netif_tx_unlock_bh(txq);

	if (running)
		virtnet_napi_tx_enable(vi, sq->vq, &sq->napi);
	return err;
}

/*
 * Send command via the control virtqueue and check status.  Commands
 * supported by the hypervisor, as indicated by feature bits, should
 * never fail unless improperly formatted.
 */
static bool virtnet_send_command_reply(struct virtnet_info *vi, u8 class, u8 cmd,
				       struct scatterlist *out,
				       struct scatterlist *in)
{
	struct scatterlist *sgs[5], hdr, stat;
	u32 out_num = 0, in_num = 0;
	bool ok;
	int ret;

	/* Caller should know better */
	BUG_ON(!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ));

	mutex_lock(&vi->cvq_lock);
	vi->ctrl->status = ~0;
	vi->ctrl->hdr.class = class;
	vi->ctrl->hdr.cmd = cmd;
	/* Add header */
	sg_init_one(&hdr, &vi->ctrl->hdr, sizeof(vi->ctrl->hdr));
	sgs[out_num++] = &hdr;

	if (out)
		sgs[out_num++] = out;

	/* Add return status. */
	sg_init_one(&stat, &vi->ctrl->status, sizeof(vi->ctrl->status));
	sgs[out_num + in_num++] = &stat;

	if (in)
		sgs[out_num + in_num++] = in;

	BUG_ON(out_num + in_num > ARRAY_SIZE(sgs));
	ret = virtqueue_add_sgs(vi->cvq, sgs, out_num, in_num, vi, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		ret = virtnet_cvq_response(vi, true, true);
		if (ret)
			goto err_out;

		ret = virtqueue_add_sgs(vi->cvq, sgs, out_num, in_num, vi, GFP_ATOMIC);
	}
	if (ret < 0)
		goto err_out;

	if (unlikely(!virtqueue_kick(vi->cvq)))
		goto unlock;

	ret = virtnet_cvq_response(vi, true, false);
	if (ret)
		goto err_out;

unlock:
	ok = vi->ctrl->status == VIRTIO_NET_OK;
	mutex_unlock(&vi->cvq_lock);
	return ok;

err_out:
	dev_warn(&vi->vdev->dev,
		 "Failed to add sgs for command vq: %d\n.", ret);
	mutex_unlock(&vi->cvq_lock);
	return false;
}

static bool virtnet_send_command(struct virtnet_info *vi, u8 class, u8 cmd,
				 struct scatterlist *out)
{
	return virtnet_send_command_reply(vi, class, cmd, out, NULL);
}

static int virtnet_set_mac_address(struct net_device *dev, void *p)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct virtio_device *vdev = vi->vdev;
	int ret;
	struct sockaddr *addr;
	struct scatterlist sg;

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STANDBY))
		return -EOPNOTSUPP;

	addr = kmemdup(p, sizeof(*addr), GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	ret = eth_prepare_mac_addr_change(dev, addr);
	if (ret)
		goto out;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR)) {
		sg_init_one(&sg, addr->sa_data, dev->addr_len);
		if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
					  VIRTIO_NET_CTRL_MAC_ADDR_SET, &sg)) {
			dev_warn(&vdev->dev,
				 "Failed to set mac address by vq command.\n");
			ret = -EINVAL;
			goto out;
		}
	} else if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC) &&
		   !virtio_has_feature(vdev, VIRTIO_F_VERSION_1)) {
		unsigned int i;

		/* Naturally, this has an atomicity problem. */
		for (i = 0; i < dev->addr_len; i++)
			virtio_cwrite8(vdev,
				       offsetof(struct virtio_net_config, mac) +
				       i, addr->sa_data[i]);
	}

	eth_commit_mac_addr_change(dev, p);
	ret = 0;

out:
	kfree(addr);
	return ret;
}

static void virtnet_stats(struct net_device *dev,
			  struct rtnl_link_stats64 *tot)
{
	struct virtnet_info *vi = netdev_priv(dev);
	unsigned int start;
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		u64 tpackets, tbytes, terrors, rpackets, rbytes, rdrops;
		struct receive_queue *rq = &vi->rq[i];
		struct send_queue *sq = &vi->sq[i];

		do {
			start = u64_stats_fetch_begin(&sq->stats.syncp);
			tpackets = u64_stats_read(&sq->stats.packets);
			tbytes   = u64_stats_read(&sq->stats.bytes);
			terrors  = u64_stats_read(&sq->stats.tx_timeouts);
		} while (u64_stats_fetch_retry(&sq->stats.syncp, start));

		do {
			start = u64_stats_fetch_begin(&rq->stats.syncp);
			rpackets = u64_stats_read(&rq->stats.packets);
			rbytes   = u64_stats_read(&rq->stats.bytes);
			rdrops   = u64_stats_read(&rq->stats.drops);
		} while (u64_stats_fetch_retry(&rq->stats.syncp, start));

		tot->rx_packets += rpackets;
		tot->tx_packets += tpackets;
		tot->rx_bytes   += rbytes;
		tot->tx_bytes   += tbytes;
		tot->rx_dropped += rdrops;
		tot->tx_errors  += terrors;
	}

	tot->tx_dropped = dev->stats.tx_dropped;
	tot->tx_fifo_errors = dev->stats.tx_fifo_errors;
	tot->rx_length_errors = dev->stats.rx_length_errors;
	tot->rx_frame_errors = dev->stats.rx_frame_errors;
}

static void virtnet_ack_link_announce(struct virtnet_info *vi)
{
	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_ANNOUNCE,
				  VIRTIO_NET_CTRL_ANNOUNCE_ACK, NULL))
		dev_warn(&vi->dev->dev, "Failed to ack link announce.\n");
}

static bool virtnet_commit_rss_command(struct virtnet_info *vi);

static void virtnet_rss_update_by_qpairs(struct virtnet_info *vi, u16 queue_pairs)
{
	u32 indir_val = 0;
	int i = 0;

	for (; i < vi->rss_indir_table_size; ++i) {
		indir_val = ethtool_rxfh_indir_default(i, queue_pairs);
		vi->rss.indirection_table[i] = indir_val;
	}
	vi->rss.max_tx_vq = queue_pairs;
}

static int virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs)
{
	struct virtio_net_ctrl_mq *mq = NULL;
	struct virtio_net_ctrl_rss old_rss;
	struct net_device *dev = vi->dev;
	struct scatterlist sg;
	int ret = 0;

	if (!vi->has_cvq || !virtio_has_feature(vi->vdev, VIRTIO_NET_F_MQ))
		return 0;

	/* Firstly check if we need update rss. Do updating if both (1) rss enabled and
	 * (2) no user configuration.
	 *
	 * During rss command processing, device updates queue_pairs using rss.max_tx_vq. That is,
	 * the device updates queue_pairs together with rss, so we can skip the sperate queue_pairs
	 * update (VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET below) and return directly.
	 */
	if (vi->has_rss && !netif_is_rxfh_configured(dev)) {
		memcpy(&old_rss, &vi->rss, sizeof(old_rss));
		if (rss_indirection_table_alloc(&vi->rss, vi->rss_indir_table_size)) {
			vi->rss.indirection_table = old_rss.indirection_table;
			return -ENOMEM;
		}

		virtnet_rss_update_by_qpairs(vi, queue_pairs);

		if (!virtnet_commit_rss_command(vi)) {
			/* restore ctrl_rss if commit_rss_command failed */
			rss_indirection_table_free(&vi->rss);
			memcpy(&vi->rss, &old_rss, sizeof(old_rss));

			dev_warn(&dev->dev, "Fail to set num of queue pairs to %d, because committing RSS failed\n",
				 queue_pairs);
			return -EINVAL;
		}
		rss_indirection_table_free(&old_rss);
		goto succ;
	}

	mq = kzalloc(sizeof(*mq), GFP_KERNEL);
	if (!mq)
		return -ENOMEM;

	mq->virtqueue_pairs = cpu_to_virtio16(vi->vdev, queue_pairs);
	sg_init_one(&sg, mq, sizeof(*mq));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MQ,
				  VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, &sg)) {
		dev_warn(&dev->dev, "Fail to set num of queue pairs to %d\n",
			 queue_pairs);
		ret = -EINVAL;
		goto out;
	}

succ:
	vi->curr_queue_pairs = queue_pairs;
	/* virtnet_open() will refill when device is going to up. */
	if (dev->flags & IFF_UP)
		schedule_delayed_work(&vi->refill, 0);

out:
	kfree(mq);
	return ret;
}

static int virtnet_close(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int i;

	/* Make sure NAPI doesn't schedule refill work */
	disable_delayed_refill(vi);
	/* Make sure refill_work doesn't re-enable napi! */
	cancel_delayed_work_sync(&vi->refill);

	for (i = 0; i < vi->max_queue_pairs; i++) {
		napi_disable(&vi->rq[i].napi);
		xdp_rxq_info_unreg(&vi->rq[i].xdp_rxq);
		virtnet_napi_tx_disable(&vi->sq[i].napi);
		virtnet_cancel_dim(vi, &vi->rq[i].dim);
	}

	return 0;
}

static void virtnet_rx_mode_work(struct work_struct *work)
{
	struct virtnet_info *vi =
		container_of(work, struct virtnet_info, rx_mode_work);
	struct net_device *dev = vi->dev;
	struct scatterlist sg[2];
	struct virtio_net_ctrl_mac *mac_data;
	struct netdev_hw_addr *ha;
	u8 *promisc_allmulti;
	int uc_count;
	int mc_count;
	void *buf;
	int i;

	/* We can't dynamically set ndo_set_rx_mode, so return gracefully */
	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_RX))
		return;

	promisc_allmulti = kzalloc(sizeof(*promisc_allmulti), GFP_KERNEL);
	if (!promisc_allmulti) {
		dev_warn(&dev->dev, "Failed to set RX mode, no memory.\n");
		return;
	}

	rtnl_lock();

	*promisc_allmulti = !!(dev->flags & IFF_PROMISC);
	sg_init_one(sg, promisc_allmulti, sizeof(*promisc_allmulti));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
				  VIRTIO_NET_CTRL_RX_PROMISC, sg))
		dev_warn(&dev->dev, "Failed to %sable promisc mode.\n",
			 *promisc_allmulti ? "en" : "dis");

	*promisc_allmulti = !!(dev->flags & IFF_ALLMULTI);
	sg_init_one(sg, promisc_allmulti, sizeof(*promisc_allmulti));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
				  VIRTIO_NET_CTRL_RX_ALLMULTI, sg))
		dev_warn(&dev->dev, "Failed to %sable allmulti mode.\n",
			 *promisc_allmulti ? "en" : "dis");

	netif_addr_lock_bh(dev);

	uc_count = netdev_uc_count(dev);
	mc_count = netdev_mc_count(dev);
	/* MAC filter - use one buffer for both lists */
	buf = kzalloc(((uc_count + mc_count) * ETH_ALEN) +
		      (2 * sizeof(mac_data->entries)), GFP_ATOMIC);
	mac_data = buf;
	if (!buf) {
		netif_addr_unlock_bh(dev);
		rtnl_unlock();
		kfree(promisc_allmulti);
		return;
	}

	sg_init_table(sg, 2);

	/* Store the unicast list and count in the front of the buffer */
	mac_data->entries = cpu_to_virtio32(vi->vdev, uc_count);
	i = 0;
	netdev_for_each_uc_addr(ha, dev)
		memcpy(&mac_data->macs[i++][0], ha->addr, ETH_ALEN);

	sg_set_buf(&sg[0], mac_data,
		   sizeof(mac_data->entries) + (uc_count * ETH_ALEN));

	/* multicast list and count fill the end */
	mac_data = (void *)&mac_data->macs[uc_count][0];

	mac_data->entries = cpu_to_virtio32(vi->vdev, mc_count);
	i = 0;
	netdev_for_each_mc_addr(ha, dev)
		memcpy(&mac_data->macs[i++][0], ha->addr, ETH_ALEN);

	netif_addr_unlock_bh(dev);

	sg_set_buf(&sg[1], mac_data,
		   sizeof(mac_data->entries) + (mc_count * ETH_ALEN));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
				  VIRTIO_NET_CTRL_MAC_TABLE_SET, sg))
		dev_warn(&dev->dev, "Failed to set MAC filter table.\n");

	rtnl_unlock();

	kfree(buf);
	kfree(promisc_allmulti);
}

static void virtnet_set_rx_mode(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

	if (vi->rx_mode_work_enabled)
		schedule_work(&vi->rx_mode_work);
}

static int virtnet_vlan_rx_add_vid(struct net_device *dev,
				   __be16 proto, u16 vid)
{
	struct virtnet_info *vi = netdev_priv(dev);
	__virtio16 *_vid = NULL;
	struct scatterlist sg;

	_vid = kzalloc(sizeof(*_vid), GFP_KERNEL);
	if (!_vid)
		return -ENOMEM;

	*_vid = cpu_to_virtio16(vi->vdev, vid);
	sg_init_one(&sg, _vid, sizeof(*_vid));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_VLAN,
				  VIRTIO_NET_CTRL_VLAN_ADD, &sg))
		dev_warn(&dev->dev, "Failed to add VLAN ID %d.\n", vid);

	kfree(_vid);
	return 0;
}

static int virtnet_vlan_rx_kill_vid(struct net_device *dev,
				    __be16 proto, u16 vid)
{
	struct virtnet_info *vi = netdev_priv(dev);
	__virtio16 *_vid = NULL;
	struct scatterlist sg;

	_vid = kzalloc(sizeof(*_vid), GFP_KERNEL);
	if (!_vid)
		return -ENOMEM;

	*_vid = cpu_to_virtio16(vi->vdev, vid);
	sg_init_one(&sg, _vid, sizeof(*_vid));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_VLAN,
				  VIRTIO_NET_CTRL_VLAN_DEL, &sg))
		dev_warn(&dev->dev, "Failed to kill VLAN ID %d.\n", vid);
	kfree(_vid);
	return 0;
}

static void virtnet_clean_affinity(struct virtnet_info *vi)
{
	int i;

	if (vi->affinity_hint_set) {
		for (i = 0; i < vi->max_queue_pairs; i++) {
			virtqueue_set_affinity(vi->rq[i].vq, NULL);
			virtqueue_set_affinity(vi->sq[i].vq, NULL);
		}

		vi->affinity_hint_set = false;
	}
}

static void virtnet_set_affinity(struct virtnet_info *vi)
{
	cpumask_var_t mask;
	int stragglers;
	int group_size;
	int i, j, cpu;
	int num_cpu;
	int stride;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL)) {
		virtnet_clean_affinity(vi);
		return;
	}

	num_cpu = num_online_cpus();
	stride = max_t(int, num_cpu / vi->curr_queue_pairs, 1);
	stragglers = num_cpu >= vi->curr_queue_pairs ?
			num_cpu % vi->curr_queue_pairs :
			0;
	cpu = cpumask_next(-1, cpu_online_mask);

	for (i = 0; i < vi->curr_queue_pairs; i++) {
		group_size = stride + (i < stragglers ? 1 : 0);

		for (j = 0; j < group_size; j++) {
			cpumask_set_cpu(cpu, mask);
			cpu = cpumask_next_wrap(cpu, cpu_online_mask,
						nr_cpu_ids, false);
		}
		virtqueue_set_affinity(vi->rq[i].vq, mask);
		virtqueue_set_affinity(vi->sq[i].vq, mask);
		__netif_set_xps_queue(vi->dev, cpumask_bits(mask), i, false);
		cpumask_clear(mask);
	}

	vi->affinity_hint_set = true;
	free_cpumask_var(mask);
}

static int virtnet_cpu_online(unsigned int cpu, struct hlist_node *node)
{
	struct virtnet_info *vi = hlist_entry_safe(node, struct virtnet_info,
						   node);
	virtnet_set_affinity(vi);
	return 0;
}

static int virtnet_cpu_dead(unsigned int cpu, struct hlist_node *node)
{
	struct virtnet_info *vi = hlist_entry_safe(node, struct virtnet_info,
						   node_dead);
	virtnet_set_affinity(vi);
	return 0;
}

static int virtnet_cpu_down_prep(unsigned int cpu, struct hlist_node *node)
{
	struct virtnet_info *vi = hlist_entry_safe(node, struct virtnet_info,
						   node);

	virtnet_clean_affinity(vi);
	return 0;
}

static enum cpuhp_state virtionet_online;

static int virtnet_cpu_notif_add(struct virtnet_info *vi)
{
	int ret;

	ret = cpuhp_state_add_instance_nocalls(virtionet_online, &vi->node);
	if (ret)
		return ret;
	ret = cpuhp_state_add_instance_nocalls(CPUHP_VIRT_NET_DEAD,
					       &vi->node_dead);
	if (!ret)
		return ret;
	cpuhp_state_remove_instance_nocalls(virtionet_online, &vi->node);
	return ret;
}

static void virtnet_cpu_notif_remove(struct virtnet_info *vi)
{
	cpuhp_state_remove_instance_nocalls(virtionet_online, &vi->node);
	cpuhp_state_remove_instance_nocalls(CPUHP_VIRT_NET_DEAD,
					    &vi->node_dead);
}

static int virtnet_send_ctrl_coal_vq_cmd(struct virtnet_info *vi,
					 u16 vqn, u32 max_usecs, u32 max_packets)
{
	struct virtio_net_ctrl_coal_vq *coal_vq = NULL;
	struct scatterlist sgs;
	int ret = 0;

	coal_vq = kzalloc(sizeof(*coal_vq), GFP_KERNEL);
	if (!coal_vq)
		return -ENOMEM;

	coal_vq->vqn = cpu_to_le16(vqn);
	coal_vq->coal.max_usecs = cpu_to_le32(max_usecs);
	coal_vq->coal.max_packets = cpu_to_le32(max_packets);
	sg_init_one(&sgs, coal_vq, sizeof(*coal_vq));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_NOTF_COAL,
				  VIRTIO_NET_CTRL_NOTF_COAL_VQ_SET,
				  &sgs))
		ret = -EINVAL;

	kfree(coal_vq);
	return ret;
}

static int virtnet_send_rx_ctrl_coal_vq_cmd(struct virtnet_info *vi,
					    u16 queue, u32 max_usecs,
					    u32 max_packets)
{
	int err;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return -EOPNOTSUPP;

	err = virtnet_send_ctrl_coal_vq_cmd(vi, rxq2vq(queue),
					    max_usecs, max_packets);
	if (err)
		return err;

	vi->rq[queue].intr_coal.max_usecs = max_usecs;
	vi->rq[queue].intr_coal.max_packets = max_packets;

	return 0;
}

static int virtnet_send_tx_ctrl_coal_vq_cmd(struct virtnet_info *vi,
					    u16 queue, u32 max_usecs,
					    u32 max_packets)
{
	int err;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return -EOPNOTSUPP;

	err = virtnet_send_ctrl_coal_vq_cmd(vi, txq2vq(queue),
					    max_usecs, max_packets);
	if (err)
		return err;

	vi->sq[queue].intr_coal.max_usecs = max_usecs;
	vi->sq[queue].intr_coal.max_packets = max_packets;

	return 0;
}

static void virtnet_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *ring)
{
	struct virtnet_info *vi = netdev_priv(dev);

	ring->rx_max_pending = vi->rq[0].vq->num_max;
	ring->tx_max_pending = vi->sq[0].vq->num_max;
	ring->rx_pending = virtqueue_get_vring_size(vi->rq[0].vq);
	ring->tx_pending = virtqueue_get_vring_size(vi->sq[0].vq);
}

static int virtnet_send_ctrl_coal_vq_cmd(struct virtnet_info *vi,
					 u16 vqn, u32 max_usecs, u32 max_packets);

static int virtnet_set_ringparam(struct net_device *dev,
				 struct ethtool_ringparam *ring)
{
	struct virtnet_info *vi = netdev_priv(dev);
	u32 rx_pending, tx_pending;
	struct receive_queue *rq;
	struct send_queue *sq;
	int i, err;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending)
		return -EINVAL;

	rx_pending = virtqueue_get_vring_size(vi->rq[0].vq);
	tx_pending = virtqueue_get_vring_size(vi->sq[0].vq);

	if (ring->rx_pending == rx_pending &&
	    ring->tx_pending == tx_pending)
		return 0;

	if (ring->rx_pending > vi->rq[0].vq->num_max)
		return -EINVAL;

	if (ring->tx_pending > vi->sq[0].vq->num_max)
		return -EINVAL;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		rq = vi->rq + i;
		sq = vi->sq + i;

		if (ring->tx_pending != tx_pending) {
			err = virtnet_tx_resize(vi, sq, ring->tx_pending);
			if (err)
				return err;

			/* Upon disabling and re-enabling a transmit virtqueue, the device must
			 * set the coalescing parameters of the virtqueue to those configured
			 * through the VIRTIO_NET_CTRL_NOTF_COAL_TX_SET command, or, if the driver
			 * did not set any TX coalescing parameters, to 0.
			 */
			err = virtnet_send_tx_ctrl_coal_vq_cmd(vi, i,
							       vi->intr_coal_tx.max_usecs,
							       vi->intr_coal_tx.max_packets);

			/* Don't break the tx resize action if the vq coalescing is not
			 * supported. The same is true for rx resize below.
			 */
			if (err && err != -EOPNOTSUPP)
				return err;
		}

		if (ring->rx_pending != rx_pending) {
			err = virtnet_rx_resize(vi, rq, ring->rx_pending);
			if (err)
				return err;

			/* The reason is same as the transmit virtqueue reset */
			err = virtnet_send_rx_ctrl_coal_vq_cmd(vi, i,
							       vi->intr_coal_rx.max_usecs,
							       vi->intr_coal_rx.max_packets);
			if (err && err != -EOPNOTSUPP)
				return err;
		}
	}

	return 0;
}

static bool virtnet_commit_rss_command(struct virtnet_info *vi)
{
	struct net_device *dev = vi->dev;
	struct scatterlist sgs[4];
	unsigned int sg_buf_size;

	/* prepare sgs */
	sg_init_table(sgs, 4);

	sg_buf_size = offsetof(struct virtio_net_ctrl_rss, hash_cfg_reserved);
	sg_set_buf(&sgs[0], &vi->rss, sg_buf_size);

	if (vi->has_rss) {
		sg_buf_size = sizeof(uint16_t) * vi->rss_indir_table_size;
		sg_set_buf(&sgs[1], vi->rss.indirection_table, sg_buf_size);
	} else {
		sg_set_buf(&sgs[1], &vi->rss.hash_cfg_reserved, sizeof(uint16_t));
	}

	sg_buf_size = offsetof(struct virtio_net_ctrl_rss, key)
			- offsetof(struct virtio_net_ctrl_rss, max_tx_vq);
	sg_set_buf(&sgs[2], &vi->rss.max_tx_vq, sg_buf_size);

	sg_buf_size = vi->rss_key_size;
	sg_set_buf(&sgs[3], vi->rss.key, sg_buf_size);

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MQ,
				  vi->has_rss ? VIRTIO_NET_CTRL_MQ_RSS_CONFIG
				  : VIRTIO_NET_CTRL_MQ_HASH_CONFIG, sgs))
		goto err;

	return true;

err:
	dev_warn(&dev->dev, "VIRTIONET issue with committing RSS sgs\n");
	return false;
}

static void virtnet_init_default_rss(struct virtnet_info *vi)
{
	vi->rss.hash_types = vi->rss_hash_types_supported;
	vi->rss_hash_types_saved = vi->rss_hash_types_supported;
	vi->rss.indirection_table_mask = vi->rss_indir_table_size
						? vi->rss_indir_table_size - 1 : 0;
	vi->rss.unclassified_queue = 0;

	virtnet_rss_update_by_qpairs(vi, vi->curr_queue_pairs);

	vi->rss.hash_key_length = vi->rss_key_size;

	netdev_rss_key_fill(vi->rss.key, vi->rss_key_size);
}

static void virtnet_get_hashflow(const struct virtnet_info *vi, struct ethtool_rxnfc *info)
{
	info->data = 0;
	switch (info->flow_type) {
	case TCP_V4_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_TCPv4) {
			info->data = RXH_IP_SRC | RXH_IP_DST |
						 RXH_L4_B_0_1 | RXH_L4_B_2_3;
		} else if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv4) {
			info->data = RXH_IP_SRC | RXH_IP_DST;
		}
		break;
	case TCP_V6_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_TCPv6) {
			info->data = RXH_IP_SRC | RXH_IP_DST |
						 RXH_L4_B_0_1 | RXH_L4_B_2_3;
		} else if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv6) {
			info->data = RXH_IP_SRC | RXH_IP_DST;
		}
		break;
	case UDP_V4_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_UDPv4) {
			info->data = RXH_IP_SRC | RXH_IP_DST |
						 RXH_L4_B_0_1 | RXH_L4_B_2_3;
		} else if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv4) {
			info->data = RXH_IP_SRC | RXH_IP_DST;
		}
		break;
	case UDP_V6_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_UDPv6) {
			info->data = RXH_IP_SRC | RXH_IP_DST |
						 RXH_L4_B_0_1 | RXH_L4_B_2_3;
		} else if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv6) {
			info->data = RXH_IP_SRC | RXH_IP_DST;
		}
		break;
	case IPV4_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv4)
			info->data = RXH_IP_SRC | RXH_IP_DST;

		break;
	case IPV6_FLOW:
		if (vi->rss_hash_types_saved & VIRTIO_NET_RSS_HASH_TYPE_IPv6)
			info->data = RXH_IP_SRC | RXH_IP_DST;

		break;
	default:
		info->data = 0;
		break;
	}
}

static bool virtnet_set_hashflow(struct virtnet_info *vi, struct ethtool_rxnfc *info)
{
	u32 new_hashtypes = vi->rss_hash_types_saved;
	bool is_disable = info->data & RXH_DISCARD;
	bool is_l4 = info->data == (RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3);

	/* supports only 'sd', 'sdfn' and 'r' */
	if (!((info->data == (RXH_IP_SRC | RXH_IP_DST)) | is_l4 | is_disable))
		return false;

	switch (info->flow_type) {
	case TCP_V4_FLOW:
		new_hashtypes &= ~(VIRTIO_NET_RSS_HASH_TYPE_IPv4 | VIRTIO_NET_RSS_HASH_TYPE_TCPv4);
		if (!is_disable)
			new_hashtypes |= VIRTIO_NET_RSS_HASH_TYPE_IPv4
				| (is_l4 ? VIRTIO_NET_RSS_HASH_TYPE_TCPv4 : 0);
		break;
	case UDP_V4_FLOW:
		new_hashtypes &= ~(VIRTIO_NET_RSS_HASH_TYPE_IPv4 | VIRTIO_NET_RSS_HASH_TYPE_UDPv4);
		if (!is_disable)
			new_hashtypes |= VIRTIO_NET_RSS_HASH_TYPE_IPv4
				| (is_l4 ? VIRTIO_NET_RSS_HASH_TYPE_UDPv4 : 0);
		break;
	case IPV4_FLOW:
		new_hashtypes &= ~VIRTIO_NET_RSS_HASH_TYPE_IPv4;
		if (!is_disable)
			new_hashtypes = VIRTIO_NET_RSS_HASH_TYPE_IPv4;
		break;
	case TCP_V6_FLOW:
		new_hashtypes &= ~(VIRTIO_NET_RSS_HASH_TYPE_IPv6 | VIRTIO_NET_RSS_HASH_TYPE_TCPv6);
		if (!is_disable)
			new_hashtypes |= VIRTIO_NET_RSS_HASH_TYPE_IPv6
				| (is_l4 ? VIRTIO_NET_RSS_HASH_TYPE_TCPv6 : 0);
		break;
	case UDP_V6_FLOW:
		new_hashtypes &= ~(VIRTIO_NET_RSS_HASH_TYPE_IPv6 | VIRTIO_NET_RSS_HASH_TYPE_UDPv6);
		if (!is_disable)
			new_hashtypes |= VIRTIO_NET_RSS_HASH_TYPE_IPv6
				| (is_l4 ? VIRTIO_NET_RSS_HASH_TYPE_UDPv6 : 0);
		break;
	case IPV6_FLOW:
		new_hashtypes &= ~VIRTIO_NET_RSS_HASH_TYPE_IPv6;
		if (!is_disable)
			new_hashtypes = VIRTIO_NET_RSS_HASH_TYPE_IPv6;
		break;
	default:
		/* unsupported flow */
		return false;
	}

	/* if unsupported hashtype was set */
	if (new_hashtypes != (new_hashtypes & vi->rss_hash_types_supported))
		return false;

	if (new_hashtypes != vi->rss_hash_types_saved) {
		vi->rss_hash_types_saved = new_hashtypes;
		vi->rss.hash_types = vi->rss_hash_types_saved;
		if (vi->dev->features & NETIF_F_RXHASH)
			return virtnet_commit_rss_command(vi);
	}

	return true;
}

static void virtnet_get_drvinfo(struct net_device *dev,
				struct ethtool_drvinfo *info)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct virtio_device *vdev = vi->vdev;

	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strlcpy(info->version, VIRTNET_DRIVER_VERSION, sizeof(info->version));
	strlcpy(info->bus_info, virtio_bus_name(vdev), sizeof(info->bus_info));

}

/* TODO: Eliminate OOO packets during switching */
static int virtnet_set_channels(struct net_device *dev,
				struct ethtool_channels *channels)
{
	struct virtnet_info *vi = netdev_priv(dev);
	u16 queue_pairs = channels->combined_count;
	int err;

	/* We don't support separate rx/tx channels.
	 * We don't allow setting 'other' channels.
	 */
	if (channels->rx_count || channels->tx_count || channels->other_count)
		return -EINVAL;

	if (queue_pairs > vi->max_queue_pairs || queue_pairs == 0)
		return -EINVAL;

	/* For now we don't support modifying channels while XDP is loaded
	 * also when XDP is loaded all RX queues have XDP programs so we only
	 * need to check a single RX queue.
	 */
	if (vi->rq[0].xdp_prog)
		return -EINVAL;

	get_online_cpus();
	err = virtnet_set_queues(vi, queue_pairs);
	if (err) {
		put_online_cpus();
		goto err;
	}
	virtnet_set_affinity(vi);
	put_online_cpus();

	netif_set_real_num_tx_queues(dev, queue_pairs);
	netif_set_real_num_rx_queues(dev, queue_pairs);
 err:
	return err;
}

static void virtnet_stats_sprintf(u8 **p, const char *fmt, const char *noq_fmt,
				  int num, int qid, const struct virtnet_stat_desc *desc)
{
	int i;

	if (qid < 0) {
		for (i = 0; i < num; ++i)
			ethtool_sprintf(p, noq_fmt, desc[i].desc);
	} else {
		for (i = 0; i < num; ++i)
			ethtool_sprintf(p, fmt, qid, desc[i].desc);
	}
}

/* qid == -1: for rx/tx queue total field */
static void virtnet_get_stats_string(struct virtnet_info *vi, int type, int qid, u8 **data)
{
	const struct virtnet_stat_desc *desc;
	const char *fmt, *noq_fmt;
	u8 *p = *data;
	u32 num;

	if (type == VIRTNET_Q_TYPE_CQ && qid >= 0) {
		noq_fmt = "cq_hw_%s";

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_CVQ) {
			desc = &virtnet_stats_cvq_desc[0];
			num = ARRAY_SIZE(virtnet_stats_cvq_desc);

			virtnet_stats_sprintf(&p, NULL, noq_fmt, num, -1, desc);
		}
	}

	if (type == VIRTNET_Q_TYPE_RX) {
		fmt = "rx%u_%s";
		noq_fmt = "rx_%s";

		desc = &virtnet_rq_stats_desc[0];
		num = ARRAY_SIZE(virtnet_rq_stats_desc);

		virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);

		fmt = "rx%u_hw_%s";
		noq_fmt = "rx_hw_%s";

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_BASIC) {
			desc = &virtnet_stats_rx_basic_desc[0];
			num = ARRAY_SIZE(virtnet_stats_rx_basic_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_CSUM) {
			desc = &virtnet_stats_rx_csum_desc[0];
			num = ARRAY_SIZE(virtnet_stats_rx_csum_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_GSO) {
			desc = &virtnet_stats_rx_gso_desc[0];
			num = ARRAY_SIZE(virtnet_stats_rx_gso_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_SPEED) {
			desc = &virtnet_stats_rx_speed_desc[0];
			num = ARRAY_SIZE(virtnet_stats_rx_speed_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}
	}

	if (type == VIRTNET_Q_TYPE_TX) {
		fmt = "tx%u_%s";
		noq_fmt = "tx_%s";

		desc = &virtnet_sq_stats_desc[0];
		num = ARRAY_SIZE(virtnet_sq_stats_desc);

		virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);

		fmt = "tx%u_hw_%s";
		noq_fmt = "tx_hw_%s";

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_BASIC) {
			desc = &virtnet_stats_tx_basic_desc[0];
			num = ARRAY_SIZE(virtnet_stats_tx_basic_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_CSUM) {
			desc = &virtnet_stats_tx_csum_desc[0];
			num = ARRAY_SIZE(virtnet_stats_tx_csum_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_GSO) {
			desc = &virtnet_stats_tx_gso_desc[0];
			num = ARRAY_SIZE(virtnet_stats_tx_gso_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}

		if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_SPEED) {
			desc = &virtnet_stats_tx_speed_desc[0];
			num = ARRAY_SIZE(virtnet_stats_tx_speed_desc);

			virtnet_stats_sprintf(&p, fmt, noq_fmt, num, qid, desc);
		}
	}

	*data = p;
}

struct virtnet_stats_ctx {
	/* Used to calculate the offset inside the output buffer. */
	u32 desc_num[3];

	/* The actual supported stat types. */
	u32 bitmap[3];

	/* Used to calculate the reply buffer size. */
	u32 size[3];

	/* Record the output buffer. */
	u64 *data;
};

static void virtnet_stats_ctx_init(struct virtnet_info *vi,
				   struct virtnet_stats_ctx *ctx,
				   u64 *data)
{
	u32 queue_type;

	ctx->data = data;

	ctx->desc_num[VIRTNET_Q_TYPE_RX] = ARRAY_SIZE(virtnet_rq_stats_desc);
	ctx->desc_num[VIRTNET_Q_TYPE_TX] = ARRAY_SIZE(virtnet_sq_stats_desc);

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_CVQ) {
		queue_type = VIRTNET_Q_TYPE_CQ;

		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_CVQ;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_cvq_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_cvq);
	}

	queue_type = VIRTNET_Q_TYPE_RX;

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_BASIC) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_RX_BASIC;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_rx_basic_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_rx_basic);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_CSUM) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_RX_CSUM;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_rx_csum_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_rx_csum);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_GSO) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_RX_GSO;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_rx_gso_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_rx_gso);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_RX_SPEED) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_RX_SPEED;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_rx_speed_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_rx_speed);
	}

	queue_type = VIRTNET_Q_TYPE_TX;

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_BASIC) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_TX_BASIC;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_tx_basic_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_tx_basic);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_CSUM) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_TX_CSUM;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_tx_csum_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_tx_csum);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_GSO) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_TX_GSO;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_tx_gso_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_tx_gso);
	}

	if (vi->device_stats_cap & VIRTIO_NET_STATS_TYPE_TX_SPEED) {
		ctx->bitmap[queue_type]   |= VIRTIO_NET_STATS_TYPE_TX_SPEED;
		ctx->desc_num[queue_type] += ARRAY_SIZE(virtnet_stats_tx_speed_desc);
		ctx->size[queue_type]     += sizeof(struct virtio_net_stats_tx_speed);
	}
}

/* stats_sum_queue - Calculate the sum of the same fields in sq or rq.
 * @sum: the position to store the sum values
 * @num: field num
 * @q_value: the first queue fields
 * @q_num: number of the queues
 */
static void stats_sum_queue(u64 *sum, u32 num, u64 *q_value, u32 q_num)
{
	u32 step = num;
	int i, j;
	u64 *p;

	for (i = 0; i < num; ++i) {
		p = sum + i;
		*p = 0;

		for (j = 0; j < q_num; ++j)
			*p += *(q_value + i + j * step);
	}
}

static void virtnet_fill_total_fields(struct virtnet_info *vi,
				      struct virtnet_stats_ctx *ctx)
{
	u64 *data, *first_rx_q, *first_tx_q;
	u32 num_cq, num_rx, num_tx;

	num_cq = ctx->desc_num[VIRTNET_Q_TYPE_CQ];
	num_rx = ctx->desc_num[VIRTNET_Q_TYPE_RX];
	num_tx = ctx->desc_num[VIRTNET_Q_TYPE_TX];

	first_rx_q = ctx->data + num_rx + num_tx + num_cq;
	first_tx_q = first_rx_q + vi->curr_queue_pairs * num_rx;

	data = ctx->data;

	stats_sum_queue(data, num_rx, first_rx_q, vi->curr_queue_pairs);

	data = ctx->data + num_rx;

	stats_sum_queue(data, num_tx, first_tx_q, vi->curr_queue_pairs);
}

/* virtnet_fill_stats - copy the stats to ethtool -S
 * The stats source is the device or the driver.
 *
 * @vi: virtio net info
 * @qid: the vq id
 * @ctx: stats ctx (initiated by virtnet_stats_ctx_init())
 * @base: pointer to the device reply or the driver stats structure.
 * @drv_stats: designate the base type (device reply, driver stats)
 * @type: the type of the device reply (if drv_stats is true, this must be zero)
 */
static void virtnet_fill_stats(struct virtnet_info *vi, u32 qid,
			       struct virtnet_stats_ctx *ctx,
			       const u8 *base, bool drv_stats, u8 reply_type)
{
	u32 queue_type, num_rx, num_tx, num_cq;
	const struct virtnet_stat_desc *desc;
	const u64_stats_t *v_stat;
	u64 offset, bitmap;
	const __le64 *v;
	int i, num;

	num_cq = ctx->desc_num[VIRTNET_Q_TYPE_CQ];
	num_rx = ctx->desc_num[VIRTNET_Q_TYPE_RX];
	num_tx = ctx->desc_num[VIRTNET_Q_TYPE_TX];

	queue_type = vq_type(vi, qid);
	bitmap = ctx->bitmap[queue_type];

	/* skip the total fields of pairs */
	offset = num_rx + num_tx;

	if (queue_type == VIRTNET_Q_TYPE_TX) {
		offset += num_cq + num_rx * vi->curr_queue_pairs + num_tx * (qid / 2);

		num = ARRAY_SIZE(virtnet_sq_stats_desc);
		if (drv_stats) {
			desc = &virtnet_sq_stats_desc[0];
			goto drv_stats;
		}

		offset += num;

	} else if (queue_type == VIRTNET_Q_TYPE_RX) {
		offset += num_cq + num_rx * (qid / 2);

		num = ARRAY_SIZE(virtnet_rq_stats_desc);
		if (drv_stats) {
			desc = &virtnet_rq_stats_desc[0];
			goto drv_stats;
		}

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_CVQ) {
		desc = &virtnet_stats_cvq_desc[0];
		num = ARRAY_SIZE(virtnet_stats_cvq_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_CVQ)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_RX_BASIC) {
		desc = &virtnet_stats_rx_basic_desc[0];
		num = ARRAY_SIZE(virtnet_stats_rx_basic_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_RX_BASIC)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_RX_CSUM) {
		desc = &virtnet_stats_rx_csum_desc[0];
		num = ARRAY_SIZE(virtnet_stats_rx_csum_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_RX_CSUM)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_RX_GSO) {
		desc = &virtnet_stats_rx_gso_desc[0];
		num = ARRAY_SIZE(virtnet_stats_rx_gso_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_RX_GSO)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_RX_SPEED) {
		desc = &virtnet_stats_rx_speed_desc[0];
		num = ARRAY_SIZE(virtnet_stats_rx_speed_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_RX_SPEED)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_TX_BASIC) {
		desc = &virtnet_stats_tx_basic_desc[0];
		num = ARRAY_SIZE(virtnet_stats_tx_basic_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_TX_BASIC)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_TX_CSUM) {
		desc = &virtnet_stats_tx_csum_desc[0];
		num = ARRAY_SIZE(virtnet_stats_tx_csum_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_TX_CSUM)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_TX_GSO) {
		desc = &virtnet_stats_tx_gso_desc[0];
		num = ARRAY_SIZE(virtnet_stats_tx_gso_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_TX_GSO)
			goto found;

		offset += num;
	}

	if (bitmap & VIRTIO_NET_STATS_TYPE_TX_SPEED) {
		desc = &virtnet_stats_tx_speed_desc[0];
		num = ARRAY_SIZE(virtnet_stats_tx_speed_desc);
		if (reply_type == VIRTIO_NET_STATS_TYPE_REPLY_TX_SPEED)
			goto found;

		offset += num;
	}

	return;

found:
	for (i = 0; i < num; ++i) {
		v = (const __le64 *)(base + desc[i].offset);
		ctx->data[offset + i] = le64_to_cpu(*v);
	}

	return;

drv_stats:
	for (i = 0; i < num; ++i) {
		v_stat = (const u64_stats_t *)(base + desc[i].offset);
		ctx->data[offset + i] = u64_stats_read(v_stat);
	}
}

static int __virtnet_get_hw_stats(struct virtnet_info *vi,
				  struct virtnet_stats_ctx *ctx,
				  struct virtio_net_ctrl_queue_stats *req,
				  int req_size, void *reply, int res_size)
{
	struct virtio_net_stats_reply_hdr *hdr;
	struct scatterlist sgs_in, sgs_out;
	void *p;
	u32 qid;
	int ok;

	sg_init_one(&sgs_out, req, req_size);
	sg_init_one(&sgs_in, reply, res_size);

	ok = virtnet_send_command_reply(vi, VIRTIO_NET_CTRL_STATS,
					VIRTIO_NET_CTRL_STATS_GET,
					&sgs_out, &sgs_in);

	if (!ok)
		return ok;

	for (p = reply; p - reply < res_size; p += le16_to_cpu(hdr->size)) {
		hdr = p;
		qid = le16_to_cpu(hdr->vq_index);
		virtnet_fill_stats(vi, qid, ctx, p, false, hdr->type);
	}

	return 0;
}

static void virtnet_make_stat_req(struct virtnet_info *vi,
				  struct virtnet_stats_ctx *ctx,
				  struct virtio_net_ctrl_queue_stats *req,
				  int qid, int *idx)
{
	int qtype = vq_type(vi, qid);
	u64 bitmap = ctx->bitmap[qtype];

	if (!bitmap)
		return;

	req->stats[*idx].vq_index = cpu_to_le16(qid);
	req->stats[*idx].types_bitmap[0] = cpu_to_le64(bitmap);
	*idx += 1;
}

static int virtnet_get_hw_stats(struct virtnet_info *vi,
				struct virtnet_stats_ctx *ctx)
{
	struct virtio_net_ctrl_queue_stats *req;
	int qnum, i, j, res_size, qtype, last_vq;
	void *reply;
	int ok;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_DEVICE_STATS))
		return 0;

	last_vq = vi->curr_queue_pairs * 2 - 1;

	qnum = 0;
	res_size = 0;
	for (i = 0; i <= last_vq ; ++i) {
		qtype = vq_type(vi, i);
		if (ctx->bitmap[qtype]) {
			++qnum;
			res_size += ctx->size[qtype];
		}
	}

	if (ctx->bitmap[VIRTNET_Q_TYPE_CQ]) {
		res_size += ctx->size[VIRTNET_Q_TYPE_CQ];
		qnum += 1;
	}

	req = kcalloc(qnum, sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	reply = kmalloc(res_size, GFP_KERNEL);
	if (!reply) {
		kfree(req);
		return -ENOMEM;
	}

	j = 0;
	for (i = 0; i <= last_vq ; ++i)
		virtnet_make_stat_req(vi, ctx, req, i, &j);

	virtnet_make_stat_req(vi, ctx, req, vi->max_queue_pairs * 2, &j);

	ok = __virtnet_get_hw_stats(vi, ctx, req, sizeof(*req) * j, reply, res_size);

	kfree(req);
	kfree(reply);

	return ok;
}

static void virtnet_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct virtnet_info *vi = netdev_priv(dev);
	unsigned int i;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		/* Generate the total field names. */
		virtnet_get_stats_string(vi, VIRTNET_Q_TYPE_RX, -1, &p);
		virtnet_get_stats_string(vi, VIRTNET_Q_TYPE_TX, -1, &p);

		virtnet_get_stats_string(vi, VIRTNET_Q_TYPE_CQ, 0, &p);

		for (i = 0; i < vi->curr_queue_pairs; ++i)
			virtnet_get_stats_string(vi, VIRTNET_Q_TYPE_RX, i, &p);

		for (i = 0; i < vi->curr_queue_pairs; ++i)
			virtnet_get_stats_string(vi, VIRTNET_Q_TYPE_TX, i, &p);
		break;
	}
}

static int virtnet_get_sset_count(struct net_device *dev, int sset)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct virtnet_stats_ctx ctx = {0};
	u32 pair_count;

	switch (sset) {
	case ETH_SS_STATS:
		virtnet_stats_ctx_init(vi, &ctx, NULL);

		pair_count = ctx.desc_num[VIRTNET_Q_TYPE_RX] + ctx.desc_num[VIRTNET_Q_TYPE_TX];

		return pair_count + ctx.desc_num[VIRTNET_Q_TYPE_CQ] +
			vi->curr_queue_pairs * pair_count;
	default:
		return -EOPNOTSUPP;
	}
}

static void virtnet_get_ethtool_stats(struct net_device *dev,
				      struct ethtool_stats *stats, u64 *data)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct virtnet_stats_ctx ctx = {0};
	unsigned int start, i;
	const u8 *stats_base;

	virtnet_stats_ctx_init(vi, &ctx, data);
	if (virtnet_get_hw_stats(vi, &ctx))
		dev_warn(&vi->dev->dev, "Failed to get hw stats.\n");

	for (i = 0; i < vi->curr_queue_pairs; i++) {
		struct receive_queue *rq = &vi->rq[i];
		struct send_queue *sq = &vi->sq[i];

		stats_base = (const u8 *)&rq->stats;
		do {
			start = u64_stats_fetch_begin(&rq->stats.syncp);
			virtnet_fill_stats(vi, i * 2, &ctx, stats_base, true, 0);
		} while (u64_stats_fetch_retry(&rq->stats.syncp, start));

		stats_base = (const u8 *)&sq->stats;
		do {
			start = u64_stats_fetch_begin(&sq->stats.syncp);
			virtnet_fill_stats(vi, i * 2 + 1, &ctx, stats_base, true, 0);
		} while (u64_stats_fetch_retry(&sq->stats.syncp, start));
	}

	virtnet_fill_total_fields(vi, &ctx);
}

static void virtnet_get_channels(struct net_device *dev,
				 struct ethtool_channels *channels)
{
	struct virtnet_info *vi = netdev_priv(dev);

	channels->combined_count = vi->curr_queue_pairs;
	channels->max_combined = vi->max_queue_pairs;
	channels->max_other = 0;
	channels->rx_count = 0;
	channels->tx_count = 0;
	channels->other_count = 0;
}

static int virtnet_set_link_ksettings(struct net_device *dev,
				      const struct ethtool_link_ksettings *cmd)
{
	struct virtnet_info *vi = netdev_priv(dev);

	return ethtool_virtdev_set_link_ksettings(dev, cmd,
						  &vi->speed, &vi->duplex);
}

static int virtnet_get_link_ksettings(struct net_device *dev,
				      struct ethtool_link_ksettings *cmd)
{
	struct virtnet_info *vi = netdev_priv(dev);

	cmd->base.speed = vi->speed;
	cmd->base.duplex = vi->duplex;
	cmd->base.port = PORT_OTHER;

	return 0;
}

static int virtnet_send_tx_notf_coal_cmds(struct virtnet_info *vi,
					  struct ethtool_coalesce *ec)
{
	struct virtio_net_ctrl_coal_tx *coal_tx = NULL;
	struct scatterlist sgs_tx;
	int i, ret = 0;

	coal_tx = kzalloc(sizeof(*coal_tx), GFP_KERNEL);
	if (!coal_tx)
		return -ENOMEM;

	coal_tx->tx_usecs = cpu_to_le32(ec->tx_coalesce_usecs);
	coal_tx->tx_max_packets = cpu_to_le32(ec->tx_max_coalesced_frames);
	sg_init_one(&sgs_tx, coal_tx, sizeof(*coal_tx));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_NOTF_COAL,
				  VIRTIO_NET_CTRL_NOTF_COAL_TX_SET,
				  &sgs_tx)) {
		ret = -EINVAL;
		goto out;
	}

	vi->intr_coal_tx.max_usecs = ec->tx_coalesce_usecs;
	vi->intr_coal_tx.max_packets = ec->tx_max_coalesced_frames;
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->sq[i].intr_coal.max_usecs = ec->tx_coalesce_usecs;
		vi->sq[i].intr_coal.max_packets = ec->tx_max_coalesced_frames;
	}

out:
	kfree(coal_tx);
	return ret;
}

static int virtnet_send_rx_notf_coal_cmds(struct virtnet_info *vi,
					  struct ethtool_coalesce *ec)
{
	bool rx_ctrl_dim_on = !!ec->use_adaptive_rx_coalesce;
	struct virtio_net_ctrl_coal_rx *coal_rx = NULL;
	struct scatterlist sgs_rx;
	int i, ret = 0;

	if (rx_ctrl_dim_on && !virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return -EOPNOTSUPP;

	if (rx_ctrl_dim_on && (ec->rx_coalesce_usecs != vi->intr_coal_rx.max_usecs ||
			       ec->rx_max_coalesced_frames != vi->intr_coal_rx.max_packets))
		return -EINVAL;

	if (rx_ctrl_dim_on && !vi->rx_dim_enabled) {
		vi->rx_dim_enabled = true;
		for (i = 0; i < vi->max_queue_pairs; i++)
			vi->rq[i].dim_enabled = true;
		return 0;
	}

	coal_rx = kzalloc(sizeof(*coal_rx), GFP_KERNEL);
	if (!coal_rx)
		return -ENOMEM;

	if (!rx_ctrl_dim_on && vi->rx_dim_enabled) {
		vi->rx_dim_enabled = false;
		for (i = 0; i < vi->max_queue_pairs; i++)
			vi->rq[i].dim_enabled = false;
	}

	/* Since the per-queue coalescing params can be set,
	 * we need apply the global new params even if they
	 * are not updated.
	 */
	coal_rx->rx_usecs = cpu_to_le32(ec->rx_coalesce_usecs);
	coal_rx->rx_max_packets = cpu_to_le32(ec->rx_max_coalesced_frames);
	sg_init_one(&sgs_rx, coal_rx, sizeof(*coal_rx));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_NOTF_COAL,
				  VIRTIO_NET_CTRL_NOTF_COAL_RX_SET,
				  &sgs_rx)) {
		ret = -EINVAL;
		goto out;
	}

	vi->intr_coal_rx.max_usecs = ec->rx_coalesce_usecs;
	vi->intr_coal_rx.max_packets = ec->rx_max_coalesced_frames;
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].intr_coal.max_usecs = ec->rx_coalesce_usecs;
		vi->rq[i].intr_coal.max_packets = ec->rx_max_coalesced_frames;
	}

out:
	kfree(coal_rx);
	return ret;
}

static int virtnet_send_notf_coal_cmds(struct virtnet_info *vi,
				       struct ethtool_coalesce *ec)
{
	int err;

	err = virtnet_send_tx_notf_coal_cmds(vi, ec);
	if (err)
		return err;

	err = virtnet_send_rx_notf_coal_cmds(vi, ec);
	if (err)
		return err;

	return 0;
}

static int virtnet_send_rx_notf_coal_vq_cmds(struct virtnet_info *vi,
					     struct ethtool_coalesce *ec,
					     u16 queue)
{
	bool rx_ctrl_dim_on = !!ec->use_adaptive_rx_coalesce;
	u32 max_usecs, max_packets;
	bool cur_rx_dim;
	int err;

	cur_rx_dim = vi->rq[queue].dim_enabled;
	max_usecs = vi->rq[queue].intr_coal.max_usecs;
	max_packets = vi->rq[queue].intr_coal.max_packets;

	if (rx_ctrl_dim_on && (ec->rx_coalesce_usecs != max_usecs ||
			       ec->rx_max_coalesced_frames != max_packets))
		return -EINVAL;

	if (rx_ctrl_dim_on && !cur_rx_dim) {
		vi->rq[queue].dim_enabled = true;
		return 0;
	}

	if (!rx_ctrl_dim_on && cur_rx_dim)
		vi->rq[queue].dim_enabled = false;

	/* If no params are updated, userspace ethtool will
	 * reject the modification.
	 */
	err = virtnet_send_rx_ctrl_coal_vq_cmd(vi, queue,
					       ec->rx_coalesce_usecs,
					       ec->rx_max_coalesced_frames);
	return err;
}

static int virtnet_send_notf_coal_vq_cmds(struct virtnet_info *vi,
					  struct ethtool_coalesce *ec,
					  u16 queue)
{
	int err;

	err = virtnet_send_rx_notf_coal_vq_cmds(vi, ec, queue);
	if (err)
		return err;

	err = virtnet_send_tx_ctrl_coal_vq_cmd(vi, queue,
					       ec->tx_coalesce_usecs,
					       ec->tx_max_coalesced_frames);
	if (err)
		return err;

	return 0;
}

static struct virtnet_coal_node *virtnet_wait_space(struct virtnet_info *vi)
{
	struct virtnet_coal_node *node;
	bool no_free_node = true;

	while (no_free_node) {
		mutex_lock(&vi->coal_free_lock);
		if (!list_empty(&vi->coal_free_list)) {
			no_free_node = false;
			node = list_first_entry(&vi->coal_free_list,
						struct virtnet_coal_node,
						list);
			list_del(&node->list);
		}
		mutex_unlock(&vi->coal_free_lock);
		if (no_free_node)
			usleep_range(1000, 2000);
	}

	return node;
}

static void virtnet_rx_dim_work(struct work_struct *work)
{
	struct dim *dim = container_of(work, struct dim, work);
	struct receive_queue *rq = container_of(dim,
			struct receive_queue, dim);
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct virtnet_coal_node *avail_coal;
	struct dim_cq_moder update_moder;

	if (!rq->dim_enabled ||
	    (update_moder.usec == rq->intr_coal.max_usecs &&
	     update_moder.pkts == rq->intr_coal.max_packets)) {
		rq->dim.state = DIM_START_MEASURE;
		return;
	}

	update_moder = net_dim_get_rx_irq_moder(vi->dev, dim);

	avail_coal = virtnet_wait_space(vi);
	avail_coal->coal_vqs.vqn = cpu_to_le16(rxq2vq(rq - vi->rq));
	avail_coal->coal_vqs.coal.max_usecs = cpu_to_le32(update_moder.usec);
	avail_coal->coal_vqs.coal.max_packets = cpu_to_le32(update_moder.pkts);

	virtnet_add_dim_command(vi, avail_coal);
}

static int virtnet_coal_params_supported(struct ethtool_coalesce *ec)
{
	/* usecs coalescing is supported only if VIRTIO_NET_F_NOTF_COAL
	 * or VIRTIO_NET_F_VQ_NOTF_COAL feature is negotiated.
	 */
	if (ec->rx_coalesce_usecs || ec->tx_coalesce_usecs)
		return -EOPNOTSUPP;

	if (ec->tx_max_coalesced_frames > 1 ||
	    ec->rx_max_coalesced_frames != 1)
		return -EINVAL;

	return 0;
}

static void virtnet_del_coal_free_list(struct virtnet_info *vi)
{
	struct virtnet_coal_node *coal_node, *tmp;

	list_for_each_entry_safe(coal_node, tmp, &vi->coal_free_list, list) {
		list_del(&coal_node->list);
		kfree(coal_node);
	}
}

static int virtnet_init_coal_list(struct virtnet_info *vi)
{
	struct virtnet_coal_node *coal_node;
	int batch_dim_nums;
	int i;

	INIT_LIST_HEAD(&vi->coal_free_list);
	mutex_init(&vi->coal_free_lock);

	INIT_DELAYED_WORK(&vi->get_cvq, virtnet_get_cvq_work);

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return 0;

	enable_get_cvq_work(vi);

	vi->dim_cmd_nums = 0;
	batch_dim_nums = min((unsigned int)vi->max_queue_pairs,
			     virtqueue_get_vring_size(vi->cvq) / 3);
	for (i = 0; i < batch_dim_nums; i++) {
		coal_node = kzalloc(sizeof(*coal_node), GFP_KERNEL);
		if (!coal_node) {
			virtnet_del_coal_free_list(vi);
			return -ENOMEM;
		}
		list_add(&coal_node->list, &vi->coal_free_list);
	}

	return 0;
}

static int virtnet_should_update_vq_weight(int dev_flags, int weight,
					   int vq_weight, bool *should_update)
{
	if (weight ^ vq_weight) {
		if (dev_flags & IFF_UP)
			return -EBUSY;
		*should_update = true;
	}

	return 0;
}

static int virtnet_set_coalesce(struct net_device *dev,
				struct ethtool_coalesce *ec)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int ret, queue_number, napi_weight;
	bool update_napi = false;

	/* Can't change NAPI weight if the link is up */
	napi_weight = ec->tx_max_coalesced_frames ? NAPI_POLL_WEIGHT : 0;
	for (queue_number = 0; queue_number < vi->max_queue_pairs; queue_number++) {
		ret = virtnet_should_update_vq_weight(dev->flags, napi_weight,
						      vi->sq[queue_number].napi.weight,
						      &update_napi);
		if (ret)
			return ret;

		if (update_napi) {
			/* All queues that belong to [queue_number, vi->max_queue_pairs] will be
			 * updated for the sake of simplicity, which might not be necessary
			 */
			break;
		}
	}

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_NOTF_COAL))
		ret = virtnet_send_notf_coal_cmds(vi, ec);
	else
		ret = virtnet_coal_params_supported(ec);

	if (ret)
		return ret;

	if (update_napi) {
		for (; queue_number < vi->max_queue_pairs; queue_number++)
			vi->sq[queue_number].napi.weight = napi_weight;
	}

	return ret;
}

static int virtnet_get_coalesce(struct net_device *dev,
				struct ethtool_coalesce *ec)
{
	struct virtnet_info *vi = netdev_priv(dev);

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_NOTF_COAL)) {
		ec->rx_coalesce_usecs = vi->intr_coal_rx.max_usecs;
		ec->tx_coalesce_usecs = vi->intr_coal_tx.max_usecs;
		ec->tx_max_coalesced_frames = vi->intr_coal_tx.max_packets;
		ec->rx_max_coalesced_frames = vi->intr_coal_rx.max_packets;
		ec->use_adaptive_rx_coalesce = vi->rx_dim_enabled;
	} else {
		ec->rx_max_coalesced_frames = 1;

		if (vi->sq[0].napi.weight)
			ec->tx_max_coalesced_frames = 1;
	}

	return 0;
}

static int virtnet_set_per_queue_coalesce(struct net_device *dev,
					  u32 queue,
					  struct ethtool_coalesce *ec)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int ret, napi_weight;
	bool update_napi = false;

	if (queue >= vi->max_queue_pairs)
		return -EINVAL;

	/* Can't change NAPI weight if the link is up */
	napi_weight = ec->tx_max_coalesced_frames ? NAPI_POLL_WEIGHT : 0;
	ret = virtnet_should_update_vq_weight(dev->flags, napi_weight,
					      vi->sq[queue].napi.weight,
					      &update_napi);
	if (ret)
		return ret;

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		ret = virtnet_send_notf_coal_vq_cmds(vi, ec, queue);
	else
		ret = virtnet_coal_params_supported(ec);

	if (ret)
		return ret;

	if (update_napi)
		vi->sq[queue].napi.weight = napi_weight;

	return 0;
}

static int virtnet_get_per_queue_coalesce(struct net_device *dev,
					  u32 queue,
					  struct ethtool_coalesce *ec)
{
	struct virtnet_info *vi = netdev_priv(dev);

	if (queue >= vi->max_queue_pairs)
		return -EINVAL;

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL)) {
		ec->rx_coalesce_usecs = vi->rq[queue].intr_coal.max_usecs;
		ec->tx_coalesce_usecs = vi->sq[queue].intr_coal.max_usecs;
		ec->tx_max_coalesced_frames = vi->sq[queue].intr_coal.max_packets;
		ec->rx_max_coalesced_frames = vi->rq[queue].intr_coal.max_packets;
		ec->use_adaptive_rx_coalesce = vi->rq[queue].dim_enabled;
	} else {
		ec->rx_max_coalesced_frames = 1;

		if (vi->sq[queue].napi.weight)
			ec->tx_max_coalesced_frames = 1;
	}

	return 0;
}

static void virtnet_init_settings(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

	vi->speed = SPEED_UNKNOWN;
	vi->duplex = DUPLEX_UNKNOWN;
}

static void virtnet_update_settings(struct virtnet_info *vi)
{
	u32 speed;
	u8 duplex;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_SPEED_DUPLEX))
		return;

	virtio_cread_le(vi->vdev, struct virtio_net_config, speed, &speed);

	if (ethtool_validate_speed(speed))
		vi->speed = speed;

	virtio_cread_le(vi->vdev, struct virtio_net_config, duplex, &duplex);

	if (ethtool_validate_duplex(duplex))
		vi->duplex = duplex;
}

static u32 virtnet_get_rxfh_key_size(struct net_device *dev)
{
	return ((struct virtnet_info *)netdev_priv(dev))->rss_key_size;
}

static u32 virtnet_get_rxfh_indir_size(struct net_device *dev)
{
	return ((struct virtnet_info *)netdev_priv(dev))->rss_indir_table_size;
}

static int virtnet_get_rxfh(struct net_device *dev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int i;

	if (indir) {
		for (i = 0; i < vi->rss_indir_table_size; ++i)
			indir[i] = vi->rss.indirection_table[i];
	}

	if (key)
		memcpy(key, vi->rss.key, vi->rss_key_size);

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	return 0;
}

static int virtnet_set_rxfh(struct net_device *dev, const u32 *indir, const u8 *key, const u8 hfunc)
{
	struct virtnet_info *vi = netdev_priv(dev);
	bool update = false;
	int i;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (indir) {
		if (!vi->has_rss)
			return -EOPNOTSUPP;

		for (i = 0; i < vi->rss_indir_table_size; ++i)
			vi->rss.indirection_table[i] = indir[i];
		update = true;
	}

	if (key) {
		/* If either _F_HASH_REPORT or _F_RSS are negotiated, the
		 * device provides hash calculation capabilities, that is,
		 * hash_key is configured.
		 */
		if (!vi->has_rss && !vi->has_rss_hash_report)
			return -EOPNOTSUPP;

		memcpy(vi->rss.key, key, vi->rss_key_size);
		update = true;
	}

	if (update)
		virtnet_commit_rss_command(vi);

	return 0;
}

static int virtnet_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *info, u32 *rule_locs)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int rc = 0;

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = vi->curr_queue_pairs;
		break;
	case ETHTOOL_GRXFH:
		virtnet_get_hashflow(vi, info);
		break;
	default:
		rc = -EOPNOTSUPP;
	}

	return rc;
}

static int virtnet_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *info)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int rc = 0;

	switch (info->cmd) {
	case ETHTOOL_SRXFH:
		if (!virtnet_set_hashflow(vi, info))
			rc = -EINVAL;

		break;
	default:
		rc = -EOPNOTSUPP;
	}

	return rc;
}

static const struct ethtool_ops virtnet_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_MAX_FRAMES |
		ETHTOOL_COALESCE_USECS | ETHTOOL_COALESCE_USE_ADAPTIVE_RX,
	.get_drvinfo = virtnet_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = virtnet_get_ringparam,
	.set_ringparam = virtnet_set_ringparam,
	.get_strings = virtnet_get_strings,
	.get_sset_count = virtnet_get_sset_count,
	.get_ethtool_stats = virtnet_get_ethtool_stats,
	.set_channels = virtnet_set_channels,
	.get_channels = virtnet_get_channels,
	.get_ts_info = ethtool_op_get_ts_info,
	.get_link_ksettings = virtnet_get_link_ksettings,
	.set_link_ksettings = virtnet_set_link_ksettings,
	.set_coalesce = virtnet_set_coalesce,
	.get_coalesce = virtnet_get_coalesce,
	.set_per_queue_coalesce = virtnet_set_per_queue_coalesce,
	.get_per_queue_coalesce = virtnet_get_per_queue_coalesce,
	.get_rxfh_key_size = virtnet_get_rxfh_key_size,
	.get_rxfh_indir_size = virtnet_get_rxfh_indir_size,
	.get_rxfh = virtnet_get_rxfh,
	.set_rxfh = virtnet_set_rxfh,
	.get_rxnfc = virtnet_get_rxnfc,
	.set_rxnfc = virtnet_set_rxnfc,
};

static void virtnet_freeze_down(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	/* Make sure no work handler is accessing the device */
	flush_work(&vi->config_work);
	disable_rx_mode_work(vi);
	flush_work(&vi->rx_mode_work);
	disable_get_cvq_work(vi);
	flush_delayed_work(&vi->get_cvq);

	netif_tx_lock_bh(vi->dev);
	netif_device_detach(vi->dev);
	netif_tx_unlock_bh(vi->dev);
	if (netif_running(vi->dev))
		virtnet_close(vi->dev);
}

static int init_vqs(struct virtnet_info *vi);

static int virtnet_restore_up(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;
	int err;

	err = init_vqs(vi);
	if (err)
		return err;

	virtio_device_ready(vdev);

	enable_delayed_refill(vi);
	enable_rx_mode_work(vi);
	enable_get_cvq_work(vi);

	if (netif_running(vi->dev)) {
		err = virtnet_open(vi->dev);
		if (err)
			return err;
	}

	netif_tx_lock_bh(vi->dev);
	netif_device_attach(vi->dev);
	netif_tx_unlock_bh(vi->dev);
	return err;
}

static int virtnet_set_guest_offloads(struct virtnet_info *vi, u64 offloads)
{
	__virtio64 *_offloads = NULL;
	struct scatterlist sg;
	int ret = 0;

	_offloads = kzalloc(sizeof(*_offloads), GFP_KERNEL);
	if (!_offloads)
		return -ENOMEM;

	*_offloads = cpu_to_virtio64(vi->vdev, offloads);

	sg_init_one(&sg, _offloads, sizeof(*_offloads));

	if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_GUEST_OFFLOADS,
				  VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, &sg)) {
		dev_warn(&vi->dev->dev, "Fail to set guest offload.\n");
		ret = -EINVAL;
	}

	kfree(_offloads);
	return ret;
}

static int virtnet_clear_guest_offloads(struct virtnet_info *vi)
{
	u64 offloads = 0;

	if (!vi->guest_offloads)
		return 0;

	return virtnet_set_guest_offloads(vi, offloads);
}

static int virtnet_restore_guest_offloads(struct virtnet_info *vi)
{
	u64 offloads = vi->guest_offloads;

	if (!vi->guest_offloads)
		return 0;

	return virtnet_set_guest_offloads(vi, offloads);
}

static int virtnet_xdp_set(struct net_device *dev, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack)
{
	unsigned long int max_sz = PAGE_SIZE - sizeof(struct padded_vnet_hdr);
	struct virtnet_info *vi = netdev_priv(dev);
	struct bpf_prog *old_prog;
	u16 xdp_qp = 0, curr_qp;
	int i, err;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)
	    && (virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	        virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO6) ||
	        virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_ECN) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_UFO) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_CSUM) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO4) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO6))) {
		NL_SET_ERR_MSG_MOD(extack, "Can't set XDP while host is implementing GRO_HW/CSUM, disable GRO_HW/CSUM first");
		return -EOPNOTSUPP;
	}

	if (vi->mergeable_rx_bufs && !vi->any_header_sg) {
		NL_SET_ERR_MSG_MOD(extack, "XDP expects header/data in single page, any_header_sg required");
		return -EINVAL;
	}

	if (dev->mtu > max_sz) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large to enable XDP");
		netdev_warn(dev, "XDP requires MTU less than %lu\n", max_sz);
		return -EINVAL;
	}

	curr_qp = vi->curr_queue_pairs - vi->xdp_queue_pairs;
	if (prog)
		xdp_qp = nr_cpu_ids;

	/* XDP requires extra queues for XDP_TX */
	if (curr_qp + xdp_qp > vi->max_queue_pairs) {
		netdev_warn(dev, "XDP request %i queues but max is %i. XDP_TX and XDP_REDIRECT will operate in a slower locked tx mode.\n",
			    curr_qp + xdp_qp, vi->max_queue_pairs);
		xdp_qp = 0;
	}

	old_prog = rtnl_dereference(vi->rq[0].xdp_prog);
	if (!prog && !old_prog)
		return 0;

	if (prog)
		bpf_prog_add(prog, vi->max_queue_pairs - 1);

	/* Make sure NAPI is not using any XDP TX queues for RX. */
	if (netif_running(dev)) {
		for (i = 0; i < vi->max_queue_pairs; i++) {
			napi_disable(&vi->rq[i].napi);
			virtnet_napi_tx_disable(&vi->sq[i].napi);
		}
	}

	if (!prog) {
		for (i = 0; i < vi->max_queue_pairs; i++) {
			rcu_assign_pointer(vi->rq[i].xdp_prog, prog);
			if (i == 0)
				virtnet_restore_guest_offloads(vi);
		}
		synchronize_net();
	}

	err = virtnet_set_queues(vi, curr_qp + xdp_qp);
	if (err)
		goto err;
	netif_set_real_num_rx_queues(dev, curr_qp + xdp_qp);
	vi->xdp_queue_pairs = xdp_qp;

	if (prog) {
		vi->xdp_enabled = true;
		for (i = 0; i < vi->max_queue_pairs; i++) {
			rcu_assign_pointer(vi->rq[i].xdp_prog, prog);
			if (i == 0 && !old_prog)
				virtnet_clear_guest_offloads(vi);
		}
	} else {
		vi->xdp_enabled = false;
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		if (old_prog)
			bpf_prog_put(old_prog);
		if (netif_running(dev)) {
			virtnet_napi_enable(vi->rq[i].vq, &vi->rq[i].napi);
			virtnet_napi_tx_enable(vi, vi->sq[i].vq,
					       &vi->sq[i].napi);
		}
	}

	return 0;

err:
	if (!prog) {
		virtnet_clear_guest_offloads(vi);
		for (i = 0; i < vi->max_queue_pairs; i++)
			rcu_assign_pointer(vi->rq[i].xdp_prog, old_prog);
	}

	if (netif_running(dev)) {
		for (i = 0; i < vi->max_queue_pairs; i++) {
			virtnet_napi_enable(vi->rq[i].vq, &vi->rq[i].napi);
			virtnet_napi_tx_enable(vi, vi->sq[i].vq,
					       &vi->sq[i].napi);
		}
	}
	if (prog)
		bpf_prog_sub(prog, vi->max_queue_pairs - 1);
	return err;
}

static enum hrtimer_restart virtnet_xsk_timeout(struct hrtimer *timer)
{
	struct send_queue *sq;

	sq = container_of(timer, struct send_queue, xsk.timer);

	virtqueue_napi_schedule(&sq->napi, sq->vq);

	u64_stats_update_begin(&sq->stats.syncp);
	u64_stats_inc(&sq->stats.xsk_timer_run);
	u64_stats_update_end(&sq->stats.syncp);

	return HRTIMER_NORESTART;
}

static int virtnet_xsk_pool_enable(struct net_device *dev,
				   struct xsk_buff_pool *pool,
				   u16 qid)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct send_queue *sq = &vi->sq[qid];
	struct virtnet_xsk_hdr *hdr;
	int n, ret = 0;

	if (qid >= dev->real_num_rx_queues || qid >= dev->real_num_tx_queues)
		return -EINVAL;

	if (qid >= vi->curr_queue_pairs)
		return -EINVAL;

	rcu_read_lock();

	ret = -EBUSY;
	if (rcu_dereference(sq->xsk.pool))
		goto end;

	/* check last xsk wait for hdr been free */
	if (rcu_dereference(sq->xsk.hdr))
		goto end;

	n = virtqueue_get_vring_size(sq->vq);
	n = min(xsk_num_max, n * (xsk_num_percent % 100) / 100);

	ret = -ENOMEM;
	hdr = kcalloc(n, sizeof(struct virtnet_xsk_hdr), GFP_ATOMIC);
	if (!hdr)
		goto end;

	memset(&sq->xsk, 0, sizeof(sq->xsk));

	sq->xsk.hdr_pro = n;
	sq->xsk.hdr_n   = n;

	hrtimer_init(&sq->xsk.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	sq->xsk.timer.function = virtnet_xsk_timeout;

	/* Here is already protected by rtnl_lock, so rcu_assign_pointer is
	 * safe.
	 */
	rcu_assign_pointer(sq->xsk.pool, pool);
	rcu_assign_pointer(sq->xsk.hdr, hdr);

	ret = 0;
end:
	rcu_read_unlock();

	return ret;
}

static int virtnet_xsk_pool_disable(struct net_device *dev, u16 qid)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct send_queue *sq = &vi->sq[qid];
	struct netdev_queue *txq;
	struct xsk_buff_pool *pool;

	if (qid >= dev->real_num_rx_queues || qid >= dev->real_num_tx_queues)
		return -EINVAL;

	if (qid >= vi->curr_queue_pairs)
		return -EINVAL;

	pool = sq->xsk.pool;

	/* Here is already protected by rtnl_lock, so rcu_assign_pointer is
	 * safe.
	 */
	rcu_assign_pointer(sq->xsk.pool, NULL);

	hrtimer_cancel(&sq->xsk.timer);

	synchronize_rcu(); /* Sync with the XSK wakeup and with NAPI. */

	txq = netdev_get_tx_queue(vi->dev, qid);

	__netif_tx_lock_bh(txq);
	if (sq->xsk.hdr_pro - sq->xsk.hdr_con == sq->xsk.hdr_n) {
		struct virtnet_xsk_hdr *hdr = NULL;

		/* this has race with the virt_xsk_complete when
		 * sq->xsk.umem == NULL. So add lock to protect.
		 */
		hdr = rcu_replace_pointer(sq->xsk.hdr, hdr, true);

		kfree(hdr);
		sq->xsk.pgs = NULL;
	} else {
		sq->xsk.pgs = xsk_pool_pgs_delay_unpin(pool, &sq->xsk.npgs);
	}
	__netif_tx_unlock_bh(txq);

	return 0;
}

static int virtnet_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return virtnet_xdp_set(dev, xdp->prog, xdp->extack);
	case XDP_SETUP_XSK_POOL:
		if (xdp->xsk.pool)
			return virtnet_xsk_pool_enable(dev, xdp->xsk.pool,
						       xdp->xsk.queue_id);
		else
			return virtnet_xsk_pool_disable(dev, xdp->xsk.queue_id);
	default:
		return -EINVAL;
	}
}

static int virtnet_xsk_xmit(struct send_queue *sq, struct xdp_desc *desc)
{
	struct virtnet_info *vi = sq->vq->vdev->priv;
	struct virtnet_xsk_hdr *xskhdr, *hdr;
	struct page *page;
	void *ptr;
	u32 idx;
	int err;

	page = xsk_pool_get_page(sq->xsk.pool, desc->addr);

	idx = sq->xsk.hdr_con % sq->xsk.hdr_n;

	hdr = rcu_dereference(sq->xsk.hdr);

	xskhdr = hdr + idx;

	xskhdr->len = desc->len;

	sg_init_table(sq->sg, 2);
	sg_set_buf(sq->sg, &xskhdr->hdr, vi->hdr_len);
	sg_set_page(sq->sg + 1, page, desc->len, offset_in_page(desc->addr));

	ptr = xdp_to_ptr(&xskhdr->type);

	err = virtqueue_add_outbuf(sq->vq, sq->sg, 2, ptr, GFP_ATOMIC);
	if (unlikely(err))
		sq->xsk.last_desc = *desc;
	else
		sq->xsk.hdr_con++;

	return err;
}

static bool virtnet_xsk_dev_is_full(struct send_queue *sq)
{
	if (sq->vq->num_free <  2 + MAX_SKB_FRAGS)
		return true;

	if (sq->xsk.hdr_con == sq->xsk.hdr_pro)
		return true;

	return false;
}

static int virtnet_xsk_xmit_zc(struct send_queue *sq,
			       struct xsk_buff_pool *pool, unsigned int budget)
{
	struct xdp_desc desc;
	int err, packet = 0;
	int ret = -EAGAIN;

	if (sq->xsk.last_desc.addr) {
		err = virtnet_xsk_xmit(sq, &sq->xsk.last_desc);
		if (unlikely(err))
			return -EBUSY;

		++packet;
		sq->xsk.last_desc.addr = 0;
	}

	while (budget-- > 0) {
		if (virtnet_xsk_dev_is_full(sq)) {
			ret = -EBUSY;
			break;
		}

		if (!xsk_tx_peek_desc(pool, &desc)) {
			/* done */
			ret = 0;
			break;
		}

		err = virtnet_xsk_xmit(sq, &desc);
		if (unlikely(err)) {
			ret = -EBUSY;
			break;
		}

		++packet;
	}

	if (packet) {
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			u64_stats_inc(&sq->stats.kicks);
			u64_stats_update_end(&sq->stats.syncp);
		}

		xsk_tx_release(pool);
	}

	return ret;
}

static int virtnet_xsk_run(struct send_queue *sq,
			   struct xsk_buff_pool *pool, int budget)
{
	int err, ret = 0;
	unsigned int packets = 0, _packets = 0;
	unsigned int bytes = 0, _bytes = 0;
	unsigned int timer = 0, devfull = 0;

	sq->xsk.wait_slot = false;

	__free_old_xmit_ptr(sq, true, false, &_packets, &_bytes);
	packets += _packets;
	bytes += _bytes;

	err = virtnet_xsk_xmit_zc(sq, pool, xsk_budget);
	if (!err) {
		struct xdp_desc desc;

		clear_bit(VIRTNET_XSK_TXNAPI_RUNNING, &sq->xsk.state);

		/* Memory barrier make sure xsk_umem_consume_tx must come after
		 * clear_bit option.
		 * Race breaker: If new data is coming after last xmit
		 * but before flag change
		 */
		smp_mb__after_atomic();

		/* Check again if there is data in the tx queue. If there is no
		 * data, we can exit directly. If there is still data, then
		 * napi needs to wake up again.
		 */
		if (!xsk_tx_peek_desc(pool, &desc))
			goto end;

		/* this after if check, so memory barrier is no needed. */
		set_bit(VIRTNET_XSK_TXNAPI_RUNNING, &sq->xsk.state);

		sq->xsk.last_desc = desc;
		ret = budget;
		goto end;
	}

	if (err == -EAGAIN) {
		ret = budget;
		goto end;
	}

	/* -EBUSY: wait tx ring avali.
	 *	by tx interrupt or rx interrupt or start_xmit or timer
	 */

	__free_old_xmit_ptr(sq, true, false, &_packets, &_bytes);
	packets += _packets;
	bytes += _bytes;

	if (!virtnet_xsk_dev_is_full(sq)) {
		ret = budget;
		goto end;
	}

	devfull = 1;

	sq->xsk.wait_slot = true;

	if (xsk_check_timeout) {
		timer = 1;
		hrtimer_start(&sq->xsk.timer,
			      ns_to_ktime(xsk_check_timeout * 1000),
			      HRTIMER_MODE_REL_PINNED);
	}

	virtnet_sq_stop_check(sq, true);

end:
	u64_stats_update_begin(&sq->stats.syncp);
	u64_stats_add(&sq->stats.bytes, bytes);
	u64_stats_add(&sq->stats.packets, packets);
	u64_stats_add(&sq->stats.xsk_run, 1);
	u64_stats_add(&sq->stats.xsk_devfull, devfull);
	u64_stats_add(&sq->stats.xsk_timer, timer);
	u64_stats_update_end(&sq->stats.syncp);

	return ret;
}

static int virtnet_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct xsk_buff_pool *pool;
	struct netdev_queue *txq;
	struct send_queue *sq;
	int work = 0;

	if (!netif_running(dev))
		return -ENETDOWN;

	if (qid >= vi->curr_queue_pairs)
		return -EINVAL;

	sq = &vi->sq[qid];

	rcu_read_lock();

	pool = rcu_dereference(sq->xsk.pool);
	if (!pool)
		goto end;

	if (test_and_set_bit(VIRTNET_XSK_TXNAPI_RUNNING, &sq->xsk.state))
		goto end;

	txq = netdev_get_tx_queue(dev, qid);

	local_bh_disable();
	__netif_tx_lock(txq, raw_smp_processor_id());

	work = virtnet_xsk_run(sq, pool, xsk_budget);

	__netif_tx_unlock(txq);
	local_bh_enable();

	if (work == xsk_budget)
		virtqueue_napi_schedule(&sq->napi, sq->vq);

	u64_stats_update_begin(&sq->stats.syncp);
	u64_stats_inc(&sq->stats.xsk_wakeup);
	u64_stats_update_end(&sq->stats.syncp);

end:
	rcu_read_unlock();
	return 0;
}

static int virtnet_get_phys_port_name(struct net_device *dev, char *buf,
				      size_t len)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int ret;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_STANDBY))
		return -EOPNOTSUPP;

	ret = snprintf(buf, len, "sby");
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static int virtnet_set_features(struct net_device *dev,
				netdev_features_t features)
{
	struct virtnet_info *vi = netdev_priv(dev);
	u64 offloads;
	int err;

	if ((dev->features ^ features) & NETIF_F_GRO_HW) {
		if (vi->xdp_enabled)
			return -EBUSY;

		if (features & NETIF_F_GRO_HW)
			offloads = vi->guest_offloads_capable;
		else
			offloads = vi->guest_offloads_capable &
				   ~GUEST_OFFLOAD_GRO_HW_MASK;

		err = virtnet_set_guest_offloads(vi, offloads);
		if (err)
			return err;
		vi->guest_offloads = offloads;
	}

	if ((dev->features ^ features) & NETIF_F_RXHASH) {
		if (features & NETIF_F_RXHASH)
			vi->rss.hash_types = vi->rss_hash_types_saved;
		else
			vi->rss.hash_types = VIRTIO_NET_HASH_REPORT_NONE;

		if (!virtnet_commit_rss_command(vi))
			return -EINVAL;
	}

	return 0;
}

static void virtnet_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
	struct virtnet_info *vi = netdev_priv(dev);
	u32 i;

	for (i = 0; i < vi->curr_queue_pairs; i++) {
		struct netdev_queue *dev_queue = netdev_get_tx_queue(dev, i);
		struct send_queue *sq = &vi->sq[i];

		if (!netif_xmit_stopped(dev_queue))
			continue;

		u64_stats_update_begin(&sq->stats.syncp);
		u64_stats_inc(&sq->stats.tx_timeouts);
		u64_stats_update_end(&sq->stats.syncp);

		netdev_warn(dev, "TX timeout on queue: %d, sq: %s, vq: 0x%x, name: %s, usecs since last trans: %u\n",
			    i, sq->name, sq->vq->index, sq->vq->name,
			    jiffies_to_usecs(jiffies - dev_queue->trans_start));
	}
}

static int virtnet_init_irq_moder(struct virtnet_info *vi)
{
	u8 profile_flags = 0, coal_flags = 0;
	int ret, i;

	profile_flags |= DIM_PROFILE_RX;
	coal_flags |= DIM_COALESCE_USEC | DIM_COALESCE_PKTS;
	ret = net_dim_init_irq_moder(vi->dev, profile_flags, coal_flags,
				     DIM_CQ_PERIOD_MODE_START_FROM_EQE,
				     0, virtnet_rx_dim_work, NULL);

	if (ret)
		return ret;

	for (i = 0; i < vi->max_queue_pairs; i++)
		net_dim_setting(vi->dev, &vi->rq[i].dim, false);

	return 0;
}

static void virtnet_free_irq_moder(struct virtnet_info *vi)
{
	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL))
		return;

	rtnl_lock();
	net_dim_free_irq_moder(vi->dev);
	rtnl_unlock();
}

static const struct net_device_ops virtnet_netdev = {
	.ndo_open            = virtnet_open,
	.ndo_stop   	     = virtnet_close,
	.ndo_start_xmit      = start_xmit,
	.ndo_validate_addr   = eth_validate_addr,
	.ndo_set_mac_address = virtnet_set_mac_address,
	.ndo_set_rx_mode     = virtnet_set_rx_mode,
	.ndo_get_stats64     = virtnet_stats,
	.ndo_vlan_rx_add_vid = virtnet_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = virtnet_vlan_rx_kill_vid,
	.ndo_bpf		= virtnet_xdp,
	.ndo_xdp_xmit		= virtnet_xdp_xmit,
	.ndo_xsk_wakeup	        = virtnet_xsk_wakeup,
	.ndo_features_check	= passthru_features_check,
	.ndo_get_phys_port_name	= virtnet_get_phys_port_name,
	.ndo_set_features	= virtnet_set_features,
	.ndo_tx_timeout		= virtnet_tx_timeout,
};

static void virtnet_config_changed_work(struct work_struct *work)
{
	struct virtnet_info *vi =
		container_of(work, struct virtnet_info, config_work);
	u16 v;

	if (virtio_cread_feature(vi->vdev, VIRTIO_NET_F_STATUS,
				 struct virtio_net_config, status, &v) < 0)
		return;

	if (v & VIRTIO_NET_S_ANNOUNCE) {
		netdev_notify_peers(vi->dev);
		virtnet_ack_link_announce(vi);
	}

	/* Ignore unknown (future) status bits */
	v &= VIRTIO_NET_S_LINK_UP;

	if (vi->status == v)
		return;

	vi->status = v;

	if (vi->status & VIRTIO_NET_S_LINK_UP) {
		virtnet_update_settings(vi);
		netif_carrier_on(vi->dev);
		netif_tx_wake_all_queues(vi->dev);
	} else {
		netif_carrier_off(vi->dev);
		netif_tx_stop_all_queues(vi->dev);
	}
}

static void virtnet_config_changed(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	schedule_work(&vi->config_work);
}

static void virtnet_free_queues(struct virtnet_info *vi)
{
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		__netif_napi_del(&vi->rq[i].napi);
		__netif_napi_del(&vi->sq[i].napi);
	}

	/* We called __netif_napi_del(),
	 * we need to respect an RCU grace period before freeing vi->rq
	 */
	synchronize_net();

	kfree(vi->rq);
	kfree(vi->sq);
	kfree(vi->ctrl);
}

static void _free_receive_bufs(struct virtnet_info *vi)
{
	struct bpf_prog *old_prog;
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		while (vi->rq[i].pages)
			__free_pages(get_a_page(&vi->rq[i], GFP_KERNEL), 0);

		old_prog = rtnl_dereference(vi->rq[i].xdp_prog);
		RCU_INIT_POINTER(vi->rq[i].xdp_prog, NULL);
		if (old_prog)
			bpf_prog_put(old_prog);
	}
}

static void free_receive_bufs(struct virtnet_info *vi)
{
	rtnl_lock();
	_free_receive_bufs(vi);
	rtnl_unlock();
}

static void free_receive_page_frags(struct virtnet_info *vi)
{
	int i;
	for (i = 0; i < vi->max_queue_pairs; i++)
		if (vi->rq[i].alloc_frag.page)
			put_page(vi->rq[i].alloc_frag.page);
}

static void virtnet_sq_free_unused_buf(struct virtqueue *vq, void *buf)
{
	if (!is_xdp_frame(buf)) {
		dev_kfree_skb(buf);
	} else {
		struct virtnet_xdp_type *xtype;

		xtype = ptr_to_xtype(buf);

		if (xtype->type != XDP_TYPE_XSK)
			xdp_return_frame(xtype_got_ptr(xtype));
	}
}

static void virtnet_rq_free_unused_buf(struct virtqueue *vq, void *buf)
{
	struct virtnet_info *vi = vq->vdev->priv;
	int i = vq2rxq(vq);

	if (vi->mergeable_rx_bufs)
		put_page(virt_to_head_page(buf));
	else if (vi->big_packets)
		give_pages(&vi->rq[i], buf);
	else
		put_page(virt_to_head_page(buf));
}

static void free_unused_bufs(struct virtnet_info *vi)
{
	void *buf;
	u64 n;
	int i;
	struct send_queue *sq;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		struct virtqueue *vq = vi->sq[i].vq;

		sq = vi->sq + i;
		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL)
			virtnet_sq_free_unused_buf(vq, buf);

		n = sq->xsk.hdr_con + sq->xsk.hdr_n;
		n -= sq->xsk.hdr_pro;
		if (n)
			xsk_tx_completed(sq->xsk.pool, n);
		cond_resched();
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		struct virtqueue *vq = vi->rq[i].vq;
		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL)
			virtnet_rq_free_unused_buf(vq, buf);
		cond_resched();
	}
}

static void virtnet_del_vqs(struct virtnet_info *vi)
{
	struct virtio_device *vdev = vi->vdev;

	virtnet_clean_affinity(vi);

	vdev->config->del_vqs(vdev);

	virtnet_free_queues(vi);
}

/* How large should a single buffer be so a queue full of these can fit at
 * least one full packet?
 * Logic below assumes the mergeable buffer header is used.
 */
static unsigned int mergeable_min_buf_len(struct virtnet_info *vi, struct virtqueue *vq)
{
	const unsigned int hdr_len = vi->hdr_len;
	unsigned int rq_size = virtqueue_get_vring_size(vq);
	unsigned int packet_len = vi->big_packets ? IP_MAX_MTU : vi->dev->max_mtu;
	unsigned int buf_len = hdr_len + ETH_HLEN + VLAN_HLEN + packet_len;
	unsigned int min_buf_len = DIV_ROUND_UP(buf_len, rq_size);

	return max(max(min_buf_len, hdr_len) - hdr_len,
		   (unsigned int)GOOD_PACKET_LEN);
}

static int virtnet_find_vqs(struct virtnet_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	const char **names;
	int ret = -ENOMEM;
	int total_vqs;
	bool *ctx;
	u16 i;

	/* We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by
	 * possible N-1 RX/TX queue pairs used in multiqueue mode, followed by
	 * possible control vq.
	 */
	total_vqs = vi->max_queue_pairs * 2 +
		    virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ);

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc_array(total_vqs, sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc_array(total_vqs, sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;
	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		ctx = kcalloc(total_vqs, sizeof(*ctx), GFP_KERNEL);
		if (!ctx)
			goto err_ctx;
	} else {
		ctx = NULL;
	}

	/* Parameters for control virtqueue, if any */
	if (vi->has_cvq) {
		callbacks[total_vqs - 1] = NULL;
		names[total_vqs - 1] = "control";
	}

	/* Allocate/initialize parameters for send/receive virtqueues */
	for (i = 0; i < vi->max_queue_pairs; i++) {
		callbacks[rxq2vq(i)] = skb_recv_done;
		callbacks[txq2vq(i)] = skb_xmit_done;
		sprintf(vi->rq[i].name, "input.%u", i);
		sprintf(vi->sq[i].name, "output.%u", i);
		names[rxq2vq(i)] = vi->rq[i].name;
		names[txq2vq(i)] = vi->sq[i].name;
		if (ctx)
			ctx[rxq2vq(i)] = true;
	}

	ret = vi->vdev->config->find_vqs(vi->vdev, total_vqs, vqs, callbacks,
					 names, ctx, NULL);
	if (ret)
		goto err_find;

	if (vi->has_cvq) {
		vi->cvq = vqs[total_vqs - 1];
		if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VLAN))
			vi->dev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].vq = vqs[rxq2vq(i)];
		vi->rq[i].min_buf_len = mergeable_min_buf_len(vi, vi->rq[i].vq);
		vi->sq[i].vq = vqs[txq2vq(i)];
	}

	/* run here: ret == 0. */


err_find:
	kfree(ctx);
err_ctx:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static int virtnet_alloc_queues(struct virtnet_info *vi)
{
	int i;

	vi->ctrl = kzalloc(sizeof(*vi->ctrl), GFP_KERNEL);
	if (!vi->ctrl)
		goto err_ctrl;
	vi->sq = kcalloc(vi->max_queue_pairs, sizeof(*vi->sq), GFP_KERNEL);
	if (!vi->sq)
		goto err_sq;
	vi->rq = kcalloc(vi->max_queue_pairs, sizeof(*vi->rq), GFP_KERNEL);
	if (!vi->rq)
		goto err_rq;

	INIT_DELAYED_WORK(&vi->refill, refill_work);
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].pages = NULL;
		netif_napi_add(vi->dev, &vi->rq[i].napi, virtnet_poll,
			       napi_weight);
		netif_tx_napi_add(vi->dev, &vi->sq[i].napi, virtnet_poll_tx,
				  napi_tx ? napi_weight : 0);

		sg_init_table(vi->rq[i].sg, ARRAY_SIZE(vi->rq[i].sg));
		ewma_pkt_len_init(&vi->rq[i].mrg_avg_pkt_len);
		sg_init_table(vi->sq[i].sg, ARRAY_SIZE(vi->sq[i].sg));

		u64_stats_init(&vi->rq[i].stats.syncp);
		u64_stats_init(&vi->sq[i].stats.syncp);
	}

	return 0;

err_rq:
	kfree(vi->sq);
err_sq:
	kfree(vi->ctrl);
err_ctrl:
	return -ENOMEM;
}

static int init_vqs(struct virtnet_info *vi)
{
	int ret;

	/* Allocate send & receive queues */
	ret = virtnet_alloc_queues(vi);
	if (ret)
		goto err;

	ret = virtnet_find_vqs(vi);
	if (ret)
		goto err_free;

	get_online_cpus();
	virtnet_set_affinity(vi);
	put_online_cpus();

	return 0;

err_free:
	virtnet_free_queues(vi);
err:
	return ret;
}

#ifdef CONFIG_SYSFS
static ssize_t mergeable_rx_buffer_size_show(struct netdev_rx_queue *queue,
		char *buf)
{
	struct virtnet_info *vi = netdev_priv(queue->dev);
	unsigned int queue_index = get_netdev_rx_queue_index(queue);
	unsigned int headroom = virtnet_get_headroom(vi);
	unsigned int tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	struct ewma_pkt_len *avg;

	BUG_ON(queue_index >= vi->max_queue_pairs);
	avg = &vi->rq[queue_index].mrg_avg_pkt_len;
	return sprintf(buf, "%u\n",
		       get_mergeable_buf_len(&vi->rq[queue_index], avg,
				       SKB_DATA_ALIGN(headroom + tailroom)));
}

static struct rx_queue_attribute mergeable_rx_buffer_size_attribute =
	__ATTR_RO(mergeable_rx_buffer_size);

static struct attribute *virtio_net_mrg_rx_attrs[] = {
	&mergeable_rx_buffer_size_attribute.attr,
	NULL
};

static const struct attribute_group virtio_net_mrg_rx_group = {
	.name = "virtio_net",
	.attrs = virtio_net_mrg_rx_attrs
};
#endif

static bool virtnet_fail_on_feature(struct virtio_device *vdev,
				    unsigned int fbit,
				    const char *fname, const char *dname)
{
	if (!virtio_has_feature(vdev, fbit))
		return false;

	dev_err(&vdev->dev, "device advertises feature %s but not %s",
		fname, dname);

	return true;
}

#define VIRTNET_FAIL_ON(vdev, fbit, dbit)			\
	virtnet_fail_on_feature(vdev, fbit, #fbit, dbit)

static bool virtnet_validate_features(struct virtio_device *vdev)
{
	if (!virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ) &&
	    (VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_RX,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_VLAN,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_GUEST_ANNOUNCE,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_MQ, "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_RSS,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_HASH_REPORT,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_NOTF_COAL,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_VQ_NOTF_COAL,
			     "VIRTIO_NET_F_CTRL_VQ"))) {
		return false;
	}

	return true;
}

#define MIN_MTU ETH_MIN_MTU
#define MAX_MTU ETH_MAX_MTU

static int virtnet_validate(struct virtio_device *vdev)
{
	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (!virtnet_validate_features(vdev))
		return -EINVAL;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
		int mtu = virtio_cread16(vdev,
					 offsetof(struct virtio_net_config,
						  mtu));
		if (mtu < MIN_MTU)
			__virtio_clear_bit(vdev, VIRTIO_NET_F_MTU);
	}

	return 0;
}

/* This operation should not fail anything, if it fails it will be as
 * if this operation never happened, i.e. everything else continues
 * normally and all coalescing parameters remain 0.
 */
static int virtnet_get_coal_init_value(struct virtnet_info *vi,
				       u16 vqn, bool is_tx)
{
	struct virtio_net_ctrl_coal_vq *coal_vq = NULL;
	struct scatterlist sgs_in, sgs_out;
	u32 usecs, pkts, i;
	bool ret;

	coal_vq = kzalloc(sizeof(*coal_vq), GFP_KERNEL);
	if (!coal_vq)
		return -ENOMEM;

	coal_vq->vqn = vqn;
	sg_init_one(&sgs_out, &coal_vq->vqn, sizeof(coal_vq->vqn));
	sg_init_one(&sgs_in, &coal_vq->coal, sizeof(coal_vq->coal));
	ret = virtnet_send_command_reply(vi, VIRTIO_NET_CTRL_NOTF_COAL,
					 VIRTIO_NET_CTRL_NOTF_COAL_VQ_GET,
					 &sgs_out, &sgs_in);
	if (!ret) {
		kfree(coal_vq);
		dev_warn(&vi->dev->dev, "getting initial coalescing failed\n");
		return !ret;
	}

	usecs = le32_to_cpu(coal_vq->coal.max_usecs);
	pkts = le32_to_cpu(coal_vq->coal.max_packets);
	if (is_tx) {
		vi->intr_coal_tx.max_usecs = usecs;
		vi->intr_coal_tx.max_packets = pkts;
		for (i = 0; i < vi->max_queue_pairs; i++) {
			vi->sq[i].intr_coal.max_usecs = usecs;
			vi->sq[i].intr_coal.max_packets = pkts;
		}
	} else {
		vi->intr_coal_rx.max_usecs = usecs;
		vi->intr_coal_rx.max_packets = pkts;
		for (i = 0; i < vi->max_queue_pairs; i++) {
			vi->rq[i].intr_coal.max_usecs = usecs;
			vi->rq[i].intr_coal.max_packets = pkts;
		}
	}

	kfree(coal_vq);
	return 0;
}

static int virtnet_probe(struct virtio_device *vdev)
{
	struct virtio_net_stats_capabilities *stats_cap = NULL;
	int i, err = -ENOMEM;
	struct net_device *dev;
	struct virtnet_info *vi;
	u16 max_queue_pairs;
	int mtu;

	/* Find if host supports multiqueue/rss virtio_net device */
	max_queue_pairs = 1;
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MQ) || virtio_has_feature(vdev, VIRTIO_NET_F_RSS))
		max_queue_pairs =
		     virtio_cread16(vdev, offsetof(struct virtio_net_config, max_virtqueue_pairs));

	/* We need at least 2 queue's */
	if (max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
	    max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
	    !virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		max_queue_pairs = 1;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
	SET_NETDEV_DEV(dev, &vdev->dev);

	/* Do we support "hardware" checksums? */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
		/* This opens up the world of extra features. */
		dev->hw_features |= NETIF_F_HW_CSUM | NETIF_F_SG;
		if (csum)
			dev->features |= NETIF_F_HW_CSUM | NETIF_F_SG;

		if (virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
			dev->hw_features |= NETIF_F_TSO
				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
		}
		/* Individual feature bits: what can host handle? */
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
			dev->hw_features |= NETIF_F_TSO;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
			dev->hw_features |= NETIF_F_TSO6;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
			dev->hw_features |= NETIF_F_TSO_ECN;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_USO))
			dev->hw_features |= NETIF_F_GSO_UDP_L4;

		dev->features |= NETIF_F_GSO_ROBUST;

		if (gso)
			dev->features |= dev->hw_features & NETIF_F_ALL_TSO;
		/* (!csum && gso) case will be fixed by register_netdev() */
	}

	/* The device validates the packet checksum and sets DATA_VALID
	 * regardless of whether VIRTIO_NET_F_GUEST_CSUM is negotiated.
	 * We do not allow users to switch rx checksum offload for now.
	 */
	dev->features |= NETIF_F_RXCSUM;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6))
		dev->features |= NETIF_F_GRO_HW;
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS))
		dev->hw_features |= NETIF_F_GRO_HW;

	dev->vlan_features = dev->features;

	/* MTU range: 68 - 65535 */
	dev->min_mtu = MIN_MTU;
	dev->max_mtu = MAX_MTU;

	/* Configuration may specify what MAC to use.  Otherwise random. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC))
		virtio_cread_bytes(vdev,
				   offsetof(struct virtio_net_config, mac),
				   dev->dev_addr, dev->addr_len);
	else
		eth_hw_addr_random(dev);

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;

	INIT_WORK(&vi->config_work, virtnet_config_changed_work);
	INIT_WORK(&vi->rx_mode_work, virtnet_rx_mode_work);
	spin_lock_init(&vi->refill_lock);

	/* If we can receive ANY GSO packets, we must allocate large ones. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_UFO) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_UFO) ||
		(virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO4) &&
		 virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_USO6)))
		vi->big_packets = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
		vi->mergeable_rx_bufs = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_HASH_REPORT))
		vi->has_rss_hash_report = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_RSS)) {
		vi->has_rss = true;

		vi->rss_indir_table_size =
			virtio_cread16(vdev, offsetof(struct virtio_net_config,
				rss_max_indirection_table_length));
	}
	err = rss_indirection_table_alloc(&vi->rss, vi->rss_indir_table_size);
	if (err)
		goto free;

	if (vi->has_rss || vi->has_rss_hash_report) {
		vi->rss_key_size =
			virtio_cread8(vdev, offsetof(struct virtio_net_config, rss_max_key_size));
		if (vi->rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE) {
			dev_err(&vdev->dev, "rss_max_key_size=%u exceeds the limit %u.\n",
				vi->rss_key_size, VIRTIO_NET_RSS_MAX_KEY_SIZE);
			err = -EINVAL;
			goto free;
		}

		vi->rss_hash_types_supported =
		    virtio_cread32(vdev, offsetof(struct virtio_net_config, supported_hash_types));
		vi->rss_hash_types_supported &=
				~(VIRTIO_NET_RSS_HASH_TYPE_IP_EX |
				  VIRTIO_NET_RSS_HASH_TYPE_TCP_EX |
				  VIRTIO_NET_RSS_HASH_TYPE_UDP_EX);

		dev->hw_features |= NETIF_F_RXHASH;
	}

	if (vi->has_rss_hash_report)
		vi->hdr_len = sizeof(struct virtio_net_hdr_v1_hash);
	else if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
		 virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		vi->hdr_len = sizeof(struct virtio_net_hdr);

	if (virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->any_header_sg = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		vi->has_cvq = true;

	mutex_init(&vi->cvq_lock);

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
		mtu = virtio_cread16(vdev,
				     offsetof(struct virtio_net_config,
					      mtu));
		if (mtu < dev->min_mtu) {
			/* Should never trigger: MTU was previously validated
			 * in virtnet_validate.
			 */
			dev_err(&vdev->dev,
				"device MTU appears to have changed it is now %d < %d",
				mtu, dev->min_mtu);
			err = -EINVAL;
			goto free;
		}

		dev->mtu = mtu;
		dev->max_mtu = mtu;

		/* TODO: size buffers correctly in this case. */
		if (dev->mtu > ETH_DATA_LEN)
			vi->big_packets = true;
	}

	if (vi->any_header_sg)
		dev->needed_headroom = vi->hdr_len;

	/* Enable multiqueue by default */
	if (num_online_cpus() >= max_queue_pairs)
		vi->curr_queue_pairs = max_queue_pairs;
	else
		vi->curr_queue_pairs = num_online_cpus();
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
	if (err)
		goto free;

	if (virtnet_init_coal_list(vi))
		goto free;

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_NOTF_COAL)) {
		vi->intr_coal_rx.max_usecs = 0;
		vi->intr_coal_tx.max_usecs = 0;
		vi->intr_coal_rx.max_packets = 0;

		/* Keep the default values of the coalescing parameters
		 * aligned with the default napi_tx state.
		 */
		if (vi->sq[0].napi.weight)
			vi->intr_coal_tx.max_packets = 1;
		else
			vi->intr_coal_tx.max_packets = 0;
	}

#ifdef CONFIG_SYSFS
	if (vi->mergeable_rx_bufs)
		dev->sysfs_rx_queue_group = &virtio_net_mrg_rx_group;
#endif
	netif_set_real_num_tx_queues(dev, vi->curr_queue_pairs);
	netif_set_real_num_rx_queues(dev, vi->curr_queue_pairs);

	virtnet_init_settings(dev);

	if (virtio_has_feature(vdev, VIRTIO_NET_F_STANDBY)) {
		vi->failover = net_failover_create(vi->dev);
		if (IS_ERR(vi->failover)) {
			err = PTR_ERR(vi->failover);
			goto free_vqs;
		}
	}

	if (vi->has_rss || vi->has_rss_hash_report)
		virtnet_init_default_rss(vi);

	enable_rx_mode_work(vi);

	/* serialize netdev register + virtio_device_ready() with ndo_open() */
	rtnl_lock();

	err = register_netdevice(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		rtnl_unlock();
		goto free_failover;
	}

	virtio_device_ready(vdev);

	if (vi->has_rss || vi->has_rss_hash_report) {
		if (!virtnet_commit_rss_command(vi)) {
			dev_warn(&vdev->dev, "RSS disabled because committing failed.\n");
			dev->hw_features &= ~NETIF_F_RXHASH;
			vi->has_rss_hash_report = false;
			vi->has_rss = false;
		}
	}

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_DEVICE_STATS)) {
		struct scatterlist sg;
		__le64 v;

		stats_cap = kzalloc(sizeof(*stats_cap), GFP_KERNEL);
		if (!stats_cap) {
			rtnl_unlock();
			err = -ENOMEM;
			goto free_unregister_netdev;
		}

		sg_init_one(&sg, stats_cap, sizeof(*stats_cap));

		if (!virtnet_send_command_reply(vi, VIRTIO_NET_CTRL_STATS,
						VIRTIO_NET_CTRL_STATS_QUERY,
						NULL, &sg)) {
			pr_debug("virtio_net: fail to get stats capability\n");
			rtnl_unlock();
			err = -EINVAL;
			goto free_stats;
		}

		v = stats_cap->supported_stats_types[0];
		vi->device_stats_cap = le64_to_cpu(v);
	}

	rtnl_unlock();

	err = virtnet_cpu_notif_add(vi);
	if (err) {
		pr_debug("virtio_net: registering cpu notifier failed\n");
		goto free_stats;
	}

	virtnet_set_queues(vi, vi->curr_queue_pairs);

	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_VQ_NOTF_COAL)) {
		/* The reason is the same as VIRTIO_NET_F_NOTF_COAL. */
		for (i = 0; i < vi->max_queue_pairs; i++)
			if (vi->sq[i].napi.weight)
				vi->sq[i].intr_coal.max_packets = 1;

		err = virtnet_init_irq_moder(vi);
		if (err)
			goto free;

		/* Getting the initial irq values from the first rxq
		 * and txq. Even if it fails, the probe should continue.
		 */
		virtnet_get_coal_init_value(vi, rxq2vq(0), false);
		virtnet_get_coal_init_value(vi, txq2vq(0), true);
	}

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	netif_carrier_off(dev);
	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
		schedule_work(&vi->config_work);
	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		virtnet_update_settings(vi);
		netif_carrier_on(dev);
	}

	for (i = 0; i < ARRAY_SIZE(guest_offloads); i++)
		if (virtio_has_feature(vi->vdev, guest_offloads[i]))
			set_bit(guest_offloads[i], &vi->guest_offloads);
	vi->guest_offloads_capable = vi->guest_offloads;

	pr_debug("virtnet: registered device %s with %d RX and TX vq's\n",
		 dev->name, max_queue_pairs);

	return 0;

free_stats:
	kfree(stats_cap);
free_unregister_netdev:
	vi->vdev->config->reset(vdev);

	unregister_netdev(dev);
free_failover:
	net_failover_destroy(vi->failover);
free_vqs:
	cancel_delayed_work_sync(&vi->refill);
	free_receive_page_frags(vi);
	virtnet_del_vqs(vi);
free:
	free_netdev(dev);
	return err;
}

static void remove_vq_common(struct virtnet_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers in both send and recv, if any. */
	free_unused_bufs(vi);

	free_receive_bufs(vi);

	free_receive_page_frags(vi);

	virtnet_del_vqs(vi);
}

static void virtnet_remove(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	virtnet_cpu_notif_remove(vi);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vi->config_work);
	disable_rx_mode_work(vi);
	flush_work(&vi->rx_mode_work);
	disable_get_cvq_work(vi);
	flush_delayed_work(&vi->get_cvq);

	unregister_netdev(vi->dev);

	virtnet_free_irq_moder(vi);

	net_failover_destroy(vi->failover);

	virtnet_del_coal_free_list(vi);

	remove_vq_common(vi);

	rss_indirection_table_free(&vi->rss);

	free_netdev(vi->dev);
}

static __maybe_unused int virtnet_freeze(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	virtnet_cpu_notif_remove(vi);
	virtnet_freeze_down(vdev);
	remove_vq_common(vi);

	return 0;
}

static __maybe_unused int virtnet_restore(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;
	int err;

	err = virtnet_restore_up(vdev);
	if (err)
		return err;
	virtnet_set_queues(vi, vi->curr_queue_pairs);

	err = virtnet_cpu_notif_add(vi);
	if (err) {
		virtnet_freeze_down(vdev);
		remove_vq_common(vi);
		return err;
	}

	return 0;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

#define VIRTNET_FEATURES \
	VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, \
	VIRTIO_NET_F_MAC, \
	VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_HOST_TSO6, \
	VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6, \
	VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_UFO, \
	VIRTIO_NET_F_HOST_USO, VIRTIO_NET_F_GUEST_USO4, VIRTIO_NET_F_GUEST_USO6, \
	VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS, VIRTIO_NET_F_CTRL_VQ, \
	VIRTIO_NET_F_CTRL_RX, VIRTIO_NET_F_CTRL_VLAN, \
	VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_MQ, \
	VIRTIO_NET_F_CTRL_MAC_ADDR, \
	VIRTIO_NET_F_MTU, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, \
	VIRTIO_NET_F_SPEED_DUPLEX, VIRTIO_NET_F_STANDBY, \
	VIRTIO_NET_F_RSS, VIRTIO_NET_F_HASH_REPORT, VIRTIO_NET_F_NOTF_COAL, \
	VIRTIO_NET_F_VQ_NOTF_COAL, VIRTIO_NET_F_DEVICE_STATS

static unsigned int features[] = {
	VIRTNET_FEATURES,
};

static unsigned int features_legacy[] = {
	VIRTNET_FEATURES,
	VIRTIO_NET_F_GSO,
	VIRTIO_F_ANY_LAYOUT,
};

static unsigned int features_force_xdp[] = {
	VIRTIO_NET_F_CSUM,
	VIRTIO_NET_F_MAC,
	VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_HOST_TSO6,
	VIRTIO_NET_F_HOST_ECN,
	VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS, VIRTIO_NET_F_CTRL_VQ,
	VIRTIO_NET_F_CTRL_RX, VIRTIO_NET_F_CTRL_VLAN,
	VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_MQ,
	VIRTIO_NET_F_CTRL_MAC_ADDR,
	VIRTIO_NET_F_CTRL_GUEST_OFFLOADS,
	VIRTIO_NET_F_SPEED_DUPLEX, VIRTIO_NET_F_STANDBY,
	VIRTIO_NET_F_RSS, VIRTIO_NET_F_HASH_REPORT,
	VIRTIO_NET_F_NOTF_COAL, VIRTIO_NET_F_VQ_NOTF_COAL,
	VIRTIO_NET_F_DEVICE_STATS,
	/* legacy */
	VIRTIO_NET_F_GSO,
	VIRTIO_F_ANY_LAYOUT,
};

static struct virtio_driver virtio_net_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.feature_table_legacy = features_legacy,
	.feature_table_size_legacy = ARRAY_SIZE(features_legacy),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.validate =	virtnet_validate,
	.probe =	virtnet_probe,
	.remove =	virtnet_remove,
	.config_changed = virtnet_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtnet_freeze,
	.restore =	virtnet_restore,
#endif
};

static void virtio_net_off_lro(unsigned int *features, int size)
{
	unsigned long long mask;
	unsigned int df = 0;
	int i;

	for (i = 0; i < size; ++i) {
		mask = 1ULL << features[i];

		if (mask & GUEST_OFFLOAD_GRO_HW_MASK)
			continue;

		df = features[i];
		break;
	}

	for (i = 0; i < size; ++i) {
		mask = 1ULL << features[i];

		if (mask & GUEST_OFFLOAD_GRO_HW_MASK)
			features[i] = df;
	}
}

static void virtio_net_check_lro(void)
{
	if (lro)
		return;

	virtio_net_off_lro(features, ARRAY_SIZE(features));
	virtio_net_off_lro(features_legacy, ARRAY_SIZE(features_legacy));
}

static __init int virtio_net_driver_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "virtio/net:online",
				      virtnet_cpu_online,
				      virtnet_cpu_down_prep);
	if (ret < 0)
		goto out;
	virtionet_online = ret;
	ret = cpuhp_setup_state_multi(CPUHP_VIRT_NET_DEAD, "virtio/net:dead",
				      NULL, virtnet_cpu_dead);
	if (ret)
		goto err_dead;

	if (force_xdp) {
		virtio_net_driver.feature_table = features_force_xdp;
		virtio_net_driver.feature_table_size =
			ARRAY_SIZE(features_force_xdp) - 2;

		virtio_net_driver.feature_table_legacy = features_force_xdp;
		virtio_net_driver.feature_table_size_legacy =
			ARRAY_SIZE(features_force_xdp);
	} else {
		virtio_net_check_lro();
	}

        ret = register_virtio_driver(&virtio_net_driver);
	if (ret)
		goto err_virtio;
	return 0;
err_virtio:
	cpuhp_remove_multi_state(CPUHP_VIRT_NET_DEAD);
err_dead:
	cpuhp_remove_multi_state(virtionet_online);
out:
	return ret;
}
module_init(virtio_net_driver_init);

static __exit void virtio_net_driver_exit(void)
{
	unregister_virtio_driver(&virtio_net_driver);
	cpuhp_remove_multi_state(CPUHP_VIRT_NET_DEAD);
	cpuhp_remove_multi_state(virtionet_online);
}
module_exit(virtio_net_driver_exit);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio network driver");
MODULE_LICENSE("GPL");
