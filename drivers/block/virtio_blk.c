// SPDX-License-Identifier: GPL-2.0-only
//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#include <linux/numa.h>
#include <uapi/linux/virtio_ring.h>
#include <linux/cdev.h>
#include <linux/io_uring.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/debugfs.h>
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
#include "../virtio/virtio_pci_common.h"
#include <linux/virtio_config.h>
#include "virtio_blk_ext.h"
#endif

#define CREATE_TRACE_POINTS
#include <trace/events/virtio_blk.h>

#define PART_BITS 4
#define VQ_NAME_LEN 16
#define MAX_DISCARD_SEGMENTS 256u

/* The maximum number of sg elements that fit into a virtqueue */
#define VIRTIO_BLK_MAX_SG_ELEMS 32768
#define VIRTBLK_MINORS		(1U << MINORBITS)

#ifdef CONFIG_ARCH_NO_SG_CHAIN
#define VIRTIO_BLK_INLINE_SG_CNT	0
#else
#define VIRTIO_BLK_INLINE_SG_CNT	2
#endif

static unsigned int num_request_queues;
module_param(num_request_queues, uint, 0644);
MODULE_PARM_DESC(num_request_queues,
		 "Limit the number of request queues to use for blk device. "
		 "0 for no limit. "
		 "Values > nr_cpu_ids truncated to nr_cpu_ids.");

static unsigned int poll_queues;
module_param(poll_queues, uint, 0644);
MODULE_PARM_DESC(poll_queues, "The number of dedicated virtqueues for polling I/O");

static int major;
static DEFINE_IDA(vd_index_ida);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static DEFINE_IDA(vd_chr_minor_ida);
#endif
static dev_t vd_chr_devt;
static struct class *vd_chr_class;

static struct workqueue_struct *virtblk_wq;

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
enum virtblk_ring_t {
	/* ring_pair submission queue */
	VIRTBLK_RING_SQ = 0,
	/* ring_pair completion queue */
	VIRTBLK_RING_CQ = 1,
	VIRTBLK_RING_NUM = 2
};

struct virtblk_cq_req {
	struct virtio_blk_outhdr out_hdr;
	u8 status;
	struct scatterlist inline_sg[2];
	struct scatterlist *sgs[2];
};

struct virtblk_indir_desc {
	struct vring_desc *desc;
	dma_addr_t dma_addr;
	u32 len;
};
#endif

struct virtblk_uring_cmd_pdu {
	struct request *req;
	struct bio *bio;
};

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	/* check num for CQ */
	u16 counter;
	/* prealloced prefill req for CQ */
	struct virtblk_cq_req *cq_req;
#endif
} ____cacheline_aligned_in_smp;

struct virtio_blk {
	/*
	 * This mutex must be held by anything that may run after
	 * virtblk_remove() sets vblk->vdev to NULL.
	 *
	 * blk-mq, virtqueue processing, and sysfs attribute code paths are
	 * shut down before vblk->vdev is set to NULL and therefore do not need
	 * to hold this mutex.
	 */
	struct mutex vdev_mutex;
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/*
	 * Tracks references from block_device_operations open/release and
	 * virtio_driver probe/remove so this object can be freed once no
	 * longer in use.
	 */
	refcount_t refs;

	/* Ida index - used to track minor number allocations. */
	int index;

	/* num of vqs */
	int num_vqs;
	int io_queues[HCTX_MAX_TYPES];
	struct virtio_blk_vq *vqs;

	struct cdev cdev;
	struct device cdev_device;

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	bool ring_pair;
	bool pt_enable;
	bool hide_bdev;
	/* saved indirect desc pointer, dma_addr and dma_len for SQ */
	struct virtblk_indir_desc **indir_desc;
#endif

#ifdef CONFIG_DEBUG_FS
	struct dentry *dbg_dir;
#endif

};

struct virtblk_req {
	struct virtio_blk_outhdr out_hdr;
	u8 status;
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	struct scatterlist inline_sg[2];
#endif
	struct sg_table sg_table;
	struct sg_table sg_table_extra;
	struct scatterlist sg[];
};

#define virtblk_bio_set_disk(bio, disk)			\
do {							\
	if ((bio)->bi_disk != disk)			\
		bio_clear_flag(bio, BIO_BPS_THROTTLED);	\
	(bio)->bi_disk = disk;				\
	(bio)->bi_partno = 0;				\
	bio_associate_blkg(bio);			\
} while (0)

static inline blk_status_t virtblk_result(struct virtblk_req *vbr)
{
	switch (vbr->status) {
	case VIRTIO_BLK_S_OK:
		return BLK_STS_OK;
	case VIRTIO_BLK_S_UNSUPP:
		return BLK_STS_NOTSUPP;
	default:
		return BLK_STS_IOERR;
	}
}

static inline struct virtio_blk_vq *get_virtio_blk_vq(struct blk_mq_hw_ctx *hctx)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct virtio_blk_vq *vq = &vblk->vqs[hctx->queue_num];

	return vq;
}

static inline bool vbr_is_bidirectional(struct virtblk_req *vbr)
{
	struct request *req = blk_mq_rq_from_pdu(vbr);

	return op_is_bidirectional(req->cmd_flags);
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static int virtblk_map_sg(struct virtqueue *vq, struct scatterlist *sglist,
			  enum dma_data_direction dir)
{
	struct scatterlist *sg, *last;

	for (sg = sglist; sg; sg = sg_next(sg)) {
		sg->dma_address = virtqueue_dma_map_page_attrs(vq, sg_page(sg),
					sg->offset, sg->length, dir, 0);
		if (virtqueue_dma_mapping_error(vq, sg->dma_address)) {
			last = sg;
			goto out;
		}
	}
	return 0;
out:
	for (sg = sglist; sg && sg != last; sg = sg_next(sg))
		virtqueue_dma_unmap_page_attrs(vq, sg->dma_address,
					       sg->length, dir, 0);
	return -ENOMEM;
}

static void virtblk_unmap_sg(struct virtqueue *vq, struct scatterlist *sglist,
			     enum dma_data_direction dir)
{
	struct scatterlist *sg;

	for (sg = sglist; sg; sg = sg_next(sg))
		virtqueue_dma_unmap_page_attrs(vq, sg->dma_address,
					       sg->length, dir, 0);
}

static int virtblk_rq_map(struct virtqueue *vq, struct scatterlist *sgs[],
			  unsigned int out_sgs, unsigned int in_sgs)
{
	int i, ret, done_out_sgs, done_in_sgs;

	for (i = 0; i < out_sgs; i++) {
		ret = virtblk_map_sg(vq, sgs[i], DMA_TO_DEVICE);
		if (ret < 0) {
			done_out_sgs = i;
			goto cleanup_out_map;
		}
	}

	for (; i < out_sgs + in_sgs; i++) {
		ret = virtblk_map_sg(vq, sgs[i], DMA_FROM_DEVICE);
		if (ret < 0) {
			done_out_sgs = out_sgs;
			done_in_sgs = i - out_sgs;
			goto cleanup_in_map;
		}
	}
	return 0;

cleanup_in_map:
	for (i = out_sgs; i < out_sgs + done_in_sgs; i++)
		virtblk_unmap_sg(vq, sgs[i], DMA_FROM_DEVICE);
cleanup_out_map:
	for (i = 0; i < done_out_sgs; i++)
		virtblk_unmap_sg(vq, sgs[i], DMA_TO_DEVICE);
	return -ENOMEM;
}

static void virtblk_rq_unmap(struct virtqueue *vq, struct virtblk_req *vbr)
{
	struct request *req = blk_mq_rq_from_pdu(vbr);
	int dir;

	virtblk_unmap_sg(vq, &vbr->inline_sg[0], DMA_TO_DEVICE);
	virtblk_unmap_sg(vq, &vbr->inline_sg[1], DMA_FROM_DEVICE);

	if (!blk_rq_nr_phys_segments(req))
		return;

	if (vbr_is_bidirectional(vbr)) {
		virtblk_unmap_sg(vq, vbr->sg_table.sgl, DMA_TO_DEVICE);
		virtblk_unmap_sg(vq, vbr->sg_table_extra.sgl, DMA_FROM_DEVICE);
	} else {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
			dir = DMA_TO_DEVICE;
		else
			dir = DMA_FROM_DEVICE;
		virtblk_unmap_sg(vq, vbr->sg_table.sgl, dir);
	}
}

static inline void virtblk_save_desc(struct virtqueue *vq, struct virtblk_req *vbr,
					struct vring_desc *desc, dma_addr_t dma_addr,
					u32 len)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	struct request *req = blk_mq_rq_from_pdu(vbr);
	int tag = req->tag, qid = vq->index / VIRTBLK_RING_NUM;
	struct virtblk_indir_desc *indir_desc = &vblk->indir_desc[qid][tag];

	indir_desc->desc = desc;
	indir_desc->dma_addr = dma_addr;
	indir_desc->len = len;
}

static inline void virtblk_unmap_and_clear_desc(struct virtqueue *vq,
						struct virtblk_req *vbr)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	struct request *req = blk_mq_rq_from_pdu(vbr);
	int tag = req->tag, qid = vq->index / VIRTBLK_RING_NUM;
	struct virtblk_indir_desc *indir_desc = &vblk->indir_desc[qid][tag];

	WARN_ON(!indir_desc->desc);
	virtqueue_dma_unmap_page_attrs(vq, indir_desc->dma_addr,
				       indir_desc->len, DMA_TO_DEVICE, 0);

	kfree(indir_desc->desc);
	indir_desc->desc = NULL;
}

static int virtblk_qid_to_sq_qid(int qid)
{
	return qid * VIRTBLK_RING_NUM;
}

static int virtblk_qid_to_cq_qid(int qid)
{
	return qid * VIRTBLK_RING_NUM + 1;
}

static void virtblk_recycle_buf(struct virtqueue *vq)
{
	unsigned int unused;

	while (virtqueue_get_buf(vq, &unused))
		;
}

static inline int virtblk_cq_rq_map(struct virtqueue *vq, struct scatterlist *sgs[])
{
	int ret;

	ret = virtblk_map_sg(vq, sgs[0], DMA_TO_DEVICE);
	if (ret < 0)
		return ret;
	ret = virtblk_map_sg(vq, sgs[1], DMA_FROM_DEVICE);
	if (ret < 0)
		virtblk_unmap_sg(vq, sgs[0], DMA_TO_DEVICE);

	return ret;
}

static void virtblk_cq_rq_unmap(struct virtqueue *vq, struct scatterlist *sgs[])
{
	virtblk_unmap_sg(vq, sgs[0], DMA_TO_DEVICE);
	virtblk_unmap_sg(vq, sgs[1], DMA_FROM_DEVICE);
}

static inline void virtblk_kfree_vqs_cq_reqs(struct virtio_blk *vblk)
{
	int i;

	if (!vblk->ring_pair)
		return;

	if (vblk->vqs != NULL) {
		for (i = 0; i < vblk->num_vqs; i++) {
			if ((i % VIRTBLK_RING_NUM) == VIRTBLK_RING_CQ)
				kfree(vblk->vqs[i].cq_req);
		}
	}
}

static inline void virtblk_kfree_vblk_indir_descs(struct virtio_blk *vblk)
{
	int i;

	if (!vblk->ring_pair)
		return;

	if (vblk->indir_desc != NULL) {
		for (i = 0; i < vblk->num_vqs / VIRTBLK_RING_NUM; i++)
			kfree(vblk->indir_desc[i]);
	}
	kfree(vblk->indir_desc);
}

static int virtblk_prefill_res(struct virtio_blk *vblk,
		struct virtqueue **vqs, int num_vqs)
{
	int i, j, ret, fail_i, fail_j;
	unsigned int vring_size;
	unsigned long flags;
	struct virtblk_cq_req *vbr_res;

	for (i = 1; i < num_vqs; i += VIRTBLK_RING_NUM) {
		vring_size = virtqueue_get_vring_size(vqs[i]);
		vblk->vqs[i].counter = 0;

		spin_lock_irqsave(&vblk->vqs[i].lock, flags);
		for (j = 0; j < vring_size; j++) {
			vbr_res = &vblk->vqs[i].cq_req[j];
			vbr_res->out_hdr.rpair.tag = cpu_to_virtio16(vblk->vdev,
									vblk->vqs[i].counter);
			vblk->vqs[i].counter += 1;
			sg_init_one(&vbr_res->inline_sg[0], &vbr_res->out_hdr,
							sizeof(struct virtio_blk_outhdr));
			sg_init_one(&vbr_res->inline_sg[1], &vbr_res->status, sizeof(u8));

			vbr_res->sgs[0] = &vbr_res->inline_sg[0];
			vbr_res->sgs[1] = &vbr_res->inline_sg[1];

			ret = virtblk_cq_rq_map(vqs[i], vbr_res->sgs);
			if (ret < 0) {
				spin_unlock_irqrestore(&vblk->vqs[i].lock, flags);
				goto err;
			}

			ret = virtqueue_add_sgs(vqs[i], vbr_res->sgs, 1, 1, vbr_res, GFP_ATOMIC);
			if (ret < 0) {
				virtblk_cq_rq_unmap(vqs[i], vbr_res->sgs);
				spin_unlock_irqrestore(&vblk->vqs[i].lock, flags);
				goto err;
			}
		}
		virtqueue_kick(vqs[i]);
		spin_unlock_irqrestore(&vblk->vqs[i].lock, flags);
	}
	return 0;

err:
	fail_i = i;
	fail_j = j;
	for (i = 1; i <= fail_i; i += VIRTBLK_RING_NUM) {
		if (i == fail_i)
			vring_size = fail_j;
		else
			vring_size = virtqueue_get_vring_size(vqs[i]);

		for (j = 0; j < vring_size; j++) {
			vbr_res = &vblk->vqs[i].cq_req[j];
			virtblk_cq_rq_unmap(vqs[i], vbr_res->sgs);
		}
	}
	return -1;
}

static int virtblk_add_req_bidirectional_rpair(struct virtqueue *vq,
		struct virtblk_req *vbr, struct scatterlist *data_sg,
		struct scatterlist *data_sg_extra)
{
	struct scatterlist *sgs[4];
	struct scatterlist *hdr = &vbr->inline_sg[0];
	struct scatterlist *status = &vbr->inline_sg[1];
	struct vring_desc *desc;
	unsigned int num_out = 0, num_in = 0;
	dma_addr_t dma_addr;
	u32 dma_len;
	int ret;

	/*
	 * vritblk_add_req use 'bool' have_data, while we use int num to
	 * validate both OUT and IN direction have data. For bidirectional
	 * request, __blk_bios_map_sg_bidir() should map at least 2 segments.
	 */
	if ((sg_nents(data_sg) == 0) || (sg_nents(data_sg_extra) == 0))
		return -EINVAL;

	sg_init_one(hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sg_init_one(status, &vbr->status, sizeof(vbr->status));
	sgs[num_out++] = hdr;
	sgs[num_out++] = data_sg;
	sgs[num_out + num_in++] = data_sg_extra;
	sgs[num_out + num_in++] = status;

	virtblk_recycle_buf(vq);
	ret = virtblk_rq_map(vq, sgs, num_out, num_in);
	if (ret < 0)
		return ret;

	ret = virtqueue_add_sgs_rpair(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
	if (ret < 0) {
		virtblk_rq_unmap(vq, vbr);
		return ret;
	}
	desc = virtqueue_indir_get_last_desc_split(vq, &dma_addr, &dma_len);
	virtblk_save_desc(vq, vbr, desc, dma_addr, dma_len);

	return ret;
}

static int virtblk_add_req_rpair(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist *sgs[3];
	struct scatterlist *hdr = &vbr->inline_sg[0];
	struct scatterlist *status = &vbr->inline_sg[1];
	struct vring_desc *desc;
	unsigned int num_out = 0, num_in = 0;
	dma_addr_t dma_addr;
	u32 dma_len;
	int ret;

	sg_init_one(hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = hdr;

	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
			sgs[num_out++] = data_sg;
		else
			sgs[num_out + num_in++] = data_sg;
	}

	sg_init_one(status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = status;

	virtblk_recycle_buf(vq);
	ret = virtblk_rq_map(vq, sgs, num_out, num_in);
	if (ret < 0)
		return ret;

	ret = virtqueue_add_sgs_rpair(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
	if (ret < 0) {
		virtblk_rq_unmap(vq, vbr);
		return ret;
	}
	desc = virtqueue_indir_get_last_desc_split(vq, &dma_addr, &dma_len);
	virtblk_save_desc(vq, vbr, desc, dma_addr, dma_len);

	return ret;
}

static inline void *virtblk_get_buf(struct virtio_blk *vblk, struct virtqueue *vq, u32 *len)
{
	struct virtblk_req *vbr;
	struct virtqueue *sq_vq;

	vbr = virtqueue_get_buf(vq, len);
	if (vbr) {
		/* get request from paired req ring in ring_pair mode */
		int qid = vq->index / VIRTBLK_RING_NUM;
		int tag = *len;
		struct request *req = blk_mq_tag_to_rq(vblk->tag_set.tags[qid], tag);
		struct virtblk_cq_req *vbr_res = (void *)vbr;
		int ret;

		sq_vq = vblk->vqs[vq->index - 1].vq;
		if (!req) {
			pr_err("could not locate request for tag %#x, queue %d\n",
				tag, qid);
			return NULL;
		}

		vbr = blk_mq_rq_to_pdu(req);
		/* set status to the real response status. */
		vbr->status = vbr_res->status;
		virtblk_rq_unmap(sq_vq, vbr);
		virtblk_unmap_and_clear_desc(sq_vq, vbr);

		vbr_res->out_hdr.rpair.tag = cpu_to_virtio16(vblk->vdev,
							vblk->vqs[vq->index].counter++);
		ret = virtqueue_add_sgs(vq, vbr_res->sgs, 1, 1, vbr_res, GFP_ATOMIC);
		if (ret < 0)
			pr_err("failed to refill res ring %d\n", ret);

	}
	return vbr;
}
#endif

static int virtblk_add_req_bidirectional(struct virtqueue *vq,
		struct virtblk_req *vbr, struct scatterlist *data_sg,
		struct scatterlist *data_sg_extra)
{
	struct scatterlist hdr, status, *sgs[4];
	unsigned int num_out = 0, num_in = 0;

	/*
	 * vritblk_add_req use 'bool' have_data, while we use int num to
	 * validate both OUT and IN direction have data. For bidirectional
	 * request, __blk_bios_map_sg_bidir() should map at least 2 segments.
	 */
	if ((sg_nents(data_sg) == 0) || (sg_nents(data_sg_extra) == 0))
		return -EINVAL;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out++] = &hdr;
	sgs[num_out++] = data_sg;
	sgs[num_out + num_in++] = data_sg_extra;
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

static int virtblk_add_req(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist hdr, status, *sgs[3];
	unsigned int num_out = 0, num_in = 0;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = &hdr;

	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
			sgs[num_out++] = data_sg;
		else
			sgs[num_out + num_in++] = data_sg;
	}

	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

static int virtblk_setup_discard_write_zeroes(struct request *req, bool unmap)
{
	unsigned short segments = blk_rq_nr_discard_segments(req);
	unsigned short n = 0;
	struct virtio_blk_discard_write_zeroes *range;
	struct bio *bio;
	u32 flags = 0;

	if (unmap)
		flags |= VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP;

	range = kmalloc_array(segments, sizeof(*range), GFP_ATOMIC);
	if (!range)
		return -ENOMEM;

	/*
	 * Single max discard segment means multi-range discard isn't
	 * supported, and block layer only runs contiguity merge like
	 * normal RW request. So we can't reply on bio for retrieving
	 * each range info.
	 */
	if (queue_max_discard_segments(req->q) == 1) {
		range[0].flags = cpu_to_le32(flags);
		range[0].num_sectors = cpu_to_le32(blk_rq_sectors(req));
		range[0].sector = cpu_to_le64(blk_rq_pos(req));
		n = 1;
	} else {
		__rq_for_each_bio(bio, req) {
			u64 sector = bio->bi_iter.bi_sector;
			u32 num_sectors = bio->bi_iter.bi_size >> SECTOR_SHIFT;

			range[n].flags = cpu_to_le32(flags);
			range[n].num_sectors = cpu_to_le32(num_sectors);
			range[n].sector = cpu_to_le64(sector);
			n++;
		}
	}

	WARN_ON_ONCE(n != segments);

	req->special_vec.bv_page = virt_to_page(range);
	req->special_vec.bv_offset = offset_in_page(range);
	req->special_vec.bv_len = sizeof(*range) * segments;
	req->rq_flags |= RQF_SPECIAL_PAYLOAD;

	return 0;
}

static void virtblk_unmap_data(struct request *req, struct virtblk_req *vbr)
{
	if (blk_rq_nr_phys_segments(req))
		sg_free_table_chained(&vbr->sg_table,
				      VIRTIO_BLK_INLINE_SG_CNT);
}

static void virtblk_unmap_data_bidirectional(struct request *req,
					     struct virtblk_req *vbr)
{
	if (blk_rq_nr_phys_segments(req)) {
		sg_free_table_chained(&vbr->sg_table,
				      VIRTIO_BLK_INLINE_SG_CNT);
		sg_free_table_chained(&vbr->sg_table_extra,
				      VIRTIO_BLK_INLINE_SG_CNT);

	}
}

static int virtblk_map_data_bidirectional(struct blk_mq_hw_ctx *hctx,
				struct request *req, struct virtblk_req *vbr)
{
	int err;

	vbr->sg_table.sgl = vbr->sg;
	err = sg_alloc_table_chained(&vbr->sg_table,
				     blk_rq_nr_phys_segments(req),
				     vbr->sg_table.sgl,
				     VIRTIO_BLK_INLINE_SG_CNT);
	if (unlikely(err))
		return -ENOMEM;

	vbr->sg_table_extra.sgl = &vbr->sg[VIRTIO_BLK_INLINE_SG_CNT];
	err = sg_alloc_table_chained(&vbr->sg_table_extra,
				     blk_rq_nr_phys_segments(req),
				     vbr->sg_table_extra.sgl,
				     VIRTIO_BLK_INLINE_SG_CNT);
	if (unlikely(err)) {
		sg_free_table_chained(&vbr->sg_table,
				      VIRTIO_BLK_INLINE_SG_CNT);
		return -ENOMEM;
	}

	return blk_rq_map_sg_bidir(hctx->queue, req,
				vbr->sg_table.sgl, vbr->sg_table_extra.sgl);
}

static int virtblk_map_data(struct blk_mq_hw_ctx *hctx, struct request *req,
		struct virtblk_req *vbr)
{
	int err;

	if (!blk_rq_nr_phys_segments(req))
		return 0;

	vbr->sg_table.sgl = vbr->sg;
	err = sg_alloc_table_chained(&vbr->sg_table,
				     blk_rq_nr_phys_segments(req),
				     vbr->sg_table.sgl,
				     VIRTIO_BLK_INLINE_SG_CNT);
	if (unlikely(err))
		return -ENOMEM;

	return blk_rq_map_sg(hctx->queue, req, vbr->sg_table.sgl);
}

static void virtblk_cleanup_cmd(struct request *req)
{
	if (req->rq_flags & RQF_SPECIAL_PAYLOAD) {
		kfree(page_address(req->special_vec.bv_page) +
		      req->special_vec.bv_offset);
	}
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static blk_status_t virtblk_setup_cmd_rpair(struct virtio_device *vdev,
				      struct request *req,
				      struct virtblk_req *vbr)
{
	bool unmap = false;
	u32 type;
	u64 sector = 0;
	u32 ioprio;

	/* for ring_pair, tag is used and occupied high 16bit of ioprio*/
	vbr->out_hdr.rpair.tag = cpu_to_virtio16(vdev, req->tag);

	switch (req_op(req)) {
	case REQ_OP_READ:
		type = VIRTIO_BLK_T_IN;
		sector = blk_rq_pos(req);
		break;
	case REQ_OP_WRITE:
		type = VIRTIO_BLK_T_OUT;
		sector = blk_rq_pos(req);
		break;
	case REQ_OP_FLUSH:
		type = VIRTIO_BLK_T_FLUSH;
		break;
	case REQ_OP_DISCARD:
		type = VIRTIO_BLK_T_DISCARD;
		break;
	case REQ_OP_WRITE_ZEROES:
		type = VIRTIO_BLK_T_WRITE_ZEROES;
		unmap = !(req->cmd_flags & REQ_NOUNMAP);
		break;
	case REQ_OP_DRV_IN:
	case REQ_OP_DRV_OUT:
		/* Out header already filled in, nothing to do
		 * Attention, currently not support DISCARD and
		 * WRITE_ZEROES for VIRTBLK_PASSTHROUGH.
		 */
		return 0;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	ioprio = req_get_ioprio(req);
	vbr->out_hdr.type = cpu_to_virtio32(vdev, type);
	vbr->out_hdr.sector = cpu_to_virtio64(vdev, sector);
	vbr->out_hdr.rpair.ioprio = cpu_to_virtio16(vdev, (u16)ioprio);

	if (type == VIRTIO_BLK_T_DISCARD || type == VIRTIO_BLK_T_WRITE_ZEROES) {
		if (virtblk_setup_discard_write_zeroes(req, unmap))
			return BLK_STS_RESOURCE;
	}

	return 0;
}
#endif

static blk_status_t virtblk_setup_cmd(struct virtio_device *vdev,
				      struct request *req,
				      struct virtblk_req *vbr)
{
	bool unmap = false;
	u32 type;
	u64 sector = 0;

	switch (req_op(req)) {
	case REQ_OP_READ:
		type = VIRTIO_BLK_T_IN;
		sector = blk_rq_pos(req);
		break;
	case REQ_OP_WRITE:
		type = VIRTIO_BLK_T_OUT;
		sector = blk_rq_pos(req);
		break;
	case REQ_OP_FLUSH:
		type = VIRTIO_BLK_T_FLUSH;
		break;
	case REQ_OP_DISCARD:
		type = VIRTIO_BLK_T_DISCARD;
		break;
	case REQ_OP_WRITE_ZEROES:
		type = VIRTIO_BLK_T_WRITE_ZEROES;
		unmap = !(req->cmd_flags & REQ_NOUNMAP);
		break;
	case REQ_OP_DRV_IN:
	case REQ_OP_DRV_OUT:
		/* Out header already filled in, nothing to do
		 * Attention, currently not support DISCARD and
		 * WRITE_ZEROES for VIRTBLK_PASSTHROUGH.
		 */
		return 0;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	vbr->out_hdr.type = cpu_to_virtio32(vdev, type);
	vbr->out_hdr.sector = cpu_to_virtio64(vdev, sector);
#ifdef CONFIG_VIRTIO_BLK_PASS_REQFLAG
	vbr->out_hdr.reqinfo.ioprio = cpu_to_virtio16(vdev, (u16)req_get_ioprio(req));
	if (req_op(req) == REQ_OP_WRITE || req_op(req) == REQ_OP_READ)
		/* Extract and pack request flags into reqinfo.flags,
		 * bit-0 informs backend that feature is enabled
		 */
		vbr->out_hdr.reqinfo.flags = cpu_to_virtio16(vdev,
						get_and_pack_req_cmd_flags(req));
	else
		vbr->out_hdr.reqinfo.flags = cpu_to_virtio16(vdev, 0);
#else
	vbr->out_hdr.ioprio = cpu_to_virtio32(vdev, req_get_ioprio(req));
#endif

	if (type == VIRTIO_BLK_T_DISCARD || type == VIRTIO_BLK_T_WRITE_ZEROES) {
		if (virtblk_setup_discard_write_zeroes(req, unmap))
			return BLK_STS_RESOURCE;
	}

	return 0;
}

static inline void virtblk_request_done(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

	trace_virtblk_request_done(req, vbr->status);

	if (vbr_is_bidirectional(vbr))
		virtblk_unmap_data_bidirectional(req, vbr);
	else
		virtblk_unmap_data(req, vbr);
	virtblk_cleanup_cmd(req);
	blk_mq_end_request(req, virtblk_result(vbr));
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static void virtblk_done_rpair(struct virtqueue *vq)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	bool req_done = false;
	int qid = vq->index;
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;
	bool kick = false;

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vbr = virtblk_get_buf(vblk, vblk->vqs[qid].vq, &len)) != NULL) {
			struct request *req = blk_mq_rq_from_pdu(vbr);

			if (likely(!blk_should_fake_timeout(req->q)))
				blk_mq_complete_request(req);
			req_done = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	/* In case queue is stopped waiting for more buffers. */
	if (req_done) {
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);
		kick = virtqueue_kick_prepare(vq);
	}
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

	if (kick)
		virtqueue_notify(vq);
}
#endif

static void virtblk_done(struct virtqueue *vq)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	bool req_done = false;
	int qid = vq->index;
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vbr = virtqueue_get_buf(vblk->vqs[qid].vq, &len)) != NULL) {
			struct request *req = blk_mq_rq_from_pdu(vbr);

			if (likely(!blk_should_fake_timeout(req->q)))
				blk_mq_complete_request(req);
			req_done = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	/* In case queue is stopped waiting for more buffers. */
	if (req_done)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
}

static void virtio_commit_rqs(struct blk_mq_hw_ctx *hctx)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct virtio_blk_vq *vq = &vblk->vqs[hctx->queue_num];
	bool kick;

	spin_lock_irq(&vq->lock);
	kick = virtqueue_kick_prepare(vq->vq);
	spin_unlock_irq(&vq->lock);

	if (kick)
		virtqueue_notify(vq->vq);
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static blk_status_t virtio_queue_rq_rpair(struct blk_mq_hw_ctx *hctx,
			   const struct blk_mq_queue_data *bd)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	unsigned long flags;
	int num, qid;
	bool notify = false;
	blk_status_t status;
	int err;

	qid = virtblk_qid_to_sq_qid(hctx->queue_num);
	status = virtblk_setup_cmd_rpair(vblk->vdev, req, vbr);
	if (unlikely(status))
		return status;

	blk_mq_start_request(req);

	if (vbr_is_bidirectional(vbr))
		num = virtblk_map_data_bidirectional(hctx, req, vbr);
	else
		num = virtblk_map_data(hctx, req, vbr);

	trace_virtio_queue_rq_rpair(req, vbr_is_bidirectional(vbr), num);

	if (unlikely(num < 0)) {
		virtblk_cleanup_cmd(req);
		return BLK_STS_RESOURCE;
	}

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	if (vbr_is_bidirectional(vbr))
		err = virtblk_add_req_bidirectional_rpair(vblk->vqs[qid].vq,
				      vbr, vbr->sg_table.sgl,
				      vbr->sg_table_extra.sgl);
	else
		err = virtblk_add_req_rpair(vblk->vqs[qid].vq, vbr,
				      vbr->sg_table.sgl, num);

	if (err) {
		virtqueue_kick(vblk->vqs[qid].vq);
		/* Don't stop the queue if -ENOMEM: we may have failed to
		 * bounce the buffer due to global resource outage.
		 */
		if (err == -ENOSPC)
			blk_mq_stop_hw_queue(hctx);
		spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
		if (vbr_is_bidirectional(vbr))
			virtblk_unmap_data_bidirectional(req, vbr);
		else
			virtblk_unmap_data(req, vbr);
		virtblk_cleanup_cmd(req);
		switch (err) {
		case -ENOSPC:
			return BLK_STS_DEV_RESOURCE;
		case -ENOMEM:
			return BLK_STS_RESOURCE;
		default:
			return BLK_STS_IOERR;
		}
	}

	if (bd->last && virtqueue_kick_prepare(vblk->vqs[qid].vq))
		notify = true;
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

	if (notify)
		virtqueue_notify(vblk->vqs[qid].vq);
	return BLK_STS_OK;
}
#endif

static blk_status_t virtio_queue_rq(struct blk_mq_hw_ctx *hctx,
			   const struct blk_mq_queue_data *bd)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	unsigned long flags;
	int num;
	int qid = hctx->queue_num;
	bool notify = false;
	blk_status_t status;
	int err;

	status = virtblk_setup_cmd(vblk->vdev, req, vbr);
	if (unlikely(status))
		return status;

	blk_mq_start_request(req);

	if (vbr_is_bidirectional(vbr))
		num = virtblk_map_data_bidirectional(hctx, req, vbr);
	else
		num = virtblk_map_data(hctx, req, vbr);

	trace_virtio_queue_rq(req, vbr_is_bidirectional(vbr), num);

	if (unlikely(num < 0)) {
		virtblk_cleanup_cmd(req);
		return BLK_STS_RESOURCE;
	}

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	if (vbr_is_bidirectional(vbr))
		err = virtblk_add_req_bidirectional(vblk->vqs[qid].vq,
				      vbr, vbr->sg_table.sgl,
				      vbr->sg_table_extra.sgl);
	else
		err = virtblk_add_req(vblk->vqs[qid].vq, vbr,
				      vbr->sg_table.sgl, num);

	if (err) {
		virtqueue_kick(vblk->vqs[qid].vq);
		/* Don't stop the queue if -ENOMEM: we may have failed to
		 * bounce the buffer due to global resource outage.
		 */
		if (err == -ENOSPC)
			blk_mq_stop_hw_queue(hctx);
		spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
		if (vbr_is_bidirectional(vbr))
			virtblk_unmap_data_bidirectional(req, vbr);
		else
			virtblk_unmap_data(req, vbr);
		virtblk_cleanup_cmd(req);
		switch (err) {
		case -ENOSPC:
			return BLK_STS_DEV_RESOURCE;
		case -ENOMEM:
			return BLK_STS_RESOURCE;
		default:
			return BLK_STS_IOERR;
		}
	}

	if (bd->last && virtqueue_kick_prepare(vblk->vqs[qid].vq))
		notify = true;
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

	if (notify)
		virtqueue_notify(vblk->vqs[qid].vq);
	return BLK_STS_OK;
}

/* return id (s/n) string for *disk to *id_str
 */
static int virtblk_get_id(struct gendisk *disk, char *id_str)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	struct virtblk_req *vbr;
	int err;

	req = blk_get_request(q, REQ_OP_DRV_IN, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	vbr = blk_mq_rq_to_pdu(req);
	vbr->out_hdr.type = cpu_to_virtio32(vblk->vdev, VIRTIO_BLK_T_GET_ID);
	vbr->out_hdr.ioprio = cpu_to_virtio32(vblk->vdev, req_get_ioprio(req));
	vbr->out_hdr.sector = 0;

	err = blk_rq_map_kern(q, req, id_str, VIRTIO_BLK_ID_BYTES, GFP_KERNEL);
	if (err)
		goto out;

	blk_execute_rq(vblk->disk, req, false);
	err = blk_status_to_errno(virtblk_result(vbr));
out:
	blk_put_request(req);
	return err;
}

static void virtblk_get(struct virtio_blk *vblk)
{
	refcount_inc(&vblk->refs);
}

static void virtblk_put(struct virtio_blk *vblk)
{
	if (refcount_dec_and_test(&vblk->refs)) {
		ida_simple_remove(&vd_index_ida, vblk->index);
		mutex_destroy(&vblk->vdev_mutex);
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
		virtblk_kfree_vblk_indir_descs(vblk);
#endif
		kfree(vblk);
	}
}

static int virtblk_device_open(struct virtio_blk *vblk)
{
	int ret = 0;

	mutex_lock(&vblk->vdev_mutex);

	if (vblk->vdev)
		virtblk_get(vblk);
	else
		ret = -ENXIO;

	mutex_unlock(&vblk->vdev_mutex);
	return ret;
}

static void virtblk_device_release(struct virtio_blk *vblk)
{
	virtblk_put(vblk);
}

static int virtblk_open(struct block_device *bdev, fmode_t mode)
{
	return virtblk_device_open(bdev->bd_disk->private_data);
}

static void virtblk_release(struct gendisk *disk, fmode_t mode)
{
	virtblk_device_release(disk->private_data);
}

/* We provide getgeo only to please some old bootloader/partitioning tools */
static int virtblk_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
	struct virtio_blk *vblk = bd->bd_disk->private_data;
	int ret = 0;

	mutex_lock(&vblk->vdev_mutex);

	if (!vblk->vdev) {
		ret = -ENXIO;
		goto out;
	}

	/* see if the host passed in geometry config */
	if (virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_GEOMETRY)) {
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.cylinders, &geo->cylinders);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.heads, &geo->heads);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.sectors, &geo->sectors);
	} else {
		/* some standard values, similar to sd */
		geo->heads = 1 << 6;
		geo->sectors = 1 << 5;
		geo->cylinders = get_capacity(bd->bd_disk) >> 11;
	}
out:
	mutex_unlock(&vblk->vdev_mutex);
	return ret;
}

static const struct block_device_operations virtblk_fops = {
	.owner  = THIS_MODULE,
	.open = virtblk_open,
	.release = virtblk_release,
	.getgeo = virtblk_getgeo,
};

static int index_to_minor(int index)
{
	return index << PART_BITS;
}

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

static ssize_t serial_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	int err;

	/* sysfs gives us a PAGE_SIZE buffer */
	BUILD_BUG_ON(PAGE_SIZE < VIRTIO_BLK_ID_BYTES);

	buf[VIRTIO_BLK_ID_BYTES] = '\0';
	err = virtblk_get_id(disk, buf);
	if (!err)
		return strlen(buf);

	if (err == -EIO) /* Unsupported? Make it empty. */
		return 0;

	return err;
}

static DEVICE_ATTR_RO(serial);

/* The queue's logical block size must be set before calling this */
static void virtblk_update_capacity(struct virtio_blk *vblk, bool resize)
{
	struct virtio_device *vdev = vblk->vdev;
	struct request_queue *q = vblk->disk->queue;
	char cap_str_2[10], cap_str_10[10];
	unsigned long long nblocks;
	u64 capacity;

	/* Host must always specify the capacity. */
	virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

	/* If capacity is too big, truncate with warning. */
	if ((sector_t)capacity != capacity) {
		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
			 (unsigned long long)capacity);
		capacity = (sector_t)-1;
	}

	nblocks = DIV_ROUND_UP_ULL(capacity, queue_logical_block_size(q) >> 9);

	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

	dev_notice(&vdev->dev,
		   "[%s] %s%llu %d-byte logical blocks (%s/%s)\n",
		   vblk->disk->disk_name,
		   resize ? "new size: " : "",
		   nblocks,
		   queue_logical_block_size(q),
		   cap_str_10,
		   cap_str_2);

	set_capacity_revalidate_and_notify(vblk->disk, capacity, true);
}

static void virtblk_config_changed_work(struct work_struct *work)
{
	struct virtio_blk *vblk =
		container_of(work, struct virtio_blk, config_work);

	virtblk_update_capacity(vblk, true);
}

static void virtblk_config_changed(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	queue_work(virtblk_wq, &vblk->config_work);
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
bool virtblk_rpair_disable;
module_param_named(rpair_disable, virtblk_rpair_disable, bool, 0444);
MODULE_PARM_DESC(rpair_disable, "disable vring pair detective. (0=Not [default], 1=Yes)");

int check_ext_feature(struct virtio_blk *vblk, void __iomem *ioaddr,
						u32 *host_ext_features,
						u32 *guest_ext_features)
{
	int ret = 0;

	ret = virtblk_get_ext_feature(ioaddr, host_ext_features);
	if (ret < 0)
		return ret;

	vblk->ring_pair = !!(*host_ext_features & VIRTIO_BLK_EXT_F_RING_PAIR);
	if (vblk->ring_pair)
		*guest_ext_features |= (VIRTIO_BLK_EXT_F_RING_PAIR);
	vblk->pt_enable = !!(*host_ext_features & VIRTIO_BLK_EXT_F_PT_ENABLE);
	if (vblk->pt_enable)
		*guest_ext_features |= (VIRTIO_BLK_EXT_F_PT_ENABLE);
	vblk->hide_bdev = !!(*host_ext_features & VIRTIO_BLK_EXT_F_HIDE_BLOCK);
	if (vblk->hide_bdev)
		*guest_ext_features |= (VIRTIO_BLK_EXT_F_HIDE_BLOCK);

	return 0;
}

static int init_vq_rpair(struct virtio_blk *vblk)
{
	int err = 0;
	int i;
	vq_callback_t **callbacks;
	const char **names;
	struct virtqueue **vqs;
	unsigned short num_vqs;
	unsigned int num_poll_vqs, num_queues, num_poll_queues, vring_size;
	u32 ext_host_features = 0, ext_guest_features = 0, ext_bar_offset = 0;
	struct virtio_device *vdev = vblk->vdev;
	struct irq_affinity desc = { 0, };
	void __iomem *ioaddr = NULL;

	err = virtblk_get_ext_feature_bar(vdev, &ext_bar_offset);
	/* if check ext feature error, fall back to orig virtqueue use. */
	if ((err < 0) || !ext_bar_offset)
		return 1;

	ioaddr = pci_iomap_range(to_vp_device(vdev)->pci_dev, 0, ext_bar_offset, 16);
	if (!ioaddr) {
		err = 1;
		goto negotiate_err;
	}

	err = check_ext_feature(vblk, ioaddr, &ext_host_features, &ext_guest_features);
	if ((err < 0) || !vblk->ring_pair) {
		err = 1;
		goto negotiate_err;
	}

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_MQ,
				   struct virtio_blk_config, num_queues,
				   &num_vqs);
	if (err)
		num_vqs = 1;

	if (!err && !num_vqs) {
		dev_err(&vdev->dev, "MQ advertised but zero queues reported\n");
		err = -EINVAL;
		goto negotiate_err;
	}

	if (num_vqs % VIRTBLK_RING_NUM) {
		dev_err(&vdev->dev,
			"RING_PAIR advertised but odd queues reported\n");
		err = 1;
		goto negotiate_err;
	}

	/* ring pair only support split virtqueue + indirect enabled */
	if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED) ||
		!virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC)) {
		dev_err(&vdev->dev, "rpair only support indir+split queue\n");
		err = 1;
		goto negotiate_err;
	}

	virtblk_set_ext_feature(ioaddr, ext_guest_features);
	pci_iounmap(to_vp_device(vdev)->pci_dev, ioaddr);
	dev_info(&vdev->dev, "rpair enabled, ext_guest_feature set 0x%x\n",
						ext_guest_features);

	num_queues = num_vqs / VIRTBLK_RING_NUM;
	num_queues = min_t(unsigned int,
		min_not_zero(num_request_queues, nr_cpu_ids),
		num_queues);
	num_poll_queues = min_t(unsigned int, poll_queues, num_queues - 1);
	num_poll_vqs = num_poll_queues * VIRTBLK_RING_NUM;
	num_vqs = num_queues * VIRTBLK_RING_NUM;

	vblk->io_queues[HCTX_TYPE_DEFAULT] = num_queues - num_poll_queues;
	vblk->io_queues[HCTX_TYPE_READ] = 0;
	vblk->io_queues[HCTX_TYPE_POLL] = num_poll_queues;

	dev_info(&vdev->dev, "%d/%d/%d default/read/poll queues\n",
				vblk->io_queues[HCTX_TYPE_DEFAULT],
				vblk->io_queues[HCTX_TYPE_READ],
				vblk->io_queues[HCTX_TYPE_POLL]);

	vblk->vqs = kmalloc_array(num_vqs, sizeof(*vblk->vqs),
				  GFP_KERNEL | __GFP_ZERO);
	if (!vblk->vqs)
		return -ENOMEM;

	names = kmalloc_array(num_vqs, sizeof(*names), GFP_KERNEL);
	callbacks = kmalloc_array(num_vqs, sizeof(*callbacks), GFP_KERNEL);
	vqs = kmalloc_array(num_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!names || !callbacks || !vqs) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_vqs - num_poll_vqs; i++) {
		unsigned int index = i / VIRTBLK_RING_NUM;
		unsigned int role = i % VIRTBLK_RING_NUM;

		if (role == VIRTBLK_RING_SQ) {
			callbacks[i] = NULL;
			snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req.%d", index);
		} else {
			callbacks[i] = virtblk_done_rpair;
			snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "res.%d", index);
		}
		names[i] = vblk->vqs[i].name;
	}

	for (; i < num_vqs; i++) {
		unsigned int index = i / VIRTBLK_RING_NUM;
		unsigned int role = i % VIRTBLK_RING_NUM;

		if (role == VIRTBLK_RING_SQ)
			snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req-poll.%d", index);
		else
			snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "res-poll.%d", index);
		callbacks[i] = NULL;
		names[i] = vblk->vqs[i].name;
	}

	/* Discover virtqueues and write information to configuration.  */
	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, &desc);
	if (err)
		goto out;

	/*
	 * Publish num_vqs before the cq_req allocation loop so that the
	 * error path in virtblk_kfree_vqs_cq_reqs() can iterate over all
	 * already-allocated cq_req arrays when one of the allocations fails.
	 */
	vblk->num_vqs = num_vqs;

	for (i = 0; i < num_vqs; i++) {
		vring_size = virtqueue_get_vring_size(vqs[i]);
		if ((i % VIRTBLK_RING_NUM) == VIRTBLK_RING_CQ) {
			vblk->vqs[i].cq_req = kmalloc_array(vring_size,
					sizeof(struct virtblk_cq_req),
					GFP_KERNEL | __GFP_ZERO);
			if (!vblk->vqs[i].cq_req) {
				err = -ENOMEM;
				vdev->config->del_vqs(vdev);
				goto out;
			}
		} else {
			virtqueue_set_save_indir(vqs[i]);
			vblk->vqs[i].cq_req = NULL;
		}
		virtqueue_set_dma_premapped(vqs[i]);
		spin_lock_init(&vblk->vqs[i].lock);
		vblk->vqs[i].vq = vqs[i];
	}

	err = virtblk_prefill_res(vblk, vqs, num_vqs);
	if (err < 0)
		vdev->config->del_vqs(vdev);

out:
	kfree(vqs);
	kfree(callbacks);
	kfree(names);
	if (err < 0) {
		virtblk_kfree_vqs_cq_reqs(vblk);
		kfree(vblk->vqs);
	}
	return err;

negotiate_err:
	if (ioaddr) {
		ext_guest_features &= ~VIRTIO_BLK_EXT_F_RING_PAIR;
		virtblk_set_ext_feature(ioaddr, ext_guest_features);
		pci_iounmap(to_vp_device(vdev)->pci_dev, ioaddr);
	}
	vblk->ring_pair = false;
	return err;
}
#endif

static int init_vq(struct virtio_blk *vblk)
{
	int err = 1;
	int i;
	vq_callback_t **callbacks;
	const char **names;
	struct virtqueue **vqs;
	unsigned short num_vqs;
	unsigned int num_poll_vqs;
	struct virtio_device *vdev = vblk->vdev;
	struct irq_affinity desc = { 0, };

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	vblk->ring_pair = false;
	vblk->pt_enable = false;
	vblk->hide_bdev = false;

	/* ext feature only support for virtio_blk over pci device currently */
	if (!virtblk_rpair_disable && dev_is_pci(vblk->vdev->dev.parent))
		err = init_vq_rpair(vblk);

	/* if err > 0, then vring pair fall back to original virtqueue use*/
	if (err <= 0)
		return err;
#endif
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_MQ,
				   struct virtio_blk_config, num_queues,
				   &num_vqs);
	if (err)
		num_vqs = 1;

	if (!err && !num_vqs) {
		dev_err(&vdev->dev, "MQ advertised but zero queues reported\n");
		return -EINVAL;
	}

	num_vqs = min_t(unsigned int,
			min_not_zero(num_request_queues, nr_cpu_ids),
			num_vqs);

	num_poll_vqs = min_t(unsigned int, poll_queues, num_vqs - 1);

	vblk->io_queues[HCTX_TYPE_DEFAULT] = num_vqs - num_poll_vqs;
	vblk->io_queues[HCTX_TYPE_READ] = 0;
	vblk->io_queues[HCTX_TYPE_POLL] = num_poll_vqs;

	dev_info(&vdev->dev, "%d/%d/%d default/read/poll queues\n",
				vblk->io_queues[HCTX_TYPE_DEFAULT],
				vblk->io_queues[HCTX_TYPE_READ],
				vblk->io_queues[HCTX_TYPE_POLL]);

	vblk->vqs = kmalloc_array(num_vqs, sizeof(*vblk->vqs), GFP_KERNEL);
	if (!vblk->vqs)
		return -ENOMEM;

	names = kmalloc_array(num_vqs, sizeof(*names), GFP_KERNEL);
	callbacks = kmalloc_array(num_vqs, sizeof(*callbacks), GFP_KERNEL);
	vqs = kmalloc_array(num_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!names || !callbacks || !vqs) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_vqs - num_poll_vqs; i++) {
		callbacks[i] = virtblk_done;
		snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req.%d", i);
		names[i] = vblk->vqs[i].name;
	}

	for (; i < num_vqs; i++) {
		callbacks[i] = NULL;
		snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req_poll.%d", i);
		names[i] = vblk->vqs[i].name;
	}

	/* Discover virtqueues and write information to configuration.  */
	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, &desc);
	if (err)
		goto out;

	for (i = 0; i < num_vqs; i++) {
		spin_lock_init(&vblk->vqs[i].lock);
		vblk->vqs[i].vq = vqs[i];
	}
	vblk->num_vqs = num_vqs;

out:
	kfree(vqs);
	kfree(callbacks);
	kfree(names);
	if (err)
		kfree(vblk->vqs);
	return err;
}

/*
 * Legacy naming scheme used for virtio devices.  We are stuck with it for
 * virtio blk but don't ever use it for any new driver.
 */
static int virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
	const int base = 'z' - 'a' + 1;
	char *begin = buf + strlen(prefix);
	char *end = buf + buflen;
	char *p;
	int unit;

	p = end - 1;
	*p = '\0';
	unit = base;
	do {
		if (p == begin)
			return -EINVAL;
		*--p = 'a' + (index % unit);
		index = (index / unit) - 1;
	} while (index >= 0);

	memmove(begin, p, end - p);
	memcpy(buf, prefix, strlen(prefix));

	return 0;
}

static int virtblk_get_cache_mode(struct virtio_device *vdev)
{
	u8 writeback;
	int err;

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE,
				   struct virtio_blk_config, wce,
				   &writeback);

	/*
	 * If WCE is not configurable and flush is not available,
	 * assume no writeback cache is in use.
	 */
	if (err)
		writeback = virtio_has_feature(vdev, VIRTIO_BLK_F_FLUSH);

	return writeback;
}

static void virtblk_update_cache_mode(struct virtio_device *vdev)
{
	u8 writeback = virtblk_get_cache_mode(vdev);
	struct virtio_blk *vblk = vdev->priv;

	blk_queue_write_cache(vblk->disk->queue, writeback, false);
	revalidate_disk_size(vblk->disk, true);
}

static const char *const virtblk_cache_types[] = {
	"write through", "write back"
};

static ssize_t
cache_type_store(struct device *dev, struct device_attribute *attr,
		 const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	struct virtio_device *vdev = vblk->vdev;
	int i;

	BUG_ON(!virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_CONFIG_WCE));
	i = sysfs_match_string(virtblk_cache_types, buf);
	if (i < 0)
		return i;

	virtio_cwrite8(vdev, offsetof(struct virtio_blk_config, wce), i);
	virtblk_update_cache_mode(vdev);
	return count;
}

static ssize_t
cache_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	u8 writeback = virtblk_get_cache_mode(vblk->vdev);

	BUG_ON(writeback >= ARRAY_SIZE(virtblk_cache_types));
	return snprintf(buf, 40, "%s\n", virtblk_cache_types[writeback]);
}

static DEVICE_ATTR_RW(cache_type);

static struct attribute *virtblk_attrs[] = {
	&dev_attr_serial.attr,
	&dev_attr_cache_type.attr,
	NULL,
};

static umode_t virtblk_attrs_are_visible(struct kobject *kobj,
		struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	struct virtio_device *vdev = vblk->vdev;

	if (a == &dev_attr_cache_type.attr &&
	    !virtio_has_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE))
		return S_IRUGO;

	return a->mode;
}

static const struct attribute_group virtblk_attr_group = {
	.attrs = virtblk_attrs,
	.is_visible = virtblk_attrs_are_visible,
};

static const struct attribute_group *virtblk_attr_groups[] = {
	&virtblk_attr_group,
	NULL,
};

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
int blk_mq_virtio_map_queues_rpair(struct blk_mq_queue_map *qmap,
	struct virtio_device *vdev, int first_vec)
{
	const struct cpumask *mask;
	unsigned int queue, cpu;

	if (!vdev->config->get_vq_affinity)
		goto fallback;

	for (queue = 0; queue < qmap->nr_queues; queue++) {
		mask = vdev->config->get_vq_affinity(vdev, first_vec +
						virtblk_qid_to_cq_qid(queue));
		if (!mask)
			goto fallback;

		for_each_cpu(cpu, mask)
			qmap->mq_map[cpu] = qmap->queue_offset + queue;
	}

	return 0;
fallback:
	return blk_mq_map_queues(qmap);
}

static int virtblk_map_queues_rpair(struct blk_mq_tag_set *set)
{
	struct virtio_blk *vblk = set->driver_data;
	int i, qoff;

	for (i = 0, qoff = 0; i < set->nr_maps; i++) {
		struct blk_mq_queue_map *map = &set->map[i];

		map->nr_queues = vblk->io_queues[i];
		map->queue_offset = qoff;
		qoff += map->nr_queues;

		if (map->nr_queues == 0)
			continue;

		/*
		 * Regular queues have interrupts and hence CPU affinity is
		 * defined by the core virtio code, but polling queues have
		 * no interrupts so we let the block layer assign CPU affinity.
		 */
		if (i == HCTX_TYPE_POLL)
			blk_mq_map_queues(&set->map[i]);
		else
			blk_mq_virtio_map_queues_rpair(&set->map[i], vblk->vdev, 0);
	}

	return 0;
}
#endif

static int virtblk_map_queues(struct blk_mq_tag_set *set)
{
	struct virtio_blk *vblk = set->driver_data;
	int i, qoff;

	for (i = 0, qoff = 0; i < set->nr_maps; i++) {
		struct blk_mq_queue_map *map = &set->map[i];

		map->nr_queues = vblk->io_queues[i];
		map->queue_offset = qoff;
		qoff += map->nr_queues;

		if (map->nr_queues == 0)
			continue;

		/*
		 * Regular queues have interrupts and hence CPU affinity is
		 * defined by the core virtio code, but polling queues have
		 * no interrupts so we let the block layer assign CPU affinity.
		 */
		if (i == HCTX_TYPE_POLL)
			blk_mq_map_queues(&set->map[i]);
		else
			blk_mq_virtio_map_queues(&set->map[i], vblk->vdev, 0);
	}

	return 0;
}

static void virtblk_complete_batch(struct io_comp_batch *iob)
{
	struct request *req;

	rq_list_for_each(&iob->req_list, req) {
		if (op_is_bidirectional(req->cmd_flags))
			virtblk_unmap_data_bidirectional(req,
						blk_mq_rq_to_pdu(req));
		else
			virtblk_unmap_data(req, blk_mq_rq_to_pdu(req));
		virtblk_cleanup_cmd(req);
	}
	blk_mq_end_request_batch(iob);
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static int virtblk_poll_rpair(struct blk_mq_hw_ctx *hctx, struct io_comp_batch *iob)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct virtio_blk_vq *vq = &vblk->vqs[virtblk_qid_to_cq_qid(hctx->queue_num)];
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;
	int found = 0;
	bool kick = false;

	/* get buf from paired CQ ring in ring_pair mode */
	spin_lock_irqsave(&vq->lock, flags);

	while ((vbr = virtblk_get_buf(vblk, vq->vq, &len)) != NULL) {
		struct request *req = blk_mq_rq_from_pdu(vbr);

		found++;
		if (!blk_mq_complete_request_remote(req) &&
		    !blk_mq_add_to_batch(req, iob, vbr->status,
						virtblk_complete_batch))
			virtblk_request_done(req);
	}

	if (found) {
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);
		kick = virtqueue_kick_prepare(vq->vq);
	}

	spin_unlock_irqrestore(&vq->lock, flags);

	if (kick)
		virtqueue_notify(vq->vq);

	return found;
}
#endif

static int virtblk_poll(struct blk_mq_hw_ctx *hctx, struct io_comp_batch *iob)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct virtio_blk_vq *vq = get_virtio_blk_vq(hctx);
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;
	int found = 0;

	spin_lock_irqsave(&vq->lock, flags);

	while ((vbr = virtqueue_get_buf(vq->vq, &len)) != NULL) {
		struct request *req = blk_mq_rq_from_pdu(vbr);

		found++;
		if (!blk_mq_complete_request_remote(req) &&
		    !blk_mq_add_to_batch(req, iob, vbr->status,
						virtblk_complete_batch))
			virtblk_request_done(req);
	}

	if (found)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);

	spin_unlock_irqrestore(&vq->lock, flags);

	return found;
}

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static const struct blk_mq_ops virtio_mq_pair_ops = {
	.queue_rq	= virtio_queue_rq_rpair,
	.commit_rqs	= virtio_commit_rqs,
	.complete	= virtblk_request_done,
	.map_queues	= virtblk_map_queues_rpair,
	.poll		= virtblk_poll_rpair,
};
#endif

static const struct blk_mq_ops virtio_mq_ops = {
	.queue_rq	= virtio_queue_rq,
	.commit_rqs	= virtio_commit_rqs,
	.complete	= virtblk_request_done,
	.map_queues	= virtblk_map_queues,
	.poll		= virtblk_poll,
};

static inline struct virtblk_uring_cmd_pdu *virtblk_uring_cmd_pdu(
		struct io_uring_cmd *ioucmd)
{
	return io_uring_cmd_to_pdu(ioucmd, struct virtblk_uring_cmd_pdu);
}

static void virtblk_uring_task_cb(struct io_uring_cmd *ioucmd)
{
	struct virtblk_uring_cmd_pdu *pdu = virtblk_uring_cmd_pdu(ioucmd);
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(pdu->req);
	blk_status_t status = virtblk_result(vbr);

	if (pdu->bio)
		blk_rq_unmap_user(pdu->bio);
	/* for dynamic request, vbr will be freed after this */
	blk_mq_free_request(pdu->req);

	/* currently result has no use, it should be zero as cqe->res */
	io_uring_cmd_done(ioucmd, status, 0);
}

static void virtblk_uring_cmd_end_io(struct request *req, blk_status_t err)
{
	struct io_uring_cmd *ioucmd = req->end_io_data;
	struct virtblk_uring_cmd_pdu *pdu = virtblk_uring_cmd_pdu(ioucmd);
	/* extract bio before reusing the same field for request */
	struct bio *bio = pdu->bio;
	void *cookie = READ_ONCE(ioucmd->cookie);

	pdu->req = req;
	req->bio = bio;

	/*
	 * For iopoll, complete it directly.
	 * Otherwise, move the completion to task work.
	 */
	if (cookie != NULL && blk_rq_is_poll(req))
		virtblk_uring_task_cb(ioucmd);
	else
		io_uring_cmd_complete_in_task(ioucmd, virtblk_uring_task_cb);
}

static int virtblk_map_user_bidirectional(struct request *req, uintptr_t ubuffer,
		unsigned int iov_count, unsigned int write_iov_count)
{
	int ret;

	/*
	 * USER command should ensure write_iov_count < iov_count
	 */
	if (write_iov_count >= iov_count)
		return -EINVAL;

	/*
	 * now bidirectional only support READ-after-WRITE mode,
	 * set WRITE first and clear it later.
	 */
	req->cmd_flags |= WRITE;
	ret = blk_rq_map_user_io(req, NULL, (void __user *)ubuffer,
				write_iov_count, GFP_KERNEL, true,
				0, false, rq_data_dir(req));
	if (ret)
		return ret;

	ubuffer += write_iov_count * sizeof(struct iovec);
	req->cmd_flags &= ~WRITE;

	ret = blk_rq_map_user_io(req, NULL, (void __user *)ubuffer,
				(iov_count - write_iov_count), GFP_KERNEL,
				true, 0, false, rq_data_dir(req));
	if (ret)
		blk_rq_unmap_user(req->bio);

	return ret;
}
static int virtblk_map_user_request(struct request *req, uintptr_t ubuffer,
		unsigned int bufflen, bool vec, unsigned int num)
{
	struct request_queue *q = req->q;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

	if (vbr_is_bidirectional(vbr))
		return virtblk_map_user_bidirectional(req, ubuffer,
						      bufflen, num);

	if (!vec)
		return blk_rq_map_user(q, req, NULL, (void __user *)ubuffer,
				       bufflen, GFP_KERNEL);

	return blk_rq_map_user_io(req, NULL, (void __user *)ubuffer, bufflen,
			GFP_KERNEL, true, 0, false, rq_data_dir(req));
}

static int virtblk_uring_cmd_io(struct virtio_blk *vblk,
		struct io_uring_cmd *ioucmd, unsigned int issue_flags, bool vec)
{
	struct virtblk_uring_cmd_pdu *pdu = virtblk_uring_cmd_pdu(ioucmd);
	const struct virtblk_uring_cmd *cmd = ioucmd->cmd;
	struct request_queue *q = vblk->disk->queue;
	struct virtblk_req *vbr;
	struct request *req;
	struct bio *bio;
	unsigned int rq_flags = 0;
	blk_mq_req_flags_t blk_flags = 0;
	u32 type;
	uintptr_t data;
	unsigned long data_len, flag, write_iov_count;
	int ret;

	type = READ_ONCE(cmd->type);
	flag = READ_ONCE(cmd->flag);
	data = READ_ONCE(cmd->data);
	data_len = READ_ONCE(cmd->data_len);
	write_iov_count = READ_ONCE(cmd->write_iov_count);

	/* Only support OUT and IN for uring_cmd currently */
	if ((type != VIRTIO_BLK_T_OUT) && (type != VIRTIO_BLK_T_IN))
		return -EOPNOTSUPP;

	if (issue_flags & IO_URING_F_NONBLOCK) {
		rq_flags = REQ_NOWAIT;
		blk_flags = BLK_MQ_REQ_NOWAIT;
	}
	if (issue_flags & IO_URING_F_IOPOLL)
		rq_flags |= REQ_POLLED;
	if (flag & VIRTBLK_URING_F_BIDIR)
		rq_flags |= REQ_BIDIR;
	rq_flags |= (type & VIRTIO_BLK_T_OUT) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
retry:
	req = blk_mq_alloc_request(q, rq_flags, blk_flags);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->rq_flags |= RQF_DONTPREP;
	vbr = blk_mq_rq_to_pdu(req);
	vbr->out_hdr.ioprio = cpu_to_virtio32(vblk->vdev, READ_ONCE(cmd->ioprio));
	vbr->out_hdr.sector = cpu_to_virtio64(vblk->vdev, READ_ONCE(cmd->sector));
	vbr->out_hdr.type = cpu_to_virtio32(vblk->vdev, type);

	if (data && data_len) {
		ret = virtblk_map_user_request(req, data, data_len, vec, write_iov_count);
		if (ret) {
			blk_mq_free_request(req);
			return ret;
		}
	} else {
		/* user should ensure passthrough command have data */
		blk_mq_free_request(req);
		return -EINVAL;
	}

	if ((issue_flags & IO_URING_F_IOPOLL) && (rq_flags & REQ_POLLED)) {
		if (unlikely(!req->bio)) {
			/* we can't poll this, so alloc regular req instead */
			blk_mq_free_request(req);
			rq_flags &= ~REQ_POLLED;
			goto retry;
		} else {
			WRITE_ONCE(ioucmd->cookie, req);
			/* In fact, only first bio in req will use REQ_POLLED */
			for (bio = req->bio; bio; bio = bio->bi_next)
				req->bio->bi_opf |= REQ_POLLED;
		}
	}

	trace_virtblk_uring_cmd_io(req, type, cmd->sector);

	/* to free bio on completion, as req->bio will be null at that time */
	pdu->bio = req->bio;
	req->end_io_data = ioucmd;
	/* for bid command, req have more than one bio, should associate all */
	for (bio = req->bio; bio; bio = bio->bi_next)
		virtblk_bio_set_disk(bio, vblk->disk);

	blk_execute_rq_nowait(NULL, req, 0, virtblk_uring_cmd_end_io);
	return -EIOCBQUEUED;
}

static int virtblk_uring_cmd(struct virtio_blk *vblk, struct io_uring_cmd *ioucmd,
			     unsigned int issue_flags)
{
	int ret;

	/* currently we need 128 bytes sqe and 16 bytes cqe */
	if ((issue_flags & IO_URING_F_SQE128) != IO_URING_F_SQE128)
		return -EOPNOTSUPP;

	switch (ioucmd->cmd_op) {
	case VIRTBLK_URING_CMD_IO:
		ret = virtblk_uring_cmd_io(vblk, ioucmd, issue_flags, false);
		break;
	case VIRTBLK_URING_CMD_IO_VEC:
		ret = virtblk_uring_cmd_io(vblk, ioucmd, issue_flags, true);
		break;
	default:
		ret = -ENOTTY;
	}

	return ret;
}

static int virtblk_chr_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{
	struct virtio_blk *vblk = container_of(file_inode(ioucmd->file)->i_cdev,
			struct virtio_blk, cdev);

	return virtblk_uring_cmd(vblk, ioucmd, issue_flags);
}

int virtblk_chr_uring_cmd_iopoll(struct io_uring_cmd *ioucmd,
				 struct io_comp_batch *iob, unsigned int poll_flags)
{
	struct request *req;
	int ret = 0;
	struct virtio_blk *vblk;
	struct request_queue *q;

	req = READ_ONCE(ioucmd->cookie);
	vblk = container_of(file_inode(ioucmd->file)->i_cdev,
			struct virtio_blk, cdev);
	q = vblk->disk->queue;
	if (test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		ret = bio_poll(req->bio, iob, poll_flags);
	return ret;
}

static int virtblk_chr_open(struct inode *inode, struct file *file)
{
	return virtblk_device_open(container_of(inode->i_cdev, struct virtio_blk, cdev));
}

static int virtblk_chr_release(struct inode *inode, struct file *file)
{
	virtblk_device_release(container_of(inode->i_cdev, struct virtio_blk, cdev));
	return 0;
}

static const struct file_operations virtblk_chr_fops = {
	.owner		= THIS_MODULE,
	.open		= virtblk_chr_open,
	.release	= virtblk_chr_release,
	.uring_cmd	= virtblk_chr_uring_cmd,
	.uring_cmd_iopoll = virtblk_chr_uring_cmd_iopoll,
};

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static void virtblk_cdev_rel(struct device *dev)
{
	ida_free(&vd_chr_minor_ida, MINOR(dev->devt));
}

static void virtblk_cdev_del(struct cdev *cdev, struct device *cdev_device)
{
	cdev_device_del(cdev, cdev_device);
	put_device(cdev_device);
}

static int virtblk_cdev_add(struct virtio_blk *vblk)
{
	struct cdev *cdev = &vblk->cdev;
	struct device *cdev_device = &vblk->cdev_device;
	int minor, ret;

	minor = ida_alloc(&vd_chr_minor_ida, GFP_KERNEL);
	if (minor < 0)
		return minor;

	device_initialize(cdev_device);
	cdev_device->parent = &vblk->vdev->dev;
	cdev_device->devt = MKDEV(MAJOR(vd_chr_devt), minor);
	cdev_device->class = vd_chr_class;
	cdev_device->release = virtblk_cdev_rel;

	ret = dev_set_name(cdev_device, "%sc0", vblk->disk->disk_name);
	if (ret)
		goto fail;

	cdev_init(cdev, &virtblk_chr_fops);
	cdev->owner = THIS_MODULE;
	ret = cdev_device_add(cdev, cdev_device);
	if (ret)
		goto fail;

	return 0;
fail:
	put_device(cdev_device);
	return ret;
}
#endif

#ifdef CONFIG_DEBUG_FS
static int virtblk_dbg_virtqueues_show(struct seq_file *s, void *unused)
{
	struct virtio_blk *vblk = s->private;
	unsigned long flags;
	int i;

	for (i = 0; i < vblk->num_vqs; i++) {
		spin_lock_irqsave(&vblk->vqs[i].lock, flags);
		virtqueue_show_split_message(vblk->vqs[i].vq, s);
		spin_unlock_irqrestore(&vblk->vqs[i].lock, flags);
	}
	return 0;
}

static int virtblk_dbg_virtqueues_open(struct inode *inode, struct file *file)
{
	return single_open(file, virtblk_dbg_virtqueues_show, inode->i_private);
}

static const struct file_operations virtblk_dbg_virtqueue_ops = {
	.open = virtblk_dbg_virtqueues_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static int virtblk_dbg_rqs_show(struct seq_file *s, void *unused)
{
	struct virtio_blk *vblk = s->private;
	struct virtblk_indir_desc *indir_desc;
	int i, j;

	seq_printf(s, "ring_pair is %d\n", vblk->ring_pair);
	if (!vblk->ring_pair)
		return 0;

	for (i = 0; i < vblk->num_vqs / VIRTBLK_RING_NUM; i++) {
		for (j = 0; j < vblk->tag_set.queue_depth; j++) {
			indir_desc = &vblk->indir_desc[i][j];
			if (indir_desc->desc) {
				seq_printf(s, "hctx %d, tag %d, desc 0x%px, ",
					i / VIRTBLK_RING_NUM, j,
					indir_desc->desc);
				seq_printf(s, "dma_addr 0x%llx, len 0x%x\n",
					indir_desc->dma_addr, indir_desc->len);
			}
		}
	}

	return 0;
}

static int virtblk_dbg_rqs_open(struct inode *inode, struct file *file)
{
	return single_open(file, virtblk_dbg_rqs_show, inode->i_private);
}

static const struct file_operations virtblk_dbg_rqs_ops = {
	.open = virtblk_dbg_rqs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static int virtio_blk_dev_dbg_init(struct virtio_blk *vblk)
{
	struct dentry *dir, *parent_block_dir;

	parent_block_dir = vblk->disk->queue->debugfs_dir;
	if (!parent_block_dir)
		return -EIO;

	dir = debugfs_create_dir("insight", parent_block_dir);
	if (IS_ERR(dir)) {
		dev_err(&vblk->vdev->dev, "Failed to get debugfs dir for '%s'\n",
			vblk->disk->disk_name);
		return -EIO;
	}

	debugfs_create_file("virtqueues", 0444, dir, vblk, &virtblk_dbg_virtqueue_ops);
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	debugfs_create_file("rpair", 0444, dir, vblk, &virtblk_dbg_rqs_ops);
#endif
	vblk->dbg_dir = dir;
	return 0;
}

static void virtblk_dev_dbg_close(struct virtio_blk *vblk)
{
	debugfs_remove_recursive(vblk->dbg_dir);
}
#else
static int virtblk_dev_dbg_init(struct virtio_blk *vblk) { return 0; }
static void virtblk_dev_dbg_close(struct virtio_blk *vblk) { }
#endif

static unsigned int virtblk_queue_depth;
module_param_named(queue_depth, virtblk_queue_depth, uint, 0444);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
static unsigned short virtblk_dyn_max_rqs = 16384;
module_param_named(dyn_max_rqs, virtblk_dyn_max_rqs, short, 0444);
MODULE_PARM_DESC(dyn_max_rqs, "Max requests per rpair(0~65535), default 2^14");
#endif

static int virtblk_probe(struct virtio_device *vdev)
{
	struct virtio_blk *vblk;
	struct request_queue *q;
	int err, index;

	u32 v, blk_size, max_size, sg_elems, opt_io_size;
	u16 min_io_size;
	u8 physical_block_exp, alignment_offset;
	unsigned int queue_depth;
	size_t max_dma_size;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	err = ida_simple_get(&vd_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need to know how many segments before we allocate. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
				   struct virtio_blk_config, seg_max,
				   &sg_elems);

	/* We need at least one SG element, whatever they say. */
	if (err || !sg_elems)
		sg_elems = 1;

	/* Prevent integer overflows and honor max vq size */
	sg_elems = min_t(u32, sg_elems, VIRTIO_BLK_MAX_SG_ELEMS - 2);

	vdev->priv = vblk = kzalloc(sizeof(*vblk), GFP_KERNEL);
	if (!vblk) {
		err = -ENOMEM;
		goto out_free_index;
	}

	/* This reference is dropped in virtblk_remove(). */
	refcount_set(&vblk->refs, 1);
	mutex_init(&vblk->vdev_mutex);

	vblk->vdev = vdev;

	INIT_WORK(&vblk->config_work, virtblk_config_changed_work);

	err = init_vq(vblk);
	if (err)
		goto out_free_vblk;

	/* FIXME: How many partitions?  How long is a piece of string? */
	vblk->disk = alloc_disk(1 << PART_BITS);
	if (!vblk->disk) {
		err = -ENOMEM;
		goto out_free_vq;
	}

	/* Default queue sizing is to fill the ring. */
	if (likely(!virtblk_queue_depth)) {
		queue_depth = vblk->vqs[0].vq->num_free;
		/* ... but without indirect descs, we use 2 descs per req */
		if (!virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC))
			queue_depth /= 2;
	} else {
		queue_depth = virtblk_queue_depth;
	}

	memset(&vblk->tag_set, 0, sizeof(vblk->tag_set));
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	if (vblk->ring_pair) {
		vblk->tag_set.ops = &virtio_mq_pair_ops;
		vblk->tag_set.nr_hw_queues = vblk->num_vqs / VIRTBLK_RING_NUM;
		/* For ring pair, we don't want to use io scheduler. So we set
		 * NO_SCHED flag, in this case BLK_MQ_F_SHOULD_MERGE is unused.
		 */
		vblk->tag_set.flags = BLK_MQ_F_DYN_ALLOC | BLK_MQ_F_NO_SCHED;
		vblk->tag_set.queue_depth = virtblk_dyn_max_rqs;
		vblk->tag_set.nr_static_rqs = queue_depth;
	} else {
		vblk->tag_set.ops = &virtio_mq_ops;
		vblk->tag_set.nr_hw_queues = vblk->num_vqs;
		vblk->tag_set.queue_depth = queue_depth;
		vblk->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	}
#else
	vblk->tag_set.ops = &virtio_mq_ops;
	vblk->tag_set.nr_hw_queues = vblk->num_vqs;
	vblk->tag_set.queue_depth = queue_depth;
	vblk->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
#endif
	vblk->tag_set.numa_node = NUMA_NO_NODE;
	/* For bidirectional passthrough vblk request, both WRITE and READ
	 * operations need pre-alloc inline SGs. So we should prealloc twice
	 * the size than original ways. Due to the inability to predict whether
	 * a request is bidirectional, there may be memory wastage, but won't
	 * be significant.
	 */
	vblk->tag_set.cmd_size =
		sizeof(struct virtblk_req) +
		sizeof(struct scatterlist) * 2 * VIRTIO_BLK_INLINE_SG_CNT;
	vblk->tag_set.driver_data = vblk;
	vblk->tag_set.nr_maps = 1;
	if (vblk->io_queues[HCTX_TYPE_POLL])
		vblk->tag_set.nr_maps = 3;

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	/* Beginning here, we know queue_depth of tag_set, so we should alloc
	 * vblk->indir_desc here. If alloc goes -ENOMEM, kfree will be
	 * executed.
	 */
	if (vblk->ring_pair) {
		int i;
		vblk->indir_desc = kmalloc_array(vblk->num_vqs / VIRTBLK_RING_NUM,
						sizeof(struct virtblk_indir_desc *),
						GFP_KERNEL | __GFP_ZERO);
		if (!vblk->indir_desc) {
			err = -ENOMEM;
			goto out_put_disk;
		}
		for (i = 0; i < vblk->num_vqs / VIRTBLK_RING_NUM ; i++) {
			vblk->indir_desc[i] = kmalloc_array(vblk->tag_set.queue_depth,
							sizeof(struct virtblk_indir_desc),
							GFP_KERNEL | __GFP_ZERO);
			if (!vblk->indir_desc[i]) {
				err = -ENOMEM;
				goto out_put_disk;
			}
		}
	}

#endif

	err = blk_mq_alloc_tag_set(&vblk->tag_set);
	if (err)
		goto out_put_disk;

	q = blk_mq_init_queue(&vblk->tag_set);
	if (IS_ERR(q)) {
		err = -ENOMEM;
		goto out_free_tags;
	}
	vblk->disk->queue = q;

	q->queuedata = vblk;

	virtblk_name_format("vd", index, vblk->disk->disk_name, DISK_NAME_LEN);

	vblk->disk->major = major;
	vblk->disk->first_minor = index_to_minor(index);
	vblk->disk->private_data = vblk;
	vblk->disk->fops = &virtblk_fops;
	vblk->disk->flags |= GENHD_FL_EXT_DEVT;
	vblk->index = index;

	/* configure queue flush support */
	virtblk_update_cache_mode(vdev);

	/* If disk is read-only in the host, the guest should obey */
	if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
		set_disk_ro(vblk->disk, 1);

	/* We can handle whatever the host told us to handle. */
	blk_queue_max_segments(q, sg_elems);

	/* No real sector limit. */
	blk_queue_max_hw_sectors(q, -1U);

	max_dma_size = virtio_max_dma_size(vdev);
	max_size = max_dma_size > U32_MAX ? U32_MAX : max_dma_size;

	/* Host can optionally specify maximum segment size and number of
	 * segments. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SIZE_MAX,
				   struct virtio_blk_config, size_max, &v);
	if (!err)
		max_size = min(max_size, v);

	blk_queue_max_segment_size(q, max_size);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	if (vblk->pt_enable)
		blk_queue_dma_alignment(q, 0);
#endif

	/* Host can optionally specify the block size of the device */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_BLK_SIZE,
				   struct virtio_blk_config, blk_size,
				   &blk_size);
	if (!err) {
		err = blk_validate_block_size(blk_size);
		if (err) {
			dev_err(&vdev->dev,
				"virtio_blk: invalid block size: 0x%x\n",
				blk_size);
			goto out_free_tags;
		}

		blk_queue_logical_block_size(q, blk_size);
	} else
		blk_size = queue_logical_block_size(q);

	/* Use topology information if available */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, physical_block_exp,
				   &physical_block_exp);
	if (!err && physical_block_exp)
		blk_queue_physical_block_size(q,
				blk_size * (1 << physical_block_exp));

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, alignment_offset,
				   &alignment_offset);
	if (!err && alignment_offset)
		blk_queue_alignment_offset(q, blk_size * alignment_offset);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, min_io_size,
				   &min_io_size);
	if (!err && min_io_size)
		blk_queue_io_min(q, blk_size * min_io_size);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, opt_io_size,
				   &opt_io_size);
	if (!err && opt_io_size)
		blk_queue_io_opt(q, blk_size * opt_io_size);

	if (virtio_has_feature(vdev, VIRTIO_BLK_F_DISCARD)) {
		virtio_cread(vdev, struct virtio_blk_config,
			     discard_sector_alignment, &v);
		if (v)
			q->limits.discard_granularity = v << SECTOR_SHIFT;
		else
			q->limits.discard_granularity = blk_size;

		virtio_cread(vdev, struct virtio_blk_config,
			     max_discard_sectors, &v);
		blk_queue_max_discard_sectors(q, v ? v : UINT_MAX);

		virtio_cread(vdev, struct virtio_blk_config, max_discard_seg,
			     &v);

		/*
		 * max_discard_seg == 0 is out of spec but we always
		 * handled it.
		 */
		if (!v)
			v = sg_elems;
		blk_queue_max_discard_segments(q,
					       min(v, MAX_DISCARD_SEGMENTS));

		blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
	}

	if (virtio_has_feature(vdev, VIRTIO_BLK_F_WRITE_ZEROES)) {
		virtio_cread(vdev, struct virtio_blk_config,
			     max_write_zeroes_sectors, &v);
		blk_queue_max_write_zeroes_sectors(q, v ? v : UINT_MAX);
	}

	virtblk_update_capacity(vblk, false);
	virtio_device_ready(vdev);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	if (!vblk->hide_bdev)
		device_add_disk(&vdev->dev, vblk->disk, virtblk_attr_groups);
#else
	device_add_disk(&vdev->dev, vblk->disk, virtblk_attr_groups);
#endif
	virtio_blk_dev_dbg_init(vblk);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	if (vblk->pt_enable)
		WARN_ON(virtblk_cdev_add(vblk));
#endif

	return 0;

out_free_tags:
	blk_mq_free_tag_set(&vblk->tag_set);
out_put_disk:
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	virtblk_kfree_vblk_indir_descs(vblk);
#endif
	put_disk(vblk->disk);
out_free_vq:
	vdev->config->del_vqs(vdev);
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	virtblk_kfree_vqs_cq_reqs(vblk);
#endif
	kfree(vblk->vqs);
out_free_vblk:
	kfree(vblk);
out_free_index:
	ida_simple_remove(&vd_index_ida, index);
out:
	return err;
}

static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	virtblk_dev_dbg_close(vblk);
	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	if (vblk->pt_enable)
		virtblk_cdev_del(&vblk->cdev, &vblk->cdev_device);
#endif

	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);

	blk_mq_free_tag_set(&vblk->tag_set);

	mutex_lock(&vblk->vdev_mutex);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	/* Virtqueues are stopped, nothing can use vblk->vdev anymore. */
	vblk->vdev = NULL;

	put_disk(vblk->disk);
	vdev->config->del_vqs(vdev);
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	virtblk_kfree_vqs_cq_reqs(vblk);
#endif
	kfree(vblk->vqs);

	mutex_unlock(&vblk->vdev_mutex);

	virtblk_put(vblk);
}

#ifdef CONFIG_PM_SLEEP
static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	struct request_queue *q = vblk->disk->queue;

	/* Ensure no requests in virtqueues before deleting vqs. */
	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue_nowait(q);
	blk_mq_unfreeze_queue(q);

	/* Ensure we don't receive any more interrupts */
	vdev->config->reset(vdev);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

	vdev->config->del_vqs(vdev);
#ifdef CONFIG_VIRTIO_BLK_RING_PAIR
	virtblk_kfree_vqs_cq_reqs(vblk);
#endif
	kfree(vblk->vqs);

	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	ret = init_vq(vdev->priv);
	if (ret)
		return ret;

	virtio_device_ready(vdev);
	blk_mq_unquiesce_queue(vblk->disk->queue);

	return 0;
}
#endif

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features_legacy[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_WRITE_ZEROES,
}
;
static unsigned int features[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_WRITE_ZEROES,
};

static struct virtio_driver virtio_blk = {
	.feature_table			= features,
	.feature_table_size		= ARRAY_SIZE(features),
	.feature_table_legacy		= features_legacy,
	.feature_table_size_legacy	= ARRAY_SIZE(features_legacy),
	.driver.name			= KBUILD_MODNAME,
	.driver.owner			= THIS_MODULE,
	.id_table			= id_table,
	.probe				= virtblk_probe,
	.remove				= virtblk_remove,
	.config_changed			= virtblk_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze				= virtblk_freeze,
	.restore			= virtblk_restore,
#endif
};

static int __init init(void)
{
	int error;

	virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
	if (!virtblk_wq)
		return -ENOMEM;

	major = register_blkdev(0, "virtblk");
	if (major < 0) {
		error = major;
		goto out_destroy_workqueue;
	}

	error = alloc_chrdev_region(&vd_chr_devt, 0, VIRTBLK_MINORS,
				"vblk-generic");
	if (error < 0)
		goto out_unregister_blkdev;

	vd_chr_class = class_create(THIS_MODULE, "vblk-generic");
	if (IS_ERR(vd_chr_class)) {
		error = PTR_ERR(vd_chr_class);
		goto out_unregister_chardev;
	}

	error = register_virtio_driver(&virtio_blk);
	if (error)
		goto out_destroy_class;

	return 0;

out_destroy_class:
	class_destroy(vd_chr_class);
out_unregister_chardev:
	unregister_chrdev_region(vd_chr_devt, VIRTBLK_MINORS);
out_unregister_blkdev:
	unregister_blkdev(major, "virtblk");
out_destroy_workqueue:
	destroy_workqueue(virtblk_wq);
	return error;
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_blk);
	class_destroy(vd_chr_class);
	unregister_chrdev_region(vd_chr_devt, VIRTBLK_MINORS);
	unregister_blkdev(major, "virtblk");
	destroy_workqueue(virtblk_wq);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio block driver");
MODULE_LICENSE("GPL");
