// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>
#include <linux/security.h>
#include <linux/nospec.h>

#include <uapi/linux/io_uring.h>
#include <asm/ioctls.h>

#include "io_uring.h"
#include "rsrc.h"
#include "uring_cmd.h"

static struct uring_cache *io_uring_async_get(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_cache_entry *entry;
	struct uring_cache *cache;

	entry = io_alloc_cache_get(&ctx->uring_cache);
	if (entry) {
		cache = container_of(entry, struct uring_cache, cache);
		req->flags |= REQ_F_ASYNC_DATA;
		/*
		 * The cached object may still own an iovec. Claim it for this
		 * req so ->cleanup frees it even if this command never calls
		 * io_uring_cmd_import_fixed_vec(): io_clean_op() gates
		 * ->cleanup on REQ_F_NEED_CLEANUP, and its kfree() of the
		 * async data does not reach ->vec.iovec.
		 */
		if (cache->vec.iovec)
			req->flags |= REQ_F_NEED_CLEANUP;
		req->async_data = cache;
		return cache;
	}
	if (!io_alloc_async_data(req)) {
		cache = req->async_data;
		/*
		 * Upstream has the alloc cache do this, by passing the object
		 * size as init_bytes to io_alloc_cache_init(). 6.6's
		 * io_alloc_cache_init() has no such parameter, and the fresh
		 * allocation happens in io_alloc_async_data(), which every
		 * opcode shares, so clear it here instead.
		 */
		memset(cache, 0, sizeof(*cache));
		return cache;
	}
	return NULL;
}

static void io_req_uring_cleanup(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct uring_cache *cache = req->async_data;

	if (issue_flags & IO_URING_F_UNLOCKED)
		return;

	io_alloc_cache_vec_kasan(&cache->vec);
	if (cache->vec.nr > IO_VEC_CACHE_SOFT_CAP)
		io_vec_free(&cache->vec);

	if (io_alloc_cache_put(&req->ctx->uring_cache, &cache->cache)) {
		ioucmd->sqe = NULL;
		req->async_data = NULL;
		req->flags &= ~(REQ_F_ASYNC_DATA|REQ_F_NEED_CLEANUP);
	}
}

void io_uring_cmd_cleanup(struct io_kiocb *req)
{
	struct uring_cache *cache = req->async_data;

	/*
	 * Release only ->vec, never the object itself. io_clean_op() can run
	 * from __io_req_complete_post() holding just ->completion_lock, while
	 * ctx->uring_cache is uring_lock protected; the async data is
	 * reclaimed by io_clean_op()'s own kfree().
	 */
	io_vec_free(&cache->vec);
}

static void io_uring_cmd_work(struct io_kiocb *req, struct io_tw_state *ts)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	unsigned issue_flags = ts->locked ? 0 : IO_URING_F_UNLOCKED;

	ioucmd->task_work_cb(ioucmd, issue_flags);
}

void __io_uring_cmd_do_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned),
			unsigned flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	ioucmd->task_work_cb = task_work_cb;
	req->io_task_work.func = io_uring_cmd_work;
	__io_req_task_work_add(req, flags);
}
EXPORT_SYMBOL_GPL(__io_uring_cmd_do_in_task);

void io_uring_cmd_do_in_task_lazy(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned))
{
	__io_uring_cmd_do_in_task(ioucmd, task_work_cb, IOU_F_TWQ_LAZY_WAKE);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_do_in_task_lazy);

static inline void io_req_set_cqe32_extra(struct io_kiocb *req,
					  u64 extra1, u64 extra2)
{
	req->big_cqe.extra1 = extra1;
	req->big_cqe.extra2 = extra2;
}

/*
 * Called by consumers of io_uring_cmd, if they originally returned
 * -EIOCBQUEUED upon receiving the command.
 */
void io_uring_cmd_done(struct io_uring_cmd *ioucmd, ssize_t ret, ssize_t res2,
		       unsigned issue_flags)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
	if (req->ctx->flags & IORING_SETUP_CQE32)
		io_req_set_cqe32_extra(req, res2, 0);
	io_req_uring_cleanup(req, issue_flags);
	if (req->ctx->flags & IORING_SETUP_IOPOLL) {
		/* order with io_iopoll_req_issued() checking ->iopoll_complete */
		smp_store_release(&req->iopoll_completed, 1);
	} else {
		struct io_tw_state ts = {
			.locked = !(issue_flags & IO_URING_F_UNLOCKED),
		};
		io_req_task_complete(req, &ts);
	}
}
EXPORT_SYMBOL_GPL(io_uring_cmd_done);

static int io_uring_cmd_prep_setup(struct io_kiocb *req,
				   const struct io_uring_sqe *sqe)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct uring_cache *cache;

	cache = io_uring_async_get(req);
	if (cache) {
		memcpy(cache->sqes, sqe, uring_sqe_size(req->ctx));
		ioucmd->sqe = req->async_data;
		return 0;
	}
	return -ENOMEM;
}

int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);

	if (sqe->__pad1)
		return -EINVAL;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	if (ioucmd->flags & ~IORING_URING_CMD_FIXED)
		return -EINVAL;

	if (ioucmd->flags & IORING_URING_CMD_FIXED) {
		struct io_ring_ctx *ctx = req->ctx;
		u16 index;

		req->buf_index = READ_ONCE(sqe->buf_index);
		if (unlikely(req->buf_index >= ctx->nr_user_bufs))
			return -EFAULT;
		index = array_index_nospec(req->buf_index, ctx->nr_user_bufs);
		req->imu = ctx->user_bufs[index];
		io_req_set_rsrc_node(req, ctx, 0);
	}
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);

	return io_uring_cmd_prep_setup(req, sqe);
}

int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	struct io_ring_ctx *ctx = req->ctx;
	struct file *file = req->file;
	int ret;

	if (!file->f_op->uring_cmd)
		return -EOPNOTSUPP;

	ret = security_uring_cmd(ioucmd);
	if (ret)
		return ret;

	if (ctx->flags & IORING_SETUP_SQE128)
		issue_flags |= IO_URING_F_SQE128;
	if (ctx->flags & IORING_SETUP_CQE32)
		issue_flags |= IO_URING_F_CQE32;
	if (ctx->flags & IORING_SETUP_IOPOLL) {
		if (!file->f_op->uring_cmd_iopoll)
			return -EOPNOTSUPP;
		issue_flags |= IO_URING_F_IOPOLL;
		req->iopoll_completed = 0;
		WRITE_ONCE(ioucmd->cookie, NULL);
	}

	ret = file->f_op->uring_cmd(ioucmd, issue_flags);
	if (ret == -EAGAIN || ret == -EIOCBQUEUED)
		return ret;

	if (ret < 0)
		req_set_fail(req);
	io_req_uring_cleanup(req, issue_flags);
	io_req_set_res(req, ret, 0);
	return ret;
}

int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	return io_import_fixed(rw, iter, req->imu, ubuf, len);
}
EXPORT_SYMBOL_GPL(io_uring_cmd_import_fixed);

#if defined(CONFIG_NET)
int io_uring_cmd_sock(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct socket *sock = cmd->file->private_data;
	struct sock *sk = sock->sk;
	struct proto *prot = READ_ONCE(sk->sk_prot);
	int ret, arg = 0;

	if (!prot || !prot->ioctl)
		return -EOPNOTSUPP;

	switch (cmd->cmd_op) {
	case SOCKET_URING_OP_SIOCINQ:
		ret = prot->ioctl(sk, SIOCINQ, &arg);
		if (ret)
			return ret;
		return arg;
	case SOCKET_URING_OP_SIOCOUTQ:
		ret = prot->ioctl(sk, SIOCOUTQ, &arg);
		if (ret)
			return ret;
		return arg;
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL_GPL(io_uring_cmd_sock);
#endif

void io_uring_cache_free(struct io_cache_entry *entry)
{
	struct uring_cache *cache = container_of(entry, struct uring_cache, cache);

	io_vec_free(&cache->vec);
	kfree(cache);
}
