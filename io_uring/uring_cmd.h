// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

struct uring_cache {
	union {
		struct io_cache_entry cache;
		struct io_uring_sqe sqes[2];
	};
	/*
	 * Must stay outside the union: the entry embedded above is what the
	 * intrusive alloc cache links through, so anything sharing storage
	 * with it gets clobbered while the object sits in the cache.
	 */
	struct iou_vec		vec;
};

int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
void io_uring_cmd_cleanup(struct io_kiocb *req);
void io_uring_cache_free(struct io_cache_entry *entry);
