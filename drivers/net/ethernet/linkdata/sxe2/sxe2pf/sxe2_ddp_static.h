/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ddp_static.h
 * @brief: 内置静态 DDP 数据访问接口（数据本体在 sxe2_ddp_static.c，
 *         由 gen_ddp_seg_c.py --driver 基于 sxe2.cfg 生成）
 */

#ifndef __SXE2_DDP_STATIC_H__
#define __SXE2_DDP_STATIC_H__

#include <linux/types.h>

struct sxe2_adapter;

/* 组装连续 DDP 包映像（devm 托管），失败返回 ERR_PTR */
void *sxe2_ddp_static_assemble(struct sxe2_adapter *adapter, u32 *total);

/* 内置包版本自描述 */
void sxe2_ddp_static_ver_get(u16 *drv_maj, u16 *drv_mnr,
			     u16 *fw_maj, u16 *fw_mnr);

#endif
