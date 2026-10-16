/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_COMPAT_H
#define NBL_COMPAT_H

#define HAS_IB_DEVICE_OPS
#define GET_HW_STATS_V1
#define QUERY_GID_VER_1
#define NBL_RDMA_ALLOC_MR_VER_0
#define NBL_RDMA_ALLOC_MW_VER_2
#define REREG_MR_VER_2
#define IB_GET_NETDEV_V1
#define IB_UMEM_GET_V3
#define CREATE_AH_VER_6
#define HAS_DMA_MAP_FEATURE
#define DMA_MAP_OPS_H_IN_LINUX
#define RDMA_MMAP_DB_SUPPORT
#define UMEM_GET_SGL_V2
#define ALLOC_HW_STATS_V1
#define RDMA_ALLOC_HW_STAT_V1
#define ALLOC_UCONTEXT_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define NBL_CREATE_QP_V1
#define NBL_RDMA_DESTROY_CQ_VER_2
#define HAS_CREATE_USER_AH
#define kc_ib_register_device(device, name, dev)  \
	ib_register_device(device, name, dev)
#define LINUX_TASKLET
#define BUS_FIND_DEVICE_HAS_CONST_MATCH
#define DEREG_MR_HAS_UDATA
#define DMA_RESV_H_EXIST
#define DESTROY_AH_VER_2
#define HAS_AUX_DEV_ID
#define UMEM_HAS_IS_ODP
#define HAS_IB_UMEM_NUM_DMA_BLOCKS
#define IB_DEVICE_HAS_COREDEV
#define IB_DEVICE_HAS_PORT_DATA
#define DESTROY_QP_HAS_UDATA
#define HAS_IB_UMEM_FIND_BEST_PGSZ
#define HAVE_REGISTER_NETDEVICE_NOTIFIER_DEV_NET
#define ALLOC_PD_VER_3
#define DEALLOC_PD_VER_4

#endif  /*NBL_COMPAT_H*/
