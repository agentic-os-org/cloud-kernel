# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_RESCTRL_FS)		+= rdtgroup.o ctrlmondata.o monitor.o
obj-$(CONFIG_RESCTRL_FS_PSEUDO_LOCK)	+= pseudo_lock.o

# To allow define_trace.h's recursive include:
CFLAGS_monitor.o = -I$(src)

obj-$(CONFIG_RISCV_CBQRI)			+= cbqri.o
cbqri-y						+= cbqri_devices.o
cbqri-$(CONFIG_RISCV_CBQRI_RESCTRL_FS)		+= cbqri_resctrl.o
cbqri-$(CONFIG_RISCV_CBQRI_CAPACITY)		+= cbqri_capacity.o
