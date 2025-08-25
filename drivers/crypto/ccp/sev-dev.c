// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Encrypted Virtualization (SEV) interface
 *
 * Copyright (C) 2016,2019 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/ccp.h>
#include <linux/firmware.h>
#include <linux/gfp.h>
#include <linux/cpufeature.h>
#include <linux/psp-csv.h>
#include <linux/crash_dump.h>
#ifdef CONFIG_HYGON_CSV
#include <asm/csv.h>
#endif
#include <asm/smp.h>
#include <asm/cacheflush.h>

#include "psp-dev.h"
#include "sev-dev.h"

#include "hygon/csv-dev.h"

#define DEVICE_NAME		"sev"
#define SEV_FW_FILE		"amd/sev.fw"
#define CSV_FW_FILE		"hygon/csv.fw"
#define SEV_FW_NAME_SIZE	64

DEFINE_MUTEX(sev_cmd_mutex);
static struct sev_misc_dev *misc_dev;

static int psp_cmd_timeout = 100;
module_param(psp_cmd_timeout, int, 0644);
MODULE_PARM_DESC(psp_cmd_timeout, " default timeout value, in seconds, for PSP commands");

static int psp_probe_timeout = 5;
module_param(psp_probe_timeout, int, 0644);
MODULE_PARM_DESC(psp_probe_timeout, " default timeout value, in seconds, during PSP device probe");

MODULE_FIRMWARE("amd/amd_sev_fam17h_model0xh.sbin"); /* 1st gen EPYC */
MODULE_FIRMWARE("amd/amd_sev_fam17h_model3xh.sbin"); /* 2nd gen EPYC */
MODULE_FIRMWARE("amd/amd_sev_fam19h_model0xh.sbin"); /* 3rd gen EPYC */

static bool psp_dead;
static int psp_timeout;

extern int is_hygon_psp;
extern struct psp_misc_dev *psp_misc;
extern int psp_mutex_lock_timeout(struct psp_mutex *mutex, uint64_t ms);
extern int psp_mutex_trylock(struct psp_mutex *mutex);
extern int psp_mutex_unlock(struct psp_mutex *mutex);
extern int psp_mutex_enabled;

static int csv_comm_mode = CSV_COMM_MAILBOX_ON;

/* Trusted Memory Region (TMR):
 *   The TMR is a 1MB area that must be 1MB aligned.  Use the page allocator
 *   to allocate the memory, which will return aligned memory for the specified
 *   allocation order.
 */
#define SEV_ES_TMR_SIZE		(1024 * 1024)
static void *sev_es_tmr;

static inline bool sev_version_greater_or_equal(u8 maj, u8 min)
{
	struct sev_device *sev = psp_master->sev_data;

	if (sev->api_major > maj)
		return true;

	if (sev->api_major == maj && sev->api_minor >= min)
		return true;

	return false;
}

static void sev_irq_handler(int irq, void *data, unsigned int status)
{
	struct sev_device *sev = data;
	int reg;

	/* Check if it is command completion: */
	if (!(status & SEV_CMD_COMPLETE))
		return;

	/* Check if it is SEV command completion: */
	reg = ioread32(sev->io_regs + sev->vdata->cmdresp_reg);
	if ((reg & PSP_CMDRESP_RESP) ||
	    ((boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) &&
	     (csv_comm_mode == CSV_COMM_RINGBUFFER_ON))) {
		sev->int_rcvd = 1;
		wake_up(&sev->int_queue);
	}
}

static int sev_wait_cmd_ioc(struct sev_device *sev,
			    unsigned int *reg, unsigned int timeout)
{
	int ret;

	ret = wait_event_timeout(sev->int_queue,
			sev->int_rcvd, timeout * HZ);
	if (!ret)
		return -ETIMEDOUT;

	*reg = ioread32(sev->io_regs + sev->vdata->cmdresp_reg);

	return 0;
}

static int csv_wait_cmd_ioc_ring_buffer(struct sev_device *sev,
					unsigned int *reg,
					unsigned int timeout)
{
	int ret;

	ret = wait_event_timeout(sev->int_queue,
			sev->int_rcvd, timeout * HZ);
	if (!ret)
		return -ETIMEDOUT;

	*reg = ioread32(sev->io_regs + sev->vdata->cmdbuff_addr_lo_reg);

	return 0;
}

static int sev_cmd_buffer_len(int cmd)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		switch (cmd) {
		case CSV_CMD_HGSC_CERT_IMPORT:
			return sizeof(struct csv_data_hgsc_cert_import);
		case CSV_CMD_RING_BUFFER:
			return sizeof(struct csv_data_ring_buffer);
		case CSV3_CMD_LAUNCH_ENCRYPT_DATA:
			return sizeof(struct csv3_data_launch_encrypt_data);
		case CSV_CMD_LAUNCH_ENCRYPT_VMCB:
			return sizeof(struct csv_data_launch_encrypt_vmcb);
		case CSV_CMD_UPDATE_NPT:
			return sizeof(struct csv_data_update_npt);
		case CSV3_CMD_UPDATE_NPT_EX:
			return sizeof(struct csv3_data_update_npt_ex);
		case CSV_CMD_SET_SMR:
			return sizeof(struct csv_data_set_smr);
		case CSV_CMD_SET_SMCR:
			return sizeof(struct csv_data_set_smcr);
		case CSV3_CMD_SET_GUEST_PRIVATE_MEMORY:
		case CSV3_CMD_SET_GUEST_PRIVATE_MEMORY_EX:
			return sizeof(struct csv3_data_set_guest_private_memory);
		case CSV_CMD_DBG_READ_VMSA:
			return sizeof(struct csv_data_dbg_read_vmsa);
		case CSV_CMD_DBG_READ_MEM:
			return sizeof(struct csv_data_dbg_read_mem);
		case CSV_CMD_SEND_ENCRYPT_DATA:
			return sizeof(struct csv_data_send_encrypt_data);
		case CSV_CMD_SEND_ENCRYPT_CONTEXT:
			return sizeof(struct csv_data_send_encrypt_context);
		case CSV_CMD_RECEIVE_ENCRYPT_DATA:
			return sizeof(struct csv_data_receive_encrypt_data);
		case CSV_CMD_RECEIVE_ENCRYPT_CONTEXT:
			return sizeof(struct csv_data_receive_encrypt_context);
		case CSV3_CMD_LAUNCH_FINISH_EX:
			return sizeof(struct csv3_data_launch_finish_ex);
		default:
			break;
		}
	}

	switch (cmd) {
	case SEV_CMD_INIT:			return sizeof(struct sev_data_init);
	case SEV_CMD_PLATFORM_STATUS:		return sizeof(struct sev_user_data_status);
	case SEV_CMD_PEK_CSR:			return sizeof(struct sev_data_pek_csr);
	case SEV_CMD_PEK_CERT_IMPORT:		return sizeof(struct sev_data_pek_cert_import);
	case SEV_CMD_PDH_CERT_EXPORT:		return sizeof(struct sev_data_pdh_cert_export);
	case SEV_CMD_LAUNCH_START:		return sizeof(struct sev_data_launch_start);
	case SEV_CMD_LAUNCH_UPDATE_DATA:	return sizeof(struct sev_data_launch_update_data);
	case SEV_CMD_LAUNCH_UPDATE_VMSA:	return sizeof(struct sev_data_launch_update_vmsa);
	case SEV_CMD_LAUNCH_FINISH:		return sizeof(struct sev_data_launch_finish);
	case SEV_CMD_LAUNCH_MEASURE:		return sizeof(struct sev_data_launch_measure);
	case SEV_CMD_ACTIVATE:			return sizeof(struct sev_data_activate);
	case SEV_CMD_DEACTIVATE:		return sizeof(struct sev_data_deactivate);
	case SEV_CMD_DECOMMISSION:		return sizeof(struct sev_data_decommission);
	case SEV_CMD_GUEST_STATUS:		return sizeof(struct sev_data_guest_status);
	case SEV_CMD_DBG_DECRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_DBG_ENCRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_SEND_START:		return sizeof(struct sev_data_send_start);
	case SEV_CMD_SEND_UPDATE_DATA:		return sizeof(struct sev_data_send_update_data);
	case SEV_CMD_SEND_UPDATE_VMSA:		return sizeof(struct sev_data_send_update_vmsa);
	case SEV_CMD_SEND_FINISH:		return sizeof(struct sev_data_send_finish);
	case SEV_CMD_RECEIVE_START:		return sizeof(struct sev_data_receive_start);
	case SEV_CMD_RECEIVE_FINISH:		return sizeof(struct sev_data_receive_finish);
	case SEV_CMD_RECEIVE_UPDATE_DATA:	return sizeof(struct sev_data_receive_update_data);
	case SEV_CMD_RECEIVE_UPDATE_VMSA:	return sizeof(struct sev_data_receive_update_vmsa);
	case SEV_CMD_LAUNCH_UPDATE_SECRET:	return sizeof(struct sev_data_launch_secret);
	case SEV_CMD_DOWNLOAD_FIRMWARE:		return sizeof(struct sev_data_download_firmware);
	case SEV_CMD_GET_ID:			return sizeof(struct sev_data_get_id);
	case SEV_CMD_ATTESTATION_REPORT:	return sizeof(struct sev_data_attestation_report);
	case SEV_CMD_SEND_CANCEL:		return sizeof(struct sev_data_send_cancel);
	default:				return 0;
	}

	return 0;
}

static int __sev_do_cmd_locked(int cmd, void *data, int *psp_ret)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret = 0;
	int buf_len;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	if (psp_dead)
		return -EBUSY;

	sev = psp->sev_data;

	buf_len = sev_cmd_buffer_len(cmd);
	if (WARN_ON_ONCE(!data != !buf_len))
		return -EINVAL;

	/*
	 * Copy the incoming data to driver's scratch buffer as __pa() will not
	 * work for some memory, e.g. vmalloc'd addresses, and @data may not be
	 * physically contiguous.
	 */
	if (data)
		memcpy(sev->cmd_buf, data, buf_len);

	/* Get the physical address of the command buffer */
	phys_lsb = data ? lower_32_bits(__psp_pa(sev->cmd_buf)) : 0;
	phys_msb = data ? upper_32_bits(__psp_pa(sev->cmd_buf)) : 0;

	dev_dbg(sev->dev, "sev command id %#x buffer 0x%08x%08x timeout %us\n",
		cmd, phys_msb, phys_lsb, psp_timeout);

	print_hex_dump_debug("(in):  ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     buf_len, false);

	iowrite32(phys_lsb, sev->io_regs + sev->vdata->cmdbuff_addr_lo_reg);
	iowrite32(phys_msb, sev->io_regs + sev->vdata->cmdbuff_addr_hi_reg);

	sev->int_rcvd = 0;

	reg = cmd;
	reg <<= SEV_CMDRESP_CMD_SHIFT;
	reg |= SEV_CMDRESP_IOC;
	iowrite32(reg, sev->io_regs + sev->vdata->cmdresp_reg);

	/* wait for command completion */
	ret = sev_wait_cmd_ioc(sev, &reg, psp_timeout);
	if (ret) {
		if (psp_ret)
			*psp_ret = 0;

		dev_err(sev->dev, "sev command %#x timed out, disabling PSP\n", cmd);
		psp_dead = true;

		return ret;
	}

	psp_timeout = psp_cmd_timeout;

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(sev->dev, "sev command %#x failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	}

	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     buf_len, false);

	/*
	 * Copy potential output from the PSP back to data.  Do this even on
	 * failure in case the caller wants to glean something from the error.
	 */
	if (data)
		memcpy(data, sev->cmd_buf, buf_len);

	return ret;
}

static int sev_do_cmd(int cmd, void *data, int *psp_ret)
{
	int rc;
	int mutex_enabled = READ_ONCE(psp_mutex_enabled);

	if (is_hygon_psp && mutex_enabled) {
		if (psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex,
					PSP_MUTEX_TIMEOUT) != 1)
			return -EBUSY;
	} else {
		mutex_lock(&sev_cmd_mutex);
	}

	rc = __sev_do_cmd_locked(cmd, data, psp_ret);
	if (is_hygon_psp && mutex_enabled)
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int __csv_ring_buffer_enter_locked(int *error)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	struct csv_data_ring_buffer *data;
	struct csv_ringbuffer_queue *low_queue;
	struct csv_ringbuffer_queue *hi_queue;
	int ret = 0;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	if (csv_comm_mode == CSV_COMM_RINGBUFFER_ON)
		return -EEXIST;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	low_queue = &sev->ring_buffer[CSV_COMMAND_PRIORITY_LOW];
	hi_queue = &sev->ring_buffer[CSV_COMMAND_PRIORITY_HIGH];

	data->queue_lo_cmdptr_address = __psp_pa(low_queue->cmd_ptr.data_align);
	data->queue_lo_statval_address = __psp_pa(low_queue->stat_val.data_align);
	data->queue_hi_cmdptr_address = __psp_pa(hi_queue->cmd_ptr.data_align);
	data->queue_hi_statval_address = __psp_pa(hi_queue->stat_val.data_align);
	data->queue_lo_size = 1;
	data->queue_hi_size = 1;
	data->int_on_empty = 1;

	ret = __sev_do_cmd_locked(CSV_CMD_RING_BUFFER, data, error);
	if (!ret) {
		iowrite32(0, sev->io_regs + sev->vdata->cmdbuff_addr_hi_reg);
		csv_comm_mode = CSV_COMM_RINGBUFFER_ON;
	}

	kfree(data);
	return ret;
}

static int csv_get_cmd_status(struct sev_device *sev, int prio, int index)
{
	struct csv_queue *queue = &sev->ring_buffer[prio].stat_val;
	struct csv_statval_entry *statval = (struct csv_statval_entry *)queue->data;

	return statval[index].status;
}

static int __csv_do_ringbuf_cmds_locked(int *psp_ret)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	unsigned int rb_tail;
	unsigned int rb_ctl;
	int last_cmd_index;
	unsigned int reg, ret = 0;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	if (psp_dead)
		return -EBUSY;

	sev = psp->sev_data;

	/* update rb tail */
	rb_tail = ioread32(sev->io_regs + sev->vdata->cmdbuff_addr_hi_reg);
	rb_tail &= (~PSP_RBTAIL_QHI_TAIL_MASK);
	rb_tail |= (sev->ring_buffer[CSV_COMMAND_PRIORITY_HIGH].cmd_ptr.tail
						<< PSP_RBTAIL_QHI_TAIL_SHIFT);
	rb_tail &= (~PSP_RBTAIL_QLO_TAIL_MASK);
	rb_tail |= sev->ring_buffer[CSV_COMMAND_PRIORITY_LOW].cmd_ptr.tail;
	iowrite32(rb_tail, sev->io_regs + sev->vdata->cmdbuff_addr_hi_reg);

	/* update rb ctl to trigger psp irq */
	sev->int_rcvd = 0;

	/* PSP response to x86 only when all queue is empty or error happends */
	rb_ctl = PSP_RBCTL_X86_WRITES |
		 PSP_RBCTL_RBMODE_ACT |
		 PSP_RBCTL_CLR_INTSTAT;
	iowrite32(rb_ctl, sev->io_regs + sev->vdata->cmdresp_reg);

	/* wait for all commands in ring buffer completed */
	ret = csv_wait_cmd_ioc_ring_buffer(sev, &reg, psp_timeout * 10);
	if (ret) {
		if (psp_ret)
			*psp_ret = 0;
		dev_err(sev->dev, "csv ringbuffer mode command timed out, disabling PSP\n");
		psp_dead = true;

		return ret;
	}

	/* cmd error happends */
	if (reg & PSP_RBHEAD_QPAUSE_INT_STAT)
		ret = -EFAULT;

	if (psp_ret) {
		last_cmd_index = (reg & PSP_RBHEAD_QHI_HEAD_MASK)
					>> PSP_RBHEAD_QHI_HEAD_SHIFT;
		*psp_ret = csv_get_cmd_status(sev, CSV_COMMAND_PRIORITY_HIGH,
					      last_cmd_index);
		if (*psp_ret == 0) {
			last_cmd_index = reg & PSP_RBHEAD_QLO_HEAD_MASK;
			*psp_ret = csv_get_cmd_status(sev,
					CSV_COMMAND_PRIORITY_LOW, last_cmd_index);
		}
	}

	return ret;
}

static int csv_do_ringbuf_cmds(int *psp_ret)
{
	int mutex_enabled = READ_ONCE(psp_mutex_enabled);
	struct sev_user_data_status data;
	int rc;

	if (is_hygon_psp && mutex_enabled) {
		if (psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex,
						PSP_MUTEX_TIMEOUT) != 1) {
			return -EBUSY;
		}
	} else {
		mutex_lock(&sev_cmd_mutex);
	}

	rc = __csv_ring_buffer_enter_locked(psp_ret);
	if (rc)
		goto cmd_unlock;

	rc = __csv_do_ringbuf_cmds_locked(psp_ret);

	/* exit ringbuf mode by send CMD in mailbox mode */
	__sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, NULL);
	csv_comm_mode = CSV_COMM_MAILBOX_ON;

cmd_unlock:
	if (is_hygon_psp && mutex_enabled)
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int __sev_platform_init_locked(int *error)
{
	struct psp_device *psp = psp_master;
	struct sev_data_init data;
	struct sev_device *sev;
	int rc = 0;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	/*
	 * Skip SNP/SEV initialization under a kdump kernel as SEV/SNP
	 * may already be initialized in the previous kernel. Since no
	 * SNP/SEV guests are run under a kdump kernel, there is no
	 * need to initialize SNP or SEV during kdump boot.
	 */
	if (is_kdump_kernel())
		return 0;

	sev = psp->sev_data;

	if (sev->state == SEV_STATE_INIT)
		return 0;

	memset(&data, 0, sizeof(data));
	if (sev_es_tmr) {
		u64 tmr_pa;

		/*
		 * Do not include the encryption mask on the physical
		 * address of the TMR (firmware should clear it anyway).
		 */
		tmr_pa = __pa(sev_es_tmr);

		data.flags |= SEV_INIT_FLAGS_SEV_ES;
		data.tmr_address = tmr_pa;
		data.tmr_len = SEV_ES_TMR_SIZE;
	}

	rc = __sev_do_cmd_locked(SEV_CMD_INIT, &data, error);
	if (rc)
		return rc;

	sev->state = SEV_STATE_INIT;

	/* Prepare for first SEV guest launch after INIT */
	wbinvd_on_all_cpus();
	rc = __sev_do_cmd_locked(SEV_CMD_DF_FLUSH, NULL, error);
	if (rc)
		return rc;

	dev_dbg(sev->dev, "SEV firmware initialized\n");

	return rc;
}

int sev_platform_init(int *error)
{
	int rc;
	int mutex_enabled = READ_ONCE(psp_mutex_enabled);

	if (is_hygon_psp && mutex_enabled) {
		if (psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex,
					PSP_MUTEX_TIMEOUT) != 1)
			return -EBUSY;
	} else {
		mutex_lock(&sev_cmd_mutex);
	}

	rc = __sev_platform_init_locked(error);
	if (is_hygon_psp && mutex_enabled)
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(&sev_cmd_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(sev_platform_init);

static int __sev_platform_shutdown_locked(int *error)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	int ret;

	if (!psp || !psp->sev_data)
		return 0;

	sev = psp->sev_data;

	if (sev->state == SEV_STATE_UNINIT)
		return 0;

	ret = __sev_do_cmd_locked(SEV_CMD_SHUTDOWN, NULL, error);
	if (ret)
		return ret;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		csv_comm_mode = CSV_COMM_MAILBOX_ON;
		csv_ring_buffer_queue_free();
	}

	sev->state = SEV_STATE_UNINIT;
	dev_dbg(sev->dev, "SEV firmware shutdown\n");

	return ret;
}

static int sev_platform_shutdown(int *error)
{
	int rc;
	int mutex_enabled = READ_ONCE(psp_mutex_enabled);

	if (is_hygon_psp && mutex_enabled) {
		if (psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex,
					PSP_MUTEX_TIMEOUT) != 1)
			return -EBUSY;
	} else {
		mutex_lock(&sev_cmd_mutex);
	}
	rc = __sev_platform_shutdown_locked(NULL);
	if (is_hygon_psp && mutex_enabled)
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int sev_get_platform_state(int *state, int *error)
{
	struct sev_user_data_status data;
	int rc;

	rc = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, error);
	if (rc)
		return rc;

	*state = data.state;
	return rc;
}

static int sev_ioctl_do_reset(struct sev_issue_cmd *argp, bool writable)
{
	int state, rc;

	if (!writable)
		return -EPERM;

	/*
	 * The SEV spec requires that FACTORY_RESET must be issued in
	 * UNINIT state. Before we go further lets check if any guest is
	 * active.
	 *
	 * If FW is in WORKING state then deny the request otherwise issue
	 * SHUTDOWN command do INIT -> UNINIT before issuing the FACTORY_RESET.
	 *
	 */
	rc = sev_get_platform_state(&state, &argp->error);
	if (rc)
		return rc;

	if (state == SEV_STATE_WORKING)
		return -EBUSY;

	if (state == SEV_STATE_INIT) {
		rc = __sev_platform_shutdown_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(SEV_CMD_FACTORY_RESET, NULL, &argp->error);
}

static int sev_ioctl_do_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_user_data_status data;
	int ret;

	ret = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, &argp->error);
	if (ret)
		return ret;

	if (copy_to_user((void __user *)argp->data, &data, sizeof(data)))
		ret = -EFAULT;

	return ret;
}

static int sev_ioctl_do_pek_pdh_gen(int cmd, struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	int rc;

	if (!writable)
		return -EPERM;

	if (sev->state == SEV_STATE_UNINIT) {
		rc = __sev_platform_init_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(cmd, NULL, &argp->error);
}

static int sev_ioctl_do_pek_csr(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pek_csr input;
	struct sev_data_pek_csr data;
	void __user *input_address;
	void *blob = NULL;
	int ret;

	if (!writable)
		return -EPERM;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* userspace wants to query CSR length */
	if (!input.address || !input.length)
		goto cmd;

	/* allocate a physically contiguous buffer to store the CSR blob */
	input_address = (void __user *)input.address;
	if (input.length > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	blob = kmalloc(input.length, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	data.address = __psp_pa(blob);
	data.len = input.length;

cmd:
	if (sev->state == SEV_STATE_UNINIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_blob;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CSR, &data, &argp->error);

	 /* If we query the CSR length, FW responded with expected data. */
	input.length = data.len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_blob;
	}

	if (blob) {
		if (copy_to_user(input_address, blob, input.length))
			ret = -EFAULT;
	}

e_free_blob:
	kfree(blob);
	return ret;
}

void *psp_copy_user_blob(u64 uaddr, u32 len)
{
	if (!uaddr || !len)
		return ERR_PTR(-EINVAL);

	/* verify that blob length does not exceed our limit */
	if (len > SEV_FW_BLOB_MAX_SIZE)
		return ERR_PTR(-EINVAL);

	return memdup_user((void __user *)uaddr, len);
}
EXPORT_SYMBOL_GPL(psp_copy_user_blob);

static int sev_get_api_version(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_status status;
	int error = 0, ret;

	ret = sev_platform_status(&status, &error);
	if (ret) {
		dev_err(sev->dev,
			"SEV: failed to get status. Error: %#x\n", error);
		return 1;
	}

	sev->api_major = status.api_major;
	sev->api_minor = status.api_minor;
	sev->build = status.build;
	sev->state = status.state;

	/*
	 * The api version fields of HYGON CSV firmware are not consistent
	 * with AMD SEV firmware.
	 */
	if (is_vendor_hygon())
		csv_update_api_version(&status);

	return 0;
}

static int csv_get_api_version_locked(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_status status;
	int error = 0, ret;

	ret = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS,
				  &status, &error);
	if (ret) {
		dev_err(sev->dev,
			"CSV: failed to get status. Error: %#x\n", error);
		return ret;
	}

	sev->api_major = status.api_major;
	sev->api_minor = status.api_minor;
	sev->build = status.build;
	sev->state = status.state;

	/*
	 * The api version fields of HYGON CSV firmware are not consistent
	 * with AMD SEV firmware.
	 */
	csv_update_api_version(&status);

	return 0;
}
static int sev_get_firmware(struct device *dev,
			    const struct firmware **firmware)
{
	char fw_name_specific[SEV_FW_NAME_SIZE];
	char fw_name_subset[SEV_FW_NAME_SIZE];

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		/* Check for CSV FW to using generic name: csv.fw */
		if (firmware_request_nowarn(firmware, CSV_FW_FILE, dev) >= 0)
			return 0;
		else
			return -ENOENT;
	}

	snprintf(fw_name_specific, sizeof(fw_name_specific),
		 "amd/amd_sev_fam%.2xh_model%.2xh.sbin",
		 boot_cpu_data.x86, boot_cpu_data.x86_model);

	snprintf(fw_name_subset, sizeof(fw_name_subset),
		 "amd/amd_sev_fam%.2xh_model%.1xxh.sbin",
		 boot_cpu_data.x86, (boot_cpu_data.x86_model & 0xf0) >> 4);

	/* Check for SEV FW for a particular model.
	 * Ex. amd_sev_fam17h_model00h.sbin for Family 17h Model 00h
	 *
	 * or
	 *
	 * Check for SEV FW common to a subset of models.
	 * Ex. amd_sev_fam17h_model0xh.sbin for
	 *     Family 17h Model 00h -- Family 17h Model 0Fh
	 *
	 * or
	 *
	 * Fall-back to using generic name: sev.fw
	 */
	if ((firmware_request_nowarn(firmware, fw_name_specific, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, fw_name_subset, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, SEV_FW_FILE, dev) >= 0))
		return 0;

	return -ENOENT;
}

/* Don't fail if SEV FW couldn't be updated. Continue with existing SEV FW */
static int sev_update_firmware(struct device *dev)
{
	struct sev_data_download_firmware *data;
	const struct firmware *firmware;
	int ret, error, order;
	struct page *p;
	u64 data_size;

	if (sev_get_firmware(dev, &firmware) == -ENOENT) {
		dev_dbg(dev, "No SEV firmware file present\n");
		return -1;
	}

	/*
	 * SEV FW expects the physical address given to it to be 32
	 * byte aligned. Memory allocated has structure placed at the
	 * beginning followed by the firmware being passed to the SEV
	 * FW. Allocate enough memory for data structure + alignment
	 * padding + SEV FW.
	 */
	data_size = ALIGN(sizeof(struct sev_data_download_firmware), 32);

	order = get_order(firmware->size + data_size);
	p = alloc_pages(GFP_KERNEL, order);
	if (!p) {
		ret = -1;
		goto fw_err;
	}

	/*
	 * Copy firmware data to a kernel allocated contiguous
	 * memory region.
	 */
	data = page_address(p);
	memcpy(page_address(p) + data_size, firmware->data, firmware->size);

	data->address = __psp_pa(page_address(p) + data_size);
	data->len = firmware->size;

	ret = sev_do_cmd(SEV_CMD_DOWNLOAD_FIRMWARE, data, &error);
	if (ret)
		dev_dbg(dev, "Failed to update %s firmware: %#x\n",
			(boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
				? "CSV" : "SEV",
			error);
	else
		dev_info(dev, "%s firmware update successful\n",
			 (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
				? "CSV" : "SEV");

	__free_pages(p, order);

fw_err:
	release_firmware(firmware);

	return ret;
}

static int sev_ioctl_do_pek_import(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pek_cert_import input;
	struct sev_data_pek_cert_import data;
	void *pek_blob, *oca_blob;
	int ret;

	if (!writable)
		return -EPERM;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* copy PEK certificate blobs from userspace */
	pek_blob = psp_copy_user_blob(input.pek_cert_address, input.pek_cert_len);
	if (IS_ERR(pek_blob))
		return PTR_ERR(pek_blob);

	data.reserved = 0;
	data.pek_cert_address = __psp_pa(pek_blob);
	data.pek_cert_len = input.pek_cert_len;

	/* copy PEK certificate blobs from userspace */
	oca_blob = psp_copy_user_blob(input.oca_cert_address, input.oca_cert_len);
	if (IS_ERR(oca_blob)) {
		ret = PTR_ERR(oca_blob);
		goto e_free_pek;
	}

	data.oca_cert_address = __psp_pa(oca_blob);
	data.oca_cert_len = input.oca_cert_len;

	/* If platform is not in INIT state then transition it to INIT */
	if (sev->state != SEV_STATE_INIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_oca;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CERT_IMPORT, &data, &argp->error);

e_free_oca:
	kfree(oca_blob);
e_free_pek:
	kfree(pek_blob);
	return ret;
}

static int sev_ioctl_do_get_id2(struct sev_issue_cmd *argp)
{
	struct sev_user_data_get_id2 input;
	struct sev_data_get_id data;
	void __user *input_address;
	void *id_blob = NULL;
	int ret;

	/* SEV GET_ID is available from SEV API v0.16 and up */
	if (!sev_version_greater_or_equal(0, 16))
		return -ENOTSUPP;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	input_address = (void __user *)input.address;

	if (input.address && input.length) {
		id_blob = kmalloc(input.length, GFP_KERNEL);
		if (!id_blob)
			return -ENOMEM;

		data.address = __psp_pa(id_blob);
		data.len = input.length;
	} else {
		data.address = 0;
		data.len = 0;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_GET_ID, &data, &argp->error);

	/*
	 * Firmware will return the length of the ID value (either the minimum
	 * required length or the actual length written), return it to the user.
	 */
	input.length = data.len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free;
	}

	if (id_blob) {
		if (copy_to_user(input_address, id_blob, data.len)) {
			ret = -EFAULT;
			goto e_free;
		}
	}

e_free:
	kfree(id_blob);

	return ret;
}

static int sev_ioctl_do_get_id(struct sev_issue_cmd *argp)
{
	struct sev_data_get_id *data;
	u64 data_size, user_size;
	void *id_blob, *mem;
	int ret;

	/* SEV GET_ID available from SEV API v0.16 and up */
	if (!sev_version_greater_or_equal(0, 16))
		return -ENOTSUPP;

	/* SEV FW expects the buffer it fills with the ID to be
	 * 8-byte aligned. Memory allocated should be enough to
	 * hold data structure + alignment padding + memory
	 * where SEV FW writes the ID.
	 */
	data_size = ALIGN(sizeof(struct sev_data_get_id), 8);
	user_size = sizeof(struct sev_user_data_get_id);

	mem = kzalloc(data_size + user_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	data = mem;
	id_blob = mem + data_size;

	data->address = __psp_pa(id_blob);
	data->len = user_size;

	ret = __sev_do_cmd_locked(SEV_CMD_GET_ID, data, &argp->error);
	if (!ret) {
		if (copy_to_user((void __user *)argp->data, id_blob, data->len))
			ret = -EFAULT;
	}

	kfree(mem);

	return ret;
}

static int sev_ioctl_do_pdh_export(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pdh_cert_export input;
	void *pdh_blob = NULL, *cert_blob = NULL;
	struct sev_data_pdh_cert_export data;
	void __user *input_cert_chain_address;
	void __user *input_pdh_cert_address;
	int ret;

	/* If platform is not in INIT state then transition it to INIT. */
	if (sev->state != SEV_STATE_INIT) {
		if (!writable)
			return -EPERM;

		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			return ret;
	}

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* Userspace wants to query the certificate length. */
	if (!input.pdh_cert_address ||
	    !input.pdh_cert_len ||
	    !input.cert_chain_address)
		goto cmd;

	input_pdh_cert_address = (void __user *)input.pdh_cert_address;
	input_cert_chain_address = (void __user *)input.cert_chain_address;

	/* Allocate a physically contiguous buffer to store the PDH blob. */
	if (input.pdh_cert_len > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	/* Allocate a physically contiguous buffer to store the cert chain blob. */
	if (input.cert_chain_len > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	pdh_blob = kmalloc(input.pdh_cert_len, GFP_KERNEL);
	if (!pdh_blob)
		return -ENOMEM;

	data.pdh_cert_address = __psp_pa(pdh_blob);
	data.pdh_cert_len = input.pdh_cert_len;

	cert_blob = kmalloc(input.cert_chain_len, GFP_KERNEL);
	if (!cert_blob) {
		ret = -ENOMEM;
		goto e_free_pdh;
	}

	data.cert_chain_address = __psp_pa(cert_blob);
	data.cert_chain_len = input.cert_chain_len;

cmd:
	ret = __sev_do_cmd_locked(SEV_CMD_PDH_CERT_EXPORT, &data, &argp->error);

	/* If we query the length, FW responded with expected data. */
	input.cert_chain_len = data.cert_chain_len;
	input.pdh_cert_len = data.pdh_cert_len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_cert;
	}

	if (pdh_blob) {
		if (copy_to_user(input_pdh_cert_address,
				 pdh_blob, input.pdh_cert_len)) {
			ret = -EFAULT;
			goto e_free_cert;
		}
	}

	if (cert_blob) {
		if (copy_to_user(input_cert_chain_address,
				 cert_blob, input.cert_chain_len))
			ret = -EFAULT;
	}

e_free_cert:
	kfree(cert_blob);
e_free_pdh:
	kfree(pdh_blob);
	return ret;
}

static int csv_ioctl_do_download_firmware(struct sev_issue_cmd *argp)
{
	struct sev_data_download_firmware *data = NULL;
	struct csv_user_data_download_firmware input;
	int ret, order;
	struct page *p;
	u64 data_size;

	/* Only support DOWNLOAD_FIRMWARE if build greater or equal 1667 */
	if (!csv_version_greater_or_equal(1667)) {
		pr_err("DOWNLOAD_FIRMWARE not supported\n");
		return -EIO;
	}

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	if (!input.address) {
		argp->error = SEV_RET_INVALID_ADDRESS;
		return -EINVAL;
	}

	if (!input.length || input.length > CSV_FW_MAX_SIZE) {
		argp->error = SEV_RET_INVALID_LEN;
		return -EINVAL;
	}

	/*
	 * CSV FW expects the physical address given to it to be 32
	 * byte aligned. Memory allocated has structure placed at the
	 * beginning followed by the firmware being passed to the CSV
	 * FW. Allocate enough memory for data structure + alignment
	 * padding + CSV FW.
	 */
	data_size = ALIGN(sizeof(struct sev_data_download_firmware), 32);

	order = get_order(input.length + data_size);
	p = alloc_pages(GFP_KERNEL, order);
	if (!p)
		return -ENOMEM;

	/*
	 * Copy firmware data to a kernel allocated contiguous
	 * memory region.
	 */
	data = page_address(p);
	if (copy_from_user((void *)(page_address(p) + data_size),
			   (void *)input.address, input.length)) {
		ret = -EFAULT;
		goto err_free_page;
	}

	data->address = __psp_pa(page_address(p) + data_size);
	data->len = input.length;

	ret = __sev_do_cmd_locked(SEV_CMD_DOWNLOAD_FIRMWARE, data, &argp->error);
	if (ret) {
		pr_err("Failed to update CSV firmware: %#x\n", argp->error);
		goto err_free_page;
	} else {
		pr_info("CSV firmware update successful\n");
	}

	/*
	 * Synchronize API version status. The return value of csv_get_api_version
	 * will inform the user of any error encountered when attempting to
	 * communicate with the Hygon PSP after the DOWNLOAD_FIRMWARE API completes
	 * successfully.
	 */
	ret = csv_get_api_version_locked();

err_free_page:
	__free_pages(p, order);

	return ret;
}

static int csv_ioctl_do_hgsc_import(struct sev_issue_cmd *argp)
{
	struct csv_user_data_hgsc_cert_import input;
	struct csv_data_hgsc_cert_import *data;
	void *hgscsk_blob, *hgsc_blob;
	int ret;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy HGSCSK certificate blobs from userspace */
	hgscsk_blob = psp_copy_user_blob(input.hgscsk_cert_address, input.hgscsk_cert_len);
	if (IS_ERR(hgscsk_blob)) {
		ret = PTR_ERR(hgscsk_blob);
		goto e_free;
	}

	data->hgscsk_cert_address = __psp_pa(hgscsk_blob);
	data->hgscsk_cert_len = input.hgscsk_cert_len;

	/* copy HGSC certificate blobs from userspace */
	hgsc_blob = psp_copy_user_blob(input.hgsc_cert_address, input.hgsc_cert_len);
	if (IS_ERR(hgsc_blob)) {
		ret = PTR_ERR(hgsc_blob);
		goto e_free_hgscsk;
	}

	data->hgsc_cert_address = __psp_pa(hgsc_blob);
	data->hgsc_cert_len = input.hgsc_cert_len;

	ret = __sev_do_cmd_locked(CSV_CMD_HGSC_CERT_IMPORT, data, &argp->error);

	kfree(hgsc_blob);
e_free_hgscsk:
	kfree(hgscsk_blob);
e_free:
	kfree(data);
	return ret;
}

static long sev_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sev_issue_cmd input;
	int ret = -EFAULT;
	bool writable = file->f_mode & FMODE_WRITE;
	int mutex_enabled;

	if (!psp_master || !psp_master->sev_data)
		return -ENODEV;

	if (ioctl != SEV_ISSUE_CMD)
		return -EINVAL;

	if (copy_from_user(&input, argp, sizeof(struct sev_issue_cmd)))
		return -EFAULT;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		if (input.cmd > CSV_MAX)
			return -EINVAL;
	} else {
		if (input.cmd > SEV_MAX)
			return -EINVAL;
	}

	mutex_enabled = READ_ONCE(psp_mutex_enabled);

	if (is_hygon_psp && mutex_enabled) {
		if (psp_mutex_lock_timeout(&psp_misc->data_pg_aligned->mb_mutex,
					PSP_MUTEX_TIMEOUT) != 1)
			return -EBUSY;
	} else {
		mutex_lock(&sev_cmd_mutex);
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		switch (input.cmd) {
		case CSV_PLATFORM_INIT:
			ret = __sev_platform_init_locked(&input.error);
			goto result_to_user;
		case CSV_PLATFORM_SHUTDOWN:
			ret = __sev_platform_shutdown_locked(&input.error);
			goto result_to_user;
		case CSV_DOWNLOAD_FIRMWARE:
			ret = csv_ioctl_do_download_firmware(&input);
			goto result_to_user;
		case CSV_HGSC_CERT_IMPORT:
			ret = csv_ioctl_do_hgsc_import(&input);
			goto result_to_user;
		default:
			break;
		}
	}

	switch (input.cmd) {

	case SEV_FACTORY_RESET:
		ret = sev_ioctl_do_reset(&input, writable);
		break;
	case SEV_PLATFORM_STATUS:
		ret = sev_ioctl_do_platform_status(&input);
		break;
	case SEV_PEK_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PEK_GEN, &input, writable);
		break;
	case SEV_PDH_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PDH_GEN, &input, writable);
		break;
	case SEV_PEK_CSR:
		ret = sev_ioctl_do_pek_csr(&input, writable);
		break;
	case SEV_PEK_CERT_IMPORT:
		ret = sev_ioctl_do_pek_import(&input, writable);
		break;
	case SEV_PDH_CERT_EXPORT:
		ret = sev_ioctl_do_pdh_export(&input, writable);
		break;
	case SEV_GET_ID:
		pr_warn_once("SEV_GET_ID command is deprecated, use SEV_GET_ID2\n");
		ret = sev_ioctl_do_get_id(&input);
		break;
	case SEV_GET_ID2:
		ret = sev_ioctl_do_get_id2(&input);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

result_to_user:
	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;
out:
	if (is_hygon_psp && mutex_enabled)
		psp_mutex_unlock(&psp_misc->data_pg_aligned->mb_mutex);
	else
		mutex_unlock(&sev_cmd_mutex);

	return ret;
}

static const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

int sev_platform_status(struct sev_user_data_status *data, int *error)
{
	return sev_do_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_do_cmd(SEV_CMD_DF_FLUSH, NULL, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);


/*
 * __csv_ring_buffer_queue_init will allocate memory for command queue
 * and status queue. If error occurs, this function will return directly,
 * the caller must free the memories allocated for queues.
 *
 * Function csv_ring_buffer_queue_free() can be used to handling error
 * return by this function and cleanup ring buffer queues when exiting
 * from RING BUFFER mode.
 *
 * Return -ENOMEM if fail to allocate memory for queues, otherwise 0
 */
static int __csv_ring_buffer_queue_init(struct csv_ringbuffer_queue *ring_buffer)
{
	void *cmd_ptr_buffer = NULL;
	void *stat_val_buffer = NULL;

	/* If reach here, the command and status queues must be NULL */
	WARN_ON(ring_buffer->cmd_ptr.data ||
		ring_buffer->stat_val.data);

	cmd_ptr_buffer = kzalloc(CSV_RING_BUFFER_LEN, GFP_KERNEL);
	if (!cmd_ptr_buffer)
		return -ENOMEM;

	/* the command queue will points to @cmd_ptr_buffer */
	csv_queue_init(&ring_buffer->cmd_ptr, cmd_ptr_buffer,
		       CSV_RING_BUFFER_SIZE, CSV_RING_BUFFER_ESIZE);

	stat_val_buffer = kzalloc(CSV_RING_BUFFER_LEN, GFP_KERNEL);
	if (!stat_val_buffer)
		return -ENOMEM;

	/* the status queue will points to @stat_val_buffer */
	csv_queue_init(&ring_buffer->stat_val, stat_val_buffer,
		       CSV_RING_BUFFER_SIZE, CSV_RING_BUFFER_ESIZE);
	return 0;
}

int csv_fill_cmd_queue(int prio, int cmd, void *data, uint16_t flags)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	struct csv_cmdptr_entry cmdptr = { };

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	cmdptr.cmd_buf_ptr = __psp_pa(data);
	cmdptr.cmd_id = cmd;
	cmdptr.cmd_flags = flags;

	if (csv_enqueue_cmd(&sev->ring_buffer[prio].cmd_ptr, &cmdptr, 1) != 1)
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(csv_fill_cmd_queue);

int csv_check_stat_queue_status(int *psp_ret)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	unsigned int len;
	int prio;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	for (prio = CSV_COMMAND_PRIORITY_HIGH;
	     prio < CSV_COMMAND_PRIORITY_NUM; prio++) {
		do {
			struct csv_statval_entry statval;

			len = csv_dequeue_stat(&sev->ring_buffer[prio].stat_val,
					       &statval, 1);
			if (len) {
				if (statval.status != 0) {
					*psp_ret = statval.status;
					return -EFAULT;
				}
			}
		} while (len);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(csv_check_stat_queue_status);

int csv_ring_buffer_queue_init(void)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	int i, ret = 0;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	for (i = CSV_COMMAND_PRIORITY_HIGH; i < CSV_COMMAND_PRIORITY_NUM; i++) {
		ret = __csv_ring_buffer_queue_init(&sev->ring_buffer[i]);
		if (ret)
			goto e_free;
	}

	return 0;

e_free:
	csv_ring_buffer_queue_free();
	return ret;
}
EXPORT_SYMBOL_GPL(csv_ring_buffer_queue_init);

int csv_ring_buffer_queue_free(void)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	struct csv_ringbuffer_queue *ring_buffer;
	int i;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	for (i = 0; i < CSV_COMMAND_PRIORITY_NUM; i++) {
		ring_buffer = &sev->ring_buffer[i];

		/*
		 * If command queue is not NULL, it must points to memory
		 * that allocated in __csv_ring_buffer_queue_init().
		 */
		if (ring_buffer->cmd_ptr.data) {
			kfree((void *)ring_buffer->cmd_ptr.data);
			ring_buffer->cmd_ptr.data = 0;
		}

		/*
		 * If status queue is not NULL, it must points to memory
		 * that allocated in __csv_ring_buffer_queue_init().
		 */
		if (ring_buffer->stat_val.data) {
			kfree((void *)ring_buffer->stat_val.data);
			ring_buffer->stat_val.data = 0;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(csv_ring_buffer_queue_free);

/**
 * struct user_data_status - PLATFORM_STATUS command parameters
 *
 * @major: major API version
 * @minor: minor API version
 * @state: platform state
 * @owner: self-owned or externally owned
 * @chip_secure: ES or MP chip
 * @fw_enc: is this FW is encrypted
 * @fw_sign: is this FW is signed
 * @config_es: platform config flags for csv-es
 * @build: Firmware Build ID for this API version
 * @bl_version_debug: Bootloader VERSION_DEBUG field
 * @bl_version_minor: Bootloader VERSION_MINOR field
 * @bl_version_major: Bootloader VERSION_MAJOR field
 * @guest_count: number of active guests
 * @reserved: should set to zero
 */
struct user_data_status {
	uint8_t api_major;		/* Out */
	uint8_t api_minor;		/* Out */
	uint8_t state;			/* Out */
	uint8_t owner : 1,		/* Out */
		chip_secure : 1,	/* Out */
		fw_enc : 1,		/* Out */
		fw_sign : 1,		/* Out */
		reserved1 : 4;		/*reserved*/
	uint32_t config_es : 1,		/* Out */
		build : 31;		/* Out */
	uint32_t guest_count;		/* Out */
} __packed;

static void sev_exit(struct kref *ref)
{
	misc_deregister(&misc_dev->misc);
	kfree(misc_dev);
	misc_dev = NULL;
}

static int sev_misc_init(struct sev_device *sev)
{
	struct device *dev = sev->dev;
	int ret;

	/*
	 * SEV feature support can be detected on multiple devices but the SEV
	 * FW commands must be issued on the master. During probe, we do not
	 * know the master hence we create /dev/sev on the first device probe.
	 * sev_do_cmd() finds the right master device to which to issue the
	 * command to the firmware.
	 */
	if (!misc_dev) {
		struct miscdevice *misc;

		misc_dev = kzalloc(sizeof(*misc_dev), GFP_KERNEL);
		if (!misc_dev)
			return -ENOMEM;

		misc = &misc_dev->misc;
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = DEVICE_NAME;
		misc->fops = &sev_fops;

		ret = misc_register(misc);
		if (ret)
			return ret;

		kref_init(&misc_dev->refcount);
	} else {
		kref_get(&misc_dev->refcount);
	}

	init_waitqueue_head(&sev->int_queue);
	sev->misc = misc_dev;
	dev_dbg(dev, "registered SEV device\n");

	return 0;
}

int sev_dev_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	struct sev_device *sev;
	int ret = -ENOMEM;

	if (!boot_cpu_has(X86_FEATURE_SEV)) {
		dev_info_once(dev, "SEV: memory encryption not enabled by BIOS\n");
		return 0;
	}

	sev = devm_kzalloc(dev, sizeof(*sev), GFP_KERNEL);
	if (!sev)
		goto e_err;

	sev->cmd_buf = (void *)devm_get_free_pages(dev, GFP_KERNEL, 0);
	if (!sev->cmd_buf)
		goto e_sev;

	psp->sev_data = sev;

	sev->dev = dev;
	sev->psp = psp;

	sev->io_regs = psp->io_regs;

	sev->vdata = (struct sev_vdata *)psp->vdata->sev;
	if (!sev->vdata) {
		ret = -ENODEV;
		dev_err(dev, "sev: missing driver data\n");
		goto e_buf;
	}

	psp_set_sev_irq_handler(psp, sev_irq_handler, sev);

	ret = sev_misc_init(sev);
	if (ret)
		goto e_irq;

	dev_notice(dev, "sev enabled\n");

	return 0;

e_irq:
	psp_clear_sev_irq_handler(psp);
e_buf:
	devm_free_pages(dev, (unsigned long)sev->cmd_buf);
e_sev:
	devm_kfree(dev, sev);
e_err:
	psp->sev_data = NULL;

	dev_notice(dev, "sev initialization failed\n");

	return ret;
}

static void sev_firmware_shutdown(struct sev_device *sev)
{
	sev_platform_shutdown(NULL);

	if (sev_es_tmr) {
		/* The TMR area was encrypted, flush it from the cache */
		wbinvd_on_all_cpus();

		free_pages((unsigned long)sev_es_tmr,
			   get_order(SEV_ES_TMR_SIZE));
		sev_es_tmr = NULL;
	}
}

void sev_dev_destroy(struct psp_device *psp)
{
	struct sev_device *sev = psp->sev_data;

	if (!sev)
		return;

	sev_firmware_shutdown(sev);

	if (sev->misc)
		kref_put(&misc_dev->refcount, sev_exit);

	psp_clear_sev_irq_handler(psp);
}

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return sev_do_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

int csv_issue_ringbuf_cmds_external_user(struct file *filep, int *psp_ret)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return csv_do_ringbuf_cmds(psp_ret);
}
EXPORT_SYMBOL_GPL(csv_issue_ringbuf_cmds_external_user);

#ifdef CONFIG_HYGON_CSV
static int csv_platform_cmd_set_secure_memory_region(int *error)
{
	int ret = 0;
	unsigned int i = 0;
	struct csv_data_set_smr *cmd_set_smr = NULL;
	struct csv_data_set_smcr *cmd_set_smcr = NULL;
	struct csv_data_memory_region *smr_regions = NULL;
	unsigned int smr_num;
	enum csv_smr_source source = get_csv_smr_source();

	/* Initialize global SMRs */
	if (!csv_smr || !csv_smr_num)
		return -EINVAL;

	cmd_set_smr = kzalloc(sizeof(*cmd_set_smr), GFP_KERNEL);
	if (!cmd_set_smr)
		return -ENOMEM;

	smr_num = max_t(unsigned int, csv_smr_num, csv_smcr_num);
	smr_regions = kcalloc(smr_num, sizeof(*smr_regions),  GFP_KERNEL);
	if (!smr_regions) {
		ret = -ENOMEM;
		goto e_free_cmd_set_smr;
	}

	for (i = 0; i < csv_smr_num; i++) {
		smr_regions[i].base_address = csv_smr[i].start;
		smr_regions[i].size = csv_smr[i].size;
	}

	cmd_set_smr->smr_entry_size = 1 << csv_get_smr_entry_shift();
	cmd_set_smr->regions_paddr = __psp_pa(smr_regions);
	cmd_set_smr->nregions = csv_smr_num;

	ret = sev_do_cmd(CSV_CMD_SET_SMR, cmd_set_smr, error);
	if (ret) {
		pr_err("Fail to set SMR, ret %#x, error %#x\n", ret, *error);
		goto e_free_smr_area;
	}

	/* Initialize global SMCRs */
	if (csv_smcr && csv_smcr_num && csv_version_greater_or_equal(2407)) {
		for (i = 0; i < csv_smcr_num; i++) {
			smr_regions[i].base_address = csv_smcr[i].start;
			smr_regions[i].size = csv_smcr[i].size;
			clflush_cache_range(__va(csv_smcr[i].start), csv_smcr[i].size);
		}
		cmd_set_smr->smcr_flag = 0; /* 0 as SMCR memory flag */
		cmd_set_smr->regions_paddr = __psp_pa(smr_regions);
		cmd_set_smr->nregions = csv_smcr_num;
		ret = sev_do_cmd(CSV_CMD_SET_SMR, cmd_set_smr, error);
		if (ret)
			pr_err("Fail to set SMCR, ret %#x, error %#x\n", ret, *error);
		else
			pr_info("CSV: manage CSV3 VM by SMCR pool,%s\n",
				source == USE_CMA ? "CMA" :
				source == USE_HUGETLB ? "1G hugetlb,Metadata pool" : "?");
		goto e_free_smr_area;
	} else if (source == USE_CMA) {
		cmd_set_smcr = kzalloc(sizeof(*cmd_set_smcr), GFP_KERNEL);
		if (!cmd_set_smcr) {
			ret = -ENOMEM;
			goto e_free_smr_area;
		}

		cmd_set_smcr->base_address = csv_alloc_from_contiguous(1UL << CSV_MR_ALIGN_BITS,
							&node_online_map,
							get_order(1 << CSV_MR_ALIGN_BITS));
		if (!cmd_set_smcr->base_address) {
			pr_err("Fail to alloc SMCR memory\n");
			ret = -ENOMEM;
			goto e_free_cmd_set_smcr;
		}

		cmd_set_smcr->size = 1UL << CSV_MR_ALIGN_BITS;
		ret = sev_do_cmd(CSV_CMD_SET_SMCR, cmd_set_smcr, error);
		if (ret) {
			if (*error == SEV_RET_INVALID_COMMAND)
				ret = 0;
			else
				pr_err("Fail to set SMCR, ret %#x, error %#x\n", ret, *error);

			csv_release_to_contiguous(cmd_set_smcr->base_address,
						1UL << CSV_MR_ALIGN_BITS);
		} else {
			pr_info("CSV: manage CSV3 VM by CMA\n");
#ifdef CONFIG_SYSFS
			csv3_meta = cmd_set_smcr->size;
#endif
		}
	} else {
		pr_err("Unable to set hardware SMCR\n");
		goto e_free_smr_area;
	}

e_free_cmd_set_smcr:
	kfree((void *)cmd_set_smcr);
e_free_smr_area:
	kfree((void *)smr_regions);
e_free_cmd_set_smr:
	kfree((void *)cmd_set_smr);
	return ret;
}
#endif

void sev_pci_init(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct page *tmr_page;
	int error, rc;

	if (!sev)
		return;

	psp_timeout = psp_probe_timeout;

	if (sev_get_api_version())
		goto err;

	if (sev_version_greater_or_equal(0, 15) &&
	    (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON ||
	     csv_version_greater_or_equal(1667)) &&
	    sev_update_firmware(sev->dev) == 0)
		sev_get_api_version();

	/* Obtain the TMR memory area for SEV-ES use */
	tmr_page = alloc_pages(GFP_KERNEL, get_order(SEV_ES_TMR_SIZE));
	if (tmr_page) {
		sev_es_tmr = page_address(tmr_page);
	} else {
		sev_es_tmr = NULL;
		dev_warn(sev->dev,
			 "SEV: TMR allocation failed, SEV-ES support unavailable\n");
	}

#ifdef CONFIG_HYGON_CSV
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON &&
	    boot_cpu_has(X86_FEATURE_CSV3)) {
		/* Set SMR for CSV */
		rc = csv_platform_cmd_set_secure_memory_region(&error);
		if (rc)
			dev_warn(sev->dev,
			 "CSV3: fail to set secure memory region, CSV3 support unavailable\n");
	}
#endif

	/* Initialize the platform */
	rc = sev_platform_init(&error);
	if (rc && (error == SEV_RET_SECURE_DATA_INVALID)) {
		/*
		 * INIT command returned an integrity check failure
		 * status code, meaning that firmware load and
		 * validation of SEV related persistent data has
		 * failed and persistent state has been erased.
		 * Retrying INIT command here should succeed.
		 */
		dev_dbg(sev->dev, "SEV: retrying INIT command");
		rc = sev_platform_init(&error);
	}

	if (rc) {
		dev_err(sev->dev, "SEV: failed to INIT error %#x, rc %d\n",
			error, rc);
		return;
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		dev_info(sev->dev, "CSV API:%d.%d build:%d\n", sev->api_major,
			 sev->api_minor, hygon_csv_build);
	else
		dev_info(sev->dev, "SEV API:%d.%d build:%d\n", sev->api_major,
			 sev->api_minor, sev->build);

	return;

err:
	psp_master->sev_data = NULL;
}

void sev_pci_exit(void)
{
	struct sev_device *sev = psp_master->sev_data;

	if (!sev)
		return;

	sev_firmware_shutdown(sev);
}
