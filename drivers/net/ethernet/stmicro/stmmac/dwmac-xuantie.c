// SPDX-License-Identifier: GPL-2.0
/*
 * xuantie DWXGMAC PCI driver
 *
 * Copyright (C) 2021 Alibaba Group Holding Limited.
 * Author: David Li <xiaojin.cxj@linux.alibaba.com>
 *
 */

#include <linux/clk-provider.h>
#include <linux/pci.h>
#include <linux/dmi.h>

#include "stmmac.h"
#include "hwif.h"

#define XUANTIE_STMMAC_MSI_VEC_MAX 64
#define XUNATIE_STMMAC_MAX_RX_QUEUE 8
#define XUNATIE_STMMAC_MAX_TX_QUEUE 8

/* XuanTie ACE (AXI Cache Encoding) register offsets */
#define XUNATIE_TX_AR_ACE_CONTROL	0x3010
#define XUNATIE_RX_AW_ACE_CONTROL	0x3018
#define XUNATIE_TXRX_AWAR_ACE_CONTROL	0x301c

/* XGMAC DMA_MODE interrupt mode (INTM) field */
#define XUNATIE_DMA_MODE		0x3000
#define XUNATIE_INTM_MASK		0x3000
#define XUNATIE_INTM_MODE1		0x1000

struct stmmac_pci_info {
	int (*setup)(struct pci_dev *pdev, struct plat_stmmacenet_data *plat);
};

static int stmmac_config_single_msi(struct pci_dev *pdev,
				    struct plat_stmmacenet_data *plat,
				    struct stmmac_resources *res)
{
	int ret;

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_LEGACY);
	if (ret < 0) {
		dev_info(&pdev->dev, "%s: Single IRQ enablement failed\n",
			 __func__);
		return ret;
	}

	res->irq = pci_irq_vector(pdev, 0);
	plat->flags &= ~STMMAC_FLAG_MULTI_MSI_EN;
	dev_info(&pdev->dev, "%s: Single IRQ enablement successful\n",
		 __func__);

	return 0;
}

static int stmmac_config_multi_msi(struct pci_dev *pdev,
				   struct plat_stmmacenet_data *plat,
				   struct stmmac_resources *res)
{
	int ret;
	int i;

	if (plat->msi_rx_base_vec >= XUANTIE_STMMAC_MSI_VEC_MAX ||
	    plat->msi_tx_base_vec >= XUANTIE_STMMAC_MSI_VEC_MAX) {
		dev_info(&pdev->dev, "%s: Invalid RX & TX vector defined\n",
			 __func__);
		return -1;
	}

	ret = pci_alloc_irq_vectors(pdev, 2, XUANTIE_STMMAC_MSI_VEC_MAX,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_info(&pdev->dev, "%s: multi MSI enablement failed\n",
			 __func__);
		return ret;
	}
   /*fix me */
	/* For RX MSI */
	for (i = 0; i < XUNATIE_STMMAC_MAX_RX_QUEUE; i++) {
		res->rx_irq[i] =
			pci_irq_vector(pdev, plat->msi_rx_base_vec + i);
	}

	/* For TX MSI */
	for (i = 0; i < XUNATIE_STMMAC_MAX_TX_QUEUE; i++) {
		res->tx_irq[i] =
			pci_irq_vector(pdev, plat->msi_tx_base_vec + i);
	}

	if (plat->msi_mac_vec < XUANTIE_STMMAC_MSI_VEC_MAX)
		res->irq = pci_irq_vector(pdev, plat->msi_mac_vec);
	if (plat->msi_wol_vec < XUANTIE_STMMAC_MSI_VEC_MAX)
		res->wol_irq = pci_irq_vector(pdev, plat->msi_wol_vec);
	if (plat->msi_sfty_ce_vec < XUANTIE_STMMAC_MSI_VEC_MAX)
		res->sfty_ce_irq = pci_irq_vector(pdev, plat->msi_sfty_ce_vec);
	if (plat->msi_sfty_ue_vec < XUANTIE_STMMAC_MSI_VEC_MAX)
		res->sfty_ue_irq = pci_irq_vector(pdev, plat->msi_sfty_ue_vec);

	plat->flags |= STMMAC_FLAG_MULTI_MSI_EN;
	dev_info(&pdev->dev, "%s: multi MSI enablement successful\n", __func__);

	return 0;
}

static int stmmac_xlgmac_data(struct pci_dev *pdev,
			       struct plat_stmmacenet_data *plat)
{
	/* Set common default data first */
	//plat->clk_csr = 2;	/* clk_csr_i = 20-35MHz & MDC = clk_csr_i/16 */
	plat->has_gmac =  0;
	plat->has_gmac4 = 0;
	plat->has_xgmac = 1;

	//plat->force_thresh_dma_mode = 1;

	plat->mdio_bus_data->needs_reset = true;

	/* Set default value for multicast hash bins */
	plat->multicast_filter_bins = HASH_TABLE_SIZE;

	/* Set default value for unicast filter entries */
	plat->unicast_filter_entries = 1;

	/* Set the maxmtu to a default of JUMBO_LEN */
	plat->maxmtu = JUMBO_LEN;

	plat->tx_sched_algorithm = MTL_TX_ALGORITHM_WRR;
	for (int i = 0; i < XUNATIE_STMMAC_MAX_TX_QUEUE; i++) {
		plat->tx_queues_cfg[i].use_prio = false;
		plat->tx_queues_cfg[i].mode_to_use = MTL_QUEUE_DCB;
		plat->tx_queues_cfg[i].weight = 25;
	}

	plat->rx_sched_algorithm = MTL_RX_ALGORITHM_SP;
	for (int i = 0; i < XUNATIE_STMMAC_MAX_RX_QUEUE; i++) {
		plat->rx_queues_cfg[i].use_prio = false;
		plat->rx_queues_cfg[i].mode_to_use = MTL_QUEUE_DCB;
		plat->rx_queues_cfg[i].pkt_route = 0x0;
		plat->rx_queues_cfg[i].chan = i;
	}

	plat->bus_id = 0;
	plat->phy_addr = 0;
	plat->phy_interface = PHY_INTERFACE_MODE_GMII;

	plat->dma_cfg->pbl = 32;
	plat->dma_cfg->pblx8 = true;

	/* TODO: AXI */

	plat->axi = devm_kzalloc(&pdev->dev, sizeof(*plat->axi), GFP_KERNEL);
	if (!plat->axi)
		return -ENOMEM;

	plat->axi->axi_wr_osr_lmt = 63;
	plat->axi->axi_rd_osr_lmt = 63;

	plat->axi->axi_fb = false;
	plat->axi->axi_blen[0] = 32;
	plat->axi->axi_blen[1] = 64;
	plat->axi->axi_blen[2] = 128;
	plat->axi->axi_blen[3] = 256;
	plat->msi_mac_vec = 32;
	plat->msi_rx_base_vec = 16;
	plat->msi_tx_base_vec = 0;
	plat->tx_fifo_size = 155648;
	plat->rx_fifo_size = 163840;

	return 0;
}

static const struct stmmac_pci_info stmmac_xlgmac_pci_info = {
	.setup = stmmac_xlgmac_data,
};


static int stmmac_xgmac_data(struct pci_dev *pdev,
	struct plat_stmmacenet_data *plat)
{
/* Set common default data first */
//plat->clk_csr = 2;	/* clk_csr_i = 20-35MHz & MDC = clk_csr_i/16 */
	plat->has_xgmac = 1;
	plat->has_gmac =  0;
	plat->has_gmac4 = 0;

	//plat->force_thresh_dma_mode = 1;

	plat->mdio_bus_data->needs_reset = true;

	/* Set default value for multicast hash bins */
	plat->multicast_filter_bins = HASH_TABLE_SIZE;

	/* Set default value for unicast filter entries */
	plat->unicast_filter_entries = 1;

	/* Set the maxmtu to a default of JUMBO_LEN */
	plat->maxmtu = JUMBO_LEN;

	plat->tx_sched_algorithm = MTL_TX_ALGORITHM_WRR;
	for (int i = 0; i < XUNATIE_STMMAC_MAX_TX_QUEUE; i++) {
		plat->tx_queues_cfg[i].use_prio = false;
		plat->tx_queues_cfg[i].mode_to_use = MTL_QUEUE_DCB;
		plat->tx_queues_cfg[i].weight = 25;
		if (i > 0)
			plat->tx_queues_cfg[i].tbs_en = 1;
	}

	plat->rx_sched_algorithm = MTL_RX_ALGORITHM_SP;
	for (int i = 0; i < XUNATIE_STMMAC_MAX_RX_QUEUE; i++) {
		plat->rx_queues_cfg[i].use_prio = false;
		plat->rx_queues_cfg[i].mode_to_use = MTL_QUEUE_DCB;
		plat->rx_queues_cfg[i].pkt_route = 0x0;
		plat->rx_queues_cfg[i].chan = i;
	}

	plat->bus_id = 0;
	plat->phy_addr = 0;
	plat->phy_interface = PHY_INTERFACE_MODE_GMII;

	plat->dma_cfg->pbl = 32;
	plat->dma_cfg->pblx8 = true;

	/* TODO: AXI */

	plat->axi = devm_kzalloc(&pdev->dev, sizeof(*plat->axi), GFP_KERNEL);
	if (!plat->axi)
		return -ENOMEM;

	plat->axi->axi_wr_osr_lmt = 63;
	plat->axi->axi_rd_osr_lmt = 63;

	plat->axi->axi_fb = false;
	plat->axi->axi_blen[0] = 32;
	plat->axi->axi_blen[1] = 64;
	plat->axi->axi_blen[2] = 128;
	plat->axi->axi_blen[3] = 256;
	plat->msi_mac_vec = 32;
	plat->msi_rx_base_vec = 16;
	plat->msi_tx_base_vec = 0;
	plat->tx_fifo_size = 155648;
	plat->rx_fifo_size = 163840;

	return 0;
}

static const struct stmmac_pci_info stmmac_xgmac_pci_info = {
	.setup = stmmac_xgmac_data,
};

/* XuanTie multi-MSI needs per-channel interrupt notification (INTM = Mode1).
 * A DMA software reset clears INTM on every open, so it must be reprogrammed
 * after each DMA init; hook the shared DMA init here to keep the generic
 * dwxgmac2 code untouched.
 */
static void (*xuantie_orig_dma_init)(void __iomem *ioaddr,
				     struct stmmac_dma_cfg *dma_cfg);

static void dwmac_xuantie_dma_init(void __iomem *ioaddr,
				   struct stmmac_dma_cfg *dma_cfg)
{
	u32 value;

	xuantie_orig_dma_init(ioaddr, dma_cfg);

	/* XuanTie ACE (AXI Cache Encoding) initialization, same placement as
	 * the ali6000/xuantie baseline (dwxgmac2_dma_init).
	 */
	writel(0x30303, ioaddr + XUNATIE_TX_AR_ACE_CONTROL);
	writel(0x3030303, ioaddr + XUNATIE_RX_AW_ACE_CONTROL);
	writel(0x0303, ioaddr + XUNATIE_TXRX_AWAR_ACE_CONTROL);

	if (dma_cfg->multi_msi_en) {
		value = readl(ioaddr + XUNATIE_DMA_MODE);
		value &= ~XUNATIE_INTM_MASK;
		value |= XUNATIE_INTM_MODE1;
		writel(value, ioaddr + XUNATIE_DMA_MODE);
	}
}

static void dwmac_xuantie_hook_dma_init(struct pci_dev *pdev)
{
	struct net_device *ndev = pci_get_drvdata(pdev);
	struct stmmac_priv *priv = netdev_priv(ndev);
	static struct stmmac_dma_ops xuantie_dma_ops;

	xuantie_dma_ops = *priv->hw->dma;
	xuantie_orig_dma_init = xuantie_dma_ops.init;
	xuantie_dma_ops.init = dwmac_xuantie_dma_init;
	priv->hw->dma = &xuantie_dma_ops;
}

/**
 * stmmac_pci_probe
 *
 * @pdev: pci device pointer
 * @id: pointer to table of device id/id's.
 *
 * Description: This probing function gets called for all PCI devices which
 * match the ID table and are not "owned" by other driver yet. This function
 * gets passed a "struct pci_dev *" for each device whose entry in the ID table
 * matches the device. The probe functions returns zero when the driver choose
 * to take "ownership" of the device or an error code(-ve no) otherwise.
 */
static int stmmac_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	struct stmmac_pci_info *info =
		(struct stmmac_pci_info *)id->driver_data;
	struct plat_stmmacenet_data *plat;
	struct stmmac_resources res;
	struct net_device *ndev;
	struct stmmac_priv *priv;
	int i = 0;
	int node;
	const cpumask_t *mask;
	int cpu_local;
	int ret;

	plat = devm_kzalloc(&pdev->dev, sizeof(*plat), GFP_KERNEL);
	if (!plat)
		return -ENOMEM;

	plat->mdio_bus_data = devm_kzalloc(
		&pdev->dev, sizeof(*plat->mdio_bus_data), GFP_KERNEL);
	if (!plat->mdio_bus_data)
		return -ENOMEM;

	plat->dma_cfg =
		devm_kzalloc(&pdev->dev, sizeof(*plat->dma_cfg), GFP_KERNEL);
	if (!plat->dma_cfg)
		return -ENOMEM;

	plat->safety_feat_cfg = devm_kzalloc(
		&pdev->dev, sizeof(*plat->safety_feat_cfg), GFP_KERNEL);
	if (!plat->safety_feat_cfg)
		return -ENOMEM;

	/* Enable pci device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "%s: ERROR: failed to enable device\n",
			__func__);
		return ret;
	}

	/* Get the base address of device */
    ret = pcim_iomap_regions(pdev, BIT(0), pci_name(pdev));
    if (ret)
		return ret;

	pci_set_master(pdev);

    uint16_t cmd = 0x0;
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
	pci_write_config_word(pdev, PCI_COMMAND, cmd);
	wmb();

   /* Initialize all MSI vectors to invalid so that it can be set
	 * according to platform data settings below.
	 * Note: MSI vector takes value from 0 upto 31 (XUANTIE_STMMAC_MSI_VEC_MAX)
	 */
	plat->msi_mac_vec = XUANTIE_STMMAC_MSI_VEC_MAX;
	plat->msi_wol_vec = XUANTIE_STMMAC_MSI_VEC_MAX;
	plat->msi_sfty_ce_vec = XUANTIE_STMMAC_MSI_VEC_MAX;
	plat->msi_sfty_ue_vec = XUANTIE_STMMAC_MSI_VEC_MAX;
	plat->msi_rx_base_vec = XUANTIE_STMMAC_MSI_VEC_MAX;
	plat->msi_tx_base_vec = XUANTIE_STMMAC_MSI_VEC_MAX;

	ret = info->setup(pdev, plat);
	if (ret)
		return ret;

	memset(&res, 0, sizeof(res));
	res.addr = (void __iomem *)((uint64_t)pcim_iomap_table(pdev)[i] + 0x400f00000);
	res.irq = pdev->irq;

	plat->safety_feat_cfg->tsoee = 1;
	plat->safety_feat_cfg->mrxpee = 1;
	plat->safety_feat_cfg->mestee = 1;
	plat->safety_feat_cfg->mrxee = 1;
	plat->safety_feat_cfg->mtxee = 1;
	plat->safety_feat_cfg->epsi = 1;
	plat->safety_feat_cfg->edpp = 1;
	plat->safety_feat_cfg->prtyen = 1;
	plat->safety_feat_cfg->tmouten = 1;

	node = dev_to_node(&pdev->dev);
	mask = cpumask_of_node(node);
	cpu_local = cpumask_weight(mask);        // 本 NUMA 节点 CPU 数
	/* Set default number of RX and TX queues to use */
	plat->tx_queues_to_use = min(XUNATIE_STMMAC_MAX_RX_QUEUE, cpu_local);
	plat->rx_queues_to_use = min(XUNATIE_STMMAC_MAX_TX_QUEUE, cpu_local);

	ret = stmmac_config_multi_msi(pdev, plat, &res);
	if (ret) {
		ret = stmmac_config_single_msi(pdev, plat, &res);
		if (ret) {
			dev_err(&pdev->dev, "%s: ERROR: failed to enable IRQ\n",
				__func__);
			return ret;
		}
	}
	plat->flags |= STMMAC_FLAG_TSO_EN;
	plat->rss_en = 1;

	/* ACE (AXI Cache Encoding) is programmed from the DMA init hook
	 * (dwmac_xuantie_dma_init), matching the ali6000/xuantie baseline
	 * placement in dwxgmac2_dma_init: it is re-applied after every DMA
	 * soft reset (each open/reinit), which probe-time programming cannot
	 * guarantee.
	 */

	pci_write_config_word(pdev, PCI_COMMAND, cmd);
	wmb();

	ret = stmmac_dvr_probe(&pdev->dev, plat, &res);
	if (ret)
		return ret;

	/* The XGMAC core reports up to 16 queues via dma_cap, but the core
	 * stmmac per-queue arrays (dma_conf queues, plat queue cfg, IRQ and
	 * coalesce tables) are sized MTL_MAX_RX/TX_QUEUES. Clamp the reported
	 * capability so ethtool -L/-l never exceeds those arrays, otherwise
	 * stmmac_set_channels() would accept out-of-bounds queue counts.
	 */
	ndev = dev_get_drvdata(&pdev->dev);
	priv = netdev_priv(ndev);
	priv->dma_cap.number_rx_queues = min_t(unsigned int,
					       priv->dma_cap.number_rx_queues,
					       MTL_MAX_RX_QUEUES);
	priv->dma_cap.number_tx_queues = min_t(unsigned int,
					       priv->dma_cap.number_tx_queues,
					       MTL_MAX_TX_QUEUES);

	/* Hook the XuanTie INTM programming into the DMA init path */
	dwmac_xuantie_hook_dma_init(pdev);

	return 0;
}

/**
 * stmmac_pci_remove
 *
 * @pdev: platform device pointer
 * Description: this function calls the main to free the net resources
 * and releases the PCI resources.
 */
static void stmmac_pci_remove(struct pci_dev *pdev)
{
	int i;

	stmmac_dvr_remove(&pdev->dev);

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (pci_resource_len(pdev, i) == 0)
			continue;
		pcim_iounmap_regions(pdev, BIT(i));
		break;
	}
}

static int __maybe_unused stmmac_pci_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int ret;

	ret = stmmac_suspend(dev);
	if (ret)
		return ret;

	ret = pci_save_state(pdev);
	if (ret)
		return ret;

	pci_disable_device(pdev);
	pci_wake_from_d3(pdev, true);
	return 0;
}

static int __maybe_unused stmmac_pci_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int ret;

	pci_restore_state(pdev);
	pci_set_power_state(pdev, PCI_D0);

	ret = pci_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_master(pdev);

	return stmmac_resume(dev);
}

static SIMPLE_DEV_PM_OPS(stmmac_pm_ops, stmmac_pci_suspend, stmmac_pci_resume);

/* synthetic ID, no official vendor */
#define PCI_VENDOR_ID_STMMAC 0x1ded
#define PCI_DEVICE_ID_STMMAC_XLGMAC 0x1109
#define PCI_DEVICE_ID_STMMAC_XGMAC 0x110a

static const struct pci_device_id stmmac_id_table[] = {
	{ PCI_DEVICE_DATA(STMMAC, XLGMAC, &stmmac_xlgmac_pci_info) },
	{PCI_DEVICE_DATA(STMMAC, XGMAC, &stmmac_xgmac_pci_info)},
	{ }
};

MODULE_DEVICE_TABLE(pci, stmmac_id_table);

static struct pci_driver stmmac_pci_driver = {
	.name = STMMAC_RESOURCE_NAME,
	.id_table = stmmac_id_table,
	.probe = stmmac_pci_probe,
	.remove = stmmac_pci_remove,
	.driver         = {
		.pm     = &stmmac_pm_ops,
	},
};

module_pci_driver(stmmac_pci_driver);


MODULE_AUTHOR("Alibaba Group Holding Limited");
MODULE_DESCRIPTION("Xuantie STMMAC 10/100/1000 Ethernet PCI driver");
MODULE_LICENSE("GPL v2");
