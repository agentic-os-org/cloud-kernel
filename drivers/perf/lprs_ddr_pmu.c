// SPDX-License-Identifier: GPL-2.0-only
/*
 * DDR Sub-system PMU Events Monitoring Support
 *
 * Copyright (C) 2025 Leaprise Corporation or its affiliates.
 */

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#define LPRS_DDR_PMU_MAX_COUNTERS 16
#define LPRS_DDR_PMU_MAX_CHB_EVENTS 0x40
#define LPRS_DDR_PMU_MAX_DDRC_EVENTS 0x44

#define LPRS_DDR_PMU_PA_SHIFT 24
#define LPRS_DDR_PMU_CNT_INIT 0

#define LPRS_DDR_PMU_CHB_DOMAIN_OFFSET 0x0
#define LPRS_DDR_PMU_DDRC_DOMAIN_OFFSET 0x400

#define LPRS_DDR_PMU_REG_CFG0 0x04
#define LPRS_DDR_PMU_CNT_CLEAR_MASK GENMASK(31, 16)
#define LPRS_DDR_PMU_CNT_ENABLE_MASK GENMASK(15, 0)

#define LPRS_DDR_PMU_CNT_CLEAR_BIT(n) BIT((n) + 16)
#define LPRS_DDR_PMU_CNT_ENABLE_BIT(n) BIT(n)
#define LPRS_DDR_PMU_CNT_DISABLE_BIT(n) (~BIT(n))

#define LPRS_DDR_PMU_REG_CFG1 0x08
#define LPRS_DDR_PMU_EVENT_CFG1_DCH_SEL GENMASK(13, 13)
#define LPRS_DDR_PMU_EVENT_CFG1_ID GENMASK(12, 6)
#define LPRS_DDR_PMU_EVENT_CFG1_CNT_ID GENMASK(5, 2)
#define LPRS_DDR_PMU_EVENT_CFG1_BOUND_EN GENMASK(0, 0)

#define LPRS_DDR_PMU_REG_CNT_L(x) (0x0C + ((x) * 0x08))
#define LPRS_DDR_PMU_REG_CNT_H(x) (0x10 + ((x) * 0x08))

#define LPRS_DDR_PMU_REG_CYCLE_L 0x8C
#define LPRS_DDR_PMU_REG_CYCLE_H 0x90

/* fixed cycle event */
#define LPRS_DDR_PMU_FIXED_EVT_ID_CHB_CYCLE 0x200
#define LPRS_DDR_PMU_FIXED_EVT_ID_DDRC_CYCLE 0x300

#define LPRS_DDR_PMU_EVENT_DCH0 0
#define LPRS_DDR_PMU_EVENT_DCH1 1
#define LPRS_DDR_PMU_EVENT_DOMAIN_CHB 0
#define LPRS_DDR_PMU_EVENT_DOMAIN_DDRC 1
#define LPRS_DDR_PMU_EVENT_TYPE_GENERAL 0
#define LPRS_DDR_PMU_EVENT_TYPE_FIXED 1

#define LPRS_DDR_PMU_EVENT_CONFIG_MASK GENMASK(9, 0)
#define LPRS_DDR_PMU_EVENT_ID_MASK GENMASK(6, 0)

#define LPRS_DDR_PMU_EVENT_DCH_SHIFT 7
#define LPRS_DDR_PMU_EVENT_DOMAIN_SHIFT 8
#define LPRS_DDR_PMU_EVENT_TYPE_SHIFT 9

#define LPRS_DDR_PMU_EVENT_DCH_MASK BIT(LPRS_DDR_PMU_EVENT_DCH_SHIFT)
#define LPRS_DDR_PMU_EVENT_DOMAIN_MASK BIT(LPRS_DDR_PMU_EVENT_DOMAIN_SHIFT)
#define LPRS_DDR_PMU_EVENT_TYPE_MASK BIT(LPRS_DDR_PMU_EVENT_TYPE_SHIFT)

#define LPRS_DDR_PMU_GET_EVENT_CONFIG(event) \
	FIELD_GET(LPRS_DDR_PMU_EVENT_CONFIG_MASK, (event)->attr.config)

#define LPRS_DDR_PMU_GET_EVENT_ID(event) \
	FIELD_GET(LPRS_DDR_PMU_EVENT_ID_MASK, (event)->attr.config)

#define LPRS_DDR_PMU_GET_EVENT_DCH(event) \
	FIELD_GET(LPRS_DDR_PMU_EVENT_DCH_MASK, (event)->attr.config)

#define LPRS_DDR_PMU_GET_EVENT_DOMAIN(event) \
	FIELD_GET(LPRS_DDR_PMU_EVENT_DOMAIN_MASK, (event)->attr.config)

#define LPRS_DDR_PMU_GET_EVENT_TYPE(event) \
	FIELD_GET(LPRS_DDR_PMU_EVENT_TYPE_MASK, (event)->attr.config)

#define LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event)     \
	((LPRS_DDR_PMU_GET_EVENT_DOMAIN(event) == \
	  LPRS_DDR_PMU_EVENT_DOMAIN_CHB) ?        \
		 LPRS_DDR_PMU_CHB_DOMAIN_OFFSET : \
		 LPRS_DDR_PMU_DDRC_DOMAIN_OFFSET)

#define LPRS_DDR_PMU_GET_PMU_DOMAIN(event, pmu)   \
	((LPRS_DDR_PMU_GET_EVENT_DOMAIN(event) == \
	  LPRS_DDR_PMU_EVENT_DOMAIN_CHB) ?        \
		 &(pmu)->chb :                    \
		 &(pmu)->ddrc)

#define to_lprs_ddr_pmu(p) (container_of(p, struct lprs_ddr_pmu, pmu))

static int lprs_ddr_pmu_cpuhp_state_num;

static const struct acpi_device_id lprs_ddr_acpi_match[] = {
	{
		"LPRS0001",
	},
	{},
};
MODULE_DEVICE_TABLE(acpi, lprs_ddr_acpi_match);

struct lprs_ddr_pmu_domain {
	int num_counters;
	unsigned long *used_mask;
};

struct lprs_ddr_pmu {
	void __iomem *cfg_base;
	struct device *dev;
	struct pmu pmu;
	int cpu;

	struct lprs_ddr_pmu_domain ddrc;
	struct lprs_ddr_pmu_domain chb;
	struct hlist_node node;
};

static ssize_t lprs_ddr_pmu_event_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *ext =
		container_of(attr, struct dev_ext_attribute, attr);
	return sysfs_emit(buf, "config=0x%llx\n", (u64)ext->var);
}

static ssize_t lprs_ddr_pmu_cpumask_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(ddr_pmu->cpu));
}

static ssize_t lprs_ddr_pmu_format_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct dev_ext_attribute *ext =
		container_of(attr, struct dev_ext_attribute, attr);
	return sysfs_emit(buf, "%s\n", (char *)ext->var);
}

#define LPRS_DDR_PMU_ATTR(_name, _show_func, _config)    \
	(&((struct dev_ext_attribute[]){                 \
		{ __ATTR(_name, 0444, _show_func, NULL), \
		  (void *)(_config) } })[0]              \
		  .attr.attr)

#define LPRS_DDR_PMU_FORMAT_ATTR(_name, _config) \
	LPRS_DDR_PMU_ATTR(_name, lprs_ddr_pmu_format_show, (void *)(_config))

#define LPRS_DDR_PMU_EVENT_ATTR(_name, _config)           \
	LPRS_DDR_PMU_ATTR(_name, lprs_ddr_pmu_event_show, \
			  (unsigned long)(_config))

#define LPRS_DDR_PMU_EVENT_DCH0_SHIFTED \
	((LPRS_DDR_PMU_EVENT_DCH0) << (LPRS_DDR_PMU_EVENT_DCH_SHIFT))
#define LPRS_DDR_PMU_EVENT_DCH1_SHIFTED \
	((LPRS_DDR_PMU_EVENT_DCH1) << (LPRS_DDR_PMU_EVENT_DCH_SHIFT))
#define LPRS_DDR_PMU_EVENT_DOMAIN_CHB_SHIFTED \
	((LPRS_DDR_PMU_EVENT_DOMAIN_CHB) << (LPRS_DDR_PMU_EVENT_DOMAIN_SHIFT))
#define LPRS_DDR_PMU_EVENT_DOMAIN_DDRC_SHIFTED \
	((LPRS_DDR_PMU_EVENT_DOMAIN_DDRC) << (LPRS_DDR_PMU_EVENT_DOMAIN_SHIFT))

#define LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(prefix, cfg)                        \
	(LPRS_DDR_PMU_EVENT_ATTR(ddrc_##prefix##_sub0,                     \
				 ((cfg) |                                  \
				  LPRS_DDR_PMU_EVENT_DOMAIN_DDRC_SHIFTED | \
				  LPRS_DDR_PMU_EVENT_DCH0_SHIFTED)))

#define LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(prefix, cfg)                        \
	(LPRS_DDR_PMU_EVENT_ATTR(ddrc_##prefix##_sub1,                     \
				 ((cfg) |                                  \
				  LPRS_DDR_PMU_EVENT_DOMAIN_DDRC_SHIFTED | \
				  LPRS_DDR_PMU_EVENT_DCH1_SHIFTED)))

#define LPRS_DDR_PMU_GEN_FIXED_EVENT(prefix, cfg) \
	LPRS_DDR_PMU_EVENT_ATTR(fixed_##prefix, (cfg))

static struct attribute *lprs_ddr_pmu_events_attrs[] = {
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rd_or_wr_ps0, 0),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rd_or_wr_ps1, 1),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_wr_ps0, 2),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_wr_ps1, 3),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rd_ps0, 4),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rd_ps1, 5),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rmw_ps0, 6),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(in_rmw_ps1, 7),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(activate_ps0, 17),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(activate_ps1, 18),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rd_or_wr_ps0, 19),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rd_or_wr_ps1, 20),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(rd_activate_ps0, 21),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(rd_activate_ps1, 22),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rd_ps0, 23),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rd_ps1, 24),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_wr_ps0, 25),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_wr_ps1, 26),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rmw_ps0, 27),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(out_rmw_ps1, 28),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(precharge_ps0, 29),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(precharge_ps1, 30),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(rdwr_trans, 35),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(wcomb_ps0, 36),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(wcomb_ps1, 37),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(war, 38),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(raw, 39),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(waw, 40),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(ref_ps0, 53),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_0(ref_ps1, 54),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rd_or_wr_ps0, 0),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rd_or_wr_ps1, 1),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_wr_ps0, 2),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_wr_ps1, 3),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rd_ps0, 4),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rd_ps1, 5),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rmw_ps0, 6),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(in_rmw_ps1, 7),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(activate_ps0, 17),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(activate_ps1, 18),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rd_or_wr_ps0, 19),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rd_or_wr_ps1, 20),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(rd_activate_ps0, 21),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(rd_activate_ps1, 22),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rd_ps0, 23),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rd_ps1, 24),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_wr_ps0, 25),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_wr_ps1, 26),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rmw_ps0, 27),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(out_rmw_ps1, 28),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(precharge_ps0, 29),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(precharge_ps1, 30),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(rdwr_trans, 35),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(wcomb_ps0, 36),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(wcomb_ps1, 37),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(war, 38),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(raw, 39),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(waw, 40),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(ref_ps0, 53),
	LPRS_DDR_PMU_GEN_DDRC_EVENTS_1(ref_ps1, 54),
	LPRS_DDR_PMU_GEN_FIXED_EVENT(chb_cycle,
				     LPRS_DDR_PMU_FIXED_EVT_ID_CHB_CYCLE),
	LPRS_DDR_PMU_GEN_FIXED_EVENT(ddrc_cycle,
				     LPRS_DDR_PMU_FIXED_EVT_ID_DDRC_CYCLE),
	NULL,
};

static const struct attribute_group lprs_ddr_pmu_events_attr_group = {
	.name = "events",
	.attrs = lprs_ddr_pmu_events_attrs,
};

static struct device_attribute lprs_ddr_pmu_cpumask_attr =
	__ATTR(cpumask, 0444, lprs_ddr_pmu_cpumask_show, NULL);

static struct attribute *lprs_ddr_pmu_cpumask_attrs[] = {
	&lprs_ddr_pmu_cpumask_attr.attr,
	NULL,
};

static const struct attribute_group lprs_ddr_pmu_cpumask_attr_group = {
	.attrs = lprs_ddr_pmu_cpumask_attrs,
};

static struct attribute *lprs_ddr_pmu_format_attrs[] = {
	LPRS_DDR_PMU_FORMAT_ATTR(event, "config:0-6"),
	LPRS_DDR_PMU_FORMAT_ATTR(dch, "config:7"),
	LPRS_DDR_PMU_FORMAT_ATTR(domain, "config:8"),
	LPRS_DDR_PMU_FORMAT_ATTR(type, "config:9"),
	NULL,
};

static const struct attribute_group lprs_ddr_pmu_format_group = {
	.name = "format",
	.attrs = lprs_ddr_pmu_format_attrs,
};

static const struct attribute_group *lprs_ddr_pmu_attr_groups[] = {
	&lprs_ddr_pmu_events_attr_group,
	&lprs_ddr_pmu_cpumask_attr_group,
	&lprs_ddr_pmu_format_group,
	NULL,
};

static bool lprs_ddr_pmu_is_support_event(struct perf_event *event)
{
	u32 id = LPRS_DDR_PMU_GET_EVENT_ID(event);
	u32 domain = LPRS_DDR_PMU_GET_EVENT_DOMAIN(event);

	switch (domain) {
	case LPRS_DDR_PMU_EVENT_DOMAIN_CHB:
		return id <= LPRS_DDR_PMU_MAX_CHB_EVENTS;
	case LPRS_DDR_PMU_EVENT_DOMAIN_DDRC:
		return id <= LPRS_DDR_PMU_MAX_DDRC_EVENTS;
	default:
		return false;
	}
}

static int lprs_ddr_pmu_get_event_idx(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct lprs_ddr_pmu_domain *domain;
	int idx;

	domain = LPRS_DDR_PMU_GET_PMU_DOMAIN(event, ddr_pmu);
	for (idx = 0; idx < domain->num_counters; ++idx) {
		if (!test_and_set_bit(idx, domain->used_mask))
			return idx;
	}

	return -EBUSY;
}

static int lprs_ddr_pmu_event_init(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (is_sampling_event(event))
		return -EOPNOTSUPP;

	event->cpu = ddr_pmu->cpu;
	if (event->cpu < 0 || event->attach_state & PERF_ATTACH_TASK)
		return -EOPNOTSUPP;

	if (!lprs_ddr_pmu_is_support_event(event))
		return -EOPNOTSUPP;

	hwc->idx = -1;

	return 0;
}

static void lprs_ddr_pmu_bind_counter(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 cfg = LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) + LPRS_DDR_PMU_REG_CFG1;
	u32 val = 0;

	val = FIELD_PREP(LPRS_DDR_PMU_EVENT_CFG1_BOUND_EN, 1) |
	      FIELD_PREP(LPRS_DDR_PMU_EVENT_CFG1_CNT_ID, hwc->idx) |
	      FIELD_PREP(LPRS_DDR_PMU_EVENT_CFG1_ID,
			 LPRS_DDR_PMU_GET_EVENT_ID(event)) |
	      FIELD_PREP(LPRS_DDR_PMU_EVENT_CFG1_DCH_SEL,
			 LPRS_DDR_PMU_GET_EVENT_DCH(event));
	writel(val, ddr_pmu->cfg_base + cfg);
}

static void lprs_ddr_pmu_enable_counter(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 reg, val;

	reg = LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) + LPRS_DDR_PMU_REG_CFG0;
	val = readl(ddr_pmu->cfg_base + reg);
	val |= LPRS_DDR_PMU_CNT_ENABLE_BIT(hwc->idx);
	val |= LPRS_DDR_PMU_CNT_CLEAR_BIT(hwc->idx);
	writel(val, ddr_pmu->cfg_base + reg);
}

static void lprs_ddr_pmu_disable_counter(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 reg, val;

	reg = LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) + LPRS_DDR_PMU_REG_CFG0;
	val = readl(ddr_pmu->cfg_base + reg);

	val &= LPRS_DDR_PMU_CNT_DISABLE_BIT(hwc->idx);
	writel(val, ddr_pmu->cfg_base + reg);
}

static u64 lprs_ddr_pmu_read_counter(struct perf_event *event)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u64 cycle_high, cycle_low, high2;

	if (LPRS_DDR_PMU_GET_EVENT_TYPE(event) ==
	    LPRS_DDR_PMU_EVENT_TYPE_FIXED) {
		do {
			cycle_high =
				readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CYCLE_H);
			cycle_low =
				readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CYCLE_L);
			high2 = readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CYCLE_H);
		} while (cycle_high != high2);
	} else {
		do {
			cycle_high =
				readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CNT_H(hwc->idx));
			cycle_low =
				readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CNT_L(hwc->idx));
			high2 = readl(ddr_pmu->cfg_base +
				      LPRS_DDR_PMU_GET_DOMAIN_OFFSET(event) +
				      LPRS_DDR_PMU_REG_CNT_H(hwc->idx));
		} while (cycle_high != high2);
	}

	return (u64)(cycle_high << 32 | cycle_low);
}

static void lprs_ddr_pmu_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 delta, prev, now;

	do {
		prev = local64_read(&hwc->prev_count);
		now = lprs_ddr_pmu_read_counter(event);
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	delta = now - prev;
	local64_add(delta, &event->count);
}

static void lprs_ddr_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 pre_val;

	hwc->state = 0;

	if (LPRS_DDR_PMU_GET_EVENT_TYPE(event) ==
	    LPRS_DDR_PMU_EVENT_TYPE_FIXED) {
		pre_val = lprs_ddr_pmu_read_counter(event);
		local64_set(&hwc->prev_count, pre_val);
		return;
	}

	pre_val = LPRS_DDR_PMU_CNT_INIT;
	local64_set(&hwc->prev_count, pre_val);

	lprs_ddr_pmu_bind_counter(event);
	lprs_ddr_pmu_enable_counter(event);
}

static int lprs_ddr_pmu_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = -1;

	if (LPRS_DDR_PMU_EVENT_TYPE_GENERAL ==
	    LPRS_DDR_PMU_GET_EVENT_TYPE(event)) {
		idx = lprs_ddr_pmu_get_event_idx(event);
		if (idx < 0)
			return idx;
	}

	hwc->idx = idx;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	if (flags & PERF_EF_START)
		lprs_ddr_pmu_start(event, PERF_EF_RELOAD);

	perf_event_update_userpage(event);

	return 0;
}

static void lprs_ddr_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	if (LPRS_DDR_PMU_EVENT_TYPE_GENERAL ==
	    LPRS_DDR_PMU_GET_EVENT_TYPE(event)) {
		lprs_ddr_pmu_disable_counter(event);
	}

	lprs_ddr_pmu_event_update(event);
	hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static void lprs_ddr_pmu_del(struct perf_event *event, int flags)
{
	struct lprs_ddr_pmu *ddr_pmu = to_lprs_ddr_pmu(event->pmu);
	struct lprs_ddr_pmu_domain *domain;
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;

	lprs_ddr_pmu_stop(event, PERF_EF_UPDATE);

	domain = LPRS_DDR_PMU_GET_PMU_DOMAIN(event, ddr_pmu);
	if (idx >= 0 && idx < domain->num_counters) {
		clear_bit(idx, domain->used_mask);
		hwc->idx = -1;
	}
	perf_event_update_userpage(event);
}

static void lprs_ddr_pmu_read(struct perf_event *event)
{
	lprs_ddr_pmu_event_update(event);
}

static int lprs_ddr_pmu_domain_init(struct lprs_ddr_pmu_domain *domain,
				    struct device *dev, int num_counters)
{
	if (!domain || !dev || num_counters <= 0 ||
	    num_counters > LPRS_DDR_PMU_MAX_COUNTERS)
		return -EINVAL;

	domain->num_counters = num_counters;

	domain->used_mask = devm_bitmap_zalloc(dev, num_counters, GFP_KERNEL);
	if (!domain->used_mask)
		return -ENOMEM;

	return 0;
}

static int lprs_ddr_pmu_probe(struct platform_device *pdev)
{
	struct lprs_ddr_pmu *ddr_pmu;
	struct resource *res;
	char *name;
	int ret;

	ddr_pmu = devm_kzalloc(&pdev->dev, sizeof(*ddr_pmu), GFP_KERNEL);
	if (!ddr_pmu)
		return -ENOMEM;

	ddr_pmu->dev = &pdev->dev;

	platform_set_drvdata(pdev, ddr_pmu);

	ddr_pmu->cfg_base =
		devm_platform_get_and_ioremap_resource(pdev, 0, &res);

	if (IS_ERR(ddr_pmu->cfg_base))
		return PTR_ERR(ddr_pmu->cfg_base);

	name = devm_kasprintf(ddr_pmu->dev, GFP_KERNEL, "lprs_ddr_%llx",
			      (u64)(res->start >> LPRS_DDR_PMU_PA_SHIFT));

	if (!name)
		return -ENOMEM;

	ddr_pmu->cpu = raw_smp_processor_id();

	ret = lprs_ddr_pmu_domain_init(&ddr_pmu->ddrc, ddr_pmu->dev,
				       LPRS_DDR_PMU_MAX_COUNTERS);
	if (ret)
		return ret;

	ret = lprs_ddr_pmu_domain_init(&ddr_pmu->chb, ddr_pmu->dev,
				       LPRS_DDR_PMU_MAX_COUNTERS);
	if (ret)
		return ret;

	writel(LPRS_DDR_PMU_CNT_CLEAR_MASK,
	       ddr_pmu->cfg_base + LPRS_DDR_PMU_CHB_DOMAIN_OFFSET +
		       LPRS_DDR_PMU_REG_CFG0);

	writel(LPRS_DDR_PMU_CNT_CLEAR_MASK,
	       ddr_pmu->cfg_base + LPRS_DDR_PMU_DDRC_DOMAIN_OFFSET +
		       LPRS_DDR_PMU_REG_CFG0);

	ddr_pmu->pmu = (struct pmu){
		.module = THIS_MODULE,
		.parent = &pdev->dev,
		.task_ctx_nr = perf_invalid_context,
		.event_init = lprs_ddr_pmu_event_init,
		.add = lprs_ddr_pmu_add,
		.del = lprs_ddr_pmu_del,
		.start = lprs_ddr_pmu_start,
		.stop = lprs_ddr_pmu_stop,
		.read = lprs_ddr_pmu_read,
		.attr_groups = lprs_ddr_pmu_attr_groups,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
	};

	ret = perf_pmu_register(&ddr_pmu->pmu, name, -1);
	if (ret)
		dev_err(ddr_pmu->dev, "LPRS DDR PMU register failed!\n");
	else {
		ret = cpuhp_state_add_instance_nocalls(
			lprs_ddr_pmu_cpuhp_state_num, &ddr_pmu->node);
		if (ret) {
			dev_err(ddr_pmu->dev,
				"LPRS DDR PMU hotplug register failed!\n");
			perf_pmu_unregister(&ddr_pmu->pmu);
			return ret;
		}
	}

	return ret;
}

static int lprs_ddr_pmu_remove(struct platform_device *pdev)
{
	struct lprs_ddr_pmu *ddr_pmu = platform_get_drvdata(pdev);

	cpuhp_state_remove_instance_nocalls(lprs_ddr_pmu_cpuhp_state_num,
					    &ddr_pmu->node);

	perf_pmu_unregister(&ddr_pmu->pmu);
	return 0;
}

static struct platform_driver lprs_ddr_pmu_driver = {
	.driver = {
		.name = "lprs_ddr_pmu",
		   .acpi_match_table = lprs_ddr_acpi_match,
		   },
	.probe = lprs_ddr_pmu_probe,
	.remove = lprs_ddr_pmu_remove,
};

static int lprs_ddr_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct lprs_ddr_pmu *pmu =
		hlist_entry_safe(node, struct lprs_ddr_pmu, node);
	unsigned int target;

	if (cpu != pmu->cpu)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&pmu->pmu, cpu, target);

	pmu->cpu = target;
	return 0;
}

static int __init lprs_ddr_pmu_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
				      "lprs_ddr_pmu:online", NULL,
				      lprs_ddr_pmu_offline_cpu);

	if (ret < 0) {
		pr_err("LPRS DDR PMU: setup hotplug failed, ret = %d\n", ret);
		return ret;
	}
	lprs_ddr_pmu_cpuhp_state_num = ret;

	ret = platform_driver_register(&lprs_ddr_pmu_driver);
	if (ret)
		cpuhp_remove_multi_state(lprs_ddr_pmu_cpuhp_state_num);

	return ret;
}
module_init(lprs_ddr_pmu_init);

static void __exit lprs_ddr_pmu_exit(void)
{
	platform_driver_unregister(&lprs_ddr_pmu_driver);
	cpuhp_remove_multi_state(lprs_ddr_pmu_cpuhp_state_num);
}
module_exit(lprs_ddr_pmu_exit);

MODULE_AUTHOR("Wenjia Guo");
MODULE_AUTHOR("Yong Ma");
MODULE_AUTHOR("Jie Feng");
MODULE_DESCRIPTION("LPRS DDR PMU driver");
MODULE_LICENSE("GPL");
