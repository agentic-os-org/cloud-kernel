/*
 * arch/arm64/kernel/topology.c
 *
 * Copyright (C) 2011,2013,2014 Linaro Limited.
 *
 * Based on the arm32 version written by Vincent Guittot in turn based on
 * arch/sh/kernel/topology.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/acpi.h>
#include <linux/arch_topology.h>
#include <linux/cacheinfo.h>
#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/percpu.h>

#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/topology.h>
#include <asm/arch_timer.h>

void store_cpu_topology(unsigned int cpuid)
{
	struct cpu_topology *cpuid_topo = &cpu_topology[cpuid];
	u64 mpidr;

	if (cpuid_topo->package_id != -1)
		goto topology_populated;

	mpidr = read_cpuid_mpidr();

	/* Uniprocessor systems can rely on default topology values */
	if (mpidr & MPIDR_UP_BITMASK)
		return;

	/*
	 * This would be the place to create cpu topology based on MPIDR.
	 *
	 * However, it cannot be trusted to depict the actual topology; some
	 * pieces of the architecture enforce an artificial cap on Aff0 values
	 * (e.g. GICv3's ICC_SGI1R_EL1 limits it to 15), leading to an
	 * artificial cycling of Aff1, Aff2 and Aff3 values. IOW, these end up
	 * having absolutely no relationship to the actual underlying system
	 * topology, and cannot be reasonably used as core / package ID.
	 *
	 * If the MT bit is set, Aff0 *could* be used to define a thread ID, but
	 * we still wouldn't be able to obtain a sane core ID. This means we
	 * need to entirely ignore MPIDR for any topology deduction.
	 */
	cpuid_topo->thread_id  = -1;
	cpuid_topo->core_id    = cpuid;
	cpuid_topo->package_id = cpu_to_node(cpuid);

	pr_debug("CPU%u: cluster %d core %d thread %d mpidr %#016llx\n",
		 cpuid, cpuid_topo->package_id, cpuid_topo->core_id,
		 cpuid_topo->thread_id, mpidr);

topology_populated:
	update_siblings_masks(cpuid);
}

#ifdef CONFIG_ACPI
static bool __init acpi_cpu_is_threaded(int cpu)
{
	int is_threaded = acpi_pptt_cpu_is_thread(cpu);

	/*
	 * if the PPTT doesn't have thread information, assume a homogeneous
	 * machine and return the current CPU's thread state.
	 */
	if (is_threaded < 0)
		is_threaded = read_cpuid_mpidr() & MPIDR_MT_BITMASK;

	return !!is_threaded;
}

/*
 * Propagate the topology information of the processor_topology_node tree to the
 * cpu_topology array.
 */
int __init parse_acpi_topology(void)
{
	int cpu, topology_id;

	if (acpi_disabled)
		return 0;

	for_each_possible_cpu(cpu) {
		int i, cache_id;

		topology_id = find_acpi_cpu_topology(cpu, 0);
		if (topology_id < 0)
			return topology_id;

		if (acpi_cpu_is_threaded(cpu)) {
			cpu_topology[cpu].thread_id = topology_id;
			topology_id = find_acpi_cpu_topology(cpu, 1);
			cpu_topology[cpu].core_id   = topology_id;
		} else {
			cpu_topology[cpu].thread_id  = -1;
			cpu_topology[cpu].core_id    = topology_id;
		}
		topology_id = find_acpi_cpu_topology_cluster(cpu);
		cpu_topology[cpu].cluster_id = topology_id;
		topology_id = find_acpi_cpu_topology_package(cpu);
		cpu_topology[cpu].package_id = topology_id;

		i = acpi_find_last_cache_level(cpu);

		if (i > 0) {
			/*
			 * this is the only part of cpu_topology that has
			 * a direct relationship with the cache topology
			 */
			cache_id = find_acpi_cpu_cache_topology(cpu, i);
			if (cache_id > 0)
				cpu_topology[cpu].llc_id = cache_id;
		}
	}

	return 0;
}

static int cpu_die_map[NR_CPUS] __initdata = {[0 ... (NR_CPUS - 1)] = -1};

static int __init cpu_topology_die_map(void)
{
	int cpu, iter, die_id;

	acpi_cpu_die_init(cpu_die_map);
	for_each_possible_cpu(cpu) {
		die_id = cpu_die_map[cpu];
		cpu_topology[cpu].die_id = die_id;
		cpumask_set_cpu(cpu, &cpu_topology[cpu].die_cpus);
		if (die_id < 0)
			continue;
		for (iter = 0; iter < cpu; iter++) {
			if (cpu_topology[iter].die_id != die_id)
				continue;
			cpumask_set_cpu(cpu, &cpu_topology[iter].die_cpus);
			cpumask_set_cpu(iter, &cpu_topology[cpu].die_cpus);
		}
	}
	return 0;
}

late_initcall(cpu_topology_die_map);
#endif

static unsigned int cpufreq_khz;

struct arch_cpufreq_sample {
	unsigned int khz;
	ktime_t time;
};

static DEFINE_PER_CPU(struct arch_cpufreq_sample, samples);

static s64 arch_cpufreq_snapshot_ms = LLONG_MAX;

static int __init parse_cpufreq_snapshot_ms(char *str)
{
	int ret;
	s64 threshold_ms;

	if (!str)
		return -EINVAL;

	ret = kstrtos64(str, 10, &threshold_ms);
	if (ret)
		return ret;
	arch_cpufreq_snapshot_ms = threshold_ms;

	return 0;
}
early_param("cpufreq_snapshot_ms", parse_cpufreq_snapshot_ms);

static void arch_cpufreq_snapshot_cpu(int cpu, ktime_t now)
{
	s64 time_delta = ktime_ms_delta(now, per_cpu(samples.time, cpu));
	struct arch_cpufreq_sample *s;

	s = per_cpu_ptr(&samples, cpu);

	/* Don't bother re-computing within the cache threshold time. */
	if (s->khz && time_delta < arch_cpufreq_snapshot_ms)
		return;

	s->khz = cpufreq_get(cpu);
	if (s->khz)
		s->time = ktime_get();
}

unsigned int arch_cpufreq_get_khz(int cpu)
{
	unsigned int new_cpufreq;

	arch_cpufreq_snapshot_cpu(cpu, ktime_get());

	new_cpufreq = per_cpu(samples.khz, cpu);

	/*
	 * If the cpufreq driver can provide a value, use it.
	 * Otherwise use the cpufreq_khz.
	 */
	return new_cpufreq ? new_cpufreq : cpufreq_khz;
}

#ifdef CONFIG_ARM64_AMU_EXTN

#undef pr_fmt
#define pr_fmt(fmt) "AMU: " fmt
#define ARCH_FREQ_THRESHOLD_MS	10

static DEFINE_PER_CPU_READ_MOSTLY(unsigned long, arch_max_freq_scale);
static DEFINE_PER_CPU(u64, arch_const_cycles_prev);
static DEFINE_PER_CPU(u64, arch_core_cycles_prev);
static cpumask_var_t amu_fie_cpus;

/*
 * Sample cpu freq.
 *
 * The register SYS_AMEVCNTR0_EL0(1) increases at the fixed
 * rate of arch_timer_get_cntfrq() and can be used as timekeeper.
 * While The register SYS_AMEVCNTR0_EL0(0) counte the cpu
 * cycle elapsed. With the two registers, we can sample cpu
 * freq:
 *   delta(cycle) / delta(timekeeper)
 *
 * But these registers are halted by wfe/wfi and can't
 * in/out of the idle state synchronously, which is different
 * from x86 MSR_IA32_APERF/MSR_IA32_MPERF.
 *
 * NOTE:
 * ALL core use same freq by default(ignore big.LITTLE)
 */
static void __init __arch_cpufreq_init(void *dummy)
{
	unsigned long flags;
	u64 stable_cnt;
	u64 nonstable_cnt;
	u32 freq = arch_timer_get_cntfrq();
	u64 delta = freq / 1000 * ARCH_FREQ_THRESHOLD_MS;
	u64 counter;

	local_irq_save(flags);
	counter = stable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(1));
	nonstable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(0));
	local_irq_restore(flags);

	/*
	 * Meaningless operations & keep cpu out of
	 * wfe/wfi idle state.
	 *
	 * While sampling core freq, detecting time taking
	 * may be more than 10 miliseconds by default.
	 * REFER to: intel x86 APERFMPERF_CACHE_THRESHOLD_MS
	 */
	while (counter - stable_cnt < delta)
		counter = read_sysreg_s(SYS_AMEVCNTR0_EL0(1));

	local_irq_save(flags);
	stable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(1)) - stable_cnt;
	nonstable_cnt = read_sysreg_s(SYS_AMEVCNTR0_EL0(0)) - nonstable_cnt;
	local_irq_restore(flags);

	cpufreq_khz = div64_u64(freq * nonstable_cnt, stable_cnt) / 1000;
}

static int __init arch_cpufreq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (cpu_has_amu_feat(cpu)) {
			smp_call_function_single(cpu, __arch_cpufreq_init, NULL, 1);
			return 0;
		}
	}
	return 0;
}

late_initcall(arch_cpufreq_init);

/* Initialize counter reference per-cpu variables for the current CPU */
void init_cpu_freq_invariance_counters(void)
{
	this_cpu_write(arch_core_cycles_prev,
		       read_sysreg_s(SYS_AMEVCNTR0_CORE_EL0));
	this_cpu_write(arch_const_cycles_prev,
		       read_sysreg_s(SYS_AMEVCNTR0_CONST_EL0));
}

static int validate_cpu_freq_invariance_counters(int cpu)
{
	u64 max_freq_hz, ratio;

	if (!cpu_has_amu_feat(cpu)) {
		pr_debug("CPU%d: counters are not supported.\n", cpu);
		return -EINVAL;
	}

	if (unlikely(!per_cpu(arch_const_cycles_prev, cpu) ||
		     !per_cpu(arch_core_cycles_prev, cpu))) {
		pr_debug("CPU%d: cycle counters are not enabled.\n", cpu);
		return -EINVAL;
	}

	/* Convert maximum frequency from KHz to Hz and validate */
	max_freq_hz = cpufreq_get_hw_max_freq(cpu) * 1000;
	if (unlikely(!max_freq_hz)) {
		pr_debug("CPU%d: invalid maximum frequency.\n", cpu);
		return -EINVAL;
	}

	/*
	 * Pre-compute the fixed ratio between the frequency of the constant
	 * counter and the maximum frequency of the CPU.
	 *
	 *			      const_freq
	 * arch_max_freq_scale =   ---------------- * SCHED_CAPACITY_SCALE²
	 *			   cpuinfo_max_freq
	 *
	 * We use a factor of 2 * SCHED_CAPACITY_SHIFT -> SCHED_CAPACITY_SCALE²
	 * in order to ensure a good resolution for arch_max_freq_scale for
	 * very low arch timer frequencies (down to the KHz range which should
	 * be unlikely).
	 */
	ratio = (u64)arch_timer_get_rate() << (2 * SCHED_CAPACITY_SHIFT);
	ratio = div64_u64(ratio, max_freq_hz);
	if (!ratio) {
		WARN_ONCE(1, "System timer frequency too low.\n");
		return -EINVAL;
	}

	per_cpu(arch_max_freq_scale, cpu) = (unsigned long)ratio;

	return 0;
}

static inline bool
enable_policy_freq_counters(int cpu, cpumask_var_t valid_cpus)
{
	struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);

	if (!policy) {
		pr_debug("CPU%d: No cpufreq policy found.\n", cpu);
		return false;
	}

	if (cpumask_subset(policy->related_cpus, valid_cpus))
		cpumask_or(amu_fie_cpus, policy->related_cpus,
			   amu_fie_cpus);

	cpufreq_cpu_put(policy);

	return true;
}

static DEFINE_STATIC_KEY_FALSE(amu_fie_key);
#define amu_freq_invariant() static_branch_unlikely(&amu_fie_key)

static int __init init_amu_fie(void)
{
	cpumask_var_t valid_cpus;
	bool have_policy = false;
	int ret = 0;
	int cpu;

	if (!zalloc_cpumask_var(&valid_cpus, GFP_KERNEL))
		return -ENOMEM;

	if (!zalloc_cpumask_var(&amu_fie_cpus, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_valid_mask;
	}

	for_each_present_cpu(cpu) {
		if (validate_cpu_freq_invariance_counters(cpu))
			continue;
		cpumask_set_cpu(cpu, valid_cpus);
		have_policy |= enable_policy_freq_counters(cpu, valid_cpus);
	}

	/*
	 * If we are not restricted by cpufreq policies, we only enable
	 * the use of the AMU feature for FIE if all CPUs support AMU.
	 * Otherwise, enable_policy_freq_counters has already enabled
	 * policy cpus.
	 */
	if (!have_policy && cpumask_equal(valid_cpus, cpu_present_mask))
		cpumask_or(amu_fie_cpus, amu_fie_cpus, valid_cpus);

	if (!cpumask_empty(amu_fie_cpus)) {
		pr_info("CPUs[%*pbl]: counters will be used for FIE.",
			cpumask_pr_args(amu_fie_cpus));
		static_branch_enable(&amu_fie_key);
	}

	/*
	 * If the system is not fully invariant after AMU init, disable
	 * partial use of counters for frequency invariance.
	 */
	if (!topology_scale_freq_invariant())
		static_branch_disable(&amu_fie_key);

free_valid_mask:
	free_cpumask_var(valid_cpus);

	return ret;
}
late_initcall_sync(init_amu_fie);

#endif /* CONFIG_ARM64_AMU_EXTN */
