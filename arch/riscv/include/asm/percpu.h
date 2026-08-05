/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Union Tech Software Technology Corporation Limited
 */
#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <asm/cmpxchg.h>

#define PERCPU_OP(op, asm_op, c_op)                                            \
	static inline unsigned long __percpu_##op(void *ptr,                   \
						  unsigned long val, int size) \
	{                                                                      \
		unsigned long ret;                                             \
		switch (size) {                                                \
		case 4:                                                        \
			__asm__ __volatile__(                                  \
				"amo" #asm_op ".w"                             \
				" %[ret], %[val], %[ptr]\n"                   \
				: [ret] "=&r"(ret), [ptr] "+A"(*(u32 *)ptr)    \
				: [val] "r"(val));                             \
			break;                                                 \
		case 8:                                                        \
			__asm__ __volatile__(                                  \
				"amo" #asm_op ".d"                             \
				" %[ret], %[val], %[ptr]\n"                   \
				: [ret] "=&r"(ret), [ptr] "+A"(*(u64 *)ptr)    \
				: [val] "r"(val));                             \
			break;                                                 \
		default:                                                       \
			ret = 0;                                               \
			BUILD_BUG();                                           \
		}                                                              \
										\
		return ret c_op val;                                           \
	}

PERCPU_OP(add, add, +)
PERCPU_OP(and, and, &)
PERCPU_OP(or, or, |)
#undef PERCPU_OP

/* this_cpu_xchg */
#define _protect_xchg_local(pcp, val)                           \
	({                                                      \
		typeof(*raw_cpu_ptr(&(pcp))) __ret;             \
		preempt_disable_notrace();                      \
		__ret = xchg_relaxed(raw_cpu_ptr(&(pcp)), val); \
		preempt_enable_notrace();                       \
		__ret;                                          \
	})

/* this_cpu_cmpxchg */
#define _protect_cmpxchg_local(pcp, o, n)                         \
	({                                                        \
		typeof(*raw_cpu_ptr(&(pcp))) __ret;               \
		preempt_disable_notrace();                        \
		__ret = cmpxchg_local(raw_cpu_ptr(&(pcp)), o, n); \
		preempt_enable_notrace();                         \
		__ret;                                            \
	})

#define _pcp_protect(operation, pcp, val)                                     \
	({                                                                    \
		typeof(pcp) __retval;                                         \
		preempt_disable_notrace();                                    \
		__retval = (typeof(pcp))operation(raw_cpu_ptr(&(pcp)), (val), \
						  sizeof(pcp));               \
		preempt_enable_notrace();                                     \
		__retval;                                                     \
	})

#define _percpu_add(pcp, val) _pcp_protect(__percpu_add, pcp, val)

#define _percpu_add_return(pcp, val) _percpu_add(pcp, val)

#define _percpu_and(pcp, val) _pcp_protect(__percpu_and, pcp, val)

#define _percpu_or(pcp, val) _pcp_protect(__percpu_or, pcp, val)

#define this_cpu_add_4(pcp, val) _percpu_add(pcp, val)
#define this_cpu_add_8(pcp, val) _percpu_add(pcp, val)

#define this_cpu_add_return_4(pcp, val) _percpu_add_return(pcp, val)
#define this_cpu_add_return_8(pcp, val) _percpu_add_return(pcp, val)

#define this_cpu_and_4(pcp, val) _percpu_and(pcp, val)
#define this_cpu_and_8(pcp, val) _percpu_and(pcp, val)

#define this_cpu_or_4(pcp, val) _percpu_or(pcp, val)
#define this_cpu_or_8(pcp, val) _percpu_or(pcp, val)

#define this_cpu_xchg_4(pcp, val) _protect_xchg_local(pcp, val)
#define this_cpu_xchg_8(pcp, val) _protect_xchg_local(pcp, val)

#define this_cpu_cmpxchg_4(ptr, o, n) _protect_cmpxchg_local(ptr, o, n)
#define this_cpu_cmpxchg_8(ptr, o, n) _protect_cmpxchg_local(ptr, o, n)

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
