/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_KVM_TYPES_H
#define _ASM_ARM64_KVM_TYPES_H

#define KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE 40

/*
 * Export the KVM symbols into the importable "KVM" namespace rather
 * than the name-gated module:kvm one, so that any KVM module can
 * consume them via MODULE_IMPORT_NS("KVM").
 */
#if IS_MODULE(CONFIG_KVM)
#define EXPORT_SYMBOL_FOR_KVM(symbol)	EXPORT_SYMBOL_NS(symbol, "KVM")
#endif

#endif /* _ASM_ARM64_KVM_TYPES_H */

