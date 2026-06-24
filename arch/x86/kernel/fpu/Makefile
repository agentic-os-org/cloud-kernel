# SPDX-License-Identifier: GPL-2.0-only
#
# Build rules for the FPU support code:
#

obj-y				+= init.o bugs.o core.o regset.o signal.o xstate.o
obj-$(CONFIG_X86_HYGON_LMC_SSE2_ON) += hygon_nonatomic.o
obj-$(CONFIG_X86_HYGON_LMC_AVX2_ON) += hygon_nonatomic.o
