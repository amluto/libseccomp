/**
 * Enhanced Seccomp x86_64 Specific Code
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-x86_64.h"

#if __x86_64__
static uint64_t drop_high(uint64_t val)
{
	return val & 0xffffffff;
}

int arch_decode_sigsys(struct seccomp_data *data, const siginfo_t *si,
		       const void *uc_void)
{
	const struct ucontext *uc = uc_void;

	if (si->si_signo != SIGSYS)
		return -EINVAL;

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_X86_64) {
		data->args[0] = uc->uc_mcontext.gregs[REG_RDI];
		data->args[1] = uc->uc_mcontext.gregs[REG_RSI];
		data->args[2] = uc->uc_mcontext.gregs[REG_RDX];
		data->args[3] = uc->uc_mcontext.gregs[REG_R10];
		data->args[4] = uc->uc_mcontext.gregs[REG_R8];
		data->args[5] = uc->uc_mcontext.gregs[REG_R9];
	} else 	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_I386) {
		/*
		 * Syscall arguments are 32 bits.  Make sure we drop the
		 * high bits, even if the headers somehow think the
		 * register is signed.
		 */
		data->args[0] = drop_high(uc->uc_mcontext.gregs[REG_RBX]);
		data->args[1] = drop_high(uc->uc_mcontext.gregs[REG_RCX]);
		data->args[2] = drop_high(uc->uc_mcontext.gregs[REG_RDX]);
		data->args[3] = drop_high(uc->uc_mcontext.gregs[REG_RSI]);
		data->args[4] = drop_high(uc->uc_mcontext.gregs[REG_RDI]);
		data->args[5] = drop_high(uc->uc_mcontext.gregs[REG_RBP]);
	} else {
		return -EOPNOTSUPP;
	}

	/* This part is independent of architecture. */
	data->arch = SIGINFO_SIGSYS(si)->_arch;
	data->nr = SIGINFO_SIGSYS(si)->_syscall;
	data->instruction_pointer =
		(__u64)SIGINFO_SIGSYS(si)->_call_addr;

	return 0;
}

int arch_set_sigsys_return_value(siginfo_t *si, void *uc_void, long ret)
{
	struct ucontext *uc = uc_void;

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_X86_64) {
		uc->uc_mcontext.gregs[REG_RAX] = ret;
	} else if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_I386) {
		/*
		 * If ret is neither a sign-extended nor zero-extended 32-bit
		 * int, then reject -- it makes no sense as a 32-bit number.
		 */
		uint32_t high_bits = (uint64_t)ret >> 32;
		if (high_bits != 0 && high_bits != 0xffffffff)
			return -EINVAL;

		uc->uc_mcontext.gregs[REG_RAX] = ret;
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif

const struct arch_def arch_def_x86_64 = {
	.token = SCMP_ARCH_X86_64,
	.token_bpf = AUDIT_ARCH_X86_64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_LITTLE,
};
