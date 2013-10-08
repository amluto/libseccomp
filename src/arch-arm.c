/**
 * Enhanced Seccomp ARM Specific Code
 *
 * Copyright (c) 2013 Red Hat <pmoore@redhat.com>
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
#include "arch-arm.h"

#if __arm__
int arch_decode_sigsys(struct seccomp_data *data, const siginfo_t *si,
		       const void *uc_void)
{
	const struct ucontext *uc = uc_void;

	if (si->si_signo != SIGSYS)
		return -EINVAL;

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_ARM) {
		data->args[0] = (uint32_t)uc->uc_mcontext.arm_r0;
		data->args[1] = (uint32_t)uc->uc_mcontext.arm_r1;
		data->args[2] = (uint32_t)uc->uc_mcontext.arm_r2;
		data->args[3] = (uint32_t)uc->uc_mcontext.arm_r3;
		data->args[4] = (uint32_t)uc->uc_mcontext.arm_r4;
		data->args[5] = (uint32_t)uc->uc_mcontext.arm_r5;
	} else {
		return -EOPNOTSUPP;
	}

	data->arch = SIGINFO_SIGSYS(si)->_arch;
	data->nr = SIGINFO_SIGSYS(si)->_syscall;
	data->instruction_pointer =
		(__u32)SIGINFO_SIGSYS(si)->_call_addr;

	return 0;
}

int arch_set_sigsys_return_value(siginfo_t *si, void *uc_void, long ret)
{
	struct ucontext *uc = uc_void;

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_ARM)
		uc->uc_mcontext.arm_r0 = ret;
	else
		return -EOPNOTSUPP;

	return 0;
}
#endif

const struct arch_def arch_def_arm = {
	.token = SCMP_ARCH_ARM,
	.token_bpf = AUDIT_ARCH_ARM,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
};
