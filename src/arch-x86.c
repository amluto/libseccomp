/**
 * Enhanced Seccomp x86 Specific Code
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
#include "arch-x86.h"

/* x86 syscall numbers */
#define __x86_NR_socketcall		102
#define __x86_NR_ipc			117

const struct arch_def arch_def_x86 = {
	.token = SCMP_ARCH_X86,
	.token_bpf = AUDIT_ARCH_I386,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
};

#if __i386__
int arch_decode_sigsys(struct seccomp_data *data, const siginfo_t *si,
		       const void *uc_void)
{
	const struct ucontext *uc = uc_void;

	if (si->si_signo != SIGSYS)
		return -EINVAL;

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_I386) {
		data->args[0] = (uint32_t)uc->uc_mcontext.gregs[REG_EBX];
		data->args[1] = (uint32_t)uc->uc_mcontext.gregs[REG_ECX];
		data->args[2] = (uint32_t)uc->uc_mcontext.gregs[REG_EDX];
		data->args[3] = (uint32_t)uc->uc_mcontext.gregs[REG_ESI];
		data->args[4] = (uint32_t)uc->uc_mcontext.gregs[REG_EDI];
		data->args[5] = (uint32_t)uc->uc_mcontext.gregs[REG_EBP];
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

	if (SIGINFO_SIGSYS(si)->_arch == AUDIT_ARCH_I386)
		uc->uc_mcontext.gregs[REG_EAX] = ret;
	else
		return -EOPNOTSUPP;

	return 0;
}
#endif

/**
 * Rewrite a syscall value to match the architecture
 * @param arch the architecture definition
 * @param strict strict flag
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  If
 * @strict is true then the function will fail if the syscall can not be
 * preservered, however, if @strict is false the function will do a "best
 * effort" rewrite and not fail. Returns zero on success, negative values on
 * failure.
 *
 */
int x86_syscall_rewrite(const struct arch_def *arch, bool strict, int *syscall)
{
	if ((*syscall) <= -100 && (*syscall) >= -117)
		*syscall = __x86_NR_socketcall;
	else if ((*syscall) <= -200 && (*syscall) >= -211)
		*syscall = __x86_NR_ipc;
	else if (((*syscall) < 0) && (strict))
		return -EDOM;

	return 0;
}

/**
 * Rewrite a filter rule to match the architecture specifics
 * @param arch the architecture definition
 * @param strict strict flag
 * @param syscall the syscall number
 * @param chain the argument filter chain
 *
 * Syscalls can vary across different architectures so this function handles
 * the necessary seccomp rule rewrites to ensure the right thing is done
 * regardless of the rule or architecture.  If @strict is true then the
 * function will fail if the entire filter can not be preservered, however,
 * if @strict is false the function will do a "best effort" rewrite and not
 * fail.  Returns zero on success, negative values on failure.
 *
 */
int x86_filter_rewrite(const struct arch_def *arch, bool strict,
		       int *syscall, struct db_api_arg *chain)
{
	unsigned int iter;

	if ((*syscall) <= -100 && (*syscall) >= -117) {
		for (iter = 0; iter < x86_arg_count_max; iter++) {
			if ((chain[iter].valid != 0) && (strict))
				return -EINVAL;
		}
		chain[0].arg = 0;
		chain[0].op = SCMP_CMP_EQ;
		chain[0].mask = DATUM_MAX;
		chain[0].datum = abs(*syscall) % 100;
		chain[0].valid = 1;
		*syscall = __x86_NR_socketcall;
	} else if ((*syscall) <= -200 && (*syscall) >= -211) {
		for (iter = 0; iter < x86_arg_count_max; iter++) {
			if ((chain[iter].valid != 0) && (strict))
				return -EINVAL;
		}
		chain[0].arg = 0;
		chain[0].op = SCMP_CMP_EQ;
		chain[0].mask = DATUM_MAX;
		chain[0].datum = abs(*syscall) % 200;
		chain[0].valid = 1;
		*syscall = __x86_NR_ipc;
	} else if (((*syscall) < 0) && (strict))
		return -EDOM;

	return 0;
}
