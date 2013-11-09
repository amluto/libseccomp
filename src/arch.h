/**
 * Enhanced Seccomp Architecture/Machine Specific Code
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

#ifndef _ARCH_H
#define _ARCH_H

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

#include <seccomp.h>

#include <sys/ucontext.h>

#include "system.h"

struct db_api_arg;

struct arch_def {
	uint32_t token;
	uint32_t token_bpf;
	enum {
		ARCH_SIZE_UNSPEC = 0,
		ARCH_SIZE_32 = 32,
		ARCH_SIZE_64 = 64,
	} size;
	enum {
		ARCH_ENDIAN_UNSPEC = 0,
		ARCH_ENDIAN_LITTLE,
		ARCH_ENDIAN_BIG,
	} endian;
};

/* arch_def for the current architecture */
extern const struct arch_def *arch_def_native;

/* NOTE: Syscall mappings can be found by running the following commands
 *	 on the specific architecture's include file:
 *	   # gcc -E -dM <file> | grep '__NR_'
 *	 where <file> in many cases is /usr/include/asm/unistd.h, however,
 *	 depending on the architecture you may need to use a different header.
 *	 Further, you can automatically format this list for use as a struct
 *	 initializer with the following command:
 *	   # gcc -E -dM <file> | grep '__NR_' | \
 *	     sed -e 's/#define[ \t]\+__NR_//' | sort | \
 *	     sed -e 's/\([^ \t]\+\)\([ \t]\+\)\([0-9]\+\)/\t{ \"\1\", \3 },/'
 *	 Finally, when creating a table/array of this structure, the final
 *	 sentinel entry should be "{ NULL, __NR_SCMP_ERROR }"; see the existing
 *	 tables as an example.
 */
struct arch_syscall_def {
	const char *name;
	unsigned int num;
};

#define DATUM_MAX	((scmp_datum_t)-1)
#define D64_LO(x)	((uint32_t)((uint64_t)(x) & 0x00000000ffffffff))
#define D64_HI(x)	((uint32_t)((uint64_t)(x) >> 32))

#define ARG_COUNT_MAX	6

int arch_valid(uint32_t arch);

const struct arch_def *arch_def_lookup(uint32_t token);

int arch_arg_count_max(const struct arch_def *arch);

/**
 * Determine the argument offset
 * @param _arg the argument number
 *
 * Return the correct offset of the given argument.
 *
 */
#define arch_arg_offset(_arg)	(offsetof(struct seccomp_data, args[_arg]))

int arch_arg_offset_lo(const struct arch_def *arch, unsigned int arg);
int arch_arg_offset_hi(const struct arch_def *arch, unsigned int arg);

int arch_syscall_resolve_name(const struct arch_def *arch, const char *name);
const char *arch_syscall_resolve_num(const struct arch_def *arch, int num);

int arch_syscall_translate(const struct arch_def *arch, int *syscall);
int arch_syscall_rewrite(const struct arch_def *arch, bool strict,
			 int *syscall);

int arch_filter_rewrite(const struct arch_def *arch,
			bool strict, int *syscall, struct db_api_arg *chain);

/**
 * Decode SIGSYS data to find the offending syscall arch, nr, and args.
 * @param data the offending syscall (output)
 * @param si the siginfo pointer passed to the signal handler
 * @param uc the ucontext pointer passed to the signal handler
 *
 * Decodes values passed to a SIGSYS handler.
 *
 * This function assumes that the ucontext is native.  (Presumably,
 * anyone using libseccomp is using the same signal ABI as the one
 * with which they've compiled libseccomp.  This does not have to be
 * the same libseccomp that installed the filter in the first place,
 * though.)
 *
 * It returns a negative error code if it fails.
 */
int arch_decode_sigsys(struct seccomp_data *data, const siginfo_t *si,
		       const void *uc_void);

/**
 * Modify a signal frame to emulate a syscall return value.
 * @param si the siginfo pointer passed to the signal handler
 * @param uc the ucontext pointer passed to the signal handler
 * @param ret the value that the trapping syscall should return
 *
 * This implements seccomp_sigsys_set_return_value.  It can fail if
 * the syscall arch is unsupported or if ret doesn't make sense on that arch.
 */
int arch_set_sigsys_return_value(siginfo_t *si, void *uc, long ret);

#endif
