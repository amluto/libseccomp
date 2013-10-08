/**
 * Seccomp Library test program
 *
 * Copyright (c) 2013 Andy Lutomirski <luto@amacapital.net>
 * Copyright (c) 2013 Red Hat <pmoore@redhat.com>
 * Author: Andy Lutomirski <luto@amacapital.net>
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

#include <unistd.h>
#include <stdlib.h>

#include <seccomp.h>
#include "../src/system.h"

#include "util.h"

#define NUM_RETVALS 6

static const uint64_t args64[] = {0xdeadbeefbaadc0deull, 1ull,
				  0xffffffffffffffffull,
				  0x8000000000000000ull, 0ull, 0xffffffffull};

static const int64_t retvals64[NUM_RETVALS] = {
	0ll, 1ll, -1ll, 0x8000000000000000ll,
	0x123456789abcdef0ll, -0x123456789abcdef0ll};

static const uint64_t args32[] = {0xdeadbeef, 1, 0x7fffffff,
				  0x80000000, 0, 0xffffffff};

static const long retvals32[NUM_RETVALS] = {
	0, 1, -1, 0x80000000, 0x12345678, -0x12345678};

struct test_arch {
	uint32_t arch;
	int nr;  /* Should match getgid */
};

static const struct test_arch arches[] = {
	{ AUDIT_ARCH_I386, 47 },
	{ AUDIT_ARCH_X86_64, 104 },
};

static struct test_arch const *current_arch;
static long expected_ret;
static int passed;

static const uint64_t *arch_args(const struct test_arch *arch)
{
	return (arch->arch & __AUDIT_ARCH_64BIT) ? args64 : args32;
}

static long arch_retval(const struct test_arch *arch, int i)
{
	if (arch->arch & __AUDIT_ARCH_64BIT) {
		if (sizeof(long) < 8)
			abort();
		return retvals64[i];
	} else {
		return retvals32[i];
	}
}

static void handler(int signum, siginfo_t *si, void *uc)
{
	int i, rc;
	struct seccomp_data data;
	const uint64_t *args = arch_args(current_arch);

	if (signum != SIGSYS) {
		rc = 1;
		goto out;
	}

	rc = seccomp_sigsys_decode(&data, si, uc);
	if (rc)
		goto out;

	rc = 1;

	/* This could be significantly improved. */
	if (data.nr != current_arch->nr ||
	    data.arch != current_arch->arch)
		goto out;

	for (i = 0; i < 6; i++)
		if (data.args[i] != args[i])
			goto out;

	if (seccomp_sigsys_set_return_value(si, uc, expected_ret) != 0)
		goto out;

	passed = 1;
	return;

out:
	_exit(rc);
}

long check_arch(const struct test_arch *arch)
{
	int i;
	current_arch = arch;

	if (!util_can_syscall(arch->arch))
		return 0;

	for (i = 0; i < NUM_RETVALS; i++) {
		long retval;

		expected_ret = arch_retval(arch, i);
		passed = 0;
		retval = util_issue_raw_syscall(arch->arch, arch->nr,
						arch_args(arch));
		if (!passed || retval != expected_ret)
			return -1;
	}

	return 0;
}

long check_native(const struct test_arch *arch)
{
	int i;
	const uint64_t *args = arch_args(arch);
	current_arch = arch;

	for (i = 0; i < NUM_RETVALS; i++) {
		long retval;

		expected_ret = arch_retval(arch, i);
		passed = 0;
		retval = syscall(arch->nr,
				 (long)args[0], (long)args[1], (long)args[2],
				 (long)args[3], (long)args[4], (long)args[5]);
		if (!passed || retval != expected_ret)
			return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int i, rc;
	scmp_filter_ctx ctx;

	rc = util_trap_install_custom(handler);
	if (rc != 0) {
		goto out;
	}

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		goto out;

	/*
	 * Add possible secondary architectures.  These will fail depending
	 * on what the native architecture is, so don't worry about failure.
	 */
	seccomp_arch_add(ctx, SCMP_ARCH_X86);

	rc = seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(getgid), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_load(ctx);
	if (rc != 0)
		goto out;

	for (i = 0; i < sizeof(arches) / sizeof(arches[0]); i++) {
		rc = check_arch(&arches[i]);
		if (rc != 0)
			goto out;
	}

	/*
	 * Also check the native libc version, both as a test that the
	 * test code isn't screwed up and so that builds that only
	 * support one syscall ABI don't need to implement
	 * util_issue_raw_syscall.
	 */
	struct test_arch native;

#if defined(__x86_64__)
	native.arch = AUDIT_ARCH_X86_64;
#elif defined(__i386__)
	native.arch = AUDIT_ARCH_I386;
#elif defined(__arm__)
	native.arch = AUDIT_ARCH_ARM;
#else
#error This test case needs to be ported to your architecture.
#endif

	native.nr = __NR_getgid;
	rc = check_native(&native);
	if (rc != 0)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
