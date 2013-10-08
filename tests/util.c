/**
 * Seccomp Library utility code for tests
 *
 * Copyright (c) 2012 Red Hat <eparis@redhat.com>
 * Author: Eric Paris <eparis@redhat.com>
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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <seccomp.h>

#include "util.h"

/**
 * SIGSYS signal handler
 * @param nr the signal number
 * @param info siginfo_t pointer
 * @param void_context handler context
 *
 * Simple signal handler for SIGSYS which exits with error code 161.
 *
 */
static void _trap_handler(int signal, siginfo_t *info, void *ctx)
{
	_exit(161);
}

/**
 * Parse the arguments passed to main
 * @param argc the argument count
 * @param argv the argument pointer
 * @param opts the options structure
 *
 * This function parses the arguments passed to the test from the command line.
 * Returns zero on success and negative values on failure.
 *
 */
int util_getopt(int argc, char *argv[], struct util_options *opts)
{
	int rc = 0;

	if (opts == NULL)
		return -EFAULT;

	memset(opts, 0, sizeof(*opts));
	while (1) {
		int c, option_index = 0;
		const struct option long_options[] = {
			{"bpf", no_argument, &(opts->bpf_flg), 1},
			{"pfc", no_argument, &(opts->bpf_flg), 0},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "bp",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case 'b':
			opts->bpf_flg = 1;
			break;
		case 'p':
			opts->bpf_flg = 0;
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}

	if (rc == -EINVAL || optind < argc) {
		fprintf(stderr, "usage %s: [--bpf,-b] [--pfc,-p]\n", argv[0]);
		rc = -EINVAL;
	}

	return rc;
}

/**
 * Output the filter in either BPF or PFC
 * @param opts the options structure
 * @param ctx the filter context
 *
 * This function outputs the seccomp filter to stdout in either BPF or PFC
 * format depending on the test paramaeters supplied by @opts.
 *
 */
int util_filter_output(const struct util_options *opts,
		       const scmp_filter_ctx ctx)
{
	int rc;

	if (opts == NULL)
		return -EFAULT;

	if (opts->bpf_flg)
		rc = seccomp_export_bpf(ctx, STDOUT_FILENO);
	else
		rc = seccomp_export_pfc(ctx, STDOUT_FILENO);

	return rc;
}

/**
 * Install a TRAP action signal handler
 *
 * This function installs the TRAP action signal handler and is based on
 * examples from Will Drewry and Kees Cook.  Returns zero on success, negative
 * values on failure.
 *
 */
int util_trap_install(void)
{
	return util_trap_install_custom(&_trap_handler);
}

/**
 * Install a custum TRAP action signal handler
 *
 * This function installs a TRAP action signal handler and is based on
 * examples from Will Drewry and Kees Cook.  Returns zero on success, negative
 * values on failure.
 *
 */
int util_trap_install_custom(void (*sa)(int, siginfo_t *, void *))
{
	struct sigaction signal_handler;
	sigset_t signal_mask;

	memset(&signal_handler, 0, sizeof(signal_handler));
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGSYS);

	signal_handler.sa_sigaction = sa;
	signal_handler.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &signal_handler, NULL) < 0)
		return -errno;
	if (sigprocmask(SIG_UNBLOCK, &signal_mask, NULL))
		return -errno;
	return 0;
}

/**
 * Parse a filter action string into an action value
 * @param action the action string
 *
 * Parse a seccomp action string into the associated integer value.  Returns
 * the correct value on success, -1 on failure.
 *
 */
int util_action_parse(const char *action)
{
	if (action == NULL)
		return -1;

	if (strcasecmp(action, "KILL") == 0)
		return SCMP_ACT_KILL;
	else if (strcasecmp(action, "TRAP") == 0)
		return SCMP_ACT_TRAP;
	else if (strcasecmp(action, "ERRNO") == 0)
		return SCMP_ACT_ERRNO(163);
	else if (strcasecmp(action, "TRACE") == 0)
		return -1; /* not yet supported */
	else if (strcasecmp(action, "ALLOW") == 0)
		return SCMP_ACT_ALLOW;

	return -1;
}

/**
 * Write a string to a file
 * @param path the file path
 *
 * Open the specified file, write a string to the file, and close the file.
 * Return zero on success, negative values on error.
 *
 */
int util_file_write(const char *path)
{
	int fd;
	const char buf[] = "testing";
	ssize_t buf_len = strlen(buf);

	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return errno;
	if (write(fd, buf, buf_len) < buf_len) {
		int rc = errno;
		close(fd);
		return rc;
	}
	if (close(fd) < 0)
		return errno;

	return 0;
}

__attribute__((unused)) static void assert_32bit_args(const uint64_t args[6])
{
	int i;
	for (i = 0; i < 6; i++)
		if (args[i] != (uint32_t)args[i])
			abort();
}

#if defined(__x86_64__) || defined(__i386__)
static long do_i386_syscall(int nr, const uint64_t args[6])
{
	long ret;
	assert_32bit_args(args);

	/*
	 * This should not be used as an example of a fast or beautiful
	 * way to issue 32-bit syscalls.  It works, though.
	 *
	 * A debugger will get a bit confused if it breaks in the middle
	 * of this -- this manipulates the stack without CFI annotations.
	 * This also means that a SIGSYS handler shouldn't try to longjmp.
	 * Fortunately, this is test code.
	 */
	uint32_t dummy;

#ifdef __x86_64__
#define BP "%%rbp"
#define BX "%%rbx"
#else
#define BP "%%ebp"
#define BX "%%ebx"
#endif

	__asm__ __volatile__(
		"sub $128, %%sp\n\t"          /* protect the redzone */
		"push " BX "\n\t"             /* save ebx */
		"push " BP "\n\t"             /* save ebp */
		"mov (%[args]), %%ebx\n\t"    /* set up args[0] */
		"mov 8(%[args]), %%ecx\n\t"   /* set up args[1] */
		"mov 16(%[args]), %%edx\n\t"  /* set up args[2] */
		"mov 24(%[args]), %%esi\n\t"  /* set up args[3] */
		"mov 40(%[args]), %%ebp\n\t"  /* set up args[5] */
		"mov 32(%[args]), %%edi\n\t"  /* set up args[4] */
		"int $0x80\n\t"               /* issue the syscall */
		"pop " BP "\n\t"              /* restore ebp */
		"pop " BX "\n\t"              /* restore ebx */
		"add $128, %%sp\n\t"          /* fix the stack pointer */
		: "=a" (ret), "=D" (dummy)
		: "a" (nr), [args] "D" (args)
		: "ecx", "edx", "esi", "memory", "flags");

#undef BP

	return ret;
}
#define CAN_SYSCALL_I386
#endif

#if defined(__x86_64__)
static long do_x86_64_syscall(int nr, const uint64_t args[6])
{
	long ret;

	register uint64_t r10 asm("r10") __attribute__((unused)) = args[3];
	register uint64_t r8 asm("r8") __attribute__((unused)) = args[4];
	register uint64_t r9 asm("r9") __attribute__((unused)) = args[5];
	uint64_t dummy1, dummy2, dummy3;
	__asm__ __volatile__(
		"syscall"
		: "=a" (ret), "=D" (dummy1), "=S" (dummy2), "=d" (dummy3)
		: "a" (nr), "D" (args[0]), "S" (args[1]), "d" (args[2])
		: "memory", "flags", "r11", "rcx");

	return ret;
}
#define CAN_SYSCALL_X86_64
#endif

/**
 * Can we issue syscalls using this arch?
 * @param arch the architecture (AUDIT_ARCH_xyz)
 *
 * A false return value doesn't mean it's impossible; it just means that
 * it's not implemented.  This function is only necessary for secondary
 * arches.  x86_64 is just a bonus.
 */
int util_can_syscall(uint32_t arch)
{
#ifdef CAN_SYSCALL_I386
	if (arch == AUDIT_ARCH_I386)
		return 1;
#endif
#ifdef CAN_SYSCALL_X86_64
	if (arch == AUDIT_ARCH_X86_64)
		return 1;
#endif
	return 0;
}

/**
 * Make a system call for a possibly different architecture.
 * @param arch the architecture (AUDIT_ARCH_xyz)
 * @param nr the syscall number
 * @param args the syscall arguments (6 of them)
 *
 * This will abort if !util_can_syscall(arch).  It will also abort if the
 * arguments have high bits set and arch is 32-bit.
 */
long util_issue_raw_syscall(uint32_t arch, int nr, const uint64_t args[6])
{
#ifdef CAN_SYSCALL_I386
	if (arch == AUDIT_ARCH_I386)
		return do_i386_syscall(nr, args);
#endif
#ifdef CAN_SYSCALL_X86_64
	if (arch == AUDIT_ARCH_X86_64)
		return do_x86_64_syscall(nr, args);
#endif
#ifdef CAN_SYSCALL_ARM
	if (arch == AUDIT_ARCH_ARM)
		return do_arm_syscall(nr, args);
#endif

	abort();
}
