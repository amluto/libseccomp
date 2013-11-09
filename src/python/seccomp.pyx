#
# Seccomp Library Python Bindings
#
# Copyright (c) 2012,2013 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <pmoore@redhat.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

""" Python bindings for the libseccomp library

The libseccomp library provides and easy to use, platform independent,
interface to the Linux Kernel's syscall filtering mechanism: seccomp.  The
libseccomp API is designed to abstract away the underlying BPF based
syscall filter language and present a more conventional function-call
based filtering interface that should be familiar to, and easily adopted
by application developers.

Filter action values:
    KILL - kill the process
    ALLOW - allow the syscall to execute
    TRAP - a SIGSYS signal will be thrown
    ERRNO(x) - syscall will return (x)
    TRACE(x) - if the process is being traced, (x) will be returned to the
               tracing process via PTRACE_EVENT_SECCOMP and the
               PTRACE_GETEVENTMSG option

Argument comparison values (see the Arg class):

    NE - arg != datum_a
    LT - arg < datum_a
    LE - arg <= datum_a
    EQ - arg == datum_a
    GT - arg > datum_a
    GE - arg >= datum_a
    MASKED_EQ - (arg & datum_b) == datum_a


Example:

    import sys
    from seccomp import *

    # create a filter object with a default KILL action
    f = SyscallFilter(defaction=KILL)

    # add syscall filter rules to allow certain syscalls
    f.add_rule(ALLOW, "open")
    f.add_rule(ALLOW, "close")
    f.add_rule(ALLOW, "read", Arg(0, EQ, sys.stdin))
    f.add_rule(ALLOW, "write", Arg(0, EQ, sys.stdout))
    f.add_rule(ALLOW, "write", Arg(0, EQ, sys.stderr))
    f.add_rule(ALLOW, "rt_sigreturn")

    # load the filter into the kernel
    f.load()
"""
__author__ =  'Paul Moore <paul@paul-moore.com>'
__date__ = "7 January 2013"

cimport cython
from libc.stdint cimport uint32_t
from libc.stdlib cimport _exit
cimport libc.string

cimport libseccomp

import errno
import sys
import traceback

KILL = libseccomp.SCMP_ACT_KILL
TRAP = libseccomp.SCMP_ACT_TRAP
ALLOW = libseccomp.SCMP_ACT_ALLOW
def ERRNO(int errno):
    """The action ERRNO(x) means that the syscall will return (x).
    To conform to Linux syscall calling conventions, the syscall return
    value should almost always be a negative number.
    """
    return libseccomp.SCMP_ACT_ERRNO(errno)
def TRACE(int value):
    """The action TRACE(x) means that, if the process is being traced, (x)
    will be returned to the tracing process via PTRACE_EVENT_SECCOMP
    and the PTRACE_GETEVENTMSG option.
    """
    return libseccomp.SCMP_ACT_TRACE(value)

NE = libseccomp.SCMP_CMP_NE
LT = libseccomp.SCMP_CMP_LT
LE = libseccomp.SCMP_CMP_LE
EQ = libseccomp.SCMP_CMP_EQ
GE = libseccomp.SCMP_CMP_GE
GT = libseccomp.SCMP_CMP_GT
MASKED_EQ = libseccomp.SCMP_CMP_MASKED_EQ

def system_arch():
    """ Return the system architecture value.

    Description:
    Returns the native system architecture value.
    """
    return libseccomp.seccomp_arch_native()

def resolve_syscall(arch, syscall):
    """ Resolve the syscall.

    Arguments:
    arch - the architecture value, e.g. Arch.*
    syscall - the syscall name or number

    Description:
    Resolve an architecture's syscall name to the correct number or the
    syscall number to the correct name.
    """
    cdef char *ret_str

    if (isinstance(syscall, basestring)):
        return libseccomp.seccomp_syscall_resolve_name_arch(arch, syscall)
    elif (isinstance(syscall, int)):
        ret_str = libseccomp.seccomp_syscall_resolve_num_arch(arch, syscall)
        if ret_str is NULL:
            raise KeyError('Unknown syscall %d on arch %d' % (syscall, arch))
        else:
            return ret_str
    else:
        raise TypeError("Syscall must either be an int or str type")

cdef class Arch:
    """ Python object representing the SyscallFilter architecture values.

    Data values:
    NATIVE - the native architecture
    X86 - 32-bit x86
    X86_64 - 64-bit x86
    X32 - 64-bit x86 using the x32 ABI
    ARM - ARM
    """

    NATIVE = libseccomp.SCMP_ARCH_NATIVE
    X86 = libseccomp.SCMP_ARCH_X86
    X86_64 = libseccomp.SCMP_ARCH_X86_64
    X32 = libseccomp.SCMP_ARCH_X32
    ARM = libseccomp.SCMP_ARCH_ARM

cdef class Attr:
    """ Python object representing the SyscallFilter attributes.

    Data values:
    ACT_DEFAULT - the filter's default action
    ACT_BADARCH - the filter's bad architecture action
    CTL_NNP - the filter's "no new privileges" flag
    """
    ACT_DEFAULT = libseccomp.SCMP_FLTATR_ACT_DEFAULT
    ACT_BADARCH = libseccomp.SCMP_FLTATR_ACT_BADARCH
    CTL_NNP = libseccomp.SCMP_FLTATR_CTL_NNP

cdef class Arg:
    """ Python object representing a SyscallFilter syscall argument.
    """
    cdef libseccomp.scmp_arg_cmp _arg

    def __cinit__(self, arg, op, datum_a, datum_b = 0):
        """ Initialize the argument comparison.

        Arguments:
        arg - the argument number, starting at 0
        op - the argument comparison operator, e.g. {NE,LT,LE,...}
        datum_a - argument value
        datum_b - argument value, only valid when op == MASKED_EQ

        Description:
        Create an argument comparison object for use with SyscallFilter.
        """
        self._arg.arg = arg
        self._arg.op = op
        self._arg.datum_a = datum_a
        self._arg.datum_b = datum_b

    def to_c(self):
        """ Convert the object into a C structure.

        Description:
        Helper function which should only be used internally by
        SyscallFilter objects and exists for the sole purpose of making it
        easier to deal with the varadic functions of the libseccomp API,
        e.g. seccomp_rule_add().
        """
        return self._arg

cdef class SyscallFilter:
    """ Python object representing a seccomp syscall filter. """
    cdef int _defaction
    cdef libseccomp.scmp_filter_ctx _ctx

    def __cinit__(self, int defaction):
        self._ctx = libseccomp.seccomp_init(defaction)
        if self._ctx == NULL:
            raise RuntimeError("Library error")
        _defaction = defaction

    def __init__(self, defaction):
        """ Initialize the filter state

        Arguments:
        defaction - the default filter action

        Description:
        Initializes the seccomp filter state to the defaults.
        """

    def __dealloc__(self):
        """ Destroys the filter state and releases any resources.

        Description:
        Destroys the seccomp filter state and releases any resources
        associated with the filter state.  This function does not affect
        any seccomp filters already loaded into the kernel.
        """
        if self._ctx != NULL:
            libseccomp.seccomp_release(self._ctx)

    def reset(self, int defaction = -1):
        """ Reset the filter state.

        Arguments:
        defaction - the default filter action

        Description:
        Resets the seccomp filter state to an initial default state, if a
        default filter action is not specified in the reset call the
        original action will be reused.  This function does not affect any
        seccomp filters alread loaded into the kernel.
        """
        if defaction == -1:
            defaction = self._defaction
        rc = libseccomp.seccomp_reset(self._ctx, defaction)
        if rc == -errno.EINVAL:
            raise ValueError("Invalid action")
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))
        _defaction = defaction

    def merge(self, SyscallFilter filter):
        """ Merge two existing SyscallFilter objects.

        Arguments:
        filter - a valid SyscallFilter object

        Description:
        Merges a valid SyscallFilter object with the current SyscallFilter
        object; the passed filter object will be reset on success.  In
        order to successfully merge two seccomp filters they must have the
        same attribute values and not share any of the same architectures.
        """
        rc = libseccomp.seccomp_merge(self._ctx, filter._ctx)
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))
        filter._ctx = NULL
        filter = SyscallFilter(filter._defaction)

    def exist_arch(self, arch):
        """ Check if the seccomp filter contains a given architecture.

        Arguments:
        arch - the architecture value, e.g. Arch.*

        Description:
        Test to see if a given architecture is included in the filter.
        Return True is the architecture exists, False if it does not
        exist.
        """
        rc = libseccomp.seccomp_arch_exist(self._ctx, arch)
        if rc == 0:
            return True
        elif rc == -errno.EEXIST:
            return False
        elif rc == -errno.EINVAL:
            raise ValueError("Invalid architecture")
        else:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def add_arch(self, arch):
        """ Add an architecture to the filter.

        Arguments:
        arch - the architecture value, e.g. Arch.*

        Description:
        Add the given architecture to the filter.  Any new rules added
        after this method returns successfully will be added to this new
        architecture, but any existing rules will not be added to the new
        architecture.
        """
        rc = libseccomp.seccomp_arch_add(self._ctx, arch)
        if rc == -errno.EINVAL:
            raise ValueError("Invalid architecture")
        elif rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def remove_arch(self, arch):
        """ Remove an architecture from the filter.

        Arguments:
        arch - the architecture value, e.g. Arch.*

        Description:
        Remove the given architecture from the filter.  The filter must
        always contain at least one architecture, so if only one
        architecture exists in the filter this method will fail.
        """
        rc = libseccomp.seccomp_arch_remove(self._ctx, arch)
        if rc == -errno.EINVAL:
            raise ValueError("Invalid architecture")
        elif rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def load(self):
        """ Load the filter into the Linux Kernel.

        Description:
        Load the current filter into the Linux Kernel.  As soon as the
        method returns the filter will be active and enforcing.
        """
        rc = libseccomp.seccomp_load(self._ctx)
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def get_attr(self, attr):
        """ Get an attribute value from the filter.

        Arguments:
        attr - the attribute, e.g. Attr.*

        Description:
        Lookup the given attribute in the filter and return the
        attribute's value to the caller.
        """
        value = 0
        rc = libseccomp.seccomp_attr_get(self._ctx,
                                         attr, <uint32_t *>&value)
        if rc == -errno.EINVAL:
            raise ValueError("Invalid attribute")
        elif rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))
        return value

    def set_attr(self, attr, int value):
        """ Set a filter attribute.

        Arguments:
        attr - the attribute, e.g. Attr.*
        value - the attribute value

        Description:
        Lookup the given attribute in the filter and assign it the given
        value.
        """
        rc = libseccomp.seccomp_attr_set(self._ctx, attr, value)
        if rc == -errno.EINVAL:
            raise ValueError("Invalid attribute")
        elif rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def syscall_priority(self, syscall, int priority):
        """ Set the filter priority of a syscall.

        Arguments:
        syscall - the syscall name or number
        priority - the priority of the syscall

        Description:
        Set the filter priority of the given syscall.  A syscall with a
        higher priority will have less overhead in the generated filter
        code which is loaded into the system.  Priority values can range
        from 0 to 255 inclusive.
        """
        if priority < 0 or priority > 255:
            raise ValueError("Syscall priority must be between 0 and 255")
        if isinstance(syscall, str):
            syscall_str = syscall.encode()
            syscall_num = libseccomp.seccomp_syscall_resolve_name(syscall_str)
        elif isinstance(syscall, int):
            syscall_num = syscall
        else:
            raise TypeError("Syscall must either be an int or str type")
        rc = libseccomp.seccomp_syscall_priority(self._ctx,
                                                 syscall_num, priority)
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def add_rule(self, int action, syscall, *args):
        """ Add a new rule to filter.

        Arguments:
        action - the rule action: KILL, TRAP, ERRNO(), TRACE(), or ALLOW
        syscall - the syscall name or number
        args - variable number of Arg objects

        Description:
        Add a new rule to the filter, matching on the given syscall and an
        optional list of argument comparisons.  If the rule is triggered
        the given action will be taken by the kernel.  In order for the
        rule to trigger, the syscall as well as each argument comparison
        must be true.

        In the case where the specific rule is not valid on a specific
        architecture, e.g. socket() on 32-bit x86, this method rewrites
        the rule to the best possible match.  If you don't want this fule
        rewriting to take place use add_rule_exactly().
        """
        cdef libseccomp.scmp_arg_cmp c_arg[6]
        if isinstance(syscall, str):
            syscall_str = syscall.encode()
            syscall_num = libseccomp.seccomp_syscall_resolve_name(syscall_str)
        elif isinstance(syscall, int):
            syscall_num = syscall
        else:
            raise TypeError("Syscall must either be an int or str type")
        """ NOTE: the code below exists solely to deal with the varadic
        nature of seccomp_rule_add() function and the inability of Cython
        to handle this automatically """
        for i, arg in enumerate(args):
            c_arg[i] = arg.to_c()
        if len(args) == 0:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num, 0)
        elif len(args) == 1:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0])
        elif len(args) == 2:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0],
                                             c_arg[1])
        elif len(args) == 3:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0],
                                             c_arg[1],
                                             c_arg[2])
        elif len(args) == 4:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0],
                                             c_arg[1],
                                             c_arg[2],
                                             c_arg[3])
        elif len(args) == 5:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0],
                                             c_arg[1],
                                             c_arg[2],
                                             c_arg[3],
                                             c_arg[4])
        elif len(args) == 6:
            rc = libseccomp.seccomp_rule_add(self._ctx, action, syscall_num,
                                             len(args),
                                             c_arg[0],
                                             c_arg[1],
                                             c_arg[2],
                                             c_arg[3],
                                             c_arg[4],
                                             c_arg[5])
        else:
            raise RuntimeError("Maximum number of arguments exceeded")
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def add_rule_exactly(self, int action, syscall, *args):
        """ Add a new rule to filter.

        Arguments:
        action - the rule action: KILL, TRAP, ERRNO(), TRACE(), or ALLOW
        syscall - the syscall name or number
        args - variable number of Arg objects

        Description:
        Add a new rule to the filter, matching on the given syscall and an
        optional list of argument comparisons.  If the rule is triggered
        the given action will be taken by the kernel.  In order for the
        rule to trigger, the syscall as well as each argument comparison
        must be true.

        This method attempts to add the filter rule exactly as specified
        which can cause problems on certain architectures, e.g. socket()
        on 32-bit x86.  For a architecture independent version of this
        method use add_rule().
        """
        cdef libseccomp.scmp_arg_cmp c_arg[6]
        if isinstance(syscall, str):
            syscall_str = syscall.encode()
            syscall_num = libseccomp.seccomp_syscall_resolve_name(syscall_str)
        elif isinstance(syscall, int):
            syscall_num = syscall
        else:
            raise TypeError("Syscall must either be an int or str type")
        """ NOTE: the code below exists solely to deal with the varadic
        nature of seccomp_rule_add_exact() function and the inability of
        Cython to handle this automatically """
        for i, arg in enumerate(args):
            c_arg[i] = arg.to_c()
        if len(args) == 0:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, 0)
        elif len(args) == 1:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0])
        elif len(args) == 2:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0],
                                                   c_arg[1])
        elif len(args) == 3:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0],
                                                   c_arg[1],
                                                   c_arg[2])
        elif len(args) == 4:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0],
                                                   c_arg[1],
                                                   c_arg[2],
                                                   c_arg[3])
        elif len(args) == 5:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0],
                                                   c_arg[1],
                                                   c_arg[2],
                                                   c_arg[3],
                                                   c_arg[4])
        elif len(args) == 6:
            rc = libseccomp.seccomp_rule_add_exact(self._ctx, action,
                                                   syscall_num, len(args),
                                                   c_arg[0],
                                                   c_arg[1],
                                                   c_arg[2],
                                                   c_arg[3],
                                                   c_arg[4],
                                                   c_arg[5])
        else:
            raise RuntimeError("Maximum number of arguments exceeded")
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def export_pfc(self, file):
        """ Export the filter in PFC format.

        Arguments:
        file - the output file

        Description:
        Output the filter in Pseudo Filter Code (PFC) to the given file.
        The output is functionally equivalent to the BPF based filter
        which is loaded into the Linux Kernel.
        """
        rc = libseccomp.seccomp_export_pfc(self._ctx, file.fileno())
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

    def export_bpf(self, file):
        """ Export the filter in BPF format.

        Arguments:
        file - the output file

        Output the filter in Berkley Packet Filter (BPF) to the given
        file.  The output is identical to what is loaded into the
        Linux Kernel.
        """
        rc = libseccomp.seccomp_export_bpf(self._ctx, file.fileno())
        if rc != 0:
            raise RuntimeError(str.format("Library error (errno = {0})", rc))

@cython.internal
cdef class _SeccompDataPtr:
    """Internal hack to workaround the fact that C objects can't be passed
    into __cinit__.
    """
    cdef libseccomp.seccomp_data *_ptr

@cython.final
cdef class TrappedSyscall:
    """Represents a syscall invocation that was trapped.

    The raw arguments are stored in the args array.  All syscalls will
    have the same number of arguments, and they relate to the
    logical arguments in an architecture-specific manner.
    """
    cdef libseccomp.seccomp_data _data
    cdef readonly object args

    def __cinit__(self, _SeccompDataPtr ptr):
        libc.string.memcpy(&self._data, ptr._ptr, cython.sizeof(self._data))
        self.args = [self._data.args[i] for i in xrange(6)]

    property arch:
        """The architecture of the trapped syscall"""
        def __get__(self):
            return self._data.arch

    property nr:
        """The trapped syscall number"""
        def __get__(self):
            return self._data.nr

    property name:
        """The name of the trapped syscall"""
        def __get__(self):
            try:
                return resolve_syscall(self.arch, self.nr)
            except KeyError:
                # Return something without spaces to minimize grammar problems.
                return 'arch%x_syscall%d' % (self.arch, self.nr)

    def __str__(self):
        return '%s(%s)' % (self.name, ', '.join('0x%X' % a for a in self.args))

    def __repr__(self):
        return '<TrappedSyscall %s>' % self

cdef object _trap_handler

cdef void _raw_trap_handler(int signum, libseccomp.siginfo_t *si, void *uc):
    cdef libseccomp.seccomp_data data
    cdef _SeccompDataPtr ptr
    val = None
    emulate = False

    try:
        if libseccomp.seccomp_sigsys_decode(&data, si, uc) == 0:
            ptr = _SeccompDataPtr()
            ptr._ptr = &data
            val = TrappedSyscall(ptr)

            retval = _trap_handler(val)

            if retval != None:
                if libseccomp.seccomp_sigsys_set_return_value(si, uc,
                                                              retval) == 0:
                    emulate = True
                    return

    finally:
        # XXX: It's possible for this to recurse.  We should do something
        # to prevent that and crash more gracefully (as opposed to eventually
        # dying when the stack overflows).
        if not emulate:
            _exit(libseccomp.SIGSYS)

def set_trap_handler(handler):
    """Sets a handler for trapped syscalls.  The handler will be passed a
    TrappedSyscall object as its argument or None if libseccomp could
    not decode the trapped syscall.

    This overrides the SIGSYS handler.  It will interact badly with
    other libraries (such as the standard Python signal library) that
    may manipulate the SIGSYS handler.

    The trap handler can return None to kill the process or it can return
    an integer to cause the syscall to appear to return that integer.

    Note that, if libseccomp is unable to set the syscall return value,
    it will kill the process instead.  (This is unlikely to happen unless
    you return an out-of-bounds value.)

    You can use set_trap_handler(trace_trapped_syscall) as an easy
    default to display a traceback and exit.  Alternatively, you can
    use set_trap_handler(print_trapped_syscall) to print a short message
    to stdout and exit.
    """
    global _trap_handler
    _trap_handler = handler

    cdef libseccomp.sigaction_struct sa
    libc.string.memset(&sa, 0, cython.sizeof(sa))
    sa.sa_sigaction = _raw_trap_handler
    sa.sa_flags = libseccomp.SA_SIGINFO | libseccomp.SA_NODEFER
    libseccomp.sigemptyset(&sa.sa_mask)

    libseccomp.sigaction(libseccomp.SIGSYS, &sa, NULL)

def get_trap_handler():
    """Returns the handler most recently loaded by set_trap_handler."""
    global _trap_handler
    return _trap_handler

def print_trapped_syscall(trapped_syscall):
    """A trap handler that prints a short message to stdout."""
    if trapped_syscall is not None:
        print 'Dying due to seccomp-blocked syscall %s' % trapped_syscall
    else:
        print 'Dying due to undecodable seccomp-blocked syscall'

def trace_trapped_syscall(trapped_syscall):
    """A trap handler that prints an explanation and traceback to stderr."""
    print >>sys.stderr, 'Dying due to seccomp-blocked syscall'
    print >>sys.stderr, 'Traceback (most recent call last):'
    traceback.print_stack()
    if trapped_syscall is not None:
        print >>sys.stderr, '  %s' % trapped_syscall
    else:
        print >>sys.stderr, '  Failed to decode the offending syscall'

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
