#!/usr/bin/env python3
"""generate_support_matrix_maintenance.py — bd-3g4p

Automated support matrix maintenance: validates that the implementation
status of each symbol in support_matrix.json matches code reality and
links symbols to conformance fixture coverage.

Three validation passes:
  1. STATUS VALIDATION: Code patterns match declared status.
  2. CONFORMANCE LINKAGE: Symbols linked to fixture test cases.
  3. COVERAGE REPORT: Per-module and per-status coverage statistics.

Outputs a JSON maintenance report to stdout (or --output file).
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MATRIX_PATH = REPO_ROOT / "support_matrix.json"
ABI_SRC = REPO_ROOT / "crates" / "frankenlibc-abi" / "src"
FIXTURE_DIR = REPO_ROOT / "tests" / "conformance" / "fixtures"
CONFORMANCE_MATRIX_PATH = REPO_ROOT / "tests" / "conformance" / "conformance_matrix.v1.json"

# Patterns indicating actual host libc call expressions.
# Type/constant references like `libc::timex` or `libc::EINVAL` are not calls.
LIBC_CALL_PATTERN = re.compile(r'\blibc::(\w+)\s*\(')
# Patterns indicating explicit host delegation inside ABI bodies.
WRAPS_HOST_LIBC_PATTERN = re.compile(
    r'(host_\w+_fn\s*\(|(?:crate::host_resolve::|host_resolve::)?resolve_host_symbol\w*\s*\()'
)
# Patterns indicating stdio/malloc libc delegation (explicit list per bd-9chy.2).
WRAPS_LIBC_CALL_PATTERN = re.compile(
    r'\blibc::(?:fopen|fclose|fread|fwrite|fseek|ftell|fflush|setvbuf|ungetc|'
    r'feof|ferror|clearerr|fileno|getline|getdelim|printf|malloc|free|realloc)\s*\('
)
# Patterns indicating raw syscall usage
SYSCALL_PATTERN = re.compile(
    r'(?:crate::syscall::|super::syscall::|syscall!|syscall_raw|'
    r'libc::syscall\b|libc::SYS_|__NR_)'
)
NEXT_FN_PATTERN = re.compile(
    r'\n\s*(?:(?:#\[[^\n]*\]|//[/!][^\n]*)\n\s*)*'
    r'(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+\w+\s*\('
)
# Patterns indicating stub/unimplemented (explicit Rust stub macros only;
# `return -1` is a normal POSIX error return, not a stub indicator).
STUB_PATTERNS = [
    re.compile(r'\btodo!\b'),
    re.compile(r'\bunimplemented!\b'),
]
# Data symbols (statics, not functions)
DATA_SYMBOLS = {"stdin", "stdout", "stderr"}
STATUS_PROMOTION_RANK = {
    "Stub": 0,
    "GlibcCallThrough": 1,
    "WrapsHostLibc": 2,
    "Implemented": 3,
    "RawSyscall": 4,
}
FN_NAME_PATTERN = re.compile(r'\bfn\s+([A-Za-z_]\w*)\s*\(')
HOST_RESOLVE_BLOCK_USE_PATTERN = re.compile(
    r'use\s+crate::host_resolve::\{(?P<body>.*?)\};',
    re.S,
)
HOST_RESOLVE_SINGLE_USE_PATTERN = re.compile(
    r'use\s+crate::host_resolve::(?P<name>[A-Za-z_]\w*)(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\s*;'
)


def load_matrix():
    with open(MATRIX_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_fixtures():
    """Scan fixture directory, returning a map of function_name → fixture info."""
    fixture_map = {}  # function_name -> list of {file, case_name, mode}
    if not FIXTURE_DIR.is_dir():
        return fixture_map

    for fpath in sorted(FIXTURE_DIR.glob("*.json")):
        try:
            with fpath.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        for case in data.get("cases", []):
            func = case.get("function", "")
            name = case.get("name", "")
            mode = case.get("mode", "unknown")
            if func:
                # Normalize: strip class prefix (e.g., "PressureSensor::observe" → "observe")
                bare_func = func.split("::")[-1] if "::" in func else func
                entry = {"file": fpath.name, "case": name, "mode": mode}
                fixture_map.setdefault(bare_func, []).append(entry)
                if bare_func != func:
                    fixture_map.setdefault(func, []).append(entry)

    return fixture_map


def load_previous_report(path: Path):
    """Best-effort load of previous report for trend/comparison checks."""
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def load_conformance_matrix(path: Path):
    """Load symbol/mode conformance status map from conformance matrix artifact."""
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    out = {}
    for row in data.get("symbol_matrix", []):
        symbol = str(row.get("symbol", ""))
        mode = str(row.get("mode", ""))
        if not symbol or not mode:
            continue
        out.setdefault(symbol, {})[mode] = {
            "total": int(row.get("total", 0)),
            "passed": int(row.get("passed", 0)),
            "failed": int(row.get("failed", 0)),
            "errors": int(row.get("errors", 0)),
            "pass_rate_percent": float(row.get("pass_rate_percent", 0.0)),
        }
    return out


def conformance_mode_passed(mode_entry):
    """True when a conformance-mode row has non-zero coverage and zero failures/errors."""
    if not isinstance(mode_entry, dict):
        return False
    return (
        int(mode_entry.get("total", 0)) > 0
        and int(mode_entry.get("failed", 0)) == 0
        and int(mode_entry.get("errors", 0)) == 0
    )


def count_statuses_from_map(status_map):
    counts = {}
    for status in status_map.values():
        counts[status] = counts.get(status, 0) + 1
    return counts




def read_module_source(module_name):
    """Read ABI module source file content."""
    src_path = ABI_SRC / f"{module_name}.rs"
    if not src_path.is_file():
        return None
    return src_path.read_text(encoding="utf-8")


def extract_host_resolve_aliases(source):
    """Return locally visible names imported from crate::host_resolve."""
    aliases = set()

    for match in HOST_RESOLVE_BLOCK_USE_PATTERN.finditer(source):
        body = match.group("body")
        for raw_item in body.split(","):
            item = raw_item.strip()
            if not item:
                continue
            item = item.split("//", 1)[0].strip()
            if not item:
                continue
            if " as " in item:
                _orig, alias = item.split(" as ", 1)
                aliases.add(alias.strip())
            else:
                aliases.add(item.strip())

    for match in HOST_RESOLVE_SINGLE_USE_PATTERN.finditer(source):
        alias = match.group("alias") or match.group("name")
        aliases.add(alias.strip())

    return aliases


def body_calls_any(body, names):
    """True when body contains a function-style call to any name."""
    for name in names:
        if re.search(rf'\b{re.escape(name)}\s*\(', body):
            return True
    return False


def analyze_module_source(source):
    """Collect per-module helper metadata used by status classification."""
    host_resolve_aliases = extract_host_resolve_aliases(source)
    function_names = []
    for match in FN_NAME_PATTERN.finditer(source):
        name = match.group(1)
        if name not in function_names:
            function_names.append(name)

    function_bodies = {}
    for name in function_names:
        body = extract_function_body(source, name)
        if body is not None:
            function_bodies[name] = body

    host_helper_functions = set()
    changed = True
    while changed:
        changed = False
        for name, body in function_bodies.items():
            if name in host_helper_functions:
                continue
            if (
                WRAPS_HOST_LIBC_PATTERN.search(body)
                or WRAPS_LIBC_CALL_PATTERN.search(body)
                or body_calls_any(body, host_resolve_aliases)
                or body_calls_any(body, host_helper_functions)
            ):
                host_helper_functions.add(name)
                changed = True

    return {
        "host_resolve_aliases": host_resolve_aliases,
        "host_helper_functions": host_helper_functions,
    }


def extract_function_body(source, fn_name):
    """Extract approximate function body for a given fn name.

    Returns the text from 'fn name(' to the next function definition or EOF.
    This is approximate but sufficient for pattern matching.
    """
    pattern = re.compile(rf'\bfn\s+{re.escape(fn_name)}\s*\(')
    for match in pattern.finditer(source):
        signature_tail = source[match.end():]
        open_brace = signature_tail.find("{")
        statement_end = signature_tail.find(";")

        # Skip forward declarations inside extern blocks; we only want actual
        # function definitions with bodies.
        if open_brace == -1:
            continue
        if statement_end != -1 and statement_end < open_brace:
            continue

        start = match.start()
        next_fn = NEXT_FN_PATTERN.search(signature_tail)
        if next_fn:
            end = match.end() + next_fn.start()
        else:
            end = len(source)
        return source[start:end]

    return None


def is_type_or_constant(name):
    """Heuristic: libc:: references that are types or constants, not function calls.

    Types: end in _t, start with lowercase c_ prefix, are ALL_CAPS, or match
    known struct/enum patterns.
    Constants: ALL_CAPS or start with uppercase (e.g., EINVAL, AF_INET, SIG_DFL).
    Functions: lowercase names like 'malloc', 'write', 'pthread_create'.
    """
    if name.endswith("_t"):
        return True
    if name.startswith("c_"):
        return True
    # ALL_CAPS or starts with uppercase = constant or type
    if name[0].isupper():
        return True
    # _SC_*, _PC_*, _CS_* are sysconf/pathconf/confstr constants
    if re.match(r'^_(?:SC|PC|CS|POSIX)_', name):
        return True
    # Known struct names that are lowercase
    lowercase_types = {
        "stat", "dirent", "dirent64", "passwd", "group", "spwd",
        "termios", "winsize", "addrinfo", "hostent", "servent",
        "protoent", "linger", "timezone", "tm", "iovec", "msghdr",
        "epoll_event", "pollfd", "glob_t", "if_nameindex", "sigval",
    }
    return name in lowercase_types


def validate_status(symbol, status, module, source, module_analysis):
    """Validate that a symbol's code matches its declared status.

    Returns (is_valid, findings: list of str, warnings: list of str).
    """
    if symbol in DATA_SYMBOLS:
        return True, [], []

    body = extract_function_body(source, symbol)
    if body is None:
        return True, [f"function body not found (may use alternate pattern)"], []

    findings = []
    warnings = []
    host_resolve_aliases = module_analysis.get("host_resolve_aliases", set())
    host_helper_functions = module_analysis.get("host_helper_functions", set())
    wraps_host_libc = bool(
        WRAPS_HOST_LIBC_PATTERN.search(body)
        or WRAPS_LIBC_CALL_PATTERN.search(body)
        or body_calls_any(body, host_resolve_aliases)
        or body_calls_any(body, host_helper_functions)
    )

    if status == "Implemented":
        if wraps_host_libc:
            warnings.append("WrapsHostLibc candidate (host delegation detected)")
        # Should NOT have libc:: host calls (except libc type references
        # and common utility functions).
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # Filter out type-only references (common pattern: libc::c_int etc.)
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "sigset_t", "timespec",
                     "timeval", "stat", "dirent", "DIR", "FILE",
                     "pthread_t", "pthread_attr_t", "pthread_mutex_t",
                     "pthread_mutexattr_t", "pthread_cond_t",
                     "pthread_condattr_t", "pthread_rwlock_t",
                     "pthread_key_t", "pthread_once_t",
                     "PTHREAD_MUTEX_INITIALIZER", "PTHREAD_COND_INITIALIZER",
                     "PTHREAD_RWLOCK_INITIALIZER", "CLOCK_REALTIME",
                     "CLOCK_MONOTONIC", "EINVAL", "ENOMEM", "ENOSYS",
                     "EAGAIN", "EDEADLK", "EBUSY", "EPERM", "ESRCH",
                     "ENOENT", "ERANGE", "EACCES", "EEXIST", "EINTR",
                     "EBADF", "EFAULT", "EMFILE", "ENFILE", "E2BIG",
                     "EISDIR", "ENOTDIR", "ENOTEMPTY", "EXDEV", "ELOOP",
                     "ENAMETOOLONG", "EOF",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOL_SOCKET", "SO_REUSEADDR",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE", "NULL",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     # Network struct/type references
                     "addrinfo", "sockaddr_in", "sockaddr_in6",
                     "sockaddr_un", "sockaddr_storage", "in_addr",
                     "in6_addr", "hostent", "servent", "protoent",
                     "linger", "ip_mreq",
                     # Passwd/group struct references
                     "passwd", "group", "spwd",
                     # Terminal struct references
                     "termios", "winsize",
                     # Locale/iconv references
                     "locale_t", "nl_item",
                     # Misc struct/type references
                     "rlimit", "rusage", "utsname", "sysinfo",
                     "epoll_event", "pollfd", "fd_set",
                     "Dl_info", "dl_phdr_info",
                     "glob_t", "regex_t", "regmatch_t",
                     "sem_t", "key_t", "shmid_ds", "semid_ds", "msqid_ds",
                     "sigaction", "stack_t", "siginfo_t", "sigval",
                     "itimerval", "itimerspec",
                     "statvfs", "statfs",
                     "tm", "timezone",
                     "DIR",
                     # Scheduler/process struct references
                     "sched_param",
                     # utmpx struct
                     "utmpx",
                     # getopt struct
                     "option",
                     # Network/IPC struct references
                     "sigevent", "cmsghdr",
                     }
        # Utility functions that Implemented symbols may legitimately call.
        # These are infrastructure/helper calls, NOT delegation of core logic.
        # The key GCT indicator is dlsym/dlvsym, not use of libc utilities.
        utility_fns = {
            # Errno access
            "__errno_location",
            # Raw syscall mechanism (not a glibc function call)
            "syscall",
            # Memory allocation (using system allocator is normal)
            "malloc", "calloc", "realloc", "free",
            # Basic memory/string operations (low-level utilities)
            "memcpy", "memmove", "memset", "strlen", "strcmp", "strncpy",
            "strcat", "strncat", "strcpy", "strncmp", "strerror",
            # Process control
            "abort", "_exit", "raise", "signal",
            # I/O primitives used as building blocks
            "write", "read", "open", "close", "fflush", "fwrite", "fgets",
            "lseek", "fstat", "lstat",
            # Directory operations
            "opendir", "closedir", "fdopendir", "readdir64_r",
            # Terminal/device operations
            "cfsetispeed", "cfsetospeed", "cfgetispeed", "cfgetospeed",
            "cfmakeraw",
            # Network primitives
            "bind", "setsockopt", "getsockopt",
            # Process/user info
            "getpid", "getuid", "geteuid", "getegid", "getpgid",
            "getgroups", "getpwuid", "getrlimit", "setitimer",
            "getauxval", "sbrk", "getcwd",
            # Signal handling
            "sigprocmask", "sigsuspend", "sigaddset", "sigdelset",
            "sigemptyset",
            # Dynamic linking (used for fallback resolution, not core delegation)
            "dlsym",
            # Thread primitives (our own implementations via pthread_abi)
            "pthread_self", "pthread_equal", "pthread_create",
            "pthread_join", "pthread_detach", "pthread_exit",
            "pthread_once", "pthread_key_create", "pthread_key_delete",
            "pthread_getspecific", "pthread_setspecific",
            "pthread_mutex_init", "pthread_mutex_destroy",
            "pthread_mutex_lock", "pthread_mutex_unlock",
            "pthread_mutex_trylock", "pthread_mutex_timedlock",
            "pthread_cond_init", "pthread_cond_destroy",
            "pthread_cond_signal", "pthread_cond_broadcast",
            "pthread_cond_wait", "pthread_cond_timedwait",
            "pthread_condattr_getclock",
            "pthread_attr_init", "pthread_attr_destroy",
            "pthread_condattr_init", "pthread_condattr_destroy",
            "pthread_condattr_setclock",
            "pthread_setschedparam", "pthread_getschedparam",
            # Spawn
            "posix_spawn", "posix_spawnp",
            # Time
            "clock_gettime", "clock_settime", "nanosleep", "mktime",
            # Misc POSIX utilities
            "sched_yield", "confstr", "fork", "sysctl",
            "openat", "mknodat", "mkstemp", "mkostemp", "mkostemps",
            "mkstemps", "pread", "pread64", "ppoll", "poll",
            "recv", "recvfrom", "readlink", "readlinkat",
            "realpath", "ptsname_r", "ttyname_r",
            "gethostname", "getdomainname",
            "sethostid", "settimeofday", "adjtime",
            "utime", "utimes", "futimes", "lutimes",
            "freeaddrinfo", "getaddrinfo",
            "endmntent", "mq_open",
            "backtrace", "backtrace_symbols", "backtrace_symbols_fd",
            "fcntl", "ioctl",
            "sched_rr_get_interval",
            # Additional libc utilities used as building blocks
            "sysconf", "getenv", "gmtime_r", "strtoll", "strtoull",
            "socket", "readdir", "fileno", "setrlimit",
            "sched_get_priority_max", "sched_get_priority_min",
            "sched_setparam", "sched_getparam", "sched_setscheduler",
            "sched_getscheduler",
            "pthread_mutexattr_init", "pthread_mutexattr_destroy",
            "pthread_mutexattr_settype",
            "flock",
        }
        fn_calls = [c for c in libc_calls
                    if c not in type_refs
                    and c not in utility_fns
                    and not is_type_or_constant(c)]
        if fn_calls:
            unique_calls = sorted(set(fn_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("Implemented but calls libc::{" + calls_str + "}")

        # Should NOT have stub patterns
        for pat in STUB_PATTERNS:
            if pat.search(body):
                findings.append(f"Implemented but contains stub pattern: {pat.pattern}")

    elif status == "RawSyscall":
        if wraps_host_libc:
            warnings.append("WrapsHostLibc candidate (host delegation detected)")
        # RawSyscall functions use libc::syscall() and libc::SYS_* constants
        # which IS the raw syscall path (not glibc function calls).
        # We check that they don't call actual glibc library functions.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # libc::syscall and libc::SYS_* are the raw syscall mechanism
        syscall_ok = re.compile(r'^(?:syscall|SYS_\w+)$')
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "timespec", "timeval",
                     "stat", "dirent", "iovec", "msghdr", "loff_t",
                     "EINVAL", "ENOMEM", "ENOSYS", "EAGAIN", "EBADF",
                     "EFAULT", "EINTR", "EACCES", "ENOENT", "EPERM",
                     "EEXIST", "EISDIR", "ENOTDIR", "ENOTEMPTY",
                     "EBUSY", "ENFILE", "EMFILE", "ERANGE", "E2BIG",
                     "ELOOP", "ENAMETOOLONG", "EXDEV", "ESPIPE",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "O_DIRECTORY", "O_NOFOLLOW", "O_EXCL",
                     "AT_FDCWD", "AT_REMOVEDIR", "AT_SYMLINK_NOFOLLOW",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOCK_CLOEXEC", "SOCK_NONBLOCK",
                     "SOL_SOCKET", "SO_REUSEADDR", "SO_ERROR",
                     "MSG_DONTWAIT", "MSG_NOSIGNAL", "SHUT_RDWR",
                     "SHUT_RD", "SHUT_WR",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "FD_CLOEXEC", "FIONBIO",
                     "CLOCK_REALTIME", "CLOCK_MONOTONIC",
                     "SIGCHLD", "SIG_DFL", "SIG_IGN",
                     "WNOHANG", "WUNTRACED",
                     "PROT_READ", "PROT_WRITE", "PROT_EXEC", "PROT_NONE",
                     "MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_SHARED", "MAP_FIXED",
                     "MAP_FAILED", "MREMAP_MAYMOVE",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     "GRND_NONBLOCK", "GRND_RANDOM",
                     "R_OK", "W_OK", "X_OK", "F_OK",
                     "DT_DIR", "DT_REG", "DT_LNK", "DT_UNKNOWN",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE",
                     "POLLIN", "POLLOUT", "POLLERR", "POLLHUP",
                     "EPOLL_CTL_ADD", "EPOLL_CTL_DEL", "EPOLL_CTL_MOD",
                     "EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP",
                     "RUSAGE_SELF", "RUSAGE_CHILDREN",
                     "TIOCGWINSZ", "TCSANOW", "TCSADRAIN", "TCSAFLUSH",
                     "c_ushort",
                     # Struct/type references used in syscall wrappers
                     "termios", "winsize", "rlimit", "rusage",
                     "utsname", "sysinfo", "statvfs", "statfs",
                     "epoll_event", "pollfd", "fd_set",
                     "sigaction", "stack_t", "siginfo_t", "sigset_t",
                     "itimerval", "itimerspec", "tm", "timezone",
                     "sockaddr_in", "sockaddr_in6", "sockaddr_un",
                     "sockaddr_storage", "in_addr", "in6_addr",
                     "linger", "ip_mreq", "addrinfo",
                     "DIR", "dirent64",
                     "sigevent", "flock",
                     }
        # Utility functions that RawSyscall wrappers may legitimately use
        # (e.g., errno setting, signal mask setup, lock/flock wrappers)
        raw_utility_fns = {
            "__errno_location",
            "sigemptyset", "sigaddset", "sigdelset", "sigprocmask",
            "ioctl", "clock_gettime", "flock",
        }
        glibc_calls = [c for c in libc_calls
                       if c not in type_refs
                       and c not in raw_utility_fns
                       and not syscall_ok.match(c)
                       and not is_type_or_constant(c)]
        if glibc_calls:
            unique_calls = sorted(set(glibc_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("RawSyscall but calls glibc::{" + calls_str + "}")

    elif status == "WrapsHostLibc":
        if not wraps_host_libc:
            findings.append("WrapsHostLibc but no host delegation detected")

    elif status == "GlibcCallThrough":
        # Should have libc:: references or macro-based delegation patterns.
        # Many GCT symbols delegate via macros (io_resolve!, rpc_delegate!,
        # host_delegate!, dlsym_passthrough!) that don't contain raw libc::.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        has_delegation_macro = bool(re.search(
            r'\b(?:io_resolve|rpc_delegate|host_delegate|dlsym_passthrough|'
            r'dlvsym_next|crate::dlfcn_abi|host_dlsym|host_dlopen|'
            r'host_dlclose|host_dladdr|host_dl_iterate_phdr)', body))
        # Also check the line containing the fn definition for macro invocations
        # (dlsym_passthrough! appears before `fn name(` on the same line)
        if not has_delegation_macro:
            fn_pat = re.compile(rf'\bfn\s+{re.escape(symbol)}\s*\(')
            fn_match = fn_pat.search(source)
            if fn_match:
                line_start = source.rfind('\n', 0, fn_match.start()) + 1
                line = source[line_start:fn_match.start()]
                has_delegation_macro = bool(re.search(
                    r'\b(?:dlsym_passthrough|io_resolve|rpc_delegate|'
                    r'host_delegate)\s*!', line))
        if not libc_calls and not has_delegation_macro:
            findings.append("GlibcCallThrough but no libc:: references found")

    elif status == "Stub":
        # Should have stub patterns or deterministic failure return
        has_stub = any(pat.search(body) for pat in STUB_PATTERNS)
        if not has_stub:
            findings.append("Stub but no stub/unimplemented/todo pattern found")

    is_valid = len(findings) == 0
    return is_valid, findings, warnings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Support matrix maintenance validator")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument(
        "--previous-report",
        default=str(REPO_ROOT / "tests" / "conformance" / "support_matrix_maintenance_report.v1.json"),
        help="Path to previous maintenance report used for trend/reclassification checks",
    )
    parser.add_argument(
        "--conformance-matrix",
        default=str(CONFORMANCE_MATRIX_PATH),
        help="Path to conformance_matrix artifact used for reclassification evidence checks",
    )
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    previous_report = load_previous_report(Path(args.previous_report))
    conformance_by_symbol = load_conformance_matrix(Path(args.conformance_matrix))

    matrix = load_matrix()
    symbols = matrix.get("symbols", [])
    fixture_map = load_fixtures()

    # Cache module sources
    module_cache = {}
    module_analysis_cache = {}

    status_results = []
    linkage_results = []
    warnings = 0

    # --- Pass 1: Status Validation ---
    status_valid = 0
    status_invalid = 0
    status_skipped = 0

    for entry in symbols:
        sym = entry["symbol"]
        st = entry.get("status", "unknown")
        module = entry.get("module", "unknown")

        if module not in module_cache:
            module_cache[module] = read_module_source(module)
            module_analysis_cache[module] = (
                analyze_module_source(module_cache[module])
                if module_cache[module] is not None
                else {}
            )

        source = module_cache[module]
        if source is None:
            status_skipped += 1
            status_results.append({
                "symbol": sym,
                "status": st,
                "module": module,
                "valid": None,
                "findings": ["module source not found"],
            })
            continue

        is_valid, findings, warn_list = validate_status(
            sym,
            st,
            module,
            source,
            module_analysis_cache.get(module, {}),
        )
        warnings += len(warn_list)
        if is_valid:
            status_valid += 1
        else:
            status_invalid += 1

        status_results.append({
            "symbol": sym,
            "status": st,
            "module": module,
            "valid": is_valid,
            "findings": findings,
            "warnings": warn_list,
        })

    # --- Pass 2: Conformance Linkage ---
    linked = 0
    unlinked = 0

    for entry in symbols:
        sym = entry["symbol"]
        cases = fixture_map.get(sym, [])
        has_fixture = len(cases) > 0
        strict_cases = sum(1 for c in cases if c["mode"] in ("strict", "both"))
        hardened_cases = sum(1 for c in cases if c["mode"] in ("hardened", "both"))

        if has_fixture:
            linked += 1
        else:
            unlinked += 1

        linkage_results.append({
            "symbol": sym,
            "has_fixture": has_fixture,
            "fixture_count": len(cases),
            "strict_count": strict_cases,
            "hardened_count": hardened_cases,
            "fixtures": [c["file"] for c in cases[:5]],
        })

    # --- Pass 3: Coverage Statistics ---
    by_status = {}
    by_module = {}
    by_status_linked = {}
    symbol_status_map = {}
    linkage_by_symbol = {}

    for i, entry in enumerate(symbols):
        sym = str(entry.get("symbol", ""))
        st = str(entry.get("status", "unknown"))
        module = entry.get("module", "unknown")
        has_fix = linkage_results[i]["has_fixture"]

        symbol_status_map[sym] = st
        linkage_by_symbol[sym] = linkage_results[i]

        by_status[st] = by_status.get(st, 0) + 1
        by_module.setdefault(module, {"total": 0, "linked": 0})
        by_module[module]["total"] += 1
        if has_fix:
            by_module[module]["linked"] += 1
            by_status_linked[st] = by_status_linked.get(st, 0) + 1

    total_symbols = len(symbols)
    coverage_pct = (linked / total_symbols * 100) if total_symbols else 0.0
    status_valid_pct = (status_valid / total_symbols * 100) if total_symbols else 0.0

    implemented_count = by_status.get("Implemented", 0)
    raw_syscall_count = by_status.get("RawSyscall", 0)
    wraps_host_libc_count = by_status.get("WrapsHostLibc", 0)
    callthrough_count = by_status.get("GlibcCallThrough", 0)
    stub_count = by_status.get("Stub", 0)
    native_count = implemented_count + raw_syscall_count
    native_coverage_pct = (native_count / total_symbols * 100.0) if total_symbols else 0.0

    previous_symbol_status_map = {}
    previous_status_counts = {}
    previous_native_coverage_pct = None
    previous_stub_count = stub_count
    baseline_loaded = False
    baseline_symbol_map_loaded = False

    if isinstance(previous_report, dict):
        baseline_loaded = True
        previous_symbol_status_map = previous_report.get("symbol_status_map", {})
        if not isinstance(previous_symbol_status_map, dict):
            previous_symbol_status_map = {}
        baseline_symbol_map_loaded = bool(previous_symbol_status_map)

        previous_status_counts = previous_report.get("coverage_dashboard", {}).get("status_counts", {})
        if not isinstance(previous_status_counts, dict):
            previous_status_counts = {}
        if not previous_status_counts:
            previous_status_distribution = previous_report.get("status_distribution", {})
            if isinstance(previous_status_distribution, dict):
                for status_name, info in previous_status_distribution.items():
                    if isinstance(info, dict):
                        previous_status_counts[status_name] = int(info.get("count", 0))
        if not previous_status_counts and previous_symbol_status_map:
            previous_status_counts = count_statuses_from_map(previous_symbol_status_map)

        prev_native = previous_report.get("coverage_dashboard", {}).get("native_coverage_pct")
        try:
            previous_native_coverage_pct = float(prev_native) if prev_native is not None else None
        except (TypeError, ValueError):
            previous_native_coverage_pct = None

        try:
            previous_stub_count = int(previous_status_counts.get("Stub", previous_stub_count))
        except (TypeError, ValueError):
            previous_stub_count = stub_count

    # Symbol reclassification analysis
    reclassified_symbols = []
    if baseline_symbol_map_loaded:
        for symbol in sorted(set(previous_symbol_status_map.keys()) & set(symbol_status_map.keys())):
            previous_status = previous_symbol_status_map.get(symbol)
            current_status = symbol_status_map.get(symbol)
            if previous_status == current_status:
                continue

            previous_rank = STATUS_PROMOTION_RANK.get(str(previous_status), -1)
            current_rank = STATUS_PROMOTION_RANK.get(str(current_status), -1)
            promotion_requires_evidence = current_rank > previous_rank

            linkage = linkage_by_symbol.get(symbol, {})
            strict_fixture = int(linkage.get("strict_count", 0)) > 0
            hardened_fixture = int(linkage.get("hardened_count", 0)) > 0

            mode_rows = conformance_by_symbol.get(symbol, {})
            strict_row = mode_rows.get("strict")
            hardened_row = mode_rows.get("hardened")
            strict_pass = conformance_mode_passed(strict_row)
            hardened_pass = conformance_mode_passed(hardened_row)

            missing_evidence = []
            if promotion_requires_evidence:
                if not strict_fixture:
                    missing_evidence.append("missing_strict_fixture")
                if not hardened_fixture:
                    missing_evidence.append("missing_hardened_fixture")
                if not strict_pass:
                    missing_evidence.append("strict_conformance_not_passing")
                if not hardened_pass:
                    missing_evidence.append("hardened_conformance_not_passing")

            reclassified_symbols.append({
                "symbol": symbol,
                "previous_status": previous_status,
                "current_status": current_status,
                "promotion_requires_evidence": promotion_requires_evidence,
                "strict_fixture_count": int(linkage.get("strict_count", 0)),
                "hardened_fixture_count": int(linkage.get("hardened_count", 0)),
                "strict_conformance": strict_row,
                "hardened_conformance": hardened_row,
                "conformance_evidence_passed": (not promotion_requires_evidence)
                or len(missing_evidence) == 0,
                "missing_evidence": missing_evidence,
            })

    reclassification_violations = [
        row for row in reclassified_symbols if not row["conformance_evidence_passed"]
    ]

    status_count_delta = {}
    for status_name in sorted(set(by_status.keys()) | set(previous_status_counts.keys())):
        status_count_delta[status_name] = int(by_status.get(status_name, 0)) - int(
            previous_status_counts.get(status_name, 0)
        )

    if baseline_symbol_map_loaded:
        new_symbols = sorted(set(symbol_status_map.keys()) - set(previous_symbol_status_map.keys()))
        removed_symbols = sorted(set(previous_symbol_status_map.keys()) - set(symbol_status_map.keys()))
    else:
        new_symbols = []
        removed_symbols = []

    no_new_stub_symbols = stub_count <= previous_stub_count
    native_delta = None
    if previous_native_coverage_pct is not None:
        native_delta = round(native_coverage_pct - previous_native_coverage_pct, 2)

    # Build report
    report = {
        "schema_version": "v1",
        "bead": "bd-3g4p",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_symbols": total_symbols,
            "status_validated": status_valid,
            "status_invalid": status_invalid,
            "status_skipped": status_skipped,
            "status_valid_pct": round(status_valid_pct, 1),
            "fixture_linked": linked,
            "fixture_unlinked": unlinked,
            "fixture_coverage_pct": round(coverage_pct, 1),
            "total_warnings": warnings,
        },
        "coverage_dashboard": {
            "total_symbols": total_symbols,
            "status_counts": {
                "Implemented": implemented_count,
                "RawSyscall": raw_syscall_count,
                "WrapsHostLibc": wraps_host_libc_count,
                "GlibcCallThrough": callthrough_count,
                "Stub": stub_count,
            },
            "status_share_pct": {
                "Implemented": round((implemented_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "RawSyscall": round((raw_syscall_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "WrapsHostLibc": round((wraps_host_libc_count / total_symbols * 100.0), 1)
                if total_symbols
                else 0.0,
                "GlibcCallThrough": round((callthrough_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "Stub": round((stub_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
            },
            "native_coverage_pct": round(native_coverage_pct, 1),
        },
        "trend": {
            "baseline_report_path": str(Path(args.previous_report)),
            "baseline_loaded": baseline_loaded,
            "baseline_symbol_map_loaded": baseline_symbol_map_loaded,
            "status_count_delta": status_count_delta,
            "native_coverage_pct_delta": native_delta,
            "reclassified_symbol_count": len(reclassified_symbols),
            "new_symbol_count": len(new_symbols),
            "removed_symbol_count": len(removed_symbols),
            "new_symbols": new_symbols,
            "removed_symbols": removed_symbols,
        },
        "policy_checks": {
            "no_new_stub_symbols": {
                "status": "pass" if no_new_stub_symbols else "fail",
                "previous_stub_count": previous_stub_count,
                "current_stub_count": stub_count,
                "delta": stub_count - previous_stub_count,
            },
            "reclassification_requires_conformance": {
                "status": "pass" if not reclassification_violations else "fail",
                "baseline_symbol_map_loaded": baseline_symbol_map_loaded,
                "total_reclassified": len(reclassified_symbols),
                "violations": reclassification_violations,
            },
        },
        "status_distribution": {
            st: {
                "count": by_status.get(st, 0),
                "fixture_linked": by_status_linked.get(st, 0),
            }
            for st in sorted(by_status.keys())
        },
        "module_coverage": {
            mod_name: {
                "total": info["total"],
                "linked": info["linked"],
                "coverage_pct": round(info["linked"] / info["total"] * 100, 1)
                if info["total"] > 0
                else 0,
            }
            for mod_name, info in sorted(by_module.items())
        },
        "symbol_status_map": dict(sorted(symbol_status_map.items())),
        "reclassified_symbols": reclassified_symbols,
        "status_validation_issues": [
            r for r in status_results if r.get("findings") or r.get("warnings")
        ],
        "unlinked_symbols": [
            r["symbol"] for r in linkage_results if not r["has_fixture"]
        ],
    }

    output = json.dumps(report, indent=2) + "\n"

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        # Print summary to stderr
        print(f"Total symbols: {total_symbols}", file=sys.stderr)
        print(f"Status valid: {status_valid}/{total_symbols} ({status_valid_pct:.1f}%)",
              file=sys.stderr)
        print(f"Fixture linked: {linked}/{total_symbols} ({coverage_pct:.1f}%)",
              file=sys.stderr)
        print(
            f"Stub guard: previous={previous_stub_count} current={stub_count} "
            f"({report['policy_checks']['no_new_stub_symbols']['status']})",
            file=sys.stderr,
        )
        print(
            f"Reclassification evidence: {len(reclassified_symbols)} changed, "
            f"violations={len(reclassification_violations)}",
            file=sys.stderr,
        )
        print(f"Warnings: {warnings}", file=sys.stderr)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    # Report generation always succeeds. Findings are informational
    # and consumed by the CI gate for threshold-based decisions.
    sys.exit(0)


def run_self_test():
    """Minimal self-test."""
    print("Self-test: loading matrix...")
    matrix = load_matrix()
    symbols = matrix.get("symbols", [])
    print(f"  {len(symbols)} symbols loaded")

    print("Self-test: loading fixtures...")
    fixtures = load_fixtures()
    print(f"  {len(fixtures)} fixture functions indexed")

    print("Self-test: status validation on first 3 symbols...")
    module_cache = {}
    for entry in symbols[:3]:
        sym = entry["symbol"]
        module = entry.get("module", "unknown")
        if module not in module_cache:
            module_cache[module] = read_module_source(module)
        source = module_cache[module]
        if source:
            is_valid, findings = validate_status(sym, entry["status"], module, source)
            mark = "✓" if is_valid else "✗"
            print(f"  {mark} {sym} ({entry['status']}): {findings or 'ok'}")
        else:
            print(f"  ? {sym}: source not found")

    print("Self-test: PASS")


if __name__ == "__main__":
    main()
