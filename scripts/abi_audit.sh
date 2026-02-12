#!/usr/bin/env bash
# ABI symbol audit: exported symbol list + support classification.
#
# Produces:
#   1. Machine-readable support_matrix.json
#   2. Human-readable summary to stdout
#
# Usage:
#   bash scripts/abi_audit.sh [--json-only] [--deterministic]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUR_LIB="${PROJECT_ROOT}/target/release/libglibc_rs_abi.so"
ALT_LIB="/data/tmp/cargo-target/release/libglibc_rs_abi.so"
HOST_LIB="/usr/lib/x86_64-linux-gnu/libc.so.6"
MATRIX_OUT="${PROJECT_ROOT}/support_matrix.json"

JSON_ONLY=0
DETERMINISTIC=0
for arg in "$@"; do
  case "${arg}" in
    --json-only)
      JSON_ONLY=1
      ;;
    --deterministic)
      DETERMINISTIC=1
      ;;
    *)
      echo "ERROR: unsupported argument: ${arg}" >&2
      echo "Usage: bash scripts/abi_audit.sh [--json-only] [--deterministic]" >&2
      exit 2
      ;;
  esac
done

# Use alternate target dir if default doesn't exist.
if [[ ! -f "${OUR_LIB}" ]] && [[ -f "${ALT_LIB}" ]]; then
  OUR_LIB="${ALT_LIB}"
fi

if [[ ! -f "${OUR_LIB}" ]]; then
  echo "ERROR: Library not found. Build with: cargo build --release -p glibc-rs-abi" >&2
  exit 1
fi

# ------------------------------------------------------------------
# Symbol classification database.
# Status: Implemented | RawSyscall | GlibcCallThrough | Stub
# PerfClass: strict_hotpath | hardened_hotpath | coldpath
# ------------------------------------------------------------------

declare -A SYM_STATUS
declare -A SYM_MODULE
declare -A SYM_PERF

declare -A MOD_STRICT
declare -A MOD_HARDENED

MOD_STRICT[malloc_abi]="Safe Rust arena allocator; null on failure; double-free silently ignored"
MOD_HARDENED[malloc_abi]="Arena with healing: foreign-ptr realloc as malloc, double-free logged as HealingAction"

MOD_STRICT[string_abi]="Safe Rust string/memory ops; unbounded scans follow C semantics; no repair"
MOD_HARDENED[string_abi]="Clamps copy/scan to tracked allocation bounds; logs ClampSize/TruncateWithNull"

MOD_STRICT[wchar_abi]="Safe Rust wide-char ops; follows C semantics; no repair"
MOD_HARDENED[wchar_abi]="Clamps wide-char copy/scan to tracked allocation bounds; logs ClampSize"

MOD_STRICT[stdlib_abi]="Safe Rust stdlib (atoi/qsort/bsearch); POSIX-correct return values and errno"
MOD_HARDENED[stdlib_abi]="Stdlib with hardened membrane; repair clamping on comparator bounds"

MOD_STRICT[errno_abi]="Thread-local errno via Rust; ABI-compatible __errno_location pointer"
MOD_HARDENED[errno_abi]="Thread-local errno; no mode difference (stateless query)"

MOD_STRICT[math_abi]="Rust std::f64 math; returns NaN/Inf per IEEE 754; no repair"
MOD_HARDENED[math_abi]="Rust std::f64 math; no mode difference (pure computation)"

MOD_STRICT[ctype_abi]="Lookup-table ctype classification; returns 0/1 per POSIX C locale"
MOD_HARDENED[ctype_abi]="Lookup-table ctype; no mode difference (pure computation)"

MOD_STRICT[stdio_abi]="Delegates to host glibc FILE* ops after membrane validation; preserves host semantics"
MOD_HARDENED[stdio_abi]="Host glibc delegation; hardened membrane bounds C string scans, logs TruncateWithNull"

MOD_STRICT[io_abi]="Raw Linux syscall for dup/dup2/pipe/fcntl; POSIX errno on failure"
MOD_HARDENED[io_abi]="Raw syscall with hardened membrane; repair on invalid flags"

MOD_STRICT[unistd_abi]="Raw Linux syscall for POSIX I/O and process queries; POSIX errno on failure"
MOD_HARDENED[unistd_abi]="Raw syscall; clamps read/write count to tracked buffer bounds, defaults invalid whence/amode"

MOD_STRICT[socket_abi]="Raw Linux syscall for BSD sockets; POSIX errno on failure"
MOD_HARDENED[socket_abi]="Raw syscall; clamps send/recv buffer lengths to tracked bounds"

MOD_STRICT[inet_abi]="Pure-computation byte-order and address conversion; no syscalls"
MOD_HARDENED[inet_abi]="Pure computation; no mode difference"

MOD_STRICT[signal_abi]="Raw Linux syscall for signal handling; POSIX errno on failure"
MOD_HARDENED[signal_abi]="Raw syscall; denies invalid signal numbers instead of passing to kernel"

MOD_STRICT[time_abi]="Raw Linux syscall for time queries; POSIX errno on failure"
MOD_HARDENED[time_abi]="Raw syscall; defaults invalid clock_id to CLOCK_REALTIME"

MOD_STRICT[pthread_abi]="Delegates to host glibc pthread; preserves host semantics"
MOD_HARDENED[pthread_abi]="Host glibc pthread delegation; hardened membrane validates mutex/cond state"

MOD_STRICT[resolv_abi]="Bootstrap resolver implementation: numeric getaddrinfo/getnameinfo + gai_strerror/freeaddrinfo with deterministic EAI_* failures"
MOD_HARDENED[resolv_abi]="Resolver with deterministic repairs: invalid host/service normalized to safe defaults, evidence emitted"

MOD_STRICT[locale_abi]="Bootstrap locale implementation: setlocale supports C/POSIX and localeconv returns static C locale struct"
MOD_HARDENED[locale_abi]="Locale implementation with hardened fallback to C locale defaults on invalid input"

MOD_STRICT[iconv_abi]="Phase-1 iconv implementation for UTF-8/ISO-8859-1/UTF-16LE with deterministic errno semantics"
MOD_HARDENED[iconv_abi]="Phase-1 iconv with hardened membrane routing; deterministic bounds/error behavior"

MOD_STRICT[dlfcn_abi]="Delegates to host glibc dlopen/dlsym/dlclose/dlerror; preserves host semantics"
MOD_HARDENED[dlfcn_abi]="Host glibc delegation; hardened membrane validates path strings"

MOD_STRICT[dirent_abi]="Raw Linux syscall for directory enumeration; POSIX errno on failure"
MOD_HARDENED[dirent_abi]="Raw syscall; validates path pointer bounds before getdents64"

MOD_STRICT[resource_abi]="Raw Linux syscall for getrlimit/setrlimit; POSIX errno on failure"
MOD_HARDENED[resource_abi]="Raw syscall; denies invalid resource constants"

MOD_STRICT[termios_abi]="Raw Linux ioctl for terminal control; POSIX errno on failure"
MOD_HARDENED[termios_abi]="Raw ioctl; validates termios struct pointer bounds"

MOD_STRICT[mmap_abi]="Raw Linux syscall for virtual memory; POSIX errno on failure"
MOD_HARDENED[mmap_abi]="Raw syscall; denies conflicting prot/flags combinations"

MOD_STRICT[poll_abi]="Raw Linux syscall for I/O multiplexing; POSIX errno on failure"
MOD_HARDENED[poll_abi]="Raw syscall; clamps nfds to tracked pollfd array bounds"

MOD_STRICT[process_abi]="Raw Linux syscall for process control; POSIX errno on failure"
MOD_HARDENED[process_abi]="Raw syscall; validates argv/envp pointer arrays before execve"

MOD_STRICT[startup_abi]="Phase-0 startup skeleton for controlled fixtures; validates argc/argv/envp and captures auxv/secure-mode invariants"
MOD_HARDENED[startup_abi]="Phase-0 startup with hardened membrane routing; deterministic startup invariant capture for fixture binaries"

MOD_STRICT[unknown]="Unclassified symbol defaulting to Stub contract"
MOD_HARDENED[unknown]="Unclassified symbol; evidence emitted on every call"

# malloc_abi: Implemented (safe Rust allocator)
for s in malloc free calloc realloc posix_memalign memalign aligned_alloc; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="malloc_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# string_abi: Implemented (safe Rust)
for s in memcpy memmove memset memcmp memchr memrchr \
         strlen strcmp strcpy strncpy strcat strncat \
         strchr strrchr strstr strtok strtok_r; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="string_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# wchar_abi: Implemented (safe Rust)
for s in wcslen wcscpy wcsncpy wcscat wcscmp wcsncmp \
         wcschr wcsrchr wcsstr wmemcpy wmemmove wmemset wmemcmp wmemchr; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="wchar_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# stdlib_abi: Implemented (safe Rust + validated bootstrap env management)
for s in atoi atol strtol strtoul exit atexit qsort bsearch getenv setenv unsetenv; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="stdlib_abi"
  SYM_PERF[$s]="coldpath"
done

# errno_abi: Implemented (thread-local)
SYM_STATUS[__errno_location]="Implemented"
SYM_MODULE[__errno_location]="errno_abi"
SYM_PERF[__errno_location]="strict_hotpath"

# math_abi: Implemented (Rust std::f64)
for s in sin cos tan asin acos atan atan2 \
         exp log log10 pow fabs ceil floor round fmod \
         erf tgamma lgamma; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="math_abi"
  SYM_PERF[$s]="coldpath"
done

# ctype_abi: Implemented (lookup table)
for s in isalpha isdigit isalnum isspace isupper islower \
         isprint ispunct isxdigit toupper tolower; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="ctype_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# stdio_abi: GlibcCallThrough (wraps system FILE* operations)
for s in fopen fclose fflush fgetc fputc fgets fputs fread fwrite \
         fseek ftell rewind feof ferror clearerr ungetc fileno \
         setvbuf setbuf putchar puts getchar perror \
         snprintf sprintf fprintf printf; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="stdio_abi"
  SYM_PERF[$s]="coldpath"
done

# io_abi: RawSyscall
for s in dup dup2 pipe fcntl; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="io_abi"
  SYM_PERF[$s]="coldpath"
done

# unistd_abi: RawSyscall
for s in read write close lseek isatty getpid getppid getuid geteuid getgid getegid \
         stat fstat lstat access getcwd chdir fchdir \
         unlink rmdir link symlink readlink fsync fdatasync sleep usleep; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="unistd_abi"
  SYM_PERF[$s]="coldpath"
done

# socket_abi: RawSyscall
for s in socket bind listen accept connect send recv sendto recvfrom \
         shutdown setsockopt getsockopt getpeername getsockname; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="socket_abi"
  SYM_PERF[$s]="coldpath"
done

# inet_abi: Implemented (pure computation)
for s in htons htonl ntohs ntohl inet_pton inet_ntop inet_addr; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="inet_abi"
  SYM_PERF[$s]="coldpath"
done

# signal_abi: RawSyscall
for s in signal raise kill sigaction; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="signal_abi"
  SYM_PERF[$s]="coldpath"
done

# time_abi: RawSyscall
for s in time clock_gettime clock localtime_r; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="time_abi"
  SYM_PERF[$s]="coldpath"
done

# pthread_abi: Stub (wraps glibc pthread for now)
for s in pthread_self pthread_equal pthread_create pthread_join pthread_detach \
         pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_trylock pthread_mutex_unlock \
         pthread_cond_init pthread_cond_destroy pthread_cond_wait pthread_cond_signal pthread_cond_broadcast \
         pthread_rwlock_init pthread_rwlock_destroy pthread_rwlock_rdlock pthread_rwlock_wrlock pthread_rwlock_unlock; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="pthread_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# resolv_abi: Implemented (bootstrap numeric resolver path)
for s in getaddrinfo freeaddrinfo getnameinfo gai_strerror; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="resolv_abi"
  SYM_PERF[$s]="coldpath"
done

# locale_abi: Implemented (bootstrap C/POSIX locale)
for s in setlocale localeconv; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="locale_abi"
  SYM_PERF[$s]="coldpath"
done

# iconv_abi: Implemented (phase-1 charset conversion)
for s in iconv_open iconv iconv_close; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="iconv_abi"
  SYM_PERF[$s]="coldpath"
done

# dlfcn_abi: GlibcCallThrough
for s in dlopen dlsym dlclose dlerror; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="dlfcn_abi"
  SYM_PERF[$s]="coldpath"
done

# dirent_abi: RawSyscall
for s in opendir readdir closedir; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="dirent_abi"
  SYM_PERF[$s]="coldpath"
done

# resource_abi: RawSyscall
for s in getrlimit setrlimit; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="resource_abi"
  SYM_PERF[$s]="coldpath"
done

# termios_abi: RawSyscall
for s in tcgetattr tcsetattr cfgetispeed cfgetospeed cfsetispeed cfsetospeed \
         tcdrain tcflush tcflow tcsendbreak; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="termios_abi"
  SYM_PERF[$s]="coldpath"
done

# mmap_abi: RawSyscall
for s in mmap munmap mprotect msync madvise; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="mmap_abi"
  SYM_PERF[$s]="coldpath"
done

# poll_abi: RawSyscall
for s in poll ppoll select pselect; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="poll_abi"
  SYM_PERF[$s]="coldpath"
done

# process_abi: RawSyscall
for s in fork _exit execve execvp waitpid wait; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="process_abi"
  SYM_PERF[$s]="coldpath"
done

# startup_abi: Implemented (phase-0 startup skeleton for controlled fixtures)
for s in __libc_start_main __glibc_rs_startup_phase0 __glibc_rs_startup_snapshot; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="startup_abi"
  SYM_PERF[$s]="coldpath"
done

# Data symbols (stdio globals)
for s in stdin stdout stderr; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="stdio_abi"
  SYM_PERF[$s]="coldpath"
done

# ------------------------------------------------------------------
# Extract actual exported symbols from our .so
# ------------------------------------------------------------------
our_syms=$(nm -D --defined-only "${OUR_LIB}" 2>/dev/null | awk '{print $NF}' | sort)
our_count=$(echo "${our_syms}" | wc -l)

# ------------------------------------------------------------------
# Build JSON support matrix
# ------------------------------------------------------------------
if [[ ${DETERMINISTIC} -eq 1 ]]; then
  generated_at_utc="1970-01-01T00:00:00Z"
  library_field="$(basename "${OUR_LIB}")"
else
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  library_field="${OUR_LIB}"
fi

impl=0
raw=0
glibc=0
stub=0
default_stub=0

{
  echo "{"
  echo "  \"version\": 2,"
  echo "  \"generated_at_utc\": \"${generated_at_utc}\","
  echo "  \"library\": \"${library_field}\","
  echo "  \"total_exported\": ${our_count},"
  echo "  \"taxonomy\": {"
  echo "    \"Implemented\": \"Native Rust code owns the entire operation. No host libc dependency. Full test coverage required.\","
  echo "    \"RawSyscall\": \"ABI entrypoint marshals arguments directly to Linux syscall instruction. No glibc call-through.\","
  echo "    \"GlibcCallThrough\": \"Delegates to host glibc after membrane pre/post validation. Requires host libc at runtime.\","
  echo "    \"Stub\": \"Deterministic failure contract. Returns stable errno/error code. Documented in support policy.\","
  echo "    \"perf_classes\": {"
  echo "      \"strict_hotpath\": \"Called >= 1M/sec in typical workloads. Must meet <20ns strict budget.\","
  echo "      \"hardened_hotpath\": \"Called >= 1M/sec in hardened mode. Must meet <200ns hardened budget.\","
  echo "      \"coldpath\": \"Called < 1K/sec. No latency budget enforced.\""
  echo "    },"
  echo "    \"default_policy\": \"Any exported symbol absent from explicit classification defaults to Stub and causes drift failure (exit 3).\","
  echo "    \"mode_contract\": {"
  echo "      \"strict\": \"POSIX-correct error semantics. Membrane validates but never silently rewrites. ABI-compatible.\","
  echo "      \"hardened\": \"TSM repair enabled. Membrane applies deterministic healing (clamp, truncate, safe-default). Logs HealingAction.\""
  echo "    },"
  echo "    \"artifact_applicability\": {"
  echo "      \"Interpose\": [\"Implemented\", \"RawSyscall\", \"GlibcCallThrough\", \"Stub\"],"
  echo "      \"Replace\": [\"Implemented\", \"RawSyscall\"],"
  echo "      \"rule\": \"Implemented+RawSyscall apply to both artifacts; GlibcCallThrough+Stub are Interpose-only.\""
  echo "    }"
  echo "  },"
  echo "  \"symbols\": ["

  first=1
  while IFS= read -r sym; do
    [[ -z "$sym" ]] && continue
    status="${SYM_STATUS[$sym]:-Stub}"
    module="${SYM_MODULE[$sym]:-unknown}"
    perf="${SYM_PERF[$sym]:-coldpath}"
    strict_semantics="${MOD_STRICT[$module]:-${MOD_STRICT[unknown]}}"
    hardened_semantics="${MOD_HARDENED[$module]:-${MOD_HARDENED[unknown]}}"
    default_stub_flag="false"
    if [[ -z "${SYM_STATUS[$sym]:-}" ]]; then
      default_stub=$((default_stub + 1))
      default_stub_flag="true"
    fi

    if [[ $first -eq 0 ]]; then
      echo ","
    fi
    first=0
    printf '    {"symbol": "%s", "status": "%s", "module": "%s", "perf_class": "%s", "strict_semantics": "%s", "hardened_semantics": "%s", "default_stub": %s}' \
      "$sym" "$status" "$module" "$perf" "$strict_semantics" "$hardened_semantics" "$default_stub_flag"

    case "${status}" in
      Implemented) impl=$((impl + 1)) ;;
      RawSyscall) raw=$((raw + 1)) ;;
      GlibcCallThrough) glibc=$((glibc + 1)) ;;
      Stub) stub=$((stub + 1)) ;;
    esac
  done <<< "${our_syms}"

  echo ""
  echo "  ],"

  echo "  \"summary\": {"
  echo "    \"Implemented\": ${impl},"
  echo "    \"RawSyscall\": ${raw},"
  echo "    \"GlibcCallThrough\": ${glibc},"
  echo "    \"Stub\": ${stub},"
  echo "    \"DefaultStub\": ${default_stub}"
  echo "  }"
  echo "}"
} > "${MATRIX_OUT}"

if [[ $JSON_ONLY -eq 1 ]]; then
  echo "${MATRIX_OUT}"
  exit 0
fi

# ------------------------------------------------------------------
# Human-readable report
# ------------------------------------------------------------------
echo "=== ABI Symbol Audit ==="
echo "Library: ${OUR_LIB}"
echo "Total exported symbols: ${our_count}"
echo ""

echo "Classification:"
printf "  %-20s %d\n" "Implemented:" "$impl"
printf "  %-20s %d\n" "RawSyscall:" "$raw"
printf "  %-20s %d\n" "GlibcCallThrough:" "$glibc"
printf "  %-20s %d\n" "Stub:" "$stub"
printf "  %-20s %d\n" "DefaultStub:" "$default_stub"
echo ""

if [[ $default_stub -gt 0 ]]; then
  echo "ERROR: ${default_stub} symbol(s) fell back to default Stub classification." >&2
  echo "This is treated as taxonomy drift; classify new symbols explicitly in scripts/abi_audit.sh." >&2
  exit 3
fi

# Host comparison
if [[ -f "${HOST_LIB}" ]]; then
  host_syms=$(nm -D --defined-only "${HOST_LIB}" 2>/dev/null | awk '$2 ~ /[TtWw]/ {gsub(/@.*/, "", $NF); print $NF}' | sort -u)
  host_count=$(echo "${host_syms}" | wc -w)
  our_clean=$(echo "${our_syms}" | sort -u)
  common=$(comm -12 <(echo "${our_clean}") <(echo "${host_syms}") | wc -l)
  echo "Host libc symbols: ${host_count}"
  echo "Common with host: ${common}"
  echo "Coverage: ${common}/${host_count}"
fi

echo ""
echo "Matrix written to: ${MATRIX_OUT}"
echo ""
echo "abi_audit: PASS"
