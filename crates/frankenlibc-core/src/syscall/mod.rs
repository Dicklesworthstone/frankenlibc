//! Raw Linux syscall veneer for supported architectures.
//!
//! Provides zero-dependency raw syscall primitives using inline assembly,
//! plus typed wrappers for the syscalls needed by frankenlibc ABI entrypoints.
//!
//! This module eliminates the dependency on `libc::syscall()` for the critical
//! path, which is essential since frankenlibc IS the libc replacement.
//!
//! # Architecture
//!
//! x86_64 Linux syscall ABI:
//! - Syscall number: `rax`
//! - Arguments: `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
//! - Return: `rax` (negative values in `[-4095, -1]` indicate `-errno`)
//! - Clobbered: `rcx`, `r11`
//!
//! aarch64 Linux syscall ABI:
//! - Syscall number: `x8`
//! - Arguments: `x0`, `x1`, `x2`, `x3`, `x4`, `x5`
//! - Return: `x0` (negative values in `[-4095, -1]` indicate `-errno`)
//!
//! # Safety
//!
//! Each raw `syscallN` function is `unsafe` because the kernel trusts the
//! caller to supply valid arguments. The typed wrappers encode argument
//! types but cannot verify pointer validity — that remains the caller's
//! (or membrane's) responsibility.

#[allow(unsafe_code)]
mod raw;

pub use raw::*;

// -------------------------------------------------------------------------
// Syscall number constants (Linux)
// -------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub const SYS_READ: usize = 0;
#[cfg(target_arch = "x86_64")]
pub const SYS_WRITE: usize = 1;
#[cfg(target_arch = "x86_64")]
pub const SYS_OPEN: usize = 2;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOSE: usize = 3;
#[cfg(target_arch = "x86_64")]
pub const SYS_FSTAT: usize = 5;
#[cfg(target_arch = "x86_64")]
pub const SYS_LSEEK: usize = 8;
#[cfg(target_arch = "x86_64")]
pub const SYS_MMAP: usize = 9;
#[cfg(target_arch = "x86_64")]
pub const SYS_MPROTECT: usize = 10;
#[cfg(target_arch = "x86_64")]
pub const SYS_MUNMAP: usize = 11;
#[cfg(target_arch = "x86_64")]
pub const SYS_BRK: usize = 12;
#[cfg(target_arch = "x86_64")]
pub const SYS_IOCTL: usize = 16;
#[cfg(target_arch = "x86_64")]
pub const SYS_PIPE: usize = 22;
#[cfg(target_arch = "x86_64")]
pub const SYS_DUP: usize = 32;
#[cfg(target_arch = "x86_64")]
pub const SYS_DUP2: usize = 33;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPID: usize = 39;
#[cfg(target_arch = "x86_64")]
pub const SYS_SOCKET: usize = 41;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETEUID: usize = 107;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLONE: usize = 56;
#[cfg(target_arch = "x86_64")]
pub const SYS_FORK: usize = 57;
#[cfg(target_arch = "x86_64")]
pub const SYS_EXECVE: usize = 59;
#[cfg(target_arch = "x86_64")]
pub const SYS_EXIT: usize = 60;
#[cfg(target_arch = "x86_64")]
pub const SYS_WAIT4: usize = 61;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCNTL: usize = 72;
#[cfg(target_arch = "x86_64")]
pub const SYS_FSYNC: usize = 74;
#[cfg(target_arch = "x86_64")]
pub const SYS_PREAD64: usize = 17;
#[cfg(target_arch = "x86_64")]
pub const SYS_PWRITE64: usize = 18;
#[cfg(target_arch = "x86_64")]
pub const SYS_MSYNC: usize = 26;
#[cfg(target_arch = "x86_64")]
pub const SYS_MREMAP: usize = 25;
#[cfg(target_arch = "x86_64")]
pub const SYS_MLOCK: usize = 149;
#[cfg(target_arch = "x86_64")]
pub const SYS_MLOCK2: usize = 325;
#[cfg(target_arch = "x86_64")]
pub const SYS_MUNLOCK: usize = 150;
#[cfg(target_arch = "x86_64")]
pub const SYS_MLOCKALL: usize = 151;
#[cfg(target_arch = "x86_64")]
pub const SYS_MUNLOCKALL: usize = 152;
#[cfg(target_arch = "x86_64")]
pub const SYS_MADVISE: usize = 28;
#[cfg(target_arch = "x86_64")]
pub const SYS_FDATASYNC: usize = 75;
#[cfg(target_arch = "x86_64")]
pub const SYS_FALLOCATE: usize = 285;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETDENTS64: usize = 217;
#[cfg(target_arch = "x86_64")]
pub const SYS_EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT: usize = 257;
#[cfg(target_arch = "x86_64")]
pub const SYS_UTIMENSAT: usize = 280;
#[cfg(target_arch = "x86_64")]
pub const SYS_PIPE2: usize = 293;
#[cfg(target_arch = "x86_64")]
pub const SYS_PRLIMIT64: usize = 302;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_YIELD: usize = 24;
#[cfg(target_arch = "x86_64")]
pub const SYS_NANOSLEEP: usize = 35;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOCK_SETTIME: usize = 227;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETTIMEOFDAY: usize = 164;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOCK_GETTIME: usize = 228;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOCK_GETRES: usize = 229;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOCK_NANOSLEEP: usize = 230;
#[cfg(target_arch = "x86_64")]
pub const SYS_SENDTO: usize = 44;
#[cfg(target_arch = "x86_64")]
pub const SYS_RECVFROM: usize = 45;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETSOCKOPT: usize = 54;
#[cfg(target_arch = "x86_64")]
pub const SYS_READV: usize = 19;
#[cfg(target_arch = "x86_64")]
pub const SYS_WRITEV: usize = 20;
#[cfg(target_arch = "x86_64")]
pub const SYS_SENDFILE: usize = 40;
#[cfg(target_arch = "x86_64")]
pub const SYS_SPLICE: usize = 275;
#[cfg(target_arch = "x86_64")]
pub const SYS_TEE: usize = 276;
#[cfg(target_arch = "x86_64")]
pub const SYS_VMSPLICE: usize = 278;
#[cfg(target_arch = "x86_64")]
pub const SYS_DUP3: usize = 292;
#[cfg(target_arch = "x86_64")]
pub const SYS_PREADV: usize = 295;
#[cfg(target_arch = "x86_64")]
pub const SYS_PWRITEV: usize = 296;
#[cfg(target_arch = "x86_64")]
pub const SYS_MEMFD_CREATE: usize = 319;
#[cfg(target_arch = "x86_64")]
pub const SYS_COPY_FILE_RANGE: usize = 326;
#[cfg(target_arch = "x86_64")]
pub const SYS_PREADV2: usize = 327;
#[cfg(target_arch = "x86_64")]
pub const SYS_PWRITEV2: usize = 328;
#[cfg(target_arch = "x86_64")]
pub const SYS_READLINKAT: usize = 267;
#[cfg(target_arch = "x86_64")]
pub const SYS_FUTEX: usize = 202;
#[cfg(target_arch = "x86_64")]
pub const SYS_SET_TID_ADDRESS: usize = 218;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETTID: usize = 186;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;

#[cfg(target_arch = "aarch64")]
pub const SYS_READ: usize = 63;
#[cfg(target_arch = "aarch64")]
pub const SYS_WRITE: usize = 64;
// Legacy `open` is not a separate syscall on aarch64; use openat semantics.
#[cfg(target_arch = "aarch64")]
pub const SYS_OPEN: usize = 56;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOSE: usize = 57;
#[cfg(target_arch = "aarch64")]
pub const SYS_FSTAT: usize = 80;
#[cfg(target_arch = "aarch64")]
pub const SYS_LSEEK: usize = 62;
#[cfg(target_arch = "aarch64")]
pub const SYS_MMAP: usize = 222;
#[cfg(target_arch = "aarch64")]
pub const SYS_MPROTECT: usize = 226;
#[cfg(target_arch = "aarch64")]
pub const SYS_MUNMAP: usize = 215;
#[cfg(target_arch = "aarch64")]
pub const SYS_BRK: usize = 214;
#[cfg(target_arch = "aarch64")]
pub const SYS_IOCTL: usize = 29;
#[cfg(target_arch = "aarch64")]
pub const SYS_PIPE: usize = 59;
#[cfg(target_arch = "aarch64")]
pub const SYS_DUP: usize = 23;
#[cfg(target_arch = "aarch64")]
pub const SYS_DUP2: usize = 24;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPID: usize = 172;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETEUID: usize = 175;
#[cfg(target_arch = "aarch64")]
pub const SYS_SOCKET: usize = 198;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLONE: usize = 220;
#[cfg(target_arch = "aarch64")]
pub const SYS_FORK: usize = SYS_CLONE;
#[cfg(target_arch = "aarch64")]
pub const SYS_EXECVE: usize = 221;
#[cfg(target_arch = "aarch64")]
pub const SYS_EXIT: usize = 93;
#[cfg(target_arch = "aarch64")]
pub const SYS_WAIT4: usize = 260;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCNTL: usize = 25;
#[cfg(target_arch = "aarch64")]
pub const SYS_FSYNC: usize = 82;
#[cfg(target_arch = "aarch64")]
pub const SYS_PREAD64: usize = 67;
#[cfg(target_arch = "aarch64")]
pub const SYS_PWRITE64: usize = 68;
#[cfg(target_arch = "aarch64")]
pub const SYS_MSYNC: usize = 227;
#[cfg(target_arch = "aarch64")]
pub const SYS_MREMAP: usize = 216;
#[cfg(target_arch = "aarch64")]
pub const SYS_MLOCK: usize = 228;
#[cfg(target_arch = "aarch64")]
pub const SYS_MLOCK2: usize = 284;
#[cfg(target_arch = "aarch64")]
pub const SYS_MUNLOCK: usize = 229;
#[cfg(target_arch = "aarch64")]
pub const SYS_MLOCKALL: usize = 230;
#[cfg(target_arch = "aarch64")]
pub const SYS_MUNLOCKALL: usize = 231;
#[cfg(target_arch = "aarch64")]
pub const SYS_MADVISE: usize = 233;
#[cfg(target_arch = "aarch64")]
pub const SYS_FDATASYNC: usize = 83;
#[cfg(target_arch = "aarch64")]
pub const SYS_FALLOCATE: usize = 47;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETDENTS64: usize = 61;
#[cfg(target_arch = "aarch64")]
pub const SYS_EXIT_GROUP: usize = 94;
#[cfg(target_arch = "aarch64")]
pub const SYS_OPENAT: usize = 56;
#[cfg(target_arch = "aarch64")]
pub const SYS_UTIMENSAT: usize = 88;
#[cfg(target_arch = "aarch64")]
pub const SYS_PIPE2: usize = 59;
#[cfg(target_arch = "aarch64")]
pub const SYS_PRLIMIT64: usize = 261;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_YIELD: usize = 124;
#[cfg(target_arch = "aarch64")]
pub const SYS_NANOSLEEP: usize = 101;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOCK_SETTIME: usize = 112;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETTIMEOFDAY: usize = 170;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOCK_GETTIME: usize = 113;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOCK_GETRES: usize = 114;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOCK_NANOSLEEP: usize = 115;
#[cfg(target_arch = "aarch64")]
pub const SYS_SENDTO: usize = 206;
#[cfg(target_arch = "aarch64")]
pub const SYS_RECVFROM: usize = 207;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETSOCKOPT: usize = 208;
#[cfg(target_arch = "aarch64")]
pub const SYS_READV: usize = 65;
#[cfg(target_arch = "aarch64")]
pub const SYS_WRITEV: usize = 66;
#[cfg(target_arch = "aarch64")]
pub const SYS_PREADV: usize = 69;
#[cfg(target_arch = "aarch64")]
pub const SYS_PWRITEV: usize = 70;
#[cfg(target_arch = "aarch64")]
pub const SYS_SENDFILE: usize = 71;
#[cfg(target_arch = "aarch64")]
pub const SYS_VMSPLICE: usize = 75;
#[cfg(target_arch = "aarch64")]
pub const SYS_SPLICE: usize = 76;
#[cfg(target_arch = "aarch64")]
pub const SYS_TEE: usize = 77;
#[cfg(target_arch = "aarch64")]
pub const SYS_DUP3: usize = 24;
#[cfg(target_arch = "aarch64")]
pub const SYS_MEMFD_CREATE: usize = 279;
#[cfg(target_arch = "aarch64")]
pub const SYS_COPY_FILE_RANGE: usize = 285;
#[cfg(target_arch = "aarch64")]
pub const SYS_PREADV2: usize = 286;
#[cfg(target_arch = "aarch64")]
pub const SYS_PWRITEV2: usize = 287;
#[cfg(target_arch = "aarch64")]
pub const SYS_READLINKAT: usize = 78;
#[cfg(target_arch = "aarch64")]
pub const SYS_FUTEX: usize = 98;
#[cfg(target_arch = "aarch64")]
pub const SYS_SET_TID_ADDRESS: usize = 96;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETTID: usize = 178;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_GET_PRIORITY_MAX: usize = 125;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_GET_PRIORITY_MIN: usize = 126;

// Signal syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_KILL: usize = 62;
#[cfg(target_arch = "x86_64")]
pub const SYS_RT_SIGACTION: usize = 13;
#[cfg(target_arch = "x86_64")]
pub const SYS_RT_SIGPROCMASK: usize = 14;
#[cfg(target_arch = "x86_64")]
pub const SYS_RT_SIGPENDING: usize = 127;
#[cfg(target_arch = "x86_64")]
pub const SYS_RT_SIGTIMEDWAIT: usize = 128;
#[cfg(target_arch = "x86_64")]
pub const SYS_RT_SIGSUSPEND: usize = 130;
#[cfg(target_arch = "x86_64")]
pub const SYS_SIGALTSTACK: usize = 131;
#[cfg(target_arch = "x86_64")]
pub const SYS_PAUSE: usize = 34;
#[cfg(target_arch = "x86_64")]
pub const SYS_PPOLL: usize = 271;

// Signal syscalls - aarch64
#[cfg(target_arch = "aarch64")]
pub const SYS_KILL: usize = 129;
#[cfg(target_arch = "aarch64")]
pub const SYS_RT_SIGACTION: usize = 134;
#[cfg(target_arch = "aarch64")]
pub const SYS_RT_SIGPROCMASK: usize = 135;
#[cfg(target_arch = "aarch64")]
pub const SYS_RT_SIGPENDING: usize = 136;
#[cfg(target_arch = "aarch64")]
pub const SYS_RT_SIGTIMEDWAIT: usize = 137;
#[cfg(target_arch = "aarch64")]
pub const SYS_RT_SIGSUSPEND: usize = 133;
#[cfg(target_arch = "aarch64")]
pub const SYS_SIGALTSTACK: usize = 132;
// aarch64 does not have SYS_PAUSE; use ppoll with null mask
#[cfg(target_arch = "aarch64")]
pub const SYS_PPOLL: usize = 73;

// Poll/select syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_POLL: usize = 7;
#[cfg(target_arch = "x86_64")]
pub const SYS_SELECT: usize = 23;
#[cfg(target_arch = "x86_64")]
pub const SYS_PSELECT6: usize = 270;
#[cfg(target_arch = "x86_64")]
pub const SYS_EPOLL_CREATE1: usize = 291;
#[cfg(target_arch = "x86_64")]
pub const SYS_EPOLL_CTL: usize = 233;
#[cfg(target_arch = "x86_64")]
pub const SYS_EPOLL_PWAIT: usize = 281;
#[cfg(target_arch = "x86_64")]
pub const SYS_EVENTFD2: usize = 290;
#[cfg(target_arch = "x86_64")]
pub const SYS_TIMERFD_CREATE: usize = 283;
#[cfg(target_arch = "x86_64")]
pub const SYS_TIMERFD_SETTIME: usize = 286;
#[cfg(target_arch = "x86_64")]
pub const SYS_TIMERFD_GETTIME: usize = 287;
#[cfg(target_arch = "x86_64")]
pub const SYS_PRCTL: usize = 157;

// Poll/select syscalls - aarch64
// aarch64 does not have SYS_POLL or SYS_SELECT; use ppoll/pselect6
#[cfg(target_arch = "aarch64")]
pub const SYS_PSELECT6: usize = 72;
#[cfg(target_arch = "aarch64")]
pub const SYS_EPOLL_CREATE1: usize = 20;
#[cfg(target_arch = "aarch64")]
pub const SYS_EPOLL_CTL: usize = 21;
#[cfg(target_arch = "aarch64")]
pub const SYS_EPOLL_PWAIT: usize = 22;
#[cfg(target_arch = "aarch64")]
pub const SYS_EVENTFD2: usize = 19;
#[cfg(target_arch = "aarch64")]
pub const SYS_TIMERFD_CREATE: usize = 85;
#[cfg(target_arch = "aarch64")]
pub const SYS_TIMERFD_SETTIME: usize = 86;
#[cfg(target_arch = "aarch64")]
pub const SYS_TIMERFD_GETTIME: usize = 87;
#[cfg(target_arch = "aarch64")]
pub const SYS_PRCTL: usize = 167;

// Process management syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_SETPGID: usize = 109;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPGRP: usize = 111;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETUID: usize = 105;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETGID: usize = 106;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETEGID: usize = 108;
#[cfg(target_arch = "x86_64")]
pub const SYS_CHDIR: usize = 80;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCHDIR: usize = 81;
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOSE_RANGE: usize = 436;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_SETPARAM: usize = 142;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_GETPARAM: usize = 143;
#[cfg(target_arch = "x86_64")]
pub const SYS_UNLINKAT: usize = 263;
#[cfg(target_arch = "x86_64")]
pub const SYS_WAITID: usize = 247;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_SETSCHEDULER: usize = 144;
#[cfg(target_arch = "x86_64")]
pub const SYS_SCHED_GETSCHEDULER: usize = 145;
#[cfg(target_arch = "x86_64")]
pub const SYS_SYMLINKAT: usize = 266;
#[cfg(target_arch = "x86_64")]
pub const SYS_FACCESSAT: usize = 269;
#[cfg(target_arch = "x86_64")]
pub const SYS_MKDIRAT: usize = 258;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCHMODAT: usize = 268;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCHOWNAT: usize = 260;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCHMOD: usize = 91;
#[cfg(target_arch = "x86_64")]
pub const SYS_FCHOWN: usize = 93;
#[cfg(target_arch = "x86_64")]
pub const SYS_UMASK: usize = 95;
#[cfg(target_arch = "x86_64")]
pub const SYS_TRUNCATE: usize = 76;
#[cfg(target_arch = "x86_64")]
pub const SYS_FTRUNCATE: usize = 77;
#[cfg(target_arch = "x86_64")]
pub const SYS_FLOCK: usize = 73;
#[cfg(target_arch = "x86_64")]
pub const SYS_LINKAT: usize = 265;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETCWD: usize = 79;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPPID: usize = 110;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETUID: usize = 102;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETGID: usize = 104;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPGID: usize = 121;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETSID: usize = 124;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETSID: usize = 112;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETREUID: usize = 113;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETREGID: usize = 114;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETGROUPS: usize = 115;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETGROUPS: usize = 116;

// Process management syscalls - aarch64
#[cfg(target_arch = "aarch64")]
pub const SYS_SETPGID: usize = 154;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPGRP: usize = 155;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETUID: usize = 146;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETGID: usize = 144;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETEGID: usize = 177;
#[cfg(target_arch = "aarch64")]
pub const SYS_CHDIR: usize = 49;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCHDIR: usize = 50;
#[cfg(target_arch = "aarch64")]
pub const SYS_CLOSE_RANGE: usize = 436;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_SETPARAM: usize = 118;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_GETPARAM: usize = 121;
#[cfg(target_arch = "aarch64")]
pub const SYS_UNLINKAT: usize = 35;
#[cfg(target_arch = "aarch64")]
pub const SYS_WAITID: usize = 95;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_SETSCHEDULER: usize = 119;
#[cfg(target_arch = "aarch64")]
pub const SYS_SCHED_GETSCHEDULER: usize = 120;
#[cfg(target_arch = "aarch64")]
pub const SYS_SYMLINKAT: usize = 36;
#[cfg(target_arch = "aarch64")]
pub const SYS_FACCESSAT: usize = 48;
#[cfg(target_arch = "aarch64")]
pub const SYS_MKDIRAT: usize = 34;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCHMODAT: usize = 53;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCHOWNAT: usize = 54;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCHMOD: usize = 52;
#[cfg(target_arch = "aarch64")]
pub const SYS_FCHOWN: usize = 55;
#[cfg(target_arch = "aarch64")]
pub const SYS_UMASK: usize = 166;
#[cfg(target_arch = "aarch64")]
pub const SYS_TRUNCATE: usize = 45;
#[cfg(target_arch = "aarch64")]
pub const SYS_FTRUNCATE: usize = 46;
#[cfg(target_arch = "aarch64")]
pub const SYS_FLOCK: usize = 32;
#[cfg(target_arch = "aarch64")]
pub const SYS_LINKAT: usize = 37;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETCWD: usize = 17;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPPID: usize = 173;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETUID: usize = 174;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETGID: usize = 176;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPGID: usize = 155;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETSID: usize = 156;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETSID: usize = 157;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETREUID: usize = 145;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETREGID: usize = 143;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETGROUPS: usize = 158;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETGROUPS: usize = 159;

// Additional syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_GETRANDOM: usize = 318;
#[cfg(target_arch = "x86_64")]
pub const SYS_ALARM: usize = 37;
#[cfg(target_arch = "x86_64")]
pub const SYS_UNAME: usize = 63;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETRUSAGE: usize = 98;
#[cfg(target_arch = "x86_64")]
pub const SYS_RENAMEAT2: usize = 316;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPRIORITY: usize = 140;
#[cfg(target_arch = "x86_64")]
pub const SYS_SETPRIORITY: usize = 141;

// Additional syscalls - aarch64
#[cfg(target_arch = "aarch64")]
pub const SYS_GETRANDOM: usize = 278;
#[cfg(target_arch = "aarch64")]
pub const SYS_ALARM: usize = 0; // Not available on aarch64 - use setitimer instead
#[cfg(target_arch = "aarch64")]
pub const SYS_UNAME: usize = 160;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETRUSAGE: usize = 165;
#[cfg(target_arch = "aarch64")]
pub const SYS_RENAMEAT2: usize = 276;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPRIORITY: usize = 141;
#[cfg(target_arch = "aarch64")]
pub const SYS_SETPRIORITY: usize = 140;

// Misc syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_SYNC: usize = 162;
#[cfg(target_arch = "x86_64")]
pub const SYS_SYNCFS: usize = 306;

// Misc syscalls - aarch64
#[cfg(target_arch = "aarch64")]
pub const SYS_SYNC: usize = 81;
#[cfg(target_arch = "aarch64")]
pub const SYS_SYNCFS: usize = 267;

// Socket syscalls - x86_64
#[cfg(target_arch = "x86_64")]
pub const SYS_BIND: usize = 49;
#[cfg(target_arch = "x86_64")]
pub const SYS_LISTEN: usize = 50;
#[cfg(target_arch = "x86_64")]
pub const SYS_ACCEPT: usize = 43;
#[cfg(target_arch = "x86_64")]
pub const SYS_CONNECT: usize = 42;
#[cfg(target_arch = "x86_64")]
pub const SYS_SHUTDOWN: usize = 48;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETSOCKOPT: usize = 55;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETPEERNAME: usize = 52;
#[cfg(target_arch = "x86_64")]
pub const SYS_GETSOCKNAME: usize = 51;
#[cfg(target_arch = "x86_64")]
pub const SYS_SOCKETPAIR: usize = 53;
#[cfg(target_arch = "x86_64")]
pub const SYS_SENDMSG: usize = 46;
#[cfg(target_arch = "x86_64")]
pub const SYS_RECVMSG: usize = 47;
#[cfg(target_arch = "x86_64")]
pub const SYS_ACCEPT4: usize = 288;

// Socket syscalls - aarch64
#[cfg(target_arch = "aarch64")]
pub const SYS_BIND: usize = 200;
#[cfg(target_arch = "aarch64")]
pub const SYS_LISTEN: usize = 201;
#[cfg(target_arch = "aarch64")]
pub const SYS_ACCEPT: usize = 202;
#[cfg(target_arch = "aarch64")]
pub const SYS_CONNECT: usize = 203;
#[cfg(target_arch = "aarch64")]
pub const SYS_SHUTDOWN: usize = 210;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETSOCKOPT: usize = 209;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETPEERNAME: usize = 205;
#[cfg(target_arch = "aarch64")]
pub const SYS_GETSOCKNAME: usize = 204;
#[cfg(target_arch = "aarch64")]
pub const SYS_SOCKETPAIR: usize = 199;
#[cfg(target_arch = "aarch64")]
pub const SYS_SENDMSG: usize = 211;
#[cfg(target_arch = "aarch64")]
pub const SYS_RECVMSG: usize = 212;
#[cfg(target_arch = "aarch64")]
pub const SYS_ACCEPT4: usize = 242;

// -------------------------------------------------------------------------
// Error handling
// -------------------------------------------------------------------------

/// Maximum errno value returned by Linux syscalls.
const MAX_ERRNO: usize = 4095;

/// Convert a raw syscall return value to `Result<usize, i32>`.
///
/// On x86_64 Linux, error returns are in the range `[-(MAX_ERRNO), -1]`
/// which in unsigned representation is `[usize::MAX - MAX_ERRNO + 1, usize::MAX]`.
#[inline]
pub fn syscall_result(ret: usize) -> Result<usize, i32> {
    if ret > usize::MAX - MAX_ERRNO {
        Err(-(ret as isize) as i32)
    } else {
        Ok(ret)
    }
}

// -------------------------------------------------------------------------
// Typed syscall wrappers
// -------------------------------------------------------------------------

/// `read(fd, buf, count)` — read from a file descriptor.
///
/// # Safety
///
/// `buf` must point to a writable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe { raw::syscall3(SYS_READ, fd as usize, buf as usize, count) };
    syscall_result(ret)
}

/// `write(fd, buf, count)` — write to a file descriptor.
///
/// # Safety
///
/// `buf` must point to a readable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_write(fd: i32, buf: *const u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe { raw::syscall3(SYS_WRITE, fd as usize, buf as usize, count) };
    syscall_result(ret)
}

/// `open(pathname, flags, mode)` — open a file.
///
/// # Safety
///
/// `pathname` must be a valid null-terminated C string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_open(pathname: *const u8, flags: i32, mode: u32) -> Result<i32, i32> {
    // SAFETY: caller guarantees pathname is a valid C string.
    let ret = unsafe {
        raw::syscall3(SYS_OPEN, pathname as usize, flags as usize, mode as usize)
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `openat(dirfd, pathname, flags, mode)` — open a file relative to a directory fd.
///
/// # Safety
///
/// `pathname` must be a valid null-terminated C string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_openat(
    dirfd: i32,
    pathname: *const u8,
    flags: i32,
    mode: u32,
) -> Result<i32, i32> {
    // SAFETY: caller guarantees pathname is a valid C string.
    let ret = unsafe {
        raw::syscall4(
            SYS_OPENAT,
            dirfd as usize,
            pathname as usize,
            flags as usize,
            mode as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `close(fd)` — close a file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_close(fd: i32) -> Result<(), i32> {
    // SAFETY: close is safe to call on any fd value (bad fd just returns EBADF).
    let ret = unsafe { raw::syscall1(SYS_CLOSE, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `fstat(fd, statbuf)` — get file status by file descriptor.
///
/// # Safety
///
/// `statbuf` must be a valid pointer to a `stat` structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fstat(fd: i32, statbuf: *mut u8) -> Result<(), i32> {
    // SAFETY: caller guarantees statbuf validity.
    let ret = unsafe { raw::syscall2(SYS_FSTAT, fd as usize, statbuf as usize) };
    syscall_result(ret).map(|_| ())
}

/// `mmap(addr, length, prot, flags, fd, offset)` — map memory.
///
/// # Safety
///
/// The caller must ensure the mapping parameters are valid and that the
/// resulting memory region is used according to the requested protection.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<*mut u8, i32> {
    // SAFETY: caller is responsible for mapping validity.
    let ret = unsafe {
        raw::syscall6(
            SYS_MMAP,
            addr as usize,
            length,
            prot as usize,
            flags as usize,
            fd as usize,
            offset as usize,
        )
    };
    syscall_result(ret).map(|v| v as *mut u8)
}

/// `munmap(addr, length)` — unmap memory.
///
/// # Safety
///
/// `addr` must be page-aligned and the range `[addr, addr+length)` must
/// be a valid mapped region.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_munmap(addr: *mut u8, length: usize) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall2(SYS_MUNMAP, addr as usize, length) };
    syscall_result(ret).map(|_| ())
}

/// `mprotect(addr, length, prot)` — set protection on a memory region.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MPROTECT, addr as usize, length, prot as usize) };
    syscall_result(ret).map(|_| ())
}

/// `futex(uaddr, futex_op, val, timeout, uaddr2, val3)` — fast userspace mutex.
///
/// # Safety
///
/// `uaddr` must point to a valid aligned `u32`. Other pointer arguments
/// depend on the specific futex operation.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_futex(
    uaddr: *const u32,
    futex_op: i32,
    val: u32,
    timeout: usize,
    uaddr2: usize,
    val3: u32,
) -> Result<isize, i32> {
    // SAFETY: caller guarantees uaddr validity and op-specific invariants.
    let ret = unsafe {
        raw::syscall6(
            SYS_FUTEX,
            uaddr as usize,
            futex_op as usize,
            val as usize,
            timeout,
            uaddr2,
            val3 as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `exit_group(status)` — terminate all threads in the process.
#[inline]
#[allow(unsafe_code)]
pub fn sys_exit_group(status: i32) -> ! {
    // SAFETY: exit_group never returns.
    unsafe { raw::syscall1(SYS_EXIT_GROUP, status as usize) };
    // Unreachable, but satisfy the type system.
    loop {
        core::hint::spin_loop();
    }
}

/// `getpid()` — get process ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getpid() -> i32 {
    // SAFETY: getpid has no preconditions.
    let ret = unsafe { raw::syscall0(SYS_GETPID) };
    ret as i32
}

/// `geteuid()` — get effective user ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    let ret = unsafe { raw::syscall0(SYS_GETEUID) };
    ret as u32
}

/// `pipe2(pipefd, flags)` — create a pipe with flags.
///
/// # Safety
///
/// `pipefd` must point to a writable `[i32; 2]`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pipe2(pipefd: *mut i32, flags: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees pipefd points to valid [i32; 2].
    let ret = unsafe { raw::syscall2(SYS_PIPE2, pipefd as usize, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `dup(oldfd)` — duplicate a file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_dup(oldfd: i32) -> Result<i32, i32> {
    // SAFETY: dup is safe on any fd (bad fd returns EBADF).
    let ret = unsafe { raw::syscall1(SYS_DUP, oldfd as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `ioctl(fd, request, arg)` — device control.
///
/// # Safety
///
/// The `arg` interpretation depends on the specific `request`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_ioctl(fd: i32, request: usize, arg: usize) -> Result<i32, i32> {
    // SAFETY: caller guarantees request/arg validity.
    let ret = unsafe { raw::syscall3(SYS_IOCTL, fd as usize, request, arg) };
    syscall_result(ret).map(|v| v as i32)
}

/// `lseek(fd, offset, whence)` — reposition read/write file offset.
#[inline]
#[allow(unsafe_code)]
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, i32> {
    // SAFETY: lseek is safe on any fd (bad fd returns EBADF).
    let ret = unsafe { raw::syscall3(SYS_LSEEK, fd as usize, offset as usize, whence as usize) };
    syscall_result(ret).map(|v| v as i64)
}

/// `fsync(fd)` — synchronize a file's in-core state with storage device.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fsync(fd: i32) -> Result<(), i32> {
    // SAFETY: fsync is safe on any fd.
    let ret = unsafe { raw::syscall1(SYS_FSYNC, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getdents64(fd, dirp, count)` — get directory entries.
///
/// # Safety
///
/// `dirp` must point to a writable buffer of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees dirp/count validity.
    let ret = unsafe { raw::syscall3(SYS_GETDENTS64, fd as usize, dirp as usize, count) };
    syscall_result(ret)
}

/// `fcntl(fd, cmd, arg)` — file control.
///
/// # Safety
///
/// The `arg` interpretation depends on the specific `cmd`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, i32> {
    // SAFETY: caller guarantees cmd/arg validity.
    let ret = unsafe { raw::syscall3(SYS_FCNTL, fd as usize, cmd as usize, arg) };
    syscall_result(ret).map(|v| v as i32)
}

/// `fdatasync(fd)` — synchronize a file's data (not metadata) with storage.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fdatasync(fd: i32) -> Result<(), i32> {
    // SAFETY: fdatasync is safe on any fd.
    let ret = unsafe { raw::syscall1(SYS_FDATASYNC, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `fallocate(fd, mode, offset, len)` — manipulate file space.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> Result<(), i32> {
    // SAFETY: kernel validates fd/mode/ranges; invalid inputs return errno.
    let ret = unsafe {
        raw::syscall4(
            SYS_FALLOCATE,
            fd as usize,
            mode as usize,
            offset as usize,
            len as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `dup2(oldfd, newfd)` — duplicate a file descriptor to a specific fd.
#[inline]
#[allow(unsafe_code)]
pub fn sys_dup2(oldfd: i32, newfd: i32) -> Result<i32, i32> {
    // SAFETY: dup2/dup3 are safe on any fd values (bad fd returns EBADF).
    #[cfg(target_arch = "x86_64")]
    let ret = unsafe { raw::syscall2(SYS_DUP2, oldfd as usize, newfd as usize) };
    #[cfg(target_arch = "aarch64")]
    let ret = unsafe { raw::syscall3(SYS_DUP3, oldfd as usize, newfd as usize, 0) };
    syscall_result(ret).map(|v| v as i32)
}

/// `msync(addr, length, flags)` — synchronize a file with a memory map.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_msync(addr: *mut u8, length: usize, flags: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MSYNC, addr as usize, length, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `madvise(addr, length, advice)` — advise kernel about memory usage.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_madvise(addr: *mut u8, length: usize, advice: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MADVISE, addr as usize, length, advice as usize) };
    syscall_result(ret).map(|_| ())
}

/// `gettid()` — get the caller's thread ID (kernel TID).
#[inline]
#[allow(unsafe_code)]
pub fn sys_gettid() -> i32 {
    // SAFETY: gettid has no preconditions.
    let ret = unsafe { raw::syscall0(SYS_GETTID) };
    ret as i32
}

/// `set_tid_address(tidptr)` — set the clear_child_tid address for the calling thread.
///
/// Passing NULL (0) disables the kernel's CLONE_CHILD_CLEARTID behavior, preventing
/// the kernel from writing to the TID address on thread exit.
#[inline]
#[allow(unsafe_code)]
pub fn sys_set_tid_address(tidptr: usize) -> i32 {
    // SAFETY: set_tid_address accepts any address (including NULL).
    let ret = unsafe { raw::syscall1(SYS_SET_TID_ADDRESS, tidptr) };
    ret as i32
}

/// `exit(status)` — terminate the calling thread (not the entire process).
///
/// Unlike `exit_group`, this only terminates the calling thread.
#[inline]
#[allow(unsafe_code)]
pub fn sys_exit_thread(status: i32) -> ! {
    // SAFETY: SYS_EXIT terminates only the calling thread.
    unsafe { raw::syscall1(SYS_EXIT, status as usize) };
    loop {
        core::hint::spin_loop();
    }
}

/// Create a new thread via `clone` syscall with a child trampoline.
///
/// The child stack must be pre-populated:
/// - `[child_sp + 0]`: function pointer (`unsafe extern "C" fn(usize) -> usize`)
/// - `[child_sp + 8]`: argument to pass as first parameter to the function
///
/// After clone, the child will:
/// 1. Pop the function pointer from the stack
/// 2. Pop the argument and pass it in the first C ABI argument register
/// 3. Call the function
/// 4. Use the return value as the thread exit status
///
/// The parent receives the child's TID (or a negative errno).
///
/// # Safety
///
/// - `child_sp` must point to a properly prepared child stack as described above.
/// - The stack region must be valid and have sufficient space.
/// - `parent_tid` and `child_tid` must be valid pointers if the corresponding
///   `CLONE_PARENT_SETTID` / `CLONE_CHILD_CLEARTID` flags are set.
/// - The function pointer at `[child_sp]` must be a valid, callable function
///   that accepts a `usize` argument and returns a `usize`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_clone_thread(
    flags: usize,
    child_sp: usize,
    parent_tid: *mut i32,
    child_tid: *mut i32,
    tls: usize,
) -> Result<i32, i32> {
    // SAFETY: caller guarantees child_sp, parent_tid, child_tid validity
    // and proper stack setup. The inline asm handles parent vs child paths.
    let ret = unsafe {
        raw::clone_thread_asm(
            flags,
            child_sp,
            parent_tid as usize,
            child_tid as usize,
            tls,
        )
    };
    // Negative returns (in unsigned two's complement) indicate -errno.
    let signed = ret as isize;
    if signed < 0 {
        Err((-signed) as i32)
    } else {
        Ok(signed as i32)
    }
}

/// `pread64(fd, buf, count, offset)` — read from a file descriptor at a given offset.
///
/// # Safety
///
/// `buf` must point to a writable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe {
        raw::syscall4(
            SYS_PREAD64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        )
    };
    syscall_result(ret)
}

/// `pwrite64(fd, buf, count, offset)` — write to a file descriptor at a given offset.
///
/// # Safety
///
/// `buf` must point to a readable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pwrite64(
    fd: i32,
    buf: *const u8,
    count: usize,
    offset: i64,
) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe {
        raw::syscall4(
            SYS_PWRITE64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        )
    };
    syscall_result(ret)
}

/// `socket(domain, type, protocol)` — create an endpoint for communication.
///
/// Returns the file descriptor on success, or negative errno on failure.
#[inline]
#[allow(unsafe_code)]
pub fn sys_socket(domain: i32, socket_type: i32, protocol: i32) -> Result<i32, i32> {
    // SAFETY: socket syscall is safe to call with any arguments.
    let ret = unsafe {
        raw::syscall3(
            SYS_SOCKET,
            domain as usize,
            socket_type as usize,
            protocol as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `bind(sockfd, addr, addrlen)` — bind a name to a socket.
///
/// # Safety
///
/// `addr` must be a valid pointer to a sockaddr structure of size `addrlen`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_bind(sockfd: i32, addr: *const u8, addrlen: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall3(SYS_BIND, sockfd as usize, addr as usize, addrlen as usize) };
    syscall_result(ret).map(|_| ())
}

/// `listen(sockfd, backlog)` — listen for connections on a socket.
#[inline]
#[allow(unsafe_code)]
pub fn sys_listen(sockfd: i32, backlog: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_LISTEN, sockfd as usize, backlog as usize) };
    syscall_result(ret).map(|_| ())
}

/// `accept(sockfd, addr, addrlen)` — accept a connection on a socket.
///
/// # Safety
///
/// `addr` and `addrlen` must be valid pointers or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_accept(sockfd: i32, addr: *mut u8, addrlen: *mut u32) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall3(SYS_ACCEPT, sockfd as usize, addr as usize, addrlen as usize)
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `accept4(sockfd, addr, addrlen, flags)` — accept a connection with flags.
///
/// # Safety
///
/// `addr` and `addrlen` must be valid pointers or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_accept4(
    sockfd: i32,
    addr: *mut u8,
    addrlen: *mut u32,
    flags: i32,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_ACCEPT4,
            sockfd as usize,
            addr as usize,
            addrlen as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `connect(sockfd, addr, addrlen)` — initiate a connection on a socket.
///
/// # Safety
///
/// `addr` must be a valid pointer to a sockaddr structure of size `addrlen`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_connect(sockfd: i32, addr: *const u8, addrlen: u32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(SYS_CONNECT, sockfd as usize, addr as usize, addrlen as usize)
    };
    syscall_result(ret).map(|_| ())
}

/// `shutdown(sockfd, how)` — shut down part of a full-duplex connection.
#[inline]
#[allow(unsafe_code)]
pub fn sys_shutdown(sockfd: i32, how: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SHUTDOWN, sockfd as usize, how as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getsockopt(sockfd, level, optname, optval, optlen)` — get socket options.
///
/// # Safety
///
/// `optval` and `optlen` must be valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getsockopt(
    sockfd: i32,
    level: i32,
    optname: i32,
    optval: *mut u8,
    optlen: *mut u32,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_GETSOCKOPT,
            sockfd as usize,
            level as usize,
            optname as usize,
            optval as usize,
            optlen as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `getpeername(sockfd, addr, addrlen)` — get name of connected peer socket.
///
/// # Safety
///
/// `addr` and `addrlen` must be valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getpeername(sockfd: i32, addr: *mut u8, addrlen: *mut u32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(SYS_GETPEERNAME, sockfd as usize, addr as usize, addrlen as usize)
    };
    syscall_result(ret).map(|_| ())
}

/// `getsockname(sockfd, addr, addrlen)` — get socket name.
///
/// # Safety
///
/// `addr` and `addrlen` must be valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getsockname(sockfd: i32, addr: *mut u8, addrlen: *mut u32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(SYS_GETSOCKNAME, sockfd as usize, addr as usize, addrlen as usize)
    };
    syscall_result(ret).map(|_| ())
}

/// `socketpair(domain, type, protocol, sv)` — create a pair of connected sockets.
///
/// # Safety
///
/// `sv` must be a valid pointer to an array of two i32.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_socketpair(
    domain: i32,
    socket_type: i32,
    protocol: i32,
    sv: *mut i32,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_SOCKETPAIR,
            domain as usize,
            socket_type as usize,
            protocol as usize,
            sv as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `sendmsg(sockfd, msg, flags)` — send a message on a socket.
///
/// # Safety
///
/// `msg` must be a valid pointer to a msghdr structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sendmsg(sockfd: i32, msg: *const u8, flags: i32) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall3(SYS_SENDMSG, sockfd as usize, msg as usize, flags as usize)
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `recvmsg(sockfd, msg, flags)` — receive a message from a socket.
///
/// # Safety
///
/// `msg` must be a valid pointer to a msghdr structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_recvmsg(sockfd: i32, msg: *mut u8, flags: i32) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall3(SYS_RECVMSG, sockfd as usize, msg as usize, flags as usize)
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `prlimit64(pid, resource, new_limit, old_limit)` — get/set resource limits.
///
/// # Safety
///
/// `new_limit` and `old_limit` must be valid pointers if non-null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_prlimit64(
    pid: i32,
    resource: u32,
    new_limit: *const u8,
    old_limit: *mut u8,
) -> Result<(), i32> {
    // SAFETY: caller guarantees pointer validity.
    let ret = unsafe {
        raw::syscall4(
            SYS_PRLIMIT64,
            pid as usize,
            resource as usize,
            new_limit as usize,
            old_limit as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `sched_yield()` — yield the processor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_sched_yield() {
    // SAFETY: sched_yield is always safe to call.
    unsafe { raw::syscall0(SYS_SCHED_YIELD) };
}

/// `nanosleep(req, rem)` — high-resolution sleep.
///
/// # Safety
///
/// `req` must be a valid pointer to a timespec. `rem` may be null or valid.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_nanosleep(req: *const u8, rem: *mut u8) -> Result<(), i32> {
    // SAFETY: caller guarantees pointer validity.
    let ret = unsafe { raw::syscall2(SYS_NANOSLEEP, req as usize, rem as usize) };
    syscall_result(ret).map(|_| ())
}

/// `clock_gettime(clock_id, tp)` — get time of specified clock.
///
/// # Safety
///
/// `tp` must be a valid pointer to a timespec.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_clock_gettime(clock_id: i32, tp: *mut u8) -> Result<(), i32> {
    // SAFETY: caller guarantees tp pointer validity.
    let ret = unsafe { raw::syscall2(SYS_CLOCK_GETTIME, clock_id as usize, tp as usize) };
    syscall_result(ret).map(|_| ())
}

/// `clock_settime(clock_id, tp)` — set time of specified clock.
///
/// # Safety
///
/// `tp` must be a valid pointer to a timespec.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_clock_settime(clock_id: i32, tp: *const u8) -> Result<(), i32> {
    // SAFETY: caller guarantees tp pointer validity.
    let ret = unsafe { raw::syscall2(SYS_CLOCK_SETTIME, clock_id as usize, tp as usize) };
    syscall_result(ret).map(|_| ())
}

/// `settimeofday(tv, tz)` — set wall-clock time and timezone parameters.
///
/// # Safety
///
/// `tv` and `tz` may be null, or valid pointers to the corresponding structs.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_settimeofday(tv: *const u8, tz: *const u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SETTIMEOFDAY, tv as usize, tz as usize) };
    syscall_result(ret).map(|_| ())
}

/// `clock_getres(clock_id, res)` — get resolution of specified clock.
///
/// # Safety
///
/// `res` may be null, or a valid pointer to a timespec.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_clock_getres(clock_id: i32, res: *mut u8) -> Result<(), i32> {
    // SAFETY: caller guarantees res pointer validity if non-null.
    let ret = unsafe { raw::syscall2(SYS_CLOCK_GETRES, clock_id as usize, res as usize) };
    syscall_result(ret).map(|_| ())
}

/// `clock_nanosleep(clock_id, flags, req, rem)` — high-resolution sleep on specified clock.
///
/// # Safety
///
/// `req` must be a valid pointer to a timespec. `rem` may be null or valid.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_clock_nanosleep(
    clock_id: i32,
    flags: i32,
    req: *const u8,
    rem: *mut u8,
) -> Result<(), i32> {
    // SAFETY: caller guarantees pointer validity.
    let ret = unsafe {
        raw::syscall4(
            SYS_CLOCK_NANOSLEEP,
            clock_id as usize,
            flags as usize,
            req as usize,
            rem as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `sendto(fd, buf, len, flags, dest_addr, addrlen)` — send a message on a socket.
///
/// # Safety
///
/// `buf` must be a valid readable buffer of at least `len` bytes.
/// `dest_addr` must be a valid pointer if `addrlen > 0`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sendto(
    fd: i32,
    buf: *const u8,
    len: usize,
    flags: i32,
    dest_addr: *const u8,
    addrlen: usize,
) -> Result<isize, i32> {
    // SAFETY: caller guarantees buffer and address validity.
    let ret = unsafe {
        raw::syscall6(
            SYS_SENDTO,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            dest_addr as usize,
            addrlen,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `recvfrom(fd, buf, len, flags, src_addr, addrlen)` — receive a message from a socket.
///
/// # Safety
///
/// `buf` must be a valid writable buffer of at least `len` bytes.
/// `src_addr` and `addrlen` may be null, or must be valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_recvfrom(
    fd: i32,
    buf: *mut u8,
    len: usize,
    flags: i32,
    src_addr: *mut u8,
    addrlen: *mut u32,
) -> Result<isize, i32> {
    // SAFETY: caller guarantees buffer validity.
    let ret = unsafe {
        raw::syscall6(
            SYS_RECVFROM,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            src_addr as usize,
            addrlen as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `setsockopt(fd, level, optname, optval, optlen)` — set socket options.
///
/// # Safety
///
/// `optval` must be a valid readable pointer of at least `optlen` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_setsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *const u8,
    optlen: usize,
) -> Result<(), i32> {
    // SAFETY: caller guarantees optval validity.
    let ret = unsafe {
        raw::syscall5(
            SYS_SETSOCKOPT,
            fd as usize,
            level as usize,
            optname as usize,
            optval as usize,
            optlen,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `dup3(oldfd, newfd, flags)` — duplicate a file descriptor with flags.
#[inline]
#[allow(unsafe_code)]
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall3(SYS_DUP3, oldfd as usize, newfd as usize, flags as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `readv(fd, iov, iovcnt)` — read data into multiple buffers.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_readv(fd: i32, iov: *const u8, iovcnt: i32) -> Result<isize, i32> {
    let ret = unsafe { raw::syscall3(SYS_READV, fd as usize, iov as usize, iovcnt as usize) };
    syscall_result(ret).map(|v| v as isize)
}

/// `writev(fd, iov, iovcnt)` — write data from multiple buffers.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_writev(fd: i32, iov: *const u8, iovcnt: i32) -> Result<isize, i32> {
    let ret = unsafe { raw::syscall3(SYS_WRITEV, fd as usize, iov as usize, iovcnt as usize) };
    syscall_result(ret).map(|v| v as isize)
}

/// `sendfile(out_fd, in_fd, offset, count)` — transfer data between file descriptors.
///
/// # Safety
/// `offset` may be null or a valid pointer.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sendfile(
    out_fd: i32,
    in_fd: i32,
    offset: *mut i64,
    count: usize,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_SENDFILE,
            out_fd as usize,
            in_fd as usize,
            offset as usize,
            count,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)` — copy a range of data.
///
/// # Safety
/// Offset pointers may be null or valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_copy_file_range(
    fd_in: i32,
    off_in: *mut i64,
    fd_out: i32,
    off_out: *mut i64,
    len: usize,
    flags: u32,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall6(
            SYS_COPY_FILE_RANGE,
            fd_in as usize,
            off_in as usize,
            fd_out as usize,
            off_out as usize,
            len,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `preadv(fd, iov, iovcnt, offset)` — read data into multiple buffers at offset.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_preadv(fd: i32, iov: *const u8, iovcnt: i32, offset: i64) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_PREADV,
            fd as usize,
            iov as usize,
            iovcnt as usize,
            offset as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `pwritev(fd, iov, iovcnt, offset)` — write data from multiple buffers at offset.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pwritev(fd: i32, iov: *const u8, iovcnt: i32, offset: i64) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_PWRITEV,
            fd as usize,
            iov as usize,
            iovcnt as usize,
            offset as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `preadv2(fd, iov, iovcnt, offset, flags)` — read data with extended flags.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_preadv2(
    fd: i32,
    iov: *const u8,
    iovcnt: i32,
    offset: i64,
    flags: i32,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_PREADV2,
            fd as usize,
            iov as usize,
            iovcnt as usize,
            offset as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `pwritev2(fd, iov, iovcnt, offset, flags)` — write data with extended flags.
///
/// # Safety
/// `iov` must point to a valid array of `iovcnt` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pwritev2(
    fd: i32,
    iov: *const u8,
    iovcnt: i32,
    offset: i64,
    flags: i32,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_PWRITEV2,
            fd as usize,
            iov as usize,
            iovcnt as usize,
            offset as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `splice(fd_in, off_in, fd_out, off_out, len, flags)` — splice data between pipes.
///
/// # Safety
/// Offset pointers may be null or valid pointers.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_splice(
    fd_in: i32,
    off_in: *mut i64,
    fd_out: i32,
    off_out: *mut i64,
    len: usize,
    flags: u32,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall6(
            SYS_SPLICE,
            fd_in as usize,
            off_in as usize,
            fd_out as usize,
            off_out as usize,
            len,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `tee(fd_in, fd_out, len, flags)` — duplicate pipe content.
#[inline]
#[allow(unsafe_code)]
pub fn sys_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_TEE,
            fd_in as usize,
            fd_out as usize,
            len,
            flags as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `vmsplice(fd, iov, nr_segs, flags)` — splice user pages to pipe.
///
/// # Safety
/// `iov` must point to a valid array of `nr_segs` iovec structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_vmsplice(
    fd: i32,
    iov: *const u8,
    nr_segs: usize,
    flags: u32,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(SYS_VMSPLICE, fd as usize, iov as usize, nr_segs, flags as usize)
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `memfd_create(name, flags)` — create anonymous file.
///
/// # Safety
/// `name` must be a valid null-terminated C string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_memfd_create(name: *const u8, flags: u32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall2(SYS_MEMFD_CREATE, name as usize, flags as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `wait4(pid, wstatus, options, rusage)` — wait for process to change state.
///
/// # Safety
/// `wstatus` and `rusage` must be valid pointers or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_wait4(
    pid: i32,
    wstatus: *mut i32,
    options: i32,
    rusage: *mut u8,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_WAIT4,
            pid as usize,
            wstatus as usize,
            options as usize,
            rusage as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `execve(pathname, argv, envp)` — execute program.
///
/// # Safety
/// All pointers must be valid null-terminated arrays.
/// This function does not return on success.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_execve(
    pathname: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(SYS_EXECVE, pathname as usize, argv as usize, envp as usize)
    };
    syscall_result(ret).map(|_| ())
}

/// `readlinkat(dirfd, pathname, buf, bufsiz)` — read value of a symbolic link.
///
/// # Safety
/// `pathname` must be a valid C string, `buf` must be a valid buffer.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_readlinkat(
    dirfd: i32,
    pathname: *const u8,
    buf: *mut u8,
    bufsiz: usize,
) -> Result<isize, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_READLINKAT,
            dirfd as usize,
            pathname as usize,
            buf as usize,
            bufsiz,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `utimensat(dirfd, pathname, times, flags)` — update file timestamps.
///
/// # Safety
///
/// `pathname` and `times` may be null, or valid pointers for the syscall contract.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_utimensat(
    dirfd: i32,
    pathname: *const u8,
    times: *const u8,
    flags: i32,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_UTIMENSAT,
            dirfd as usize,
            pathname as usize,
            times as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `clone(flags, stack, ...)` — create a child process (simple fork variant).
///
/// For fork(), use flags=SIGCHLD and stack=0.
#[inline]
#[allow(unsafe_code)]
pub fn sys_clone_fork(flags: usize) -> Result<i32, i32> {
    // Simple clone for fork: flags=SIGCHLD, stack=0, no other args
    let ret = unsafe { raw::syscall2(SYS_CLONE, flags, 0) };
    syscall_result(ret).map(|v| v as i32)
}

/// `mlock(addr, len)` — lock a range of memory.
#[inline]
#[allow(unsafe_code)]
pub fn sys_mlock(addr: usize, len: usize) -> Result<(), i32> {
    // SAFETY: mlock is safe to call with any arguments.
    let ret = unsafe { raw::syscall2(SYS_MLOCK, addr, len) };
    syscall_result(ret).map(|_| ())
}

/// `mlock2(addr, len, flags)` — lock a range of memory with flags.
#[inline]
#[allow(unsafe_code)]
pub fn sys_mlock2(addr: usize, len: usize, flags: i32) -> Result<(), i32> {
    // SAFETY: mlock2 is safe to call with any arguments.
    let ret = unsafe { raw::syscall3(SYS_MLOCK2, addr, len, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `munlock(addr, len)` — unlock a range of memory.
#[inline]
#[allow(unsafe_code)]
pub fn sys_munlock(addr: usize, len: usize) -> Result<(), i32> {
    // SAFETY: munlock is safe to call with any arguments.
    let ret = unsafe { raw::syscall2(SYS_MUNLOCK, addr, len) };
    syscall_result(ret).map(|_| ())
}

/// `mlockall(flags)` — lock all of the calling process's virtual memory.
#[inline]
#[allow(unsafe_code)]
pub fn sys_mlockall(flags: i32) -> Result<(), i32> {
    // SAFETY: mlockall is safe to call with any flags.
    let ret = unsafe { raw::syscall1(SYS_MLOCKALL, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `munlockall()` — unlock all of the calling process's virtual memory.
#[inline]
#[allow(unsafe_code)]
pub fn sys_munlockall() -> Result<(), i32> {
    // SAFETY: munlockall is always safe to call.
    let ret = unsafe { raw::syscall0(SYS_MUNLOCKALL) };
    syscall_result(ret).map(|_| ())
}

/// `mremap(old_address, old_size, new_size, flags, new_address)` — remap a virtual memory address.
///
/// # Safety
///
/// The caller must ensure the memory regions are valid.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mremap(
    old_address: usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_address: usize,
) -> Result<usize, i32> {
    // SAFETY: caller guarantees memory region validity.
    let ret = unsafe {
        raw::syscall5(
            SYS_MREMAP,
            old_address,
            old_size,
            new_size,
            flags as usize,
            new_address,
        )
    };
    syscall_result(ret)
}

// -------------------------------------------------------------------------
// Signal syscalls
// -------------------------------------------------------------------------

/// `kill(pid, sig)` — send a signal to a process.
#[inline]
#[allow(unsafe_code)]
pub fn sys_kill(pid: i32, sig: i32) -> Result<(), i32> {
    // SAFETY: kill is safe to call with any arguments.
    let ret = unsafe { raw::syscall2(SYS_KILL, pid as usize, sig as usize) };
    syscall_result(ret).map(|_| ())
}

/// `rt_sigaction(signum, act, oldact, sigsetsize)` — examine and change a signal action.
///
/// # Safety
///
/// `act` and `oldact` must be valid pointers to sigaction structs or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_rt_sigaction(
    signum: i32,
    act: *const u8,
    oldact: *mut u8,
    sigsetsize: usize,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_RT_SIGACTION,
            signum as usize,
            act as usize,
            oldact as usize,
            sigsetsize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)` — examine and change blocked signals.
///
/// # Safety
///
/// `set` and `oldset` must be valid pointers to sigset_t or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_rt_sigprocmask(
    how: i32,
    set: *const u8,
    oldset: *mut u8,
    sigsetsize: usize,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_RT_SIGPROCMASK,
            how as usize,
            set as usize,
            oldset as usize,
            sigsetsize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `rt_sigpending(set, sigsetsize)` — examine pending signals.
///
/// # Safety
///
/// `set` must be a valid pointer to sigset_t.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_rt_sigpending(set: *mut u8, sigsetsize: usize) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_RT_SIGPENDING, set as usize, sigsetsize) };
    syscall_result(ret).map(|_| ())
}

/// `rt_sigtimedwait(set, info, timeout, sigsetsize)` — synchronously wait for queued signals.
///
/// # Safety
///
/// All pointers must be valid or null as appropriate.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_rt_sigtimedwait(
    set: *const u8,
    info: *mut u8,
    timeout: *const u8,
    sigsetsize: usize,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_RT_SIGTIMEDWAIT,
            set as usize,
            info as usize,
            timeout as usize,
            sigsetsize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `rt_sigsuspend(mask, sigsetsize)` — wait for a signal.
///
/// # Safety
///
/// `mask` must be a valid pointer to sigset_t.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_rt_sigsuspend(mask: *const u8, sigsetsize: usize) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_RT_SIGSUSPEND, mask as usize, sigsetsize) };
    syscall_result(ret).map(|_| ())
}

/// `sigaltstack(ss, old_ss)` — get and/or set signal stack context.
///
/// # Safety
///
/// `ss` and `old_ss` must be valid pointers to stack_t or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sigaltstack(ss: *const u8, old_ss: *mut u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SIGALTSTACK, ss as usize, old_ss as usize) };
    syscall_result(ret).map(|_| ())
}

/// `pause()` — wait for a signal.
///
/// Note: On aarch64, this is emulated via ppoll.
#[inline]
#[allow(unsafe_code)]
pub fn sys_pause() -> Result<(), i32> {
    #[cfg(target_arch = "x86_64")]
    {
        let ret = unsafe { raw::syscall0(SYS_PAUSE) };
        syscall_result(ret).map(|_| ())
    }
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 doesn't have pause, emulate with ppoll(NULL, 0, NULL, NULL)
        let ret = unsafe { raw::syscall4(SYS_PPOLL, 0, 0, 0, 0) };
        syscall_result(ret).map(|_| ())
    }
}

// -------------------------------------------------------------------------
// Poll/epoll/timerfd syscalls
// -------------------------------------------------------------------------

/// `poll(fds, nfds, timeout)` — wait for events on file descriptors.
///
/// # Safety
///
/// `fds` must be a valid pointer to `nfds` pollfd structures.
#[cfg(target_arch = "x86_64")]
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_poll(fds: *mut u8, nfds: usize, timeout: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall3(SYS_POLL, fds as usize, nfds, timeout as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `ppoll(fds, nfds, timeout, sigmask, sigsetsize)` — wait for events with signal mask.
///
/// # Safety
///
/// All pointers must be valid or null as appropriate.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_ppoll(
    fds: *mut u8,
    nfds: usize,
    timeout: *const u8,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_PPOLL,
            fds as usize,
            nfds,
            timeout as usize,
            sigmask as usize,
            sigsetsize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `select(nfds, readfds, writefds, exceptfds, timeout)` — synchronous I/O multiplexing.
///
/// # Safety
///
/// All pointers must be valid or null as appropriate.
#[cfg(target_arch = "x86_64")]
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_select(
    nfds: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    timeout: *mut u8,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_SELECT,
            nfds as usize,
            readfds as usize,
            writefds as usize,
            exceptfds as usize,
            timeout as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask_data)` — synchronous I/O multiplexing with signal mask.
///
/// # Safety
///
/// All pointers must be valid or null as appropriate.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pselect6(
    nfds: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    timeout: *const u8,
    sigmask_data: *const u8,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall6(
            SYS_PSELECT6,
            nfds as usize,
            readfds as usize,
            writefds as usize,
            exceptfds as usize,
            timeout as usize,
            sigmask_data as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `epoll_create1(flags)` — open an epoll file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_epoll_create1(flags: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall1(SYS_EPOLL_CREATE1, flags as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `epoll_ctl(epfd, op, fd, event)` — control interface for an epoll file descriptor.
///
/// # Safety
///
/// `event` must be a valid pointer to an epoll_event or null (for EPOLL_CTL_DEL).
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut u8) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            op as usize,
            fd as usize,
            event as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)` — wait for I/O events with signal mask.
///
/// # Safety
///
/// `events` must be a valid pointer to `maxevents` epoll_event structures.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_epoll_pwait(
    epfd: i32,
    events: *mut u8,
    maxevents: i32,
    timeout: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall6(
            SYS_EPOLL_PWAIT,
            epfd as usize,
            events as usize,
            maxevents as usize,
            timeout as usize,
            sigmask as usize,
            sigsetsize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `eventfd2(initval, flags)` — create a file descriptor for event notification.
#[inline]
#[allow(unsafe_code)]
pub fn sys_eventfd2(initval: u32, flags: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall2(SYS_EVENTFD2, initval as usize, flags as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `timerfd_create(clockid, flags)` — create a timer file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_timerfd_create(clockid: i32, flags: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall2(SYS_TIMERFD_CREATE, clockid as usize, flags as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `timerfd_settime(fd, flags, new_value, old_value)` — arm/disarm and fetch state of timer.
///
/// # Safety
///
/// `new_value` and `old_value` must be valid pointers to itimerspec or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_timerfd_settime(
    fd: i32,
    flags: i32,
    new_value: *const u8,
    old_value: *mut u8,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_TIMERFD_SETTIME,
            fd as usize,
            flags as usize,
            new_value as usize,
            old_value as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `timerfd_gettime(fd, curr_value)` — fetch state of timer.
///
/// # Safety
///
/// `curr_value` must be a valid pointer to itimerspec.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_timerfd_gettime(fd: i32, curr_value: *mut u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_TIMERFD_GETTIME, fd as usize, curr_value as usize) };
    syscall_result(ret).map(|_| ())
}

/// `prctl(option, arg2, arg3, arg4, arg5)` — operations on a process.
#[inline]
#[allow(unsafe_code)]
pub fn sys_prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> Result<i32, i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_PRCTL,
            option as usize,
            arg2,
            arg3,
            arg4,
            arg5,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

// -------------------------------------------------------------------------
// Process management syscalls
// -------------------------------------------------------------------------

/// `setpgid(pid, pgid)` — set process group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setpgid(pid: i32, pgid: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SETPGID, pid as usize, pgid as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getpgrp()` — get process group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getpgrp() -> i32 {
    let ret = unsafe { raw::syscall0(SYS_GETPGRP) };
    ret as i32
}

/// `setuid(uid)` — set user identity.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setuid(uid: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_SETUID, uid as usize) };
    syscall_result(ret).map(|_| ())
}

/// `setgid(gid)` — set group identity.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setgid(gid: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_SETGID, gid as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getegid()` — get effective group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getegid() -> u32 {
    let ret = unsafe { raw::syscall0(SYS_GETEGID) };
    ret as u32
}

/// `chdir(path)` — change working directory.
///
/// # Safety
///
/// `path` must be a valid null-terminated pathname.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_chdir(path: *const u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_CHDIR, path as usize) };
    syscall_result(ret).map(|_| ())
}

/// `fchdir(fd)` — change working directory via file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fchdir(fd: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_FCHDIR, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `close_range(first, last, flags)` — close a range of file descriptors.
#[inline]
#[allow(unsafe_code)]
pub fn sys_close_range(first: u32, last: u32, flags: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall3(SYS_CLOSE_RANGE, first as usize, last as usize, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `sched_setparam(pid, param)` — set scheduling parameters.
///
/// # Safety
///
/// `param` must be a valid pointer to a sched_param structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sched_setparam(pid: i32, param: *const u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SCHED_SETPARAM, pid as usize, param as usize) };
    syscall_result(ret).map(|_| ())
}

/// `sched_getparam(pid, param)` — get scheduling parameters.
///
/// # Safety
///
/// `param` must be a valid pointer to a sched_param structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sched_getparam(pid: i32, param: *mut u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SCHED_GETPARAM, pid as usize, param as usize) };
    syscall_result(ret).map(|_| ())
}

/// `unlinkat(dirfd, pathname, flags)` — remove a directory entry.
///
/// # Safety
///
/// `pathname` must be a valid null-terminated pathname.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_unlinkat(dirfd: i32, pathname: *const u8, flags: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall3(SYS_UNLINKAT, dirfd as usize, pathname as usize, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `waitid(idtype, id, infop, options, rusage)` — wait for a child process to change state (extended).
///
/// # Safety
///
/// `infop` and `rusage` must be valid pointers or null.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_waitid(
    idtype: i32,
    id: u32,
    infop: *mut u8,
    options: i32,
    rusage: *mut u8,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_WAITID,
            idtype as usize,
            id as usize,
            infop as usize,
            options as usize,
            rusage as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `sched_setscheduler(pid, policy, param)` — set scheduling policy and parameters.
///
/// # Safety
///
/// `param` must be a valid pointer to a sched_param structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_sched_setscheduler(pid: i32, policy: i32, param: *const u8) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(
            SYS_SCHED_SETSCHEDULER,
            pid as usize,
            policy as usize,
            param as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `sched_getscheduler(pid)` — get current scheduling policy.
#[inline]
#[allow(unsafe_code)]
pub fn sys_sched_getscheduler(pid: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall1(SYS_SCHED_GETSCHEDULER, pid as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `symlinkat(target, newdirfd, linkpath)` — create a symbolic link relative to directory fd.
///
/// # Safety
///
/// Both pointers must be valid NUL-terminated strings.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(
            SYS_SYMLINKAT,
            target as usize,
            newdirfd as usize,
            linkpath as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `faccessat(dirfd, pathname, mode, flags)` — check file accessibility.
///
/// # Safety
///
/// `pathname` must be a valid NUL-terminated string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_faccessat(dirfd: i32, pathname: *const u8, mode: i32, flags: i32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_FACCESSAT,
            dirfd as usize,
            pathname as usize,
            mode as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `mkdirat(dirfd, pathname, mode)` — create a directory relative to directory fd.
///
/// # Safety
///
/// `pathname` must be a valid NUL-terminated string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mkdirat(dirfd: i32, pathname: *const u8, mode: u32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall3(
            SYS_MKDIRAT,
            dirfd as usize,
            pathname as usize,
            mode as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `fchmodat(dirfd, pathname, mode, flags)` — change file mode relative to directory fd.
///
/// # Safety
///
/// `pathname` must be a valid NUL-terminated string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fchmodat(dirfd: i32, pathname: *const u8, mode: u32, flags: i32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall4(
            SYS_FCHMODAT,
            dirfd as usize,
            pathname as usize,
            mode as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `fchownat(dirfd, pathname, owner, group, flags)` — change file ownership relative to directory fd.
///
/// # Safety
///
/// `pathname` must be a valid NUL-terminated string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fchownat(dirfd: i32, pathname: *const u8, owner: u32, group: u32, flags: i32) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_FCHOWNAT,
            dirfd as usize,
            pathname as usize,
            owner as usize,
            group as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `fchmod(fd, mode)` — change file mode by file descriptor.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fchmod(fd: i32, mode: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_FCHMOD, fd as usize, mode as usize) };
    syscall_result(ret).map(|_| ())
}

/// `fchown(fd, owner, group)` — change file ownership by file descriptor.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fchown(fd: i32, owner: u32, group: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall3(SYS_FCHOWN, fd as usize, owner as usize, group as usize) };
    syscall_result(ret).map(|_| ())
}

/// `umask(mask)` — set file mode creation mask.
#[inline]
#[allow(unsafe_code)]
pub fn sys_umask(mask: u32) -> u32 {
    let ret = unsafe { raw::syscall1(SYS_UMASK, mask as usize) };
    ret as u32
}

/// `truncate(path, length)` — truncate a file to a specified length.
///
/// # Safety
///
/// `path` must be a valid NUL-terminated string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_truncate(path: *const u8, length: i64) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_TRUNCATE, path as usize, length as usize) };
    syscall_result(ret).map(|_| ())
}

/// `ftruncate(fd, length)` — truncate a file to a specified length by fd.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_ftruncate(fd: i32, length: i64) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_FTRUNCATE, fd as usize, length as usize) };
    syscall_result(ret).map(|_| ())
}

/// `flock(fd, operation)` — apply or remove an advisory lock on a file.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_flock(fd: i32, operation: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_FLOCK, fd as usize, operation as usize) };
    syscall_result(ret).map(|_| ())
}

/// `linkat(olddirfd, oldpath, newdirfd, newpath, flags)` — create a hard link.
///
/// # Safety
///
/// `oldpath` and `newpath` must be valid NUL-terminated strings.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_LINKAT,
            olddirfd as usize,
            oldpath as usize,
            newdirfd as usize,
            newpath as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `getcwd(buf, size)` — get current working directory.
///
/// # Safety
///
/// `buf` must point to a buffer of at least `size` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getcwd(buf: *mut u8, size: usize) -> Result<usize, i32> {
    let ret = unsafe { raw::syscall2(SYS_GETCWD, buf as usize, size) };
    syscall_result(ret)
}

/// `getppid()` — get parent process ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getppid() -> i32 {
    let ret = unsafe { raw::syscall0(SYS_GETPPID) };
    ret as i32
}

/// `getuid()` — get real user ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getuid() -> u32 {
    let ret = unsafe { raw::syscall0(SYS_GETUID) };
    ret as u32
}

/// `getgid()` — get real group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getgid() -> u32 {
    let ret = unsafe { raw::syscall0(SYS_GETGID) };
    ret as u32
}

/// `getpgid(pid)` — get process group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getpgid(pid: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall1(SYS_GETPGID, pid as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `getsid(pid)` — get session ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getsid(pid: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall1(SYS_GETSID, pid as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `setsid()` — create session and set process group ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setsid() -> Result<i32, i32> {
    let ret = unsafe { raw::syscall0(SYS_SETSID) };
    syscall_result(ret).map(|v| v as i32)
}

/// `setreuid(ruid, euid)` — set real and effective user IDs.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setreuid(ruid: u32, euid: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SETREUID, ruid as usize, euid as usize) };
    syscall_result(ret).map(|_| ())
}

/// `setregid(rgid, egid)` — set real and effective group IDs.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setregid(rgid: u32, egid: u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SETREGID, rgid as usize, egid as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getgroups(size, list)` — get list of supplementary group IDs.
///
/// # Safety
///
/// `list` must point to a buffer that can hold at least `size` group IDs.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getgroups(size: i32, list: *mut u32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall2(SYS_GETGROUPS, size as usize, list as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `setgroups(size, list)` — set list of supplementary group IDs.
///
/// # Safety
///
/// `list` must point to a buffer containing at least `size` group IDs.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_setgroups(size: usize, list: *const u32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_SETGROUPS, size, list as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getrandom(buf, buflen, flags)` — get random bytes.
///
/// # Safety
///
/// `buf` must point to a buffer of at least `buflen` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getrandom(buf: *mut u8, buflen: usize, flags: u32) -> Result<isize, i32> {
    let ret = unsafe { raw::syscall3(SYS_GETRANDOM, buf as usize, buflen, flags as usize) };
    syscall_result(ret).map(|v| v as isize)
}

/// `alarm(seconds)` — set an alarm clock for delivery of SIGALRM.
#[inline]
#[allow(unsafe_code)]
#[cfg(target_arch = "x86_64")]
pub fn sys_alarm(seconds: u32) -> u32 {
    let ret = unsafe { raw::syscall1(SYS_ALARM, seconds as usize) };
    ret as u32
}

/// `uname(buf)` — get name and information about current kernel.
///
/// # Safety
///
/// `buf` must point to a valid utsname structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_uname(buf: *mut u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_UNAME, buf as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getrusage(who, usage)` — get resource usage.
///
/// # Safety
///
/// `usage` must point to a valid rusage structure.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getrusage(who: i32, usage: *mut u8) -> Result<(), i32> {
    let ret = unsafe { raw::syscall2(SYS_GETRUSAGE, who as usize, usage as usize) };
    syscall_result(ret).map(|_| ())
}

/// `renameat2(olddirfd, oldpath, newdirfd, newpath, flags)` — rename a file.
///
/// # Safety
///
/// `oldpath` and `newpath` must be valid NUL-terminated strings.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_renameat2(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: u32,
) -> Result<(), i32> {
    let ret = unsafe {
        raw::syscall5(
            SYS_RENAMEAT2,
            olddirfd as usize,
            oldpath as usize,
            newdirfd as usize,
            newpath as usize,
            flags as usize,
        )
    };
    syscall_result(ret).map(|_| ())
}

/// `getpriority(which, who)` — get program scheduling priority.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getpriority(which: i32, who: i32) -> Result<i32, i32> {
    let ret = unsafe { raw::syscall2(SYS_GETPRIORITY, which as usize, who as usize) };
    // getpriority returns 20 - nice value (so 1-40), -1 on error
    // We need to handle this specially as 20 needs to be subtracted
    if (ret as isize) < 0 {
        Err(-(ret as i32))
    } else {
        Ok(20 - ret as i32)
    }
}

/// `setpriority(which, who, prio)` — set program scheduling priority.
#[inline]
#[allow(unsafe_code)]
pub fn sys_setpriority(which: i32, who: i32, prio: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall3(SYS_SETPRIORITY, which as usize, who as usize, prio as usize) };
    syscall_result(ret).map(|_| ())
}

/// `sync()` — commit filesystem caches to disk.
#[inline]
#[allow(unsafe_code)]
pub fn sys_sync() {
    unsafe { raw::syscall0(SYS_SYNC) };
}

/// `syncfs(fd)` — commit filesystem caches for the filesystem containing fd.
#[inline]
#[allow(unsafe_code)]
pub fn sys_syncfs(fd: i32) -> Result<(), i32> {
    let ret = unsafe { raw::syscall1(SYS_SYNCFS, fd as usize) };
    syscall_result(ret).map(|_| ())
}

// -------------------------------------------------------------------------
// Unit tests
// -------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn getpid_returns_positive() {
        let pid = sys_getpid();
        assert!(pid > 0, "getpid should return a positive PID, got {pid}");
    }

    #[test]
    fn getpid_is_consistent() {
        let a = sys_getpid();
        let b = sys_getpid();
        assert_eq!(
            a, b,
            "getpid should return the same value on repeated calls"
        );
    }

    #[test]
    fn write_to_stdout() {
        let msg = b"";
        // SAFETY: msg is a valid byte slice.
        let result = unsafe { sys_write(1, msg.as_ptr(), msg.len()) };
        assert_eq!(result, Ok(0), "write of 0 bytes to stdout should succeed");
    }

    #[test]
    fn pipe_read_write_roundtrip() {
        let mut fds = [0i32; 2];
        // SAFETY: fds is a valid [i32; 2].
        let pipe_res = unsafe { sys_pipe2(fds.as_mut_ptr(), 0) };
        assert!(pipe_res.is_ok(), "pipe2 should succeed");

        let msg = b"hello veneer";
        // SAFETY: msg is valid, fds[1] is the write end.
        let written = unsafe { sys_write(fds[1], msg.as_ptr(), msg.len()) };
        assert_eq!(written, Ok(msg.len()), "write should write all bytes");

        let mut buf = [0u8; 32];
        // SAFETY: buf is valid, fds[0] is the read end.
        let read = unsafe { sys_read(fds[0], buf.as_mut_ptr(), buf.len()) };
        assert_eq!(read, Ok(msg.len()), "read should return same byte count");
        assert_eq!(
            &buf[..msg.len()],
            msg,
            "read data should match written data"
        );

        assert!(sys_close(fds[0]).is_ok());
        assert!(sys_close(fds[1]).is_ok());
    }

    #[test]
    fn close_bad_fd_returns_ebadf() {
        let result = sys_close(-1);
        assert_eq!(result, Err(9), "close(-1) should return EBADF (9)");
    }

    #[test]
    fn mmap_anonymous_roundtrip() {
        let page_size = 4096usize;
        // MAP_PRIVATE=0x02, MAP_ANONYMOUS=0x20, PROT_READ=0x1, PROT_WRITE=0x2
        // SAFETY: anonymous mmap with no fd.
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                page_size,
                0x1 | 0x2,   // PROT_READ | PROT_WRITE
                0x02 | 0x20, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        };
        assert!(ptr.is_ok(), "mmap should succeed, got {ptr:?}");
        let ptr = ptr.unwrap();
        assert!(!ptr.is_null(), "mmap should return non-null");

        // Write and read back.
        // SAFETY: we just mapped this region as RW.
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42, "should be able to write/read mapped memory");
        }

        // SAFETY: valid mapping.
        let unmap = unsafe { sys_munmap(ptr, page_size) };
        assert!(unmap.is_ok(), "munmap should succeed");
    }

    #[test]
    fn mprotect_removes_write_access() {
        let page_size = 4096usize;
        // SAFETY: anonymous mmap.
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                page_size,
                0x1 | 0x2,   // PROT_READ | PROT_WRITE
                0x02 | 0x20, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        }
        .expect("mmap should succeed");

        // SAFETY: valid mapping, changing to read-only.
        let protect = unsafe { sys_mprotect(ptr, page_size, 0x1) }; // PROT_READ only
        assert!(protect.is_ok(), "mprotect should succeed");

        // We don't test the SIGSEGV here — just that the syscall itself works.
        // SAFETY: valid mapping.
        let unmap = unsafe { sys_munmap(ptr, page_size) };
        assert!(unmap.is_ok());
    }

    #[test]
    fn syscall_result_success() {
        assert_eq!(syscall_result(0), Ok(0));
        assert_eq!(syscall_result(42), Ok(42));
        assert_eq!(syscall_result(usize::MAX - 4096), Ok(usize::MAX - 4096));
    }

    #[test]
    fn syscall_result_error() {
        // -1 as usize = usize::MAX → errno 1 (EPERM)
        assert_eq!(syscall_result(usize::MAX), Err(1));
        // -9 as usize → errno 9 (EBADF)
        assert_eq!(syscall_result((-9isize) as usize), Err(9));
        // -4095 as usize → errno 4095 (max)
        assert_eq!(syscall_result((-4095isize) as usize), Err(4095));
    }

    #[test]
    fn lseek_bad_fd() {
        let result = sys_lseek(-1, 0, 0);
        assert_eq!(result, Err(9), "lseek(-1) should return EBADF");
    }

    #[test]
    fn dup_bad_fd() {
        let result = sys_dup(-1);
        assert_eq!(result, Err(9), "dup(-1) should return EBADF");
    }

    #[test]
    fn fsync_bad_fd() {
        let result = sys_fsync(-1);
        assert_eq!(result, Err(9), "fsync(-1) should return EBADF");
    }

    #[test]
    fn openat_and_close_dev_null() {
        // O_RDONLY=0, AT_FDCWD=-100
        let path = b"/dev/null\0";
        // SAFETY: path is a valid C string.
        let fd = unsafe { sys_openat(-100, path.as_ptr(), 0, 0) };
        assert!(fd.is_ok(), "openat /dev/null should succeed, got {fd:?}");
        let fd = fd.unwrap();
        assert!(fd >= 0, "fd should be non-negative");
        assert!(sys_close(fd).is_ok(), "close should succeed");
    }
}
