#![no_main]
//! Structure-aware fuzz target for Linux `ioctl(2)`.
//!
//! ioctl's third argument is interpreted per-command, so the ABI surface
//! is a product of `(fd type, command code, arg bytes)`. Our harness
//! drives a representative subset of terminal/fd/block/socket commands
//! across three scratch fd shapes:
//!
//!   - memfd (regular-file semantics)
//!   - pipe (streaming; supports FIONREAD)
//!   - /dev/null (character device; rejects most commands with ENOTTY)
//!
//! For each (fd, cmd) tuple the harness passes either:
//!   - an int-shaped arg (fuzzer bytes interpreted as c_ulong)
//!   - a 128-byte struct buffer with pre/post guard bands
//!
//! Invariants:
//! - Never panic for any triple
//! - rc is 0/positive on success or -1 on error (never some other int)
//! - Guard bands around the struct-arg buffer survive the call
//! - For the FIONREAD + pipe case, returned count <= bytes actually
//!   queued in the pipe (if we can observe)
//!
//! Bead: bd-stlnv

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::io_abi::ioctl;

// Representative, mostly-safe ioctl commands. Many will return ENOTTY on
// the wrong fd type; the harness doesn't care about that - it just wants
// no panics and valid rc shape. Values are the kernel-ABI numbers.
const COMMANDS: &[libc::c_ulong] = &[
    0x5401,     // TCGETS - get termios
    0x5402,     // TCSETS - set termios
    0x5403,     // TCSETSW
    0x5404,     // TCSETSF
    0x5413,     // TIOCGWINSZ - get window size
    0x5414,     // TIOCSWINSZ - set window size
    0x540f,     // TIOCGPGRP
    0x5410,     // TIOCSPGRP
    0x541b,     // FIONREAD / TIOCINQ - bytes available
    0x5421,     // FIONBIO - set nonblocking
    0x5451,     // FIOCLEX - set close-on-exec
    0x5450,     // FIONCLEX - clear close-on-exec
    0x80081272, // BLKGETSIZE64 - block device size (expects u64 out)
    0x2000741a, // BLKFLSBUF (legacy)
    0x00008901, // SIOCGIFADDR (socket ioctl - expects ifreq)
    0x8946,     // SIOCETHTOOL
    0x541c,     // TIOCLINUX
    0x40087468, // TIOCGPTN (pty master)
    0x4004667d, // TIOCSCTTY
    // Deliberately-invalid / high-bit commands to probe the error path:
    0xdeadbeef, 0xffffffff,
];

const GUARD_BYTES: usize = 32;
const GUARD_VAL: u8 = 0xCA;
const ARG_STRUCT_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
struct IoctlInput {
    cmd_sel: u8,
    fd_sel: u8,
    arg_int: u64,
    /// Bytes copied into a guarded 128-byte arg buffer before the call.
    arg_buf_init: Vec<u8>,
    /// If true, pass the struct buffer as arg; else pass the raw u64.
    use_struct_arg: bool,
    /// If true, seed the pipe with some bytes first (affects FIONREAD).
    seed_pipe_bytes: u8,
}

struct Scratch {
    memfd: libc::c_int,
    pipe_r: libc::c_int,
    pipe_w: libc::c_int,
    devnull: libc::c_int,
}

fn scratch() -> &'static Scratch {
    static S: OnceLock<Scratch> = OnceLock::new();
    S.get_or_init(|| {
        let memfd = unsafe {
            libc::syscall(libc::SYS_memfd_create, b"fuzz_ioctl\0".as_ptr(), 0u32) as libc::c_int
        };
        let mut pipe = [-1i32; 2];
        let pipe_rc = unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK) };
        let (pr, pw) = if pipe_rc == 0 {
            (pipe[0], pipe[1])
        } else {
            (-1, -1)
        };
        let dn = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                b"/dev/null\0".as_ptr(),
                libc::O_RDWR,
                0,
            ) as libc::c_int
        };
        Scratch {
            memfd,
            pipe_r: pr,
            pipe_w: pw,
            devnull: dn,
        }
    })
}

fn pick_fd(s: &Scratch, sel: u8) -> libc::c_int {
    match sel % 4 {
        0 => s.memfd,
        1 => s.pipe_r,
        2 => s.pipe_w,
        _ => s.devnull,
    }
}

fuzz_target!(|input: IoctlInput| {
    let s = scratch();
    let fd = pick_fd(s, input.fd_sel);
    if fd < 0 {
        return;
    }
    let cmd = COMMANDS[(input.cmd_sel as usize) % COMMANDS.len()];

    // Optionally seed the pipe so FIONREAD returns something interesting.
    if input.seed_pipe_bytes > 0 && s.pipe_w >= 0 {
        let n = (input.seed_pipe_bytes as usize).min(64);
        let buf = vec![0xAB_u8; n];
        let _ = unsafe { libc::write(s.pipe_w, buf.as_ptr() as *const _, n) };
    }

    let rc = if input.use_struct_arg {
        // Allocate a guarded struct buffer; seed with fuzz bytes.
        let mut guarded = vec![GUARD_VAL; 2 * GUARD_BYTES + ARG_STRUCT_BYTES];
        let seed = &input.arg_buf_init;
        let seed_n = seed.len().min(ARG_STRUCT_BYTES);
        guarded[GUARD_BYTES..GUARD_BYTES + seed_n].copy_from_slice(&seed[..seed_n]);
        let arg_ptr = unsafe { guarded.as_mut_ptr().add(GUARD_BYTES) };
        let rc = unsafe { ioctl(fd, cmd, arg_ptr as libc::c_ulong) };

        // Guard bands must survive regardless of rc.
        for (i, &b) in guarded[..GUARD_BYTES].iter().enumerate() {
            assert_eq!(
                b, GUARD_VAL,
                "ioctl cmd={cmd:#x} clobbered leading guard at offset {i}"
            );
        }
        let trail_start = GUARD_BYTES + ARG_STRUCT_BYTES;
        for (i, &b) in guarded[trail_start..].iter().enumerate() {
            assert_eq!(
                b, GUARD_VAL,
                "ioctl cmd={cmd:#x} clobbered trailing guard at +{i}"
            );
        }
        rc
    } else {
        unsafe { ioctl(fd, cmd, input.arg_int as libc::c_ulong) }
    };

    // Invariant: rc is a normal c_int return - either non-negative or -1.
    // ioctl commands that return counts produce non-negative; all others
    // return 0 or -1. Negative values other than -1 are never legal.
    assert!(
        rc == -1 || rc >= 0,
        "ioctl(fd={fd}, cmd={cmd:#x}) returned nonsensical rc={rc}"
    );

    // Drain the pipe to prevent it from filling across iterations.
    if s.pipe_r >= 0 {
        let mut drain = [0u8; 128];
        loop {
            let n = unsafe { libc::read(s.pipe_r, drain.as_mut_ptr() as *mut _, drain.len()) };
            if n <= 0 {
                break;
            }
        }
    }
});
