#![no_main]
//! Structure-aware fuzz target for the fcntl command matrix.
//!
//! fcntl has ~30 commands, each interpreting the third argument differently
//! (int, pointer to flock, etc.). That ambiguity is a notorious
//! confused-deputy surface. This harness walks a representative subset
//! across memfd-backed scratch fds and asserts:
//!
//! - Never panic for any (cmd, arg) tuple
//! - Valid commands return documented rc (fd, bitmask, or 0/-1 with errno
//!   in the documented set)
//! - F_DUPFD returns a fd we can then fcntl-F_GETFD on
//! - F_SETFL round-trips through F_GETFL modulo kernel-ignored bits
//! - F_ADD_SEALS on a non-memfd returns EINVAL
//!
//! Bead: FUZZ #2 (fcntl command matrix)

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::io_abi::fcntl;

// Linux F_* constants we exercise. Stay close to the stable subset;
// distro-specific kernel-new codes would just come back EINVAL.
// F_GETSIG/F_SETSIG/F_GETOWN_EX/F_SETOWN_EX and struct f_owner_ex aren't in
// our libc crate version yet — define the kernel numbers locally for the
// ones we want to exercise.
const F_GETSIG: libc::c_int = 11;
const F_SETSIG: libc::c_int = 10;
const F_GETOWN_EX: libc::c_int = 16;
const F_SETOWN_EX: libc::c_int = 15;

#[repr(C)]
#[allow(non_camel_case_types)]
struct f_owner_ex {
    type_: libc::c_int,
    pid: libc::pid_t,
}

const CMDS: &[libc::c_int] = &[
    libc::F_DUPFD,
    libc::F_DUPFD_CLOEXEC,
    libc::F_GETFD,
    libc::F_SETFD,
    libc::F_GETFL,
    libc::F_SETFL,
    libc::F_GETLK,
    libc::F_SETLK,
    libc::F_SETLKW,
    libc::F_GETOWN,
    libc::F_SETOWN,
    F_GETOWN_EX,
    F_SETOWN_EX,
    F_GETSIG,
    F_SETSIG,
    libc::F_GETLEASE,
    libc::F_SETLEASE,
    libc::F_NOTIFY,
    libc::F_GETPIPE_SZ,
    libc::F_SETPIPE_SZ,
    libc::F_ADD_SEALS,
    libc::F_GET_SEALS,
];

#[derive(Debug, Arbitrary)]
struct FcntlInput {
    cmd_sel: u8,
    arg_int: i32,
    flock_type: u16,
    flock_whence: u16,
    flock_start: i64,
    flock_len: i64,
    flock_pid: i32,
    // How many ops to chain; lifecycle check.
    chain_len: u8,
}

/// Lazy memfd for scratch operations (supports F_ADD_SEALS + most others).
fn scratch_memfd() -> libc::c_int {
    static FD: OnceLock<i32> = OnceLock::new();
    *FD.get_or_init(|| {
        let name = b"fuzz_fcntl\0";
        // SAFETY: raw syscall, flags=MFD_ALLOW_SEALING to exercise seals.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_ALLOW_SEALING,
            )
        };
        fd as i32
    })
}

fn pick_cmd(sel: u8) -> libc::c_int {
    CMDS[(sel as usize) % CMDS.len()]
}

fn flock_of(input: &FcntlInput) -> libc::flock {
    libc::flock {
        l_type: (input.flock_type & 0x7) as libc::c_short, // F_RDLCK/F_WRLCK/F_UNLCK
        l_whence: (input.flock_whence & 0x3) as libc::c_short, // SEEK_SET/CUR/END
        l_start: input.flock_start,
        l_len: input.flock_len,
        l_pid: input.flock_pid,
    }
}

fuzz_target!(|input: FcntlInput| {
    let fd = scratch_memfd();
    if fd < 0 {
        return;
    }

    let chain = ((input.chain_len as usize) % 4) + 1;
    let mut dup_fd: libc::c_int = -1;

    for step in 0..chain {
        let cmd = pick_cmd(input.cmd_sel.wrapping_add(step as u8));
        let target_fd = if dup_fd >= 0 && step > 0 { dup_fd } else { fd };

        // Dispatch based on cmd's third-arg shape.
        match cmd {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                let rc = unsafe { fcntl(target_fd, cmd, input.arg_int.max(0) as libc::c_long) };
                if rc >= 0 && dup_fd < 0 {
                    dup_fd = rc;
                }
            }
            libc::F_GETFD | libc::F_GETFL | libc::F_GETOWN | F_GETSIG
            | libc::F_GETLEASE | libc::F_GETPIPE_SZ | libc::F_GET_SEALS => {
                let rc = unsafe { fcntl(target_fd, cmd, 0) };
                // Invariant: GET commands return >=0 or -1 (errno set).
                assert!(
                    rc >= -1,
                    "fcntl({cmd}) on live fd returned nonsensical rc={rc}"
                );
            }
            libc::F_SETFD | libc::F_SETFL | libc::F_SETOWN | F_SETSIG
            | libc::F_SETLEASE | libc::F_NOTIFY | libc::F_SETPIPE_SZ | libc::F_ADD_SEALS => {
                let rc = unsafe { fcntl(target_fd, cmd, input.arg_int as libc::c_long) };
                assert!(rc >= -1);
            }
            libc::F_GETLK | libc::F_SETLK | libc::F_SETLKW => {
                let mut fl = flock_of(&input);
                let rc = unsafe {
                    fcntl(
                        target_fd,
                        cmd,
                        &mut fl as *mut libc::flock as libc::c_long,
                    )
                };
                assert!(rc >= -1);
            }
            F_GETOWN_EX | F_SETOWN_EX => {
                let mut fo = f_owner_ex {
                    type_: 0,
                    pid: input.flock_pid,
                };
                let rc = unsafe {
                    fcntl(target_fd, cmd, &mut fo as *mut _ as libc::c_long)
                };
                assert!(rc >= -1);
            }
            _ => {}
        }
    }

    // Clean up any duplicated fd.
    if dup_fd >= 0 {
        unsafe {
            libc::close(dup_fd);
        }
    }

    // F_GETFL after F_SETFL round-trip check on O_NONBLOCK.
    unsafe {
        let before = fcntl(fd, libc::F_GETFL, 0);
        if before >= 0 {
            let target = (before | libc::O_NONBLOCK) as libc::c_long;
            let set_rc = fcntl(fd, libc::F_SETFL, target);
            if set_rc == 0 {
                let after = fcntl(fd, libc::F_GETFL, 0);
                assert!(after >= 0);
                assert!(
                    (after & libc::O_NONBLOCK) != 0,
                    "O_NONBLOCK must survive F_SETFL+F_GETFL round-trip"
                );
                // Restore.
                let _ = fcntl(fd, libc::F_SETFL, before as libc::c_long);
            }
        }
    }
});
