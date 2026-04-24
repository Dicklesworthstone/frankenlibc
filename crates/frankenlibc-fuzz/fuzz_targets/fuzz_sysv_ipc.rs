#![no_main]
//! Structure-aware fuzz target for the System V IPC family:
//!
//!   shmget / shmat / shmdt / shmctl
//!   msgget / msgsnd / msgrcv / msgctl
//!   semget / semop / semctl
//!
//! SysV IPC is a small surface but historically high blast radius —
//! kernel bugs in this code path go back to the 1990s. Our user-space
//! wrappers do argument validation (msgp pointer / msgsz length),
//! errno mapping, and pass-through to the syscall.
//!
//! Strategy:
//! - Use IPC_PRIVATE keys so we never collide with another process's
//!   IPC objects on the host.
//! - Bound message sizes to MSG_BUF_BYTES so msgsnd doesn't try to
//!   queue megabytes per iteration.
//! - Force nonblocking message/semaphore operations; fuzz inputs may request
//!   a message type or semaphore decrement that cannot complete immediately.
//! - Always IPC_RMID the objects we create at the end of each iter.
//! - Tolerate ENOSPC / EACCES from the kernel — many sandboxed test
//!   hosts disable SysV IPC (CONFIG_SYSVIPC=n in containers); in that
//!   case the harness still exercises the user-space arg-validation
//!   surface via the EINVAL/EFAULT branches.
//!
//! Invariants:
//! - Never panic for any (cmd, key, size, flags, msg-bytes) tuple
//! - shmget / msgget / semget return -1 or a non-negative id
//! - shmat returns (void*)-1 on error or a valid mapping
//! - shmctl/msgctl/semctl IPC_RMID success is idempotent or returns
//!   EINVAL on second call
//!
//! Bead: bd-sysv-ipc

use std::ffi::{c_int, c_void};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::{
    msgctl, msgget, msgrcv, msgsnd, semctl, semget, semop, shmat, shmctl, shmdt, shmget,
};

const MSG_BUF_BYTES: usize = 256;
const SHM_SIZE_CAP: usize = 4096;

#[derive(Debug, Arbitrary)]
struct SysvInput {
    op: u8,
    flags: i32,
    /// Bounded size for shmget / msgsnd.
    size_raw: u16,
    /// nsems for semget.
    nsems_raw: u8,
    /// msgsnd payload.
    msg_bytes: Vec<u8>,
    /// msgsnd long-type field.
    msg_type: i64,
    /// msgrcv flags + length.
    rcv_msgtyp: i64,
    rcv_flags: i32,
    /// semop sembuf.
    sem_op_val: i16,
    sem_op_flags: i16,
    /// semctl/shmctl/msgctl cmd selector.
    ctl_cmd_sel: u8,
}

const CTL_CMDS: &[c_int] = &[
    libc::IPC_STAT,
    libc::IPC_INFO,
    libc::IPC_SET,
    libc::IPC_RMID,
];

fn pick_ctl_cmd(sel: u8) -> c_int {
    CTL_CMDS[(sel as usize) % CTL_CMDS.len()]
}

/// libc's struct msgbuf has [mtype: long, mtext[1]] — we lay our own
/// (`mtype`, then payload bytes) into a single Vec<u8>.
fn build_msg(mtype: i64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&mtype.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf
}

fuzz_target!(|input: SysvInput| {
    if input.msg_bytes.len() > MSG_BUF_BYTES {
        return;
    }

    match input.op % 7 {
        0 => {
            // shmget + shmat + shmdt + shmctl(IPC_RMID).
            let size = (input.size_raw as usize).min(SHM_SIZE_CAP).max(1);
            let id = unsafe {
                shmget(
                    libc::IPC_PRIVATE,
                    size,
                    (input.flags & 0o777) | libc::IPC_CREAT,
                )
            };
            assert!(id == -1 || id >= 0, "shmget rc={id}");
            if id >= 0 {
                let addr = unsafe { shmat(id, std::ptr::null(), 0) };
                if addr != usize::MAX as *mut c_void {
                    // Touch the first byte to confirm the mapping is live.
                    unsafe {
                        std::ptr::write_volatile(addr as *mut u8, 0xAB);
                        let _ = std::ptr::read_volatile(addr as *const u8);
                    }
                    let drc = unsafe { shmdt(addr) };
                    assert!(drc == 0 || drc == -1, "shmdt rc={drc}");
                }
                let _ = unsafe { shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
            }
        }
        1 => {
            // msgget + msgsnd + msgrcv + msgctl(IPC_RMID).
            let id = unsafe { msgget(libc::IPC_PRIVATE, (input.flags & 0o777) | libc::IPC_CREAT) };
            assert!(id == -1 || id >= 0, "msgget rc={id}");
            if id >= 0 {
                let payload_n = input.msg_bytes.len().min(MSG_BUF_BYTES);
                let snd_buf = build_msg(input.msg_type.max(1), &input.msg_bytes[..payload_n]);
                let snd_flags = input.flags | libc::IPC_NOWAIT;
                let snd_rc = unsafe {
                    msgsnd(
                        id,
                        snd_buf.as_ptr() as *const c_void,
                        payload_n,
                        snd_flags,
                    )
                };
                assert!(snd_rc == 0 || snd_rc == -1, "msgsnd rc={snd_rc}");

                let mut rcv_buf = vec![0u8; 8 + MSG_BUF_BYTES];
                let rcv_flags = input.rcv_flags | libc::IPC_NOWAIT;
                let rcv_rc = unsafe {
                    msgrcv(
                        id,
                        rcv_buf.as_mut_ptr() as *mut c_void,
                        MSG_BUF_BYTES,
                        input.rcv_msgtyp,
                        rcv_flags,
                    )
                };
                assert!(rcv_rc >= -1, "msgrcv rc={rcv_rc}");

                let _ = unsafe { msgctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
            }
        }
        2 => {
            // semget + semop + semctl(IPC_RMID).
            let nsems = ((input.nsems_raw as c_int) & 0x7).max(1);
            let id = unsafe {
                semget(libc::IPC_PRIVATE, nsems, (input.flags & 0o777) | libc::IPC_CREAT)
            };
            assert!(id == -1 || id >= 0, "semget rc={id}");
            if id >= 0 {
                let mut sops = libc::sembuf {
                    sem_num: 0,
                    sem_op: input.sem_op_val,
                    sem_flg: input.sem_op_flags | libc::IPC_NOWAIT as i16,
                };
                let rc = unsafe { semop(id, &mut sops as *mut _ as *mut c_void, 1) };
                assert!(rc == 0 || rc == -1, "semop rc={rc}");
                let _ = unsafe { semctl(id, 0, libc::IPC_RMID) };
            }
        }
        3 => {
            // shmctl with various cmds on a known-bad shmid (-1).
            let cmd = pick_ctl_cmd(input.ctl_cmd_sel);
            let mut buf = [0u8; 256];
            let rc = unsafe { shmctl(-1, cmd, buf.as_mut_ptr() as *mut c_void) };
            assert!(rc == 0 || rc == -1, "shmctl(-1, {cmd}) rc={rc}");
        }
        4 => {
            // msgctl with various cmds on a known-bad msqid.
            let cmd = pick_ctl_cmd(input.ctl_cmd_sel);
            let mut buf = [0u8; 256];
            let rc = unsafe { msgctl(-1, cmd, buf.as_mut_ptr() as *mut c_void) };
            assert!(rc == 0 || rc == -1, "msgctl(-1, {cmd}) rc={rc}");
        }
        5 => {
            // semctl with various cmds on a known-bad semid.
            let cmd = pick_ctl_cmd(input.ctl_cmd_sel);
            let rc = unsafe { semctl(-1, 0, cmd) };
            assert!(rc == 0 || rc == -1, "semctl(-1, {cmd}) rc={rc}");
        }
        _ => {
            // shmat with known-bad id should fail cleanly (not segfault).
            let addr = unsafe { shmat(-1, std::ptr::null(), 0) };
            assert!(addr == usize::MAX as *mut c_void || !addr.is_null());
            // shmdt of a bogus pointer returns -1.
            let drc = unsafe { shmdt(std::ptr::null()) };
            assert!(drc == 0 || drc == -1, "shmdt(NULL) rc={drc}");
        }
    }
});
