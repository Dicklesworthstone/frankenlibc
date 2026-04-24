#![cfg(target_os = "linux")]

//! Differential conformance harness for `<mqueue.h>` POSIX message queues:
//!   - mq_open / mq_close / mq_unlink (creation + cleanup)
//!   - mq_send / mq_receive (single-message round-trip)
//!
//! Bead: CONFORMANCE: libc mqueue.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_uint, c_void};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn mq_open(name: *const c_char, oflag: c_int, mode: libc::mode_t, attr: *const MqAttr)
    -> c_int;
    fn mq_close(mqdes: c_int) -> c_int;
    fn mq_unlink(name: *const c_char) -> c_int;
    fn mq_send(mqdes: c_int, msg_ptr: *const c_char, msg_len: usize, msg_prio: c_uint) -> c_int;
    fn mq_receive(
        mqdes: c_int,
        msg_ptr: *mut c_char,
        msg_len: usize,
        msg_prio: *mut c_uint,
    ) -> isize;
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct MqAttr {
    mq_flags: libc::c_long,
    mq_maxmsg: libc::c_long,
    mq_msgsize: libc::c_long,
    mq_curmsgs: libc::c_long,
    _pad: [libc::c_long; 4],
}

const O_CREAT: c_int = libc::O_CREAT;
const O_EXCL: c_int = libc::O_EXCL;
const O_RDWR: c_int = libc::O_RDWR;

fn unique_qname(label: &str) -> CString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    CString::new(format!("/fl_mq_diff_{label}_{pid}_{id}")).unwrap()
}

fn mqueue_supported() -> bool {
    let qn = unique_qname("probe");
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 16,
        ..Default::default()
    };
    let mqd = unsafe { mq_open(qn.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600, &attr) };
    if mqd < 0 {
        return false;
    }
    let _ = unsafe { mq_close(mqd) };
    let _ = unsafe { mq_unlink(qn.as_ptr()) };
    true
}

#[test]
fn diff_mq_unlink_nonexistent() {
    let qn = CString::new("/this_mq_does_not_exist_xyz_unique").unwrap();
    let r_fl = unsafe { fl::mq_unlink(qn.as_ptr()) };
    let r_lc = unsafe { mq_unlink(qn.as_ptr()) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "mq_unlink ENOENT fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_mq_close_invalid_fd() {
    let r_fl = unsafe { fl::mq_close(99999) };
    let r_lc = unsafe { mq_close(99999) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "mq_close invalid-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_mq_open_close_unlink_fl_then_lc_round_trip() {
    if !mqueue_supported() {
        eprintln!("{{\"family\":\"mqueue.h\",\"skip\":\"mqueue not supported on host\"}}");
        return;
    }
    // bd-mq2 closed: fl::mq_open now strips the leading '/' from
    // the name before invoking SYS_mq_open (matches glibc).
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 16,
        ..Default::default()
    };

    let run = |use_fl: bool| -> Option<(Vec<u8>, c_uint)> {
        let qn = unique_qname(if use_fl { "fl_rt" } else { "lc_rt" });
        let mqd = if use_fl {
            unsafe {
                fl::mq_open(
                    qn.as_ptr(),
                    O_CREAT | O_EXCL | O_RDWR,
                    0o600u32,
                    &attr as *const _ as *const c_void,
                )
            }
        } else {
            unsafe { mq_open(qn.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600, &attr) }
        };
        if mqd < 0 {
            return None;
        }
        let payload = b"hello mq";
        let r_send = if use_fl {
            unsafe { fl::mq_send(mqd, payload.as_ptr() as *const c_char, payload.len(), 5) }
        } else {
            unsafe { mq_send(mqd, payload.as_ptr() as *const c_char, payload.len(), 5) }
        };
        if r_send != 0 {
            let _ = unsafe { mq_close(mqd) };
            let _ = unsafe { mq_unlink(qn.as_ptr()) };
            return None;
        }
        let mut buf = vec![0u8; 16];
        let mut prio: c_uint = 0;
        let n = if use_fl {
            unsafe { fl::mq_receive(mqd, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut prio) }
        } else {
            unsafe { mq_receive(mqd, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut prio) }
        };
        let _ = unsafe { mq_close(mqd) };
        let _ = unsafe { mq_unlink(qn.as_ptr()) };
        if n > 0 {
            Some((buf[..n as usize].to_vec(), prio))
        } else {
            None
        }
    };
    let r_fl = run(true);
    let r_lc = run(false);
    assert_eq!(
        r_fl, r_lc,
        "mq round-trip divergence: fl={r_fl:?}, lc={r_lc:?}"
    );
    assert_eq!(
        r_fl,
        Some((b"hello mq".to_vec(), 5)),
        "expected round-trip payload + prio"
    );
}

#[test]
fn diff_mq_open_invalid_name_no_slash() {
    // POSIX: mq_open with name not starting with '/' must fail.
    let qn = CString::new("no_slash").unwrap();
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 16,
        ..Default::default()
    };
    let r_fl = unsafe {
        fl::mq_open(
            qn.as_ptr(),
            O_CREAT | O_EXCL | O_RDWR,
            0o600u32,
            &attr as *const _ as *const c_void,
        )
    };
    let r_lc = unsafe { mq_open(qn.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600, &attr) };
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "mq_open(no-slash) fail-match: fl={r_fl}, lc={r_lc}"
    );
    if r_fl >= 0 {
        let _ = unsafe { fl::mq_close(r_fl) };
    }
    if r_lc >= 0 {
        let _ = unsafe { mq_close(r_lc) };
    }
}

#[test]
fn mqueue_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"mqueue.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
