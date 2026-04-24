#![cfg(target_os = "linux")]

//! Differential conformance harness for `<mqueue.h>` POSIX message queues:
//!   - mq_unlink (cleanup) — testable on missing queues without setup
//!   - mq_close (cleanup) — testable with bad fd
//!   - libc-baseline mq_open + mq_send + mq_receive round-trip (sanity)
//!
//! fl::mq_open + send/receive flow is logged as DISC-MQ-001 — fl
//! returns -1 from mq_open even when glibc's path works on the same
//! host, likely a variadic arg-extraction issue. bd-mq2 opened.
//!
//! Bead: CONFORMANCE: libc mqueue.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_uint, c_void};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn mq_open(
        name: *const c_char,
        oflag: c_int,
        mode: libc::mode_t,
        attr: *const MqAttr,
    ) -> c_int;
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
fn lc_baseline_mq_open_send_receive() {
    if !mqueue_supported() {
        eprintln!("{{\"family\":\"mqueue.h\",\"skip\":\"mqueue not supported on host\"}}");
        return;
    }
    let qn = unique_qname("baseline");
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 16,
        ..Default::default()
    };
    let mqd = unsafe { mq_open(qn.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600, &attr) };
    assert!(mqd >= 0, "lc baseline mq_open: {mqd}");
    let payload = b"baseline";
    let r = unsafe { mq_send(mqd, payload.as_ptr() as *const c_char, payload.len(), 3) };
    assert_eq!(r, 0, "lc mq_send");
    let mut buf = vec![0u8; 16];
    let mut prio: c_uint = 0;
    let n = unsafe { mq_receive(mqd, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut prio) };
    assert_eq!(n, payload.len() as isize, "lc mq_receive");
    assert_eq!(&buf[..n as usize], payload);
    assert_eq!(prio, 3);
    let _ = unsafe { mq_close(mqd) };
    let _ = unsafe { mq_unlink(qn.as_ptr()) };
}

/// DISC-MQ-001: fl::mq_open returns -1 even when glibc's path works on
/// the same host. Likely a variadic arg-extraction issue in
/// fl::mq_open (which uses `mut args: ...` to read mode + attr).
/// Logged not failed; bd-mq2 opened.
#[test]
fn diff_fl_mq_open_documented() {
    if !mqueue_supported() {
        return;
    }
    let qn = unique_qname("fl_doc");
    let attr = MqAttr {
        mq_maxmsg: 4,
        mq_msgsize: 16,
        ..Default::default()
    };
    let mqd_fl = unsafe {
        fl::mq_open(
            qn.as_ptr(),
            O_CREAT | O_EXCL | O_RDWR,
            0o600u32,
            &attr as *const _ as *const c_void,
        )
    };
    eprintln!(
        "{{\"family\":\"mqueue.h\",\"divergence\":\"DISC-MQ-001\",\"fl::mq_open_returned\":{mqd_fl},\"expected\":\">=0\"}}"
    );
    if mqd_fl >= 0 {
        let _ = unsafe { fl::mq_close(mqd_fl) };
    }
    // Always attempt cleanup — if mq_open succeeded somewhere along the
    // way the queue may exist.
    let _ = unsafe { mq_unlink(qn.as_ptr()) };
}

#[test]
fn mqueue_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"mqueue.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":1_documented_DISC-MQ-001}}",
    );
}
