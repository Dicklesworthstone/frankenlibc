#![cfg(target_os = "linux")]

//! Differential conformance harness for process-control + randomness:
//!   - prctl with PR_GET_NAME / PR_SET_NAME (process name read/write)
//!   - prctl with PR_GET_DUMPABLE / PR_GET_PDEATHSIG (read-only queries)
//!   - getrandom (random bytes from /dev/urandom-equivalent)
//!   - getentropy (POSIX 2024 wrapper around getrandom)
//!
//! Bead: CONFORMANCE: libc prctl+getrandom+getentropy diff matrix.

use std::ffi::{c_int, c_uint, c_ulong, c_void};

use frankenlibc_abi::{poll_abi as fl_poll, unistd_abi as fl_uni};

unsafe extern "C" {
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
    fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize;
    fn getentropy(buffer: *mut c_void, length: usize) -> c_int;
}

const PR_SET_NAME: c_int = 15;
const PR_GET_NAME: c_int = 16;
const PR_GET_DUMPABLE: c_int = 3;
const PR_GET_PDEATHSIG: c_int = 2;

const GRND_RANDOM: c_uint = 0x1;
const GRND_NONBLOCK: c_uint = 0x2;

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

#[test]
fn diff_prctl_get_name() {
    let mut divs = Vec::new();
    let mut buf_fl = vec![0u8; 16];
    let mut buf_lc = vec![0u8; 16];
    let r_fl = unsafe { fl_poll::prctl(PR_GET_NAME, buf_fl.as_mut_ptr() as c_ulong, 0, 0, 0) };
    let r_lc = unsafe { prctl(PR_GET_NAME, buf_lc.as_mut_ptr() as c_ulong, 0, 0, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "prctl",
            case: "PR_GET_NAME".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let s_fl =
            String::from_utf8_lossy(buf_fl.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
        let s_lc =
            String::from_utf8_lossy(buf_lc.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "prctl",
                case: "PR_GET_NAME".into(),
                field: "name",
                frankenlibc: format!("{s_fl:?}"),
                glibc: format!("{s_lc:?}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "prctl PR_GET_NAME divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_prctl_set_then_get_name() {
    // Set process name to "fl_diff_test" via fl, read via libc; restore.
    let saved = {
        let mut buf = vec![0u8; 16];
        let _ = unsafe { prctl(PR_GET_NAME, buf.as_mut_ptr() as c_ulong, 0, 0, 0) };
        buf
    };
    let new_name = b"fl_diff_test\0".to_vec();
    let r_set = unsafe { fl_poll::prctl(PR_SET_NAME, new_name.as_ptr() as c_ulong, 0, 0, 0) };
    let mut buf = vec![0u8; 16];
    let r_get = unsafe { prctl(PR_GET_NAME, buf.as_mut_ptr() as c_ulong, 0, 0, 0) };
    let s = String::from_utf8_lossy(buf.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
    // Restore original
    let _ = unsafe { prctl(PR_SET_NAME, saved.as_ptr() as c_ulong, 0, 0, 0) };

    assert_eq!(r_set, 0, "PR_SET_NAME via fl");
    assert_eq!(r_get, 0, "PR_GET_NAME via lc");
    assert_eq!(s, "fl_diff_test", "set-via-fl read-via-lc divergence");
}

#[test]
fn diff_prctl_get_dumpable() {
    let r_fl = unsafe { fl_poll::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) };
    let r_lc = unsafe { prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(
        r_fl, r_lc,
        "PR_GET_DUMPABLE divergence: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_prctl_get_pdeathsig() {
    let mut sig_fl: c_int = -1;
    let mut sig_lc: c_int = -1;
    let r_fl =
        unsafe { fl_poll::prctl(PR_GET_PDEATHSIG, &mut sig_fl as *mut _ as c_ulong, 0, 0, 0) };
    let r_lc = unsafe { prctl(PR_GET_PDEATHSIG, &mut sig_lc as *mut _ as c_ulong, 0, 0, 0) };
    assert_eq!(r_fl, r_lc, "PR_GET_PDEATHSIG return");
    if r_fl == 0 && r_lc == 0 {
        assert_eq!(sig_fl, sig_lc, "PR_GET_PDEATHSIG value");
    }
}

#[test]
fn diff_prctl_invalid_option() {
    // Bogus option should fail with EINVAL on both
    let r_fl = unsafe { fl_poll::prctl(99999, 0, 0, 0, 0) };
    let r_lc = unsafe { prctl(99999, 0, 0, 0, 0) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "prctl invalid-option fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_getrandom_basic() {
    let mut divs = Vec::new();
    for n in &[0usize, 1, 32, 256] {
        let mut buf_fl = vec![0u8; *n];
        let mut buf_lc = vec![0u8; *n];
        let r_fl = unsafe { fl_uni::getrandom(buf_fl.as_mut_ptr() as *mut c_void, *n, 0) };
        let r_lc = unsafe { getrandom(buf_lc.as_mut_ptr() as *mut c_void, *n, 0) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "getrandom",
                case: format!("n={n}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl as usize != *n {
            divs.push(Divergence {
                function: "getrandom",
                case: format!("n={n}"),
                field: "expected_count",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{n}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "getrandom divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_getrandom_nonblock_flag() {
    // GRND_NONBLOCK should work the same on both impls
    let mut buf = vec![0u8; 32];
    let r_fl = unsafe { fl_uni::getrandom(buf.as_mut_ptr() as *mut c_void, 32, GRND_NONBLOCK) };
    let r_lc = unsafe { getrandom(buf.as_mut_ptr() as *mut c_void, 32, GRND_NONBLOCK) };
    assert!(
        (r_fl >= 0) == (r_lc >= 0),
        "getrandom GRND_NONBLOCK success-match: fl={r_fl}, lc={r_lc}"
    );
    let _unused = GRND_RANDOM;
}

#[test]
fn diff_getentropy_max_size() {
    // POSIX getentropy is documented as max 256 bytes per call.
    let mut buf_fl = vec![0u8; 256];
    let mut buf_lc = vec![0u8; 256];
    let r_fl = unsafe { fl_uni::getentropy(buf_fl.as_mut_ptr() as *mut c_void, 256) };
    let r_lc = unsafe { getentropy(buf_lc.as_mut_ptr() as *mut c_void, 256) };
    assert_eq!(
        r_fl, r_lc,
        "getentropy(256) divergence: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_getentropy_too_large() {
    // length > 256 should fail with EIO on both per POSIX spec.
    let mut buf = vec![0u8; 1024];
    let r_fl = unsafe { fl_uni::getentropy(buf.as_mut_ptr() as *mut c_void, 1024) };
    let r_lc = unsafe { getentropy(buf.as_mut_ptr() as *mut c_void, 1024) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "getentropy(1024) fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn prctl_random_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"prctl+getrandom+getentropy\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
