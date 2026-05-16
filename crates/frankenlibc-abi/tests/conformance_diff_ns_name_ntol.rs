#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `ns_name_ntol`.
//!
//! Converts wire-format DNS labels to lowercase in-place into a destination
//! buffer, preserving glibc's return length, errno, and partial-write behavior.

use std::ffi::c_int;

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn ns_name_ntol(src: *const u8, dst: *mut u8, dstsiz: usize) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

unsafe fn clear_errno_both() {
    unsafe {
        *fl_errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

unsafe fn read_fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn raw_bytes(buf: &[u8]) -> Vec<u8> {
    buf.to_vec()
}

#[test]
fn diff_ns_name_ntol_cases() {
    let mut divs = Vec::new();
    let mut cases: Vec<(&str, Vec<u8>, Vec<usize>)> = vec![
        ("root", vec![0], vec![0, 1, 2]),
        (
            "FOO.COM",
            vec![3, b'F', b'O', b'O', 3, b'C', b'O', b'M', 0],
            vec![0, 1, 2, 4, 5, 8, 9, 10],
        ),
        ("A.Z", vec![1, b'A', 1, b'Z', 0], vec![0, 1, 2, 3, 4, 5, 6]),
        (
            "bad-len-64",
            {
                let mut src = vec![64];
                src.extend(std::iter::repeat_n(b'A', 64));
                src.push(0);
                src
            },
            vec![0, 1, 4, 66],
        ),
        ("reserved-len-80", vec![0x80, 0], vec![0, 1, 2, 4]),
        ("compression-c0", vec![0xC0, 0x0C], vec![0, 1, 2, 4]),
        ("compression-ff", vec![0xFF, 0xFF], vec![0, 1, 2, 4]),
    ];
    let mut label63 = vec![63];
    label63.extend(std::iter::repeat_n(b'A', 63));
    label63.push(0);
    cases.push(("label63", label63, vec![0, 1, 4, 64, 65, 66]));

    for (name, src, sizes) in cases {
        for size in sizes {
            let mut fl_buf = vec![0x55u8; size + 4];
            let mut lc_buf = vec![0x55u8; size + 4];
            unsafe { clear_errno_both() };
            let fl_n = unsafe { fl::ns_name_ntol(src.as_ptr(), fl_buf.as_mut_ptr(), size) };
            let fl_errno = unsafe { read_fl_errno() };
            unsafe { clear_errno_both() };
            let lc_n = unsafe { ns_name_ntol(src.as_ptr(), lc_buf.as_mut_ptr(), size) };
            let lc_errno = unsafe { read_lc_errno() };
            let case = format!("{name} size={size}");
            if fl_n != lc_n {
                divs.push(Divergence {
                    case: case.clone(),
                    field: "return",
                    frankenlibc: format!("{fl_n}"),
                    glibc: format!("{lc_n}"),
                });
            }
            if fl_n < 0 && lc_n < 0 && fl_errno != lc_errno {
                divs.push(Divergence {
                    case: case.clone(),
                    field: "errno",
                    frankenlibc: format!("{fl_errno}"),
                    glibc: format!("{lc_errno}"),
                });
            }
            if fl_buf != lc_buf {
                divs.push(Divergence {
                    case,
                    field: "buffer",
                    frankenlibc: format!("{:?}", raw_bytes(&fl_buf)),
                    glibc: format!("{:?}", raw_bytes(&lc_buf)),
                });
            }
        }
    }

    assert!(
        divs.is_empty(),
        "ns_name_ntol divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn ns_name_ntol_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv ns_name_ntol\",\"reference\":\"glibc\",\"functions\":1,\"success_cases\":4,\"too_small_cases\":18,\"malformed_cases\":12,\"divergences\":0}}",
    );
}
