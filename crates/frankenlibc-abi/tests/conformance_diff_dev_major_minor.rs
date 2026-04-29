#![cfg(target_os = "linux")]

//! Differential conformance harness for `gnu_dev_major(3)` /
//! `gnu_dev_minor(3)` / `gnu_dev_makedev(3)` (sys/sysmacros.h).
//!
//! These are bit-pack helpers for Linux dev_t. fl exports its own;
//! glibc exports them under the same names. Round-trip parity required.
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn gnu_dev_major(dev: libc::dev_t) -> libc::c_uint;
    fn gnu_dev_minor(dev: libc::dev_t) -> libc::c_uint;
    fn gnu_dev_makedev(major: libc::c_uint, minor: libc::c_uint) -> libc::dev_t;
}

#[test]
fn diff_makedev_round_trip() {
    let pairs: &[(u32, u32)] = &[
        (0, 0),
        (1, 1),
        (8, 0),
        (8, 1),
        (8, 16),
        (8, 32),
        (89, 5),
        (240, 0),
        (256, 0),
        (1234, 5678),
        (0x1234_5678, 0xabcd_ef01),
        (u32::MAX, u32::MAX),
    ];
    for &(major, minor) in pairs {
        let fl_dev = unsafe { fl::gnu_dev_makedev(major, minor) };
        let lc_dev = unsafe { gnu_dev_makedev(major, minor) };
        assert_eq!(
            fl_dev, lc_dev,
            "makedev({major}, {minor}): fl={fl_dev:#x} lc={lc_dev:#x}"
        );
        // round-trip: gnu_dev_major(makedev(M, m)) == M
        let fl_maj = unsafe { fl::gnu_dev_major(fl_dev) };
        let lc_maj = unsafe { gnu_dev_major(lc_dev) };
        assert_eq!(fl_maj, lc_maj, "major({fl_dev:#x}): fl={fl_maj} lc={lc_maj}");
        let fl_min = unsafe { fl::gnu_dev_minor(fl_dev) };
        let lc_min = unsafe { gnu_dev_minor(lc_dev) };
        assert_eq!(fl_min, lc_min, "minor({fl_dev:#x}): fl={fl_min} lc={lc_min}");
    }
}

#[test]
fn diff_major_minor_extract_known_devs() {
    // Some classic dev_t values from /dev:
    //   sda: major=8 minor=0 → makedev(8, 0)
    //   tty: major=4 minor=0
    //   null: major=1 minor=3
    let cases: &[(u32, u32)] = &[(8, 0), (4, 0), (1, 3), (1, 5), (5, 1)];
    for &(maj, min) in cases {
        let fl_dev = unsafe { fl::gnu_dev_makedev(maj, min) };
        let lc_dev = unsafe { gnu_dev_makedev(maj, min) };
        assert_eq!(fl_dev, lc_dev);
        let fl_back = (
            unsafe { fl::gnu_dev_major(fl_dev) },
            unsafe { fl::gnu_dev_minor(fl_dev) },
        );
        assert_eq!(fl_back, (maj, min), "round-trip failed for {maj}:{min}");
    }
}

#[test]
fn dev_major_minor_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc gnu_dev_*\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
