#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // guard-page mmap/mprotect to prove no over-read

//! Page-safety proof for the wide-SIMD `scan_c_string_for_byte` path behind
//! `strchr`/`strchrnul` (bd-4rxozm). A two-page region is mapped, the second
//! page is `PROT_NONE`, and NUL-terminated strings are placed so their NUL sits
//! at every offset in the last 40 bytes of the first page. Scanning for an
//! absent target forces the scan all the way to the NUL; if the 32-byte SIMD
//! window ever read into the guard page the process would SIGSEGV. Passing
//! proves the in-page guard (`(p+i)&0xFFF <= 0x1000-32`) holds.

use std::ffi::c_char;

use frankenlibc_abi::string_abi as fl;

const PAGE: usize = 4096;

#[test]
fn strchr_never_reads_into_guard_page() {
    unsafe {
        // Map two pages; make the second inaccessible.
        let base = libc::mmap(
            std::ptr::null_mut(),
            2 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let bytes = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(PAGE), PAGE, libc::PROT_NONE),
            0,
            "mprotect guard page failed"
        );

        // For each NUL offset in the last 40 bytes of page 1, and for several
        // scan start offsets, scan for an absent byte (forces a full scan to the
        // NUL). 'z' is absent because the fill byte is 'a'.
        for nul_off in (PAGE - 40)..PAGE {
            // Fill [0, nul_off) with 'a', NUL at nul_off.
            std::ptr::write_bytes(bytes, b'a', nul_off);
            *bytes.add(nul_off) = 0;

            for &start in &[0usize, 1, 7, 8, 31, 32, nul_off.saturating_sub(33)] {
                if start > nul_off {
                    continue;
                }
                let s = bytes.add(start).cast::<c_char>();

                // strchr for absent byte must hit the NUL and return null,
                // without touching the guard page.
                let r = fl::strchr(s, b'z' as i32);
                assert!(
                    r.is_null(),
                    "strchr(absent) at start={start} nul={nul_off} expected null"
                );

                // strchrnul must return the NUL position.
                let rn = fl::strchrnul(s, b'z' as i32);
                let expect = bytes.add(nul_off).cast::<c_char>();
                assert_eq!(
                    rn, expect,
                    "strchrnul(absent) start={start} nul={nul_off} wrong NUL position"
                );

                // strchr for the present 'a' must find the first one at `start`
                // (every byte before NUL is 'a'), unless start == nul_off (empty).
                if start < nul_off {
                    let ra = fl::strchr(s, b'a' as i32);
                    assert_eq!(
                        ra, s as *mut c_char,
                        "strchr('a') start={start} should be first byte"
                    );
                }
            }
        }

        libc::munmap(base, 2 * PAGE);
    }
    eprintln!("strchr guard-page: no over-read into PROT_NONE page across all boundary offsets");
}
