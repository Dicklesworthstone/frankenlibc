#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc wcwidth oracle

//! DIAGNOSTIC (non-asserting, `#[ignore]`): full-range differential sweep of fl
//! `wcwidth` vs host glibc `wcwidth` under a C.UTF-8 locale, characterizing the
//! structural gap tracked by bd-2g7oyh.194. fl's `wcwidth` is a hand-coded range
//! list; glibc's is Unicode-table-driven, so they diverge on ~66k/195k swept
//! codepoints, dominated by Unicode-version-coupled classes (unassigned => -1,
//! wide/emoji ranges, combining marks). This harness prints a categorized
//! summary by `(fl, glibc)` width pair; it is `#[ignore]`d (not a CI gate, since
//! exact parity needs a Unicode-data-driven rewrite version-matched to glibc),
//! run on demand with `cargo test -- --ignored wcwidth_sweep`.

use std::collections::BTreeMap;

use frankenlibc_core::string::wchar as flc;

unsafe extern "C" {
    fn wcwidth(c: libc::wchar_t) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[test]
#[ignore = "diagnostic for bd-2g7oyh.194 (structural wcwidth gap); run with --ignored"]
fn wcwidth_sweep_characterize() {
    // Seed + activate a UTF-8 locale so glibc consults its width tables.
    unsafe {
        std::env::set_var("LC_ALL", "C.UTF-8");
        let loc = std::ffi::CString::new("").unwrap();
        let r = setlocale(libc::LC_ALL, loc.as_ptr());
        if r.is_null() {
            // Fall back to en_US.UTF-8 if C.UTF-8 isn't present.
            std::env::set_var("LC_ALL", "en_US.UTF-8");
            setlocale(libc::LC_ALL, loc.as_ptr());
        }
    }

    let mut total = 0u64;
    let mut diffs = 0u64;
    // Key: (fl_value, glibc_value) -> count, with a few sample codepoints.
    let mut buckets: BTreeMap<(i32, i32), (u64, Vec<u32>)> = BTreeMap::new();

    let sweep = |lo: u32, hi: u32, total: &mut u64, diffs: &mut u64, buckets: &mut BTreeMap<(i32, i32), (u64, Vec<u32>)>| {
        for cp in lo..=hi {
            // Skip surrogates (not valid scalar values).
            if (0xD800..=0xDFFF).contains(&cp) {
                continue;
            }
            let fl_v = flc::wcwidth(cp);
            let gl_v = unsafe { wcwidth(cp as libc::wchar_t) };
            *total += 1;
            if fl_v != gl_v {
                *diffs += 1;
                let e = buckets.entry((fl_v, gl_v)).or_insert((0, Vec::new()));
                e.0 += 1;
                if e.1.len() < 8 {
                    e.1.push(cp);
                }
            }
        }
    };

    sweep(0x0000, 0x2FFFF, &mut total, &mut diffs, &mut buckets); // BMP + SMP/SIP
    sweep(0xE0000, 0xE01FF, &mut total, &mut diffs, &mut buckets); // tags + VS supplement

    eprintln!("wcwidth sweep: {total} codepoints, {diffs} divergences fl vs glibc");
    eprintln!("by (fl,glibc) value pair  -> count  [sample codepoints]:");
    for ((fl_v, gl_v), (count, samples)) in &buckets {
        let s: Vec<String> = samples.iter().map(|c| format!("U+{c:04X}")).collect();
        eprintln!("  fl={fl_v:>2} glibc={gl_v:>2}  -> {count:>6}  [{}]", s.join(" "));
    }
}
