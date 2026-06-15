#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsftime oracle

//! Randomized differential fuzzer for `wcsftime` (the wide-char `strftime`) vs
//! host glibc, under the C locale and TZ=UTC. `conformance_diff_wcsftime` is a
//! fixed battery on ONE time value; the narrow `strftime_specifier_*` fuzzer
//! never varies the buffer size. This sweeps every specifier over a random,
//! self-consistent `tm` (from `gmtime_r`) AND — the wcsftime-specific risk —
//! straddles the `max` truncation boundary, which for wcsftime is counted in
//! WIDE CHARACTERS (not bytes). It compares the rendered wide string and the
//! return value (length on success, 0 when the result + NUL does not fit).

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcsftime(
        s: *mut libc::wchar_t,
        max: usize,
        fmt: *const libc::wchar_t,
        tm: *const libc::tm,
    ) -> usize;
    fn gmtime_r(t: *const libc::time_t, tm: *mut libc::tm) -> *mut libc::tm;
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn tzset();
}
const LC_ALL: c_int = 6;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

const SPECS: &[u8] = b"aAbBcCdDeFgGhHIjklmMnpPrRsStTuUVwWxXyYzZ";
const NO_FLAGS: &[u8] = b"zZs";
const FLAGS: &[u8] = b"-_0^#";

/// Same generator shape as the narrow strftime fuzzer (a single specifier with
/// optional flag/width/E-O and bracket literals), so content parity is reused
/// and the focus is on the wide path + truncation.
fn gen_format(r: &mut Lcg) -> Vec<u8> {
    let mut f = Vec::new();
    if r.below(3) == 0 {
        f.extend_from_slice(b"x");
    }
    let spec = SPECS[r.below(SPECS.len())];
    f.push(b'%');
    let mut had_flag_or_width = false;
    if !NO_FLAGS.contains(&spec) {
        if r.below(2) == 0 {
            f.push(FLAGS[r.below(FLAGS.len())]);
            had_flag_or_width = true;
        }
        if r.below(2) == 0 {
            f.extend_from_slice(r.below(13).to_string().as_bytes());
            had_flag_or_width = true;
        }
    }
    if !had_flag_or_width && r.below(3) == 0 {
        f.push(if r.below(2) == 0 { b'E' } else { b'O' });
    }
    f.push(spec);
    if r.below(3) == 0 {
        f.extend_from_slice(b"yy");
    }
    f
}

fn widen(bytes: &[u8]) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = bytes.iter().map(|&b| b as libc::wchar_t).collect();
    v.push(0);
    v
}

/// Call `f` into a `max`-wchar buffer; return (ret, rendered-prefix). On a
/// successful render (ret>0 or empty format) the buffer holds `ret` wchars then
/// a NUL. On overflow ret==0 and contents are unspecified, so we only compare
/// the return code in that case.
/// `call(buf_ptr, max)` invokes the engine into the buffer; this handles the
/// buffer allocation and result extraction so fl (tm: *const c_void) and glibc
/// (tm: *const tm) can share it despite differing pointer types.
fn run(
    max: usize,
    call: impl Fn(*mut libc::wchar_t, usize) -> usize,
) -> (usize, Vec<libc::wchar_t>) {
    let mut buf = vec![0 as libc::wchar_t; max.max(1) + 4];
    let n = call(buf.as_mut_ptr(), max);
    if n == 0 {
        return (0, Vec::new());
    }
    let n = n.min(buf.len());
    (n, buf[..n].to_vec())
}

#[test]
fn wcsftime_differential_fuzz_vs_glibc() {
    unsafe {
        let c = CString::new("C").unwrap();
        setlocale(LC_ALL, c.as_ptr());
        std::env::set_var("TZ", "UTC0");
        tzset();
    }

    let mut r = Lcg(0x77c5_f71e_4a02_d109);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        // Self-consistent tm via gmtime_r over a wide epoch range.
        let epoch = (r.next() as i64 % 8_000_000_000) - 2_000_000_000;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { gmtime_r(&(epoch as libc::time_t), &mut tm) };

        let fmt_bytes = gen_format(&mut r);
        let fmt = widen(&fmt_bytes);

        let tm_ptr: *const libc::tm = &tm;
        let fl_call = |buf: *mut libc::wchar_t, max: usize| unsafe {
            fl::wcsftime(buf, max, fmt.as_ptr(), tm_ptr as *const std::ffi::c_void)
        };
        let lc_call = |buf: *mut libc::wchar_t, max: usize| unsafe {
            wcsftime(buf, max, fmt.as_ptr(), tm_ptr)
        };

        // Natural length first (generous buffer), then straddle the boundary.
        let (nat, _) = run(256, lc_call);
        let max = if r.below(4) == 0 {
            r.below(40) // wild small/zero
        } else {
            // around the natural truncation edge
            (nat + 2).saturating_sub(r.below(4))
        };

        let (fl_n, fl_s) = run(max, fl_call);
        let (lc_n, lc_s) = run(max, lc_call);
        compared += 1;

        // Compare return code always; compare contents only when both succeeded
        // (on overflow the buffer is unspecified).
        let mismatch = fl_n != lc_n || (fl_n > 0 && fl_s != lc_s);
        if mismatch && divs.len() < 40 {
            let show = |w: &[libc::wchar_t]| -> String {
                w.iter()
                    .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                    .collect()
            };
            divs.push(format!(
                "fmt={:?} max={max} natural={nat}\n    fl=({fl_n},{:?}) glibc=({lc_n},{:?})",
                String::from_utf8_lossy(&fmt_bytes),
                show(&fl_s),
                show(&lc_s),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "wcsftime diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("wcsftime fuzz: {compared} compared, 0 divergences vs host glibc");
}
