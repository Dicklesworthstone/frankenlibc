#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getline/getdelim oracle via fmemopen

//! Randomized differential fuzzer for `getline`/`getdelim` vs host glibc. Both
//! engines read the SAME random byte buffer through their own `fmemopen` memory
//! stream and are driven line-by-line to EOF; the per-line return value and the
//! returned bytes (`buf[..ret]`) are compared. Exercises binary safety (embedded
//! NUL), delimiter inclusion, a final line with no trailing delimiter, custom
//! delimiters, and the EOF (-1) terminator. The buffer capacity `*n` is an
//! implementation detail (glibc's growth policy differs) and is NOT compared.

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn fmemopen(buf: *mut libc::c_void, size: usize, mode: *const libc::c_char) -> *mut libc::FILE;
    fn getline(lineptr: *mut *mut libc::c_char, n: *mut usize, stream: *mut libc::FILE) -> isize;
    fn getdelim(
        lineptr: *mut *mut libc::c_char,
        n: *mut usize,
        delim: libc::c_int,
        stream: *mut libc::FILE,
    ) -> isize;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
}

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

fn gen_data(r: &mut Lcg) -> Vec<u8> {
    const POOL: &[u8] = b"ab\ncd\n\x00\nxyz;:.";
    let len = 1 + r.below(40);
    (0..len).map(|_| POOL[r.below(POOL.len())]).collect()
}

/// Drive fl's getline/getdelim over `data` to EOF, returning the per-line
/// (ret, bytes) sequence.
fn run_fl(data: &[u8], delim: i32) -> Vec<(isize, Vec<u8>)> {
    let mut owned = data.to_vec();
    let mode = b"rb\0";
    let stream = unsafe {
        fl::fmemopen(
            owned.as_mut_ptr() as *mut libc::c_void,
            owned.len(),
            mode.as_ptr() as *const libc::c_char,
        )
    };
    assert!(!stream.is_null(), "fl::fmemopen failed");
    let mut out = Vec::new();
    let mut lineptr: *mut libc::c_char = std::ptr::null_mut();
    let mut n: usize = 0;
    loop {
        let ret = unsafe { fl::getdelim(&mut lineptr, &mut n, delim, stream as *mut libc::c_void) };
        if ret < 0 {
            break;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(lineptr as *const u8, ret as usize) }.to_vec();
        out.push((ret, bytes));
        if out.len() > 200 {
            break;
        }
    }
    unsafe { fl::fclose(stream as *mut libc::c_void) };
    out // lineptr is fl-heap; leak it (test process exits)
}

fn run_glibc(data: &[u8], delim: i32) -> Vec<(isize, Vec<u8>)> {
    let mut owned = data.to_vec();
    let mode = b"rb\0";
    let stream = unsafe {
        fmemopen(
            owned.as_mut_ptr() as *mut libc::c_void,
            owned.len(),
            mode.as_ptr() as *const libc::c_char,
        )
    };
    assert!(!stream.is_null(), "glibc fmemopen failed");
    let mut out = Vec::new();
    let mut lineptr: *mut libc::c_char = std::ptr::null_mut();
    let mut n: usize = 0;
    loop {
        let ret = unsafe { getdelim(&mut lineptr, &mut n, delim, stream) };
        if ret < 0 {
            break;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(lineptr as *const u8, ret as usize) }.to_vec();
        out.push((ret, bytes));
        if out.len() > 200 {
            break;
        }
    }
    unsafe { fclose(stream) };
    out
}

#[test]
fn getline_getdelim_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9e1d_07ac_4422_1100);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..100_000 {
        let data = gen_data(&mut r);
        // delim: usually '\n' (getline), sometimes a custom byte.
        let delim: i32 = match r.below(3) {
            0 => b';' as i32,
            1 => 0, // NUL delimiter
            _ => b'\n' as i32,
        };
        let fl_lines = run_fl(&data, delim);
        let lc_lines = run_glibc(&data, delim);
        compared += 1;
        if fl_lines != lc_lines && divs.len() < 25 {
            let show = |v: &Vec<(isize, Vec<u8>)>| {
                v.iter()
                    .map(|(r, b)| format!("({r},{:02x?})", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            divs.push(format!(
                "data={:02x?} delim={delim}\n    fl   = {}\n    glibc= {}",
                data,
                show(&fl_lines),
                show(&lc_lines),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "getline/getdelim diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("getline/getdelim fuzz: {compared} compared, 0 divergences vs host glibc");
}
