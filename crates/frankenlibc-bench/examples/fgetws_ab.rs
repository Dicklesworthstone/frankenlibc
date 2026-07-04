//! fgetws old per-fgetwc loop vs ASCII bulk line fast path.
use std::hint::black_box;
use std::os::raw::c_char;
use std::time::Instant;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1);
    v[idx]
}

unsafe fn open_fl(path: *const c_char, mode: *const c_char) -> *mut libc::c_void {
    let stream = unsafe { frankenlibc_abi::stdio_abi::fopen(path, mode) };
    assert!(!stream.is_null());
    unsafe {
        frankenlibc_abi::stdio_abi::setvbuf(stream, std::ptr::null_mut(), libc::_IOFBF, 1 << 16);
    }
    stream
}

unsafe fn run_new(stream: *mut libc::c_void, buf: &mut [i32], expected_lines: usize) -> usize {
    let mut lines = 0usize;
    let mut checksum = 0usize;
    loop {
        let p = unsafe {
            frankenlibc_abi::wchar_abi::fgetws(
                buf.as_mut_ptr(),
                buf.len() as i32,
                black_box(stream),
            )
        };
        if p.is_null() {
            break;
        }
        lines += 1;
        checksum = checksum
            .wrapping_add(buf[0] as usize)
            .wrapping_add(buf[95] as usize);
    }
    assert_eq!(lines, expected_lines);
    unsafe { frankenlibc_abi::stdio_abi::rewind(stream) };
    checksum
}

unsafe fn run_old(stream: *mut libc::c_void, buf: &mut [i32], expected_lines: usize) -> usize {
    let mut lines = 0usize;
    let mut checksum = 0usize;
    loop {
        let p = unsafe {
            frankenlibc_abi::wchar_abi::bench_fgetws_percall(
                buf.as_mut_ptr(),
                buf.len() as i32,
                black_box(stream),
            )
        };
        if p.is_null() {
            break;
        }
        lines += 1;
        checksum = checksum
            .wrapping_add(buf[0] as usize)
            .wrapping_add(buf[95] as usize);
    }
    assert_eq!(lines, expected_lines);
    unsafe { frankenlibc_abi::stdio_abi::rewind(stream) };
    checksum
}

fn main() {
    let path_string = format!("/tmp/frankenlibc-fgetws-ab-{}.txt\0", std::process::id());
    let path = path_string.as_ptr() as *const c_char;
    let mode = b"r\0".as_ptr() as *const c_char;
    let line = format!("{}\n", "x".repeat(95));
    let lines = 128usize;
    std::fs::write(&path_string[..path_string.len() - 1], line.repeat(lines)).unwrap();

    let new_stream = unsafe { open_fl(path, mode) };
    let old_stream = unsafe { open_fl(path, mode) };
    let mut new_buf = vec![0i32; 128];
    let mut old_buf = vec![0i32; 128];

    unsafe {
        let old_p = frankenlibc_abi::wchar_abi::bench_fgetws_percall(
            old_buf.as_mut_ptr(),
            old_buf.len() as i32,
            old_stream,
        );
        let new_p = frankenlibc_abi::wchar_abi::fgetws(
            new_buf.as_mut_ptr(),
            new_buf.len() as i32,
            new_stream,
        );
        assert!(!old_p.is_null() && !new_p.is_null());
        assert_eq!(old_buf, new_buf);
        frankenlibc_abi::stdio_abi::rewind(old_stream);
        frankenlibc_abi::stdio_abi::rewind(new_stream);
        black_box(run_old(old_stream, &mut old_buf, lines));
        black_box(run_new(new_stream, &mut new_buf, lines));
    }

    let mut old = Vec::new();
    let mut new = Vec::new();
    let rounds = 36;
    let iters = 300u64;
    for r in 0..rounds {
        if r % 2 == 0 {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_old(old_stream, &mut old_buf, lines) });
            }
            old.push(t.elapsed().as_nanos() as f64 / (iters * lines as u64) as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_new(new_stream, &mut new_buf, lines) });
            }
            new.push(t.elapsed().as_nanos() as f64 / (iters * lines as u64) as f64);
        } else {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_new(new_stream, &mut new_buf, lines) });
            }
            new.push(t.elapsed().as_nanos() as f64 / (iters * lines as u64) as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_old(old_stream, &mut old_buf, lines) });
            }
            old.push(t.elapsed().as_nanos() as f64 / (iters * lines as u64) as f64);
        }
    }
    let old_p10 = pctl(&old, 0.10);
    let new_p10 = pctl(&new, 0.10);
    println!(
        "FGETWS_ASCII_AB old_per_fgetwc={old_p10:.2}ns new_ascii_bulk={new_p10:.2}ns new/old={:.3} ({:.2}x faster)",
        new_p10 / old_p10,
        old_p10 / new_p10
    );
}
