#![cfg(target_os = "linux")]

//! Real ABI access tests in fresh processes: runtime mode is immutable.

use frankenlibc_abi::malloc_abi::{
    free, malloc, malloc_is_bump_ptr_for_tests, malloc_known_remaining_for_tests,
    malloc_segment_owned_for_tests, signal_runtime_ready_for_tests,
};
use frankenlibc_abi::string_abi::memcpy;
use frankenlibc_membrane::fingerprint::FINGERPRINT_SIZE;
use std::ffi::c_void;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_CASE: &str = "FRANKENLIBC_INTEGRITY_BOUNDS_CHILD";
const SIZE: usize = 64;

fn read_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: every caller owns the specified live allocation/metadata range.
    (0..len)
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

fn run_child(case: &str) {
    signal_runtime_ready_for_tests();
    // SAFETY: allocation has no caller-side preconditions.
    let ptr = unsafe { malloc(SIZE) }.cast::<u8>();
    assert!(!ptr.is_null());
    // Raw stores avoid warming the string validation cache while initializing.
    for i in 0..SIZE {
        // SAFETY: i is inside our allocation.
        unsafe { ptr.add(i).write_volatile(0x35) };
    }
    assert_eq!(malloc_known_remaining_for_tests(ptr.cast()), Some(SIZE));

    if case == "valid" {
        let source = [0x7Au8; 8];
        // SAFETY: disjoint readable/writable buffers of eight bytes.
        let result = unsafe { memcpy(ptr.cast(), source.as_ptr().cast(), source.len()) };
        assert_eq!(result, ptr.cast());
        assert_eq!(read_bytes(ptr, 8), source);
        // SAFETY: ptr is a live allocation from this same provider.
        unsafe { free(ptr.cast()) };
        return;
    }

    assert_eq!(std::env::var("FRANKENLIBC_MODE").as_deref(), Ok("hardened"));
    assert!(!malloc_segment_owned_for_tests(ptr.cast()));
    assert!(!malloc_is_bump_ptr_for_tests(ptr.cast()));

    if case == "quarantine" {
        let addr = ptr as usize;
        // SAFETY: release our live allocation once. The subsequent query treats
        // its numeric address as metadata, without dereferencing the pointer.
        unsafe { free(ptr.cast()) };
        assert_eq!(
            malloc_known_remaining_for_tests(addr as *const c_void),
            Some(0)
        );
        return;
    }

    if case == "one-past-end" {
        // SAFETY: a hardened membrane allocation includes eight canary bytes.
        // This deliberate overflow probe is isolated to its own child process;
        // restore the bytes before free even when the candidate fails to clamp.
        let end = unsafe { ptr.add(SIZE) };
        let saved = read_bytes(end, 8);
        let source = [0xA5u8; 8];
        let result = unsafe { memcpy(end.cast(), source.as_ptr().cast(), source.len()) };
        let observed = read_bytes(end, 8);
        let remaining = malloc_known_remaining_for_tests(end.cast());
        for (i, value) in saved.iter().enumerate() {
            // SAFETY: restore the same owned metadata range read above.
            unsafe { end.add(i).write_volatile(*value) };
        }
        // SAFETY: metadata is restored, allocation is still live.
        unsafe { free(ptr.cast()) };
        assert_eq!(result, end.cast());
        assert_eq!(remaining, Some(0));
        assert_eq!(observed, saved, "out-of-bounds write reached the canary");
        return;
    }

    let header = match case {
        "header-dst" | "header-src" => true,
        "canary-dst" | "canary-src" => false,
        _ => panic!("unknown integrity probe {case}"),
    };
    let destination = case.ends_with("-dst");
    // SAFETY: hardened non-bootstrap allocations carry a fingerprint header
    // and trailing canary. This is intentional fault injection, not a claim
    // that ordinary C callers may access bytes outside their user allocation.
    let metadata = unsafe {
        if header {
            ptr.sub(FINGERPRINT_SIZE)
        } else {
            ptr.add(SIZE)
        }
    };
    // SAFETY: owned metadata byte, restored after joining the access thread.
    let saved = unsafe { metadata.read_volatile() };
    unsafe { metadata.write_volatile(saved ^ 1) };

    let addr = ptr as usize;
    // The parent performed a positive bounds check. Use a fresh thread for
    // the access so this test exercises real integrity validation rather than
    // accidentally accepting the parent's pre-corruption cached validation.
    // This does not assert continuous integrity checking on every cache hit.
    let join_result = std::thread::spawn(move || {
        let mut output = [0x6Bu8; 8];
        let source = [0xC7u8; 8];
        let (dst, src) = if destination {
            (addr as *mut c_void, source.as_ptr().cast::<c_void>())
        } else {
            (output.as_mut_ptr().cast::<c_void>(), addr as *const c_void)
        };
        // SAFETY: the user regions are live, nonoverlapping and large enough.
        // Their allocation metadata is intentionally corrupt; hardened mode
        // must reject the access rather than treating the stored size as proof.
        let result = unsafe { memcpy(dst, src, 8) };
        let returned_destination = result == dst;
        let remaining = malloc_known_remaining_for_tests(addr as *const c_void);
        (returned_destination, remaining, output)
    })
    .join();

    // Restore and release before asserting on the access result, including a
    // panic in the worker. No dangling pointer is dereferenced after free.
    unsafe { metadata.write_volatile(saved) };
    let heap_after = read_bytes(ptr, 8);
    unsafe { free(ptr.cast()) };
    let (returned_destination, remaining, output) = join_result.expect("access worker");
    assert!(returned_destination);
    assert_eq!(
        remaining,
        Some(0),
        "integrity denial lost at the ABI projection"
    );
    if destination {
        assert_eq!(heap_after, [0x35; 8], "write reached rejected allocation");
    } else {
        assert_eq!(
            output, [0x6B; 8],
            "read from rejected allocation was copied out"
        );
    }
}

#[test]
fn integrity_bounds_matrix() {
    if let Ok(case) = std::env::var(CHILD_CASE) {
        run_child(&case);
        return;
    }

    let executable = std::env::current_exe().expect("test executable");
    let cases = [
        ("valid", "strict", "on"),
        ("valid", "hardened", "on"),
        ("header-dst", "hardened", "on"),
        ("header-src", "hardened", "on"),
        ("canary-dst", "hardened", "on"),
        ("canary-src", "hardened", "on"),
        ("header-dst", "hardened", "off"),
        ("header-src", "hardened", "off"),
        ("canary-dst", "hardened", "off"),
        ("canary-src", "hardened", "off"),
        ("one-past-end", "hardened", "on"),
        ("quarantine", "hardened", "on"),
    ];
    let mut failures = Vec::new();
    for (case, mode, math) in cases {
        let mut child = Command::new(&executable)
            .args([
                "--exact",
                "integrity_bounds_matrix",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_CASE, case)
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_RUNTIME_MATH", math)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start isolated ABI test");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut timed_out = false;
        while child.try_wait().expect("poll isolated test").is_none() {
            if Instant::now() >= deadline {
                timed_out = true;
                // Kill only the child owned by this test, then collect output.
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child
            .wait_with_output()
            .expect("collect isolated test output");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if timed_out || !output.status.success() || !stdout.contains("1 passed;") {
            failures.push(format!(
                "case={case} mode={mode} math={math} timeout={timed_out} status={}\n{stdout}\n{stderr}",
                output.status
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
