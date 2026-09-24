#![cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "standalone")))]

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
use std::ffi::{CStr, CString};
use std::process::Command;

#[path = "../../../tests/fixtures/elf_sectionless/support.rs"]
mod fixtures;

#[test]
fn native_sectionless_dlopen_runs_dependencies_relocations_tls_and_lifecycle() {
    for style in ["gnu", "sysv", "both"] {
        for packing in ["plain", "relr"] {
            let directory = fixtures::build(style, packing);
            let path = directory.join("libsectionless_root.so");
            // Run the incumbent in a separate, un-preloaded executable. A
            // libc::dlopen call in this Rust process could resolve to our export
            // in release builds and make the two test arms identical.
            let oracle = Command::new(directory.join("host_probe")).arg(&path)
                .env_remove("LD_PRELOAD").env_remove("LD_LIBRARY_PATH")
                .output().expect("execute independent host loader probe");
            fixtures::assert_success(&oracle);
            assert_eq!(String::from_utf8_lossy(&oracle.stdout), "33 4 34 33 4 34 34 12\n");
            let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: the file is compiled by the trusted fixture builder;
            // every symbol signature below matches that C source. The handle
            // stays open until all calls and worker threads have completed.
            unsafe {
                let handle = dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if handle.is_null() {
                    let error = dlerror();
                    let message = if error.is_null() { "no dlerror".into() }
                        else { CStr::from_ptr(error).to_string_lossy().into_owned() };
                    panic!("native {style}/{packing} load failed: {message}");
                }
                assert!(native_dso_handle_for_tests(handle), "host fallback is not feature coverage");
                let answer_address = dlvsym(handle, c"answer".as_ptr(), c"FIXTURE_1.0".as_ptr());
                let step_address = dlsym(handle, c"tls_step".as_ptr());
                let setter_address = dlsym(handle, c"set_finalizer_counter".as_ptr());
                assert!(!answer_address.is_null() && !step_address.is_null() && !setter_address.is_null());
                assert!(dlvsym(handle, c"answer".as_ptr(), c"MISSING_VERSION".as_ptr()).is_null());
                let _ = dlerror();
                let answer: extern "C" fn() -> i32 = std::mem::transmute(answer_address);
                let step: extern "C" fn() -> i32 = std::mem::transmute(step_address);
                let set_counter: unsafe extern "C" fn(*mut i32) = std::mem::transmute(setter_address);
                let mut finished = 0;
                set_counter(&mut finished);
                assert_eq!(answer(), 33);
                assert_eq!(step(), 4);
                assert_eq!(answer(), 34);
                let worker = std::thread::spawn(move || {
                    assert_eq!(answer(), 33);
                    assert_eq!(step(), 4);
                    assert_eq!(answer(), 34);
                });
                worker.join().expect("native TLS worker");
                assert_eq!(answer(), 34, "worker TLS must not mutate the caller's block");
                assert_eq!(dlclose(handle), 0);
                assert!(!native_dso_handle_for_tests(handle), "closed DSO must leave the native registry");
                assert_eq!(finished, 12, "the root finalizer must run while its dependencies remain alive");
            }
        }
    }
}
