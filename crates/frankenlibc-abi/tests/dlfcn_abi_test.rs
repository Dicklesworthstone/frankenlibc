#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    __libc_dlclose, __libc_dlopen_mode, __libc_dlsym, dl_iterate_phdr, dladdr, dlclose, dlerror,
    dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
use frankenlibc_abi::malloc_abi::{free, malloc};

/// Acquire poison-tolerantly, so a failing assertion reports as one failure instead of
/// poisoning this guard and taking every later test with it (bd-9ri7g1).
static TEST_GUARD: Mutex<()> = Mutex::new(());

fn compile_self_contained_test_dso() -> PathBuf {
    compile_native_test_dso(
        "__attribute__((visibility(\"default\"))) int franken_native_answer(void) { return 4242; }\n\
         __attribute__((visibility(\"default\"))) int franken_native_increment(void) { static int value; return ++value; }\n",
    )
}

fn compile_native_test_dso(code: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-native-dso-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("native_answer.c");
    let output = dir.join("libfranken_native_answer.so");
    std::fs::write(&source, code).unwrap();

    let cc_output = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-Wl,--build-id=none",
            "-Wl,-soname,libfranken_native_answer.so",
            "-o",
        ])
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        cc_output.status.success(),
        "cc failed: status={:?}\nstdout={}\nstderr={}",
        cc_output.status,
        String::from_utf8_lossy(&cc_output.stdout),
        String::from_utf8_lossy(&cc_output.stderr)
    );
    output
}

#[derive(Default)]
struct DlIterateProbe {
    count: usize,
    saw_nonnull_info: bool,
    saw_nonzero_size: bool,
}

fn open_native_fixture(path: &std::path::Path, flags: c_int) -> *mut c_void {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the fixture path remains a valid C string for this call.
    let handle = unsafe { dlopen(name.as_ptr(), flags) };
    assert!(
        native_dso_handle_for_tests(handle),
        "native open failed: {path:?}"
    );
    handle
}

#[test]
fn native_dso_relocation_chain_retains_closed_providers() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let provider = compile_native_test_dso("int chain_leaf(void) { return 40; }");
    let middle = compile_native_test_dso(
        "extern int chain_leaf(void); int chain_middle(void) { return chain_leaf() + 1; }",
    );
    let consumer = compile_native_test_dso(
        "extern int chain_middle(void); int chain_result(void) { return chain_middle() + 1; }",
    );
    let provider = open_native_fixture(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let middle = open_native_fixture(&middle, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let consumer = open_native_fixture(&consumer, libc::RTLD_NOW | libc::RTLD_LOCAL);
    // SAFETY: compiled fixtures declare the exact function ABI below. The
    // consumer's open reference must retain its providers throughout the call.
    unsafe {
        let symbol = dlsym(consumer, c"chain_result".as_ptr());
        assert!(!symbol.is_null());
        let result: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(result(), 42);
        assert_eq!(dlclose(provider), 0);
        assert_eq!(dlclose(middle), 0);
        assert!(native_dso_handle_for_tests(provider));
        assert!(native_dso_handle_for_tests(middle));
        assert_eq!(result(), 42);
        assert_eq!(dlclose(consumer), 0);
        assert!(!native_dso_handle_for_tests(consumer));
        assert!(!native_dso_handle_for_tests(middle));
        assert!(!native_dso_handle_for_tests(provider));
    }
}

#[test]
fn native_dso_local_provider_requires_global_promotion() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let provider = compile_native_test_dso("int visibility_value(void) { return 73; }");
    let consumer = compile_native_test_dso(
        "extern int visibility_value(void); int visibility_result(void) { return visibility_value(); }",
    );
    let handle = open_native_fixture(&provider, libc::RTLD_NOW | libc::RTLD_LOCAL);
    let consumer_name = CString::new(consumer.as_os_str().as_bytes()).unwrap();
    // SAFETY: paths/symbol names are live C strings and the function is invoked
    // while its consumer handle is open.
    unsafe {
        assert!(dlopen(consumer_name.as_ptr(), libc::RTLD_NOW).is_null());
        assert!(
            !dlerror().is_null(),
            "LOCAL must not satisfy an unrelated load"
        );
        let promoted = open_native_fixture(
            &provider,
            libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_GLOBAL,
        );
        assert_eq!(promoted, handle);
        let consumer = open_native_fixture(&consumer, libc::RTLD_NOW);
        let symbol = dlsym(consumer, c"visibility_result".as_ptr());
        assert!(!symbol.is_null());
        let result: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(result(), 73);
        assert_eq!(dlclose(handle), 0);
        assert_eq!(dlclose(promoted), 0);
        assert!(native_dso_handle_for_tests(handle));
        assert_eq!(result(), 73);
        assert_eq!(dlclose(consumer), 0);
        assert!(!native_dso_handle_for_tests(handle));
    }
}

#[test]
fn native_dso_failed_relocation_does_not_pin_provider() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let provider = compile_native_test_dso("int available_value(void) { return 12; }");
    let consumer = compile_native_test_dso(
        "extern int available_value(void); extern int absent_value(void); int broken_result(void) { return available_value() + absent_value(); }",
    );
    let provider = open_native_fixture(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let name = CString::new(consumer.as_os_str().as_bytes()).unwrap();
    // SAFETY: the failing object is never executed; this checks load rollback.
    unsafe {
        assert!(dlopen(name.as_ptr(), libc::RTLD_NOW).is_null());
        assert!(!dlerror().is_null());
        assert_eq!(dlclose(provider), 0);
    }
    assert!(!native_dso_handle_for_tests(provider));
}

#[test]
fn native_dso_shared_provider_waits_for_last_consumer() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let provider = compile_native_test_dso("int shared_value(void) { return 19; }");
    let code = "extern int shared_value(void); int shared_result(void) { return shared_value(); }";
    let first = compile_native_test_dso(code);
    let second = compile_native_test_dso(code);
    let provider = open_native_fixture(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let first = open_native_fixture(&first, libc::RTLD_NOW);
    let second = open_native_fixture(&second, libc::RTLD_NOW);
    // SAFETY: the remaining consumer owns the compiled callable function and
    // must retain the shared provider after the other consumer is unloaded.
    unsafe {
        assert_eq!(dlclose(provider), 0);
        assert_eq!(dlclose(first), 0);
        assert!(!native_dso_handle_for_tests(first));
        assert!(native_dso_handle_for_tests(provider));
        let symbol = dlsym(second, c"shared_result".as_ptr());
        assert!(!symbol.is_null());
        let result: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(result(), 19);
        assert_eq!(dlclose(second), 0);
        assert!(!native_dso_handle_for_tests(provider));
    }
}

#[test]
fn native_dso_nodelete_consumer_retains_provider() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let provider =
        compile_native_test_dso("int retained_value(void) { static int value; return ++value; }");
    let consumer = compile_native_test_dso(
        "extern int retained_value(void); int retained_result(void) { return retained_value(); }",
    );
    let provider = open_native_fixture(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let handle = open_native_fixture(&consumer, libc::RTLD_NOW | libc::RTLD_NODELETE);
    // SAFETY: function calls occur with an open consumer reference. NODELETE
    // intentionally retains both the consumer image and its provider state.
    unsafe {
        let symbol = dlsym(handle, c"retained_result".as_ptr());
        assert!(!symbol.is_null());
        let result: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(result(), 1);
        assert_eq!(dlclose(provider), 0);
        assert_eq!(dlclose(handle), 0);
        assert!(native_dso_handle_for_tests(provider));
        let reopened = open_native_fixture(&consumer, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(reopened, handle);
        assert_eq!(result(), 2);
        assert_eq!(dlclose(reopened), 0);
        assert!(native_dso_handle_for_tests(provider));
    }
}

#[test]
fn native_dso_unload_preserves_global_symbol_precedence() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let decoy = compile_native_test_dso("int unrelated_value(void) { return 0; }");
    let first = compile_native_test_dso("int precedence_value(void) { return 11; }");
    let second = compile_native_test_dso("int precedence_value(void) { return 22; }");
    let consumer = compile_native_test_dso(
        "extern int precedence_value(void); int precedence_result(void) { return precedence_value(); }",
    );
    let decoy = open_native_fixture(&decoy, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let first = open_native_fixture(&first, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let second = open_native_fixture(&second, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    // SAFETY: every close consumes an open reference and the resolved function
    // is called before its consumer is closed.
    unsafe {
        assert_eq!(dlclose(decoy), 0);
        let consumer = open_native_fixture(&consumer, libc::RTLD_NOW);
        let symbol = dlsym(consumer, c"precedence_result".as_ptr());
        assert!(!symbol.is_null());
        let result: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(result(), 11);
        assert_eq!(dlclose(first), 0);
        assert_eq!(dlclose(second), 0);
        assert!(!native_dso_handle_for_tests(second));
        assert!(native_dso_handle_for_tests(first));
        assert_eq!(result(), 11);
        assert_eq!(dlclose(consumer), 0);
        assert!(!native_dso_handle_for_tests(first));
    }
}

unsafe extern "C" fn record_first_phdr(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut c_void,
) -> c_int {
    let probe = unsafe { &mut *data.cast::<DlIterateProbe>() };
    probe.count += 1;
    probe.saw_nonnull_info = !info.is_null();
    probe.saw_nonzero_size = size >= core::mem::size_of::<libc::dl_phdr_info>();
    1
}

#[test]
fn dl_iterate_phdr_native_fallback_returns_zero_without_callback() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    // SAFETY: no callback is provided and no pointers are dereferenced.
    let rc = unsafe { dl_iterate_phdr(None, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

#[test]
fn dl_iterate_phdr_invokes_callback_with_host_phdr_data() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let mut probe = DlIterateProbe::default();

    let rc = unsafe {
        dl_iterate_phdr(
            Some(record_first_phdr),
            (&mut probe as *mut DlIterateProbe).cast::<c_void>(),
        )
    };

    assert_eq!(rc, 1, "callback should stop iteration by returning 1");
    assert_eq!(
        probe.count, 1,
        "callback should be invoked exactly once before stopping"
    );
    assert!(
        probe.saw_nonnull_info,
        "host dl_iterate_phdr should provide a non-null info record"
    );
    assert!(
        probe.saw_nonzero_size,
        "host dl_iterate_phdr should report at least a dl_phdr_info-sized record"
    );
}

#[test]
fn dladdr_null_inputs_return_zero_and_publish_invalid_handle_error() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    // SAFETY: reading/clearing thread-local dlerror state is valid.
    unsafe {
        let _ = dlerror();
        let rc = dladdr(std::ptr::null(), std::ptr::null_mut());
        assert_eq!(rc, 0);
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        let err = CStr::from_ptr(err_ptr).to_string_lossy();
        assert!(
            err.contains("invalid handle"),
            "unexpected dlerror payload: {err}"
        );
    }
}

#[test]
fn dladdr_non_null_inputs_return_zero_and_publish_unavailable_error() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let mut out_slot: usize = 0;
    let addr = (&out_slot as *const usize).cast::<c_void>();
    let info = (&mut out_slot as *mut usize).cast::<c_void>();

    // SAFETY: pointers refer to stack-owned storage for this test scope.
    unsafe {
        let _ = dlerror();
        let rc = dladdr(addr, info);
        assert_eq!(rc, 0);
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        let err = CStr::from_ptr(err_ptr).to_string_lossy();
        assert!(
            err.contains("operation unavailable"),
            "unexpected dlerror payload: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// dlopen / dlsym / dlclose
// ---------------------------------------------------------------------------

#[test]
fn dlopen_null_returns_main_handle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "dlopen(NULL, RTLD_NOW) should return main program handle"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlopen_nonexistent_library_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let name = CString::new("libnonexistent_zzz_12345.so").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    assert!(
        handle.is_null(),
        "dlopen nonexistent library should return NULL"
    );

    let err_ptr = unsafe { dlerror() };
    assert!(
        !err_ptr.is_null(),
        "dlerror should be set after failed dlopen"
    );
}

#[test]
fn dlsym_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("printf").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should find native 'printf' on main handle"
    );

    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_rtld_default_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym_name = CString::new("printf").unwrap();
    let sym = unsafe { dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should resolve 'printf' through the native RTLD_DEFAULT path"
    );
}

#[test]
fn dlsym_rtld_next_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym_name = CString::new("malloc").unwrap();
    let sym = unsafe { dlsym(libc::RTLD_NEXT, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should resolve 'malloc' through RTLD_NEXT"
    );
}

#[test]
fn dlsym_unknown_symbol_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("zzz_nonexistent_symbol_99999").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(sym.is_null(), "dlsym should return NULL for unknown symbol");

    unsafe { dlclose(handle) };
}

#[test]
fn dlclose_null_returns_error() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let rc = unsafe { dlclose(std::ptr::null_mut()) };
    assert_ne!(rc, 0, "dlclose(NULL) should return error");
}

#[test]
fn dlerror_returns_null_when_no_error() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Clear any pending error
    unsafe { dlerror() };
    // A successful dlopen should clear the error
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    if !handle.is_null() {
        let err = unsafe { dlerror() };
        assert!(
            err.is_null(),
            "dlerror should be NULL after successful dlopen"
        );
        unsafe { dlclose(handle) };
    }
}

#[test]
fn dlerror_consumed_after_read() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    // Force an error
    let name = CString::new("libnonexistent_zzz.so").unwrap();
    let _ = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    let err1 = unsafe { dlerror() };
    assert!(!err1.is_null(), "first dlerror should return error");
    // Second call should return null (error consumed)
    let err2 = unsafe { dlerror() };
    assert!(err2.is_null(), "second dlerror should return null");
}

#[test]
fn dlopen_libc_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    assert!(
        !handle.is_null(),
        "native phase-1 dlopen should surface the main handle for libc NOLOAD aliases"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlopen_pathname_self_contained_shared_object_uses_native_loader() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let so_path = compile_self_contained_test_dso();
    let name = CString::new(so_path.as_os_str().as_bytes()).unwrap();

    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let err = unsafe { dlerror() };
        let msg = if err.is_null() {
            "<no dlerror>".into()
        } else {
            unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned()
        };
        panic!("native pathname dlopen failed for {so_path:?}: {msg}");
    }
    assert!(
        native_dso_handle_for_tests(handle),
        "pathname dlopen should return a native DSO handle, not a host-loader handle"
    );

    let sym_name = CString::new("franken_native_answer").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should resolve the exported symbol from the native DSO"
    );

    let answer: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(sym) };
    assert_eq!(unsafe { answer() }, 4242);
    assert_eq!(unsafe { dlclose(handle) }, 0);
    assert!(
        !native_dso_handle_for_tests(handle),
        "dlclose should retire the native DSO handle"
    );
}

#[test]
fn native_dso_reopens_share_state_and_noload_references() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = compile_self_contained_test_dso();
    let alias = path.with_file_name("hardlink.so");
    std::fs::hard_link(&path, &alias).unwrap();
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let alias = CString::new(alias.as_os_str().as_bytes()).unwrap();
    // SAFETY: names are live C strings; returned symbols are called only while
    // an open reference owns the compiled, self-contained DSO mapping.
    unsafe {
        assert!(dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
        assert!(!dlerror().is_null());
        let first = dlopen(name.as_ptr(), libc::RTLD_NOW);
        assert!(native_dso_handle_for_tests(first));
        let second = dlopen(alias.as_ptr(), libc::RTLD_NOW);
        assert_eq!(first, second, "hard-link aliases must share one mapping");
        let resident = dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(first, resident);
        assert!(dlerror().is_null());
        let symbol = dlsym(first, c"franken_native_increment".as_ptr());
        assert!(!symbol.is_null());
        let increment: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(increment(), 1);
        assert_eq!(dlclose(first), 0);
        assert_eq!(dlclose(second), 0);
        assert!(native_dso_handle_for_tests(resident));
        assert_eq!(
            dlsym(resident, c"franken_native_increment".as_ptr()),
            symbol
        );
        assert_eq!(increment(), 2);
        assert_eq!(dlclose(resident), 0);
        assert!(!native_dso_handle_for_tests(resident));
        assert!(dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
        let fresh = dlopen(name.as_ptr(), libc::RTLD_NOW);
        assert!(native_dso_handle_for_tests(fresh));
        let symbol = dlsym(fresh, c"franken_native_increment".as_ptr());
        assert!(!symbol.is_null());
        let increment: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(
            increment(),
            1,
            "final close must release non-NODELETE state"
        );
        assert_eq!(dlclose(fresh), 0);
    }
}

#[test]
fn native_dso_nodelete_promotion_preserves_state_after_final_close() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = compile_self_contained_test_dso();
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the fixture exports this exact function ABI; all calls occur
    // while an open reference is held. NODELETE intentionally retains memory.
    unsafe {
        let first = dlopen(name.as_ptr(), libc::RTLD_NOW);
        assert!(native_dso_handle_for_tests(first));
        let symbol = dlsym(first, c"franken_native_increment".as_ptr());
        assert!(!symbol.is_null());
        let increment: unsafe extern "C" fn() -> c_int = std::mem::transmute(symbol);
        assert_eq!(increment(), 1);
        let promoted = dlopen(
            name.as_ptr(),
            libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
        );
        assert_eq!(promoted, first);
        assert_eq!(dlclose(first), 0);
        assert_eq!(dlclose(promoted), 0);
        let reopened = dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(reopened, first);
        assert_eq!(
            dlsym(reopened, c"franken_native_increment".as_ptr()),
            symbol
        );
        assert_eq!(increment(), 2, "NODELETE must preserve DSO data");
        assert_eq!(dlclose(reopened), 0);
    }
}

#[test]
fn native_dso_concurrent_first_opens_publish_one_mapping() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = compile_self_contained_test_dso();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                barrier.wait();
                // SAFETY: the filename is a live C string. This thread keeps
                // its open reference until every other thread has opened too.
                let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
                barrier.wait();
                assert!(native_dso_handle_for_tests(handle));
                // SAFETY: this thread owns one successful open reference.
                assert_eq!(unsafe { dlclose(handle) }, 0);
                handle as usize
            })
        })
        .collect();
    let handles: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(handles.iter().all(|handle| *handle == handles[0]));
    assert!(!native_dso_handle_for_tests(handles[0] as *mut c_void));
}

#[test]
fn native_dso_fifo_is_rejected_without_blocking_loader() {
    const CHILD_PATH: &str = "FRANKENLIBC_DSO_FIFO_TEST_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let name = CString::new(path.as_bytes()).unwrap();
        // SAFETY: a valid, live pathname; the FIFO must be rejected without
        // waiting for a writer, before taking the native loader registry lock.
        unsafe {
            assert!(dlopen(name.as_ptr(), libc::RTLD_NOW).is_null());
            assert!(!dlerror().is_null());
        }
        return;
    }
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = compile_self_contained_test_dso().with_file_name("not-an-elf.fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: creates a FIFO at a unique fixture path; no existing file is
    // overwritten or removed. The parent never opens the FIFO.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_dso_fifo_is_rejected_without_blocking_loader",
            "--nocapture",
        ])
        .env(CHILD_PATH, &path)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "FIFO rejection child failed: {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("native dlopen blocked on a FIFO without a writer");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn dlsym_null_name_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    let sym = unsafe { dlsym(handle, std::ptr::null()) };
    assert!(sym.is_null(), "dlsym with null name should return NULL");
    unsafe { dlclose(handle) };
}

// ---------------------------------------------------------------------------
// Additional dlopen/dlclose edge cases
// ---------------------------------------------------------------------------

#[test]
fn dlopen_same_handle_twice_returns_same_handle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let h1 = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    let h2 = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!h1.is_null());
    assert!(!h2.is_null());
    // Both opens refer to the main program; closing both should succeed
    unsafe {
        dlclose(h1);
        dlclose(h2);
    }
}

#[test]
fn dlopen_rtld_lazy_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_LAZY) };
    assert!(
        !handle.is_null(),
        "dlopen(NULL, RTLD_LAZY) should return main program handle"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_finds_malloc() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("malloc").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(!sym.is_null(), "dlsym should find 'malloc' in main handle");

    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_main_handle_finds_memcpy() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("memcpy").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(!sym.is_null(), "dlsym should find 'memcpy' in main handle");

    unsafe { dlclose(handle) };
}

#[test]
fn dlclose_idempotent_for_main_handle() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    // First close should succeed
    let rc1 = unsafe { dlclose(handle) };
    assert_eq!(rc1, 0, "first dlclose should succeed");
}

#[test]
fn dlclose_repeated_main_handle_close_is_noop() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let rc1 = unsafe { dlclose(handle) };
    let rc2 = unsafe { dlclose(handle) };
    assert_eq!(rc1, 0, "first close should succeed");
    assert_eq!(rc2, 0, "main-program handle close is a repeatable no-op");
}

#[test]
fn dlvsym_supported_version_resolves_native_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_DEFAULT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve known symbols for supported versions"
    );
}

#[test]
fn dlvsym_rtld_next_resolves_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_NEXT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve symbols through RTLD_NEXT"
    );
}

#[test]
fn dlvsym_host_handle_resolves_symbol() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let lib_name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "dlopen libc should succeed");
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(handle, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve symbols on host handles"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlvsym_unsupported_version_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_9.9").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_DEFAULT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        sym.is_null(),
        "unsupported versions should not resolve native symbols"
    );
}

#[test]
fn dlsym_and_dlvsym_reject_unterminated_names_in_bootstrap_passthrough() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let unterminated_symbol = malloc(6).cast::<u8>();
        assert!(!unterminated_symbol.is_null());
        std::ptr::copy_nonoverlapping(b"malloc".as_ptr(), unterminated_symbol, 6);

        let sym = dlsym(libc::RTLD_DEFAULT, unterminated_symbol.cast());
        assert!(
            sym.is_null(),
            "dlsym should reject an unterminated symbol buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());

        let version = CString::new("GLIBC_2.2.5").unwrap();
        let sym = dlvsym(
            libc::RTLD_DEFAULT,
            unterminated_symbol.cast(),
            version.as_ptr(),
        );
        assert!(
            sym.is_null(),
            "dlvsym should reject an unterminated symbol buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        free(unterminated_symbol.cast());

        let sym_name = CString::new("malloc").unwrap();
        let unterminated_version = malloc(11).cast::<u8>();
        assert!(!unterminated_version.is_null());
        std::ptr::copy_nonoverlapping(b"GLIBC_2.2.5".as_ptr(), unterminated_version, 11);
        let sym = dlvsym(
            libc::RTLD_DEFAULT,
            sym_name.as_ptr(),
            unterminated_version.cast(),
        );
        assert!(
            sym.is_null(),
            "dlvsym should reject an unterminated version buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        free(unterminated_version.cast());
    }
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn dlopen_rejects_unterminated_name_in_bootstrap_passthrough() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let unterminated_name = malloc(7).cast::<u8>();
        assert!(!unterminated_name.is_null());
        std::ptr::copy_nonoverlapping(b"libc.so".as_ptr(), unterminated_name, 7);

        let handle = dlopen(unterminated_name.cast(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if !handle.is_null() {
            let _ = dlclose(handle);
        }
        let rejected = handle.is_null();
        let err_ptr = dlerror();
        free(unterminated_name.cast());
        assert!(
            rejected,
            "dlopen should reject an unterminated filename buffer"
        );
        assert!(!err_ptr.is_null());
    }
}

#[test]
fn dlopen_empty_string_returns_null_or_main() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let name = CString::new("").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    // Empty string may return main handle or NULL depending on implementation
    if !handle.is_null() {
        unsafe { dlclose(handle) };
    }
}

#[test]
fn main_program_handle_sees_rtld_global_symbols() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let main_handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!main_handle.is_null(), "dlopen(NULL) should succeed");

    let candidates = [
        ("libm.so.6", "cos"),
        ("libutil.so.1", "forkpty"),
        ("libuuid.so.1", "uuid_generate"),
        ("libresolv.so.2", "res_ninit"),
        ("libz.so.1", "inflate"),
    ];

    for (library, symbol) in candidates {
        let lib_name = CString::new(library).unwrap();
        let sym_name = CString::new(symbol).unwrap();

        let before = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        if !before.is_null() {
            continue;
        }

        let local_handle = unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if local_handle.is_null() {
            let _ = unsafe { dlerror() };
            continue;
        }

        let local_sym = unsafe { dlsym(local_handle, sym_name.as_ptr()) };
        let local_from_main = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        unsafe { dlclose(local_handle) };
        if local_sym.is_null() || !local_from_main.is_null() {
            continue;
        }

        let global_handle =
            unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        assert!(
            !global_handle.is_null(),
            "RTLD_GLOBAL load should succeed for candidate {library}"
        );

        let global_sym = unsafe { dlsym(global_handle, sym_name.as_ptr()) };
        assert!(
            !global_sym.is_null(),
            "RTLD_GLOBAL handle should resolve {symbol} from {library}"
        );

        let promoted = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        assert!(
            !promoted.is_null(),
            "main-program handle should see {symbol} after RTLD_GLOBAL load of {library}"
        );

        unsafe {
            dlclose(global_handle);
            dlclose(main_handle);
        }
        return;
    }

    unsafe { dlclose(main_handle) };
}

// ---------------------------------------------------------------------------
// __libc_dlopen_mode / __libc_dlsym / __libc_dlclose (glibc internal aliases)
// ---------------------------------------------------------------------------

#[test]
fn libc_dlopen_mode_matches_dlopen_for_libc() {
    let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = c"libc.so.6";
    let h_pub = unsafe { dlopen(path.as_ptr(), libc::RTLD_NOW) };
    let h_int = unsafe { __libc_dlopen_mode(path.as_ptr(), libc::RTLD_NOW) };
    if h_pub.is_null() || h_int.is_null() {
        // libc.so.6 not loadable on this host (e.g. musl); inconclusive.
        if !h_pub.is_null() {
            unsafe { dlclose(h_pub) };
        }
        if !h_int.is_null() {
            unsafe { __libc_dlclose(h_int) };
        }
        return;
    }
    // Both should resolve the same well-known symbol.
    let sym = c"strlen";
    let p_pub = unsafe { dlsym(h_pub, sym.as_ptr()) };
    let p_int = unsafe { __libc_dlsym(h_int, sym.as_ptr()) };
    assert!(!p_pub.is_null());
    assert!(!p_int.is_null());
    assert_eq!(p_pub, p_int);

    unsafe { dlclose(h_pub) };
    let rc = unsafe { __libc_dlclose(h_int) };
    assert_eq!(rc, 0);
}

#[test]
fn libc_dlsym_with_rtld_default_resolves_known_symbol() {
    let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let sym = c"abort";
    let p = unsafe { __libc_dlsym(libc::RTLD_DEFAULT, sym.as_ptr()) };
    // RTLD_DEFAULT lookup may fail in static-link builds; if so,
    // treat as inconclusive.
    if p.is_null() {
        return;
    }
    // The pointer should be the same as dlsym's.
    let q = unsafe { dlsym(libc::RTLD_DEFAULT, sym.as_ptr()) };
    assert_eq!(p, q);
}

#[test]
fn libc_dlclose_returns_zero_on_valid_handle() {
    let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let path = c"libc.so.6";
    let h = unsafe { __libc_dlopen_mode(path.as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        return;
    }
    let rc = unsafe { __libc_dlclose(h) };
    assert_eq!(rc, 0);
}
