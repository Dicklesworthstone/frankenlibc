//! Thread runtime imports for natively loaded DSOs.
//!
//! Relocation binding and caller-relative dlsym/dlvsym share this table. Always
//! select FrankenLibC's ABI frontends: resolving individual host pthread names
//! would mix mutex, condition-variable, key and lifecycle ownership domains.
//! The frontends retain their existing interpose/standalone routing policy.

use crate::pthread_abi as pthread;

#[derive(Clone, Copy)]
enum Version {
    Baseline,
    Merged,
    Condition,
}

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    use Version::{Baseline, Condition, Merged};
    // Keep the version contract beside the actual implementation pointer.
    // In particular, GLIBC_2.34 is NOT an alias for every pthread function.
    let (function, contract) = match name {
        "pthread_create" => (pthread::pthread_create as *const (), Merged),
        "pthread_join" => (pthread::pthread_join as *const (), Merged),
        "pthread_detach" => (pthread::pthread_detach as *const (), Merged),
        "pthread_exit" => (pthread::pthread_exit as *const (), Baseline),
        "pthread_self" => (pthread::pthread_self as *const (), Baseline),
        "pthread_equal" => (pthread::pthread_equal as *const (), Baseline),
        "pthread_once" => (pthread::pthread_once as *const (), Merged),
        "pthread_key_create" => (pthread::pthread_key_create as *const (), Merged),
        "pthread_key_delete" => (pthread::pthread_key_delete as *const (), Merged),
        "pthread_getspecific" => (pthread::pthread_getspecific as *const (), Merged),
        "pthread_setspecific" => (pthread::pthread_setspecific as *const (), Merged),
        "pthread_mutex_init" => (pthread::pthread_mutex_init as *const (), Baseline),
        "pthread_mutex_destroy" => (pthread::pthread_mutex_destroy as *const (), Baseline),
        "pthread_mutex_lock" => (pthread::pthread_mutex_lock as *const (), Baseline),
        "pthread_mutex_trylock" => (pthread::pthread_mutex_trylock as *const (), Merged),
        "pthread_mutex_timedlock" => (pthread::pthread_mutex_timedlock as *const (), Merged),
        "pthread_mutex_unlock" => (pthread::pthread_mutex_unlock as *const (), Baseline),
        "pthread_cond_init" => (pthread::pthread_cond_init as *const (), Condition),
        "pthread_cond_destroy" => (pthread::pthread_cond_destroy as *const (), Condition),
        "pthread_cond_signal" => (pthread::pthread_cond_signal as *const (), Condition),
        "pthread_cond_broadcast" => (pthread::pthread_cond_broadcast as *const (), Condition),
        "pthread_cond_wait" => (pthread::pthread_cond_wait as *const (), Condition),
        "pthread_cond_timedwait" => (pthread::pthread_cond_timedwait as *const (), Condition),
        "pthread_rwlock_init" => (pthread::pthread_rwlock_init as *const (), Merged),
        "pthread_rwlock_destroy" => (pthread::pthread_rwlock_destroy as *const (), Merged),
        "pthread_rwlock_rdlock" => (pthread::pthread_rwlock_rdlock as *const (), Merged),
        "pthread_rwlock_tryrdlock" => (pthread::pthread_rwlock_tryrdlock as *const (), Merged),
        "pthread_rwlock_wrlock" => (pthread::pthread_rwlock_wrlock as *const (), Merged),
        "pthread_rwlock_trywrlock" => (pthread::pthread_rwlock_trywrlock as *const (), Merged),
        "pthread_rwlock_unlock" => (pthread::pthread_rwlock_unlock as *const (), Merged),
        _ => return None,
    };
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    let original = match contract {
        // The old x86-64 GLIBC_2.2.5 condition-variable ABI has a different
        // representation. These frontends implement only the modern layout.
        Condition if cfg!(target_arch = "x86_64") => "GLIBC_2.3.2",
        _ => baseline,
    };
    if version.is_some_and(|requested| {
        requested != original && !(matches!(contract, Merged) && requested == "GLIBC_2.34")
    }) {
        return None;
    }
    // No fixed-ABI shim: preserve C-unwind on cancellation points and the
    // non-returning exit entry point exactly as declared by pthread_abi.
    Some(function as usize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pthread_bindings_share_frontends_and_exact_versions() {
        let baseline = if cfg!(target_arch = "aarch64") {
            "GLIBC_2.17"
        } else {
            "GLIBC_2.2.5"
        };
        let condition = if cfg!(target_arch = "x86_64") {
            "GLIBC_2.3.2"
        } else {
            baseline
        };
        macro_rules! check {
            ($function:ident, $original:expr, $merged:expr) => {{
                let name = stringify!($function);
                let expected = Some(pthread::$function as *const () as usize as u64);
                assert_eq!(address(name, None), expected, "{name}");
                assert_eq!(address(name, Some($original)), expected, "{name}");
                assert_eq!(
                    address(name, Some("GLIBC_2.34")),
                    if $merged { expected } else { None },
                    "{name}"
                );
                for unsupported in ["GLIBC_PRIVATE", "GLIBC_9.99", "GLIBC_2.0", ""] {
                    assert_eq!(address(name, Some(unsupported)), None, "{name}");
                    // The containing runtime table must not resurrect a known
                    // name after its own version decision rejected the request.
                    assert_eq!(super::super::address(name, Some(unsupported)), None);
                }
            }};
        }
        check!(pthread_create, baseline, true);
        check!(pthread_join, baseline, true);
        check!(pthread_detach, baseline, true);
        check!(pthread_exit, baseline, false);
        check!(pthread_self, baseline, false);
        check!(pthread_equal, baseline, false);
        check!(pthread_once, baseline, true);
        check!(pthread_key_create, baseline, true);
        check!(pthread_key_delete, baseline, true);
        check!(pthread_getspecific, baseline, true);
        check!(pthread_setspecific, baseline, true);
        check!(pthread_mutex_init, baseline, false);
        check!(pthread_mutex_destroy, baseline, false);
        check!(pthread_mutex_lock, baseline, false);
        check!(pthread_mutex_trylock, baseline, true);
        check!(pthread_mutex_timedlock, baseline, true);
        check!(pthread_mutex_unlock, baseline, false);
        check!(pthread_cond_init, condition, false);
        check!(pthread_cond_destroy, condition, false);
        check!(pthread_cond_signal, condition, false);
        check!(pthread_cond_broadcast, condition, false);
        check!(pthread_cond_wait, condition, false);
        check!(pthread_cond_timedwait, condition, false);
        check!(pthread_rwlock_init, baseline, true);
        check!(pthread_rwlock_destroy, baseline, true);
        check!(pthread_rwlock_rdlock, baseline, true);
        check!(pthread_rwlock_tryrdlock, baseline, true);
        check!(pthread_rwlock_wrlock, baseline, true);
        check!(pthread_rwlock_trywrlock, baseline, true);
        check!(pthread_rwlock_unlock, baseline, true);
        assert_eq!(address("pthread_not_a_real_function", None), None);
        assert_eq!(address("malloc", None), None);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn native_pthread_rejects_the_obsolete_condition_variable_layout() {
        for name in [
            "pthread_cond_init",
            "pthread_cond_destroy",
            "pthread_cond_signal",
            "pthread_cond_broadcast",
            "pthread_cond_wait",
            "pthread_cond_timedwait",
        ] {
            assert!(address(name, Some("GLIBC_2.3.2")).is_some());
            assert_eq!(super::super::address(name, Some("GLIBC_2.2.5")), None);
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn native_pthread_dso_runs_workers_once_keys_and_dynamic_tls() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "frankenlibc-native-pthread-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("workers.c");
        let library = directory.join("workers.so");
        std::fs::write(&source, WORKERS).unwrap();
        let output = Command::new("cc")
            .args([
                "-shared", "-fPIC", "-nostdlib", "-O2", "-fno-stack-protector",
                "-Wall", "-Wextra", "-Werror", "-DFRANKENLIBC_NATIVE",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .output()
            .expect("C compiler required for the native DSO execution test");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let name = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is NUL terminated. The compiled, self-contained
        // fixture exports the declared C function and remains mapped until all
        // of its worker threads and their key destructors have completed.
        unsafe {
            let handle = crate::dlfcn_abi::dlopen(name.as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null(), "native worker DSO failed to load");
            // A host fallback must not make this integration test pass.
            assert_eq!(handle as usize & 0xff, 0x4d, "expected a native DSO handle");
            let entry = crate::dlfcn_abi::dlsym(handle, c"native_pthread_frontends".as_ptr());
            assert!(!entry.is_null());
            let run: unsafe extern "C" fn() -> i32 = std::mem::transmute(entry);
            // On failure retain the handle rather than unmapping potentially
            // running worker code. A successful fixture has joined all workers.
            assert_eq!(run(), 0, "native worker fixture failed");
            assert_eq!(crate::dlfcn_abi::dlclose(handle), 0);
        }
        // Retain process-unique temporary fixtures for failed-run diagnosis.
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const WORKERS: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <dlfcn.h>

static pthread_mutex_t guard;
static pthread_cond_t changed;
static pthread_rwlock_t totals;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t key;
static int go, sum, destroyed, once_count, key_error;
static __thread int cell = 7;

static void destroy_value(void *value) {
    pthread_mutex_lock(&guard);
    destroyed += (value == (void *)(intptr_t)1 || value == (void *)(intptr_t)2);
    pthread_mutex_unlock(&guard);
}
static void make_key(void) {
    ++once_count;
    key_error = pthread_key_create(&key, destroy_value);
}
static void *worker(void *value) {
    intptr_t id = (intptr_t)value;
    if (pthread_once(&once, make_key) || key_error) return (void *)(intptr_t)101;
    if (cell != 7) return (void *)(intptr_t)102;
    cell += (int)id;
    if (pthread_setspecific(key, value) || pthread_getspecific(key) != value)
        return (void *)(intptr_t)103;
    if (pthread_mutex_lock(&guard)) return (void *)(intptr_t)104;
    while (!go) {
        if (pthread_cond_wait(&changed, &guard)) {
            pthread_mutex_unlock(&guard);
            return (void *)(intptr_t)105;
        }
    }
    pthread_mutex_unlock(&guard);
    if (pthread_rwlock_wrlock(&totals)) return (void *)(intptr_t)106;
    sum += cell;
    pthread_rwlock_unlock(&totals);
    return (void *)(id + 40);
}

int native_pthread_frontends(void) {
    pthread_t threads[2];
    int created = 0, failure = 0;
    if (pthread_mutex_init(&guard, 0)) return 1;
    if (pthread_cond_init(&changed, 0)) return 2;
    if (pthread_rwlock_init(&totals, 0)) return 3;
    if (!pthread_equal(pthread_self(), pthread_self())) return 4;
    for (int i = 0; i < 2; ++i) {
        if (pthread_create(&threads[i], 0, worker, (void *)(intptr_t)(i + 1))) {
            failure = 5;
            break;
        }
        ++created;
    }
    pthread_mutex_lock(&guard);
    go = 1;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&guard);
    for (int i = 0; i < created; ++i) {
        void *result = 0;
        if (pthread_join(threads[i], &result)) return 6;
        if (result != (void *)(intptr_t)(i + 41)) failure = 7;
    }
    if (failure) return failure;
    if (once_count != 1 || destroyed != 2 || sum != 17 || cell != 7) return 8;
    if (pthread_getspecific(key) != 0) return 9;
    if (pthread_key_delete(key)) return 10;
    if (pthread_rwlock_tryrdlock(&totals)) return 11;
    if (pthread_rwlock_unlock(&totals)) return 12;
    if (pthread_rwlock_destroy(&totals)) return 13;
    if (pthread_cond_destroy(&changed)) return 14;
    if (pthread_mutex_destroy(&guard)) return 15;

    /* These requests enter the caller-relative native lookup bridge. */
    if (dlsym(RTLD_DEFAULT, "pthread_create") != (void *)pthread_create) return 16;
#if defined(__aarch64__)
    const char *baseline = "GLIBC_2.17";
#else
    const char *baseline = "GLIBC_2.2.5";
#endif
    if (dlvsym(RTLD_DEFAULT, "pthread_create", baseline) != (void *)pthread_create)
        return 17;
    if (dlvsym(RTLD_DEFAULT, "pthread_create", "GLIBC_2.34") != (void *)pthread_create)
        return 18;
#ifdef FRANKENLIBC_NATIVE
    /* A modern condition object must not bind the obsolete x86-64 layout. */
    if (dlvsym(RTLD_DEFAULT, "pthread_cond_wait", "GLIBC_2.2.5") != 0) return 19;
    if (!dlerror() || dlerror()) return 20;
    if (dlvsym(RTLD_DEFAULT, "pthread_mutex_lock", "GLIBC_2.34") != 0) return 21;
    if (!dlerror() || dlerror()) return 22;
#endif
    return 0;
}
"#;
}
