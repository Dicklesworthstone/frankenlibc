//! Event-loop runtime bindings for native plugins.
//!
//! Keep readiness waits, event counters, timers and deadline clocks in the same
//! errno and cancellation domain as the socket and descriptor frontends. Both
//! native relocation binding and caller-relative lookup consume this table.

use crate::{poll_abi as poll, time_abi as time};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    if let Some(address) = clock_address(name, version) {
        return Some(address);
    }
    let introduced = match name {
        "poll" | "select" | "pselect" => "GLIBC_2.2.5",
        "ppoll" => "GLIBC_2.4",
        "epoll_create" | "epoll_ctl" | "epoll_wait" => "GLIBC_2.3.2",
        "epoll_pwait" => "GLIBC_2.6",
        "epoll_create1" => "GLIBC_2.9",
        "eventfd" => "GLIBC_2.7",
        "timerfd_create" | "timerfd_settime" | "timerfd_gettime" => "GLIBC_2.8",
        _ => return None,
    };
    let supported = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        introduced
    };
    if version.is_some_and(|version| version != supported) {
        return None;
    }
    // Preserve the C-unwind cancellation points; do not add an adapter with
    // a narrower ABI or resolve the host's implementation by symbol name.
    let function = match name {
        "poll" => poll::poll as *const (),
        "ppoll" => poll::ppoll as *const (),
        "select" => poll::select as *const (),
        "pselect" => poll::pselect as *const (),
        "epoll_create" => poll::epoll_create as *const (),
        "epoll_create1" => poll::epoll_create1 as *const (),
        "epoll_ctl" => poll::epoll_ctl as *const (),
        "epoll_wait" => poll::epoll_wait as *const (),
        "epoll_pwait" => poll::epoll_pwait as *const (),
        "eventfd" => poll::eventfd as *const (),
        "timerfd_create" => poll::timerfd_create as *const (),
        "timerfd_settime" => poll::timerfd_settime as *const (),
        "timerfd_gettime" => poll::timerfd_gettime as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}

fn clock_address(name: &str, version: Option<&str>) -> Option<u64> {
    let (function, moved_from_librt) = match name {
        "clock_gettime" => (time::clock_gettime as *const (), true),
        "clock_getres" => (time::clock_getres as *const (), true),
        "gettimeofday" => (time::gettimeofday as *const (), false),
        "time" => (time::time as *const (), false),
        "clock" => (time::clock as *const (), false),
        _ => return None,
    };
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    // On x86-64 the clock query functions have the old librt ABI as well as
    // their libc GLIBC_2.17 entry. Ordinary wall/CPU-time APIs did not acquire
    // this additional version, nor did these queries acquire GLIBC_2.34.
    if version.is_some_and(|requested| {
        requested != baseline && !(moved_from_librt && requested == "GLIBC_2.17")
    }) {
        return None;
    }
    Some(function as usize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_deadline_clock_bindings_have_exact_compatibility_versions() {
        let baseline = if cfg!(target_arch = "aarch64") {
            "GLIBC_2.17"
        } else {
            "GLIBC_2.2.5"
        };
        for (name, function, moved) in [
            ("clock_gettime", time::clock_gettime as *const (), true),
            ("clock_getres", time::clock_getres as *const (), true),
            ("gettimeofday", time::gettimeofday as *const (), false),
            ("time", time::time as *const (), false),
            ("clock", time::clock as *const (), false),
        ] {
            let expected = Some(function as usize as u64);
            assert_eq!(address(name, None), expected, "{name}");
            assert_eq!(address(name, Some(baseline)), expected, "{name}");
            assert_eq!(
                address(name, Some("GLIBC_2.17")),
                if moved || cfg!(target_arch = "aarch64") { expected } else { None },
                "{name}"
            );
            for unsupported in ["GLIBC_2.34", "GLIBC_PRIVATE", "GLIBC_9.99", ""] {
                assert_eq!(address(name, Some(unsupported)), None, "{name}");
            }
        }
        assert_eq!(clock_address("timerfd_create", None), None);
        assert_eq!(address("not_a_clock_function", None), None);
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn native_deadline_dso_arms_absolute_timer_and_times_out_condition_wait() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "frankenlibc-native-deadline-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("deadline.c");
        let library = directory.join("deadline.so");
        std::fs::write(&source, DEADLINES).unwrap();
        let output = Command::new("cc")
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-fno-stack-protector",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .output()
            .expect("C compiler required for the native deadline DSO test");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let name = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: the self-contained fixture exports the declared C function
        // and closes its timer descriptor before returning. Keep it mapped
        // until all clock, timer and condition-variable operations finish.
        unsafe {
            let handle = crate::dlfcn_abi::dlopen(name.as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null(), "native deadline DSO failed to load");
            assert_eq!(handle as usize & 0xff, 0x4d, "host fallback is not a pass");
            let entry = crate::dlfcn_abi::dlsym(handle, c"native_deadline_frontends".as_ptr());
            assert!(!entry.is_null());
            let run: unsafe extern "C" fn() -> i32 = std::mem::transmute(entry);
            let result = run();
            assert_eq!(crate::dlfcn_abi::dlclose(handle), 0);
            assert_eq!(result, 0, "native deadline fixture failed");
        }
        // Retain process-unique temporary fixtures for diagnosis.
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const DEADLINES: &str = r#"
#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <dlfcn.h>

int native_deadline_frontends(void) {
    struct timespec now, resolution, after;
    struct timeval wall;
    time_t stored = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 1;
    if (clock_getres(CLOCK_MONOTONIC, &resolution)) return 2;
    if (resolution.tv_sec < 0 || resolution.tv_nsec < 0 || resolution.tv_nsec >= 1000000000)
        return 3;
    if (clock_getres(CLOCK_MONOTONIC, 0)) return 4;
    if (gettimeofday(&wall, 0) || wall.tv_usec < 0 || wall.tv_usec >= 1000000) return 5;
    time_t value = time(&stored);
    if (value == (time_t)-1 || value != stored || clock() == (clock_t)-1) return 6;

    struct itimerspec timer = {0};
    timer.it_value = now;
    timer.it_value.tv_nsec += 1000000;
    if (timer.it_value.tv_nsec >= 1000000000) {
        ++timer.it_value.tv_sec;
        timer.it_value.tv_nsec -= 1000000000;
    }
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) return 7;
    int result = 0;
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer, 0)) result = 8;
    struct pollfd ready = {fd, POLLIN, 0};
    if (!result && (poll(&ready, 1, 2000) != 1 || !(ready.revents & POLLIN))) result = 9;
    uint64_t count = 0;
    if (!result && (read(fd, &count, sizeof(count)) != sizeof(count) || count < 1)) result = 10;
    if (!result && clock_gettime(CLOCK_MONOTONIC, &after)) result = 11;
    if (!result && (after.tv_sec < timer.it_value.tv_sec ||
        (after.tv_sec == timer.it_value.tv_sec && after.tv_nsec < timer.it_value.tv_nsec)))
        result = 12;
    close(fd);
    if (result) return result;

    /* An expired absolute pthread deadline must reacquire its mutex. */
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    if (pthread_mutex_init(&mutex, 0) || pthread_cond_init(&condition, 0)) return 13;
    if (clock_gettime(CLOCK_REALTIME, &now)) return 14;
    if (pthread_mutex_lock(&mutex)) return 15;
    if (pthread_cond_timedwait(&condition, &mutex, &now) != ETIMEDOUT) return 16;
    if (pthread_mutex_trylock(&mutex) != EBUSY) return 17;
    if (pthread_mutex_unlock(&mutex)) return 18;
    if (pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 19;

    errno = 0;
    if (clock_gettime(INT_MAX, &now) != -1 || errno != EINVAL) return 20;
    if (dlsym(RTLD_DEFAULT, "clock_gettime") != (void *)clock_gettime) return 21;
    if (dlvsym(RTLD_DEFAULT, "clock_gettime", "GLIBC_2.17") != (void *)clock_gettime)
        return 22;
#if defined(__x86_64__)
    if (dlvsym(RTLD_DEFAULT, "clock_gettime", "GLIBC_2.2.5") != (void *)clock_gettime)
        return 23;
#endif
    if (dlvsym(RTLD_DEFAULT, "clock_gettime", "GLIBC_2.34") != 0) return 24;
    if (!dlerror() || dlerror()) return 25;
    return 0;
}
"#;
}
