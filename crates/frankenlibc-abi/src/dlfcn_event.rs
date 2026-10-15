//! Event-loop runtime bindings for native plugins.
//!
//! Keep readiness waits, event counters and timers in the same errno and
//! cancellation domain as the socket and descriptor frontends. Both native
//! relocation binding and caller-relative lookup consume this table.

use crate::poll_abi as poll;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
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
