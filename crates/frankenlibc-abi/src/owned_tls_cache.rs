//! Process-keyed scratch storage for opt-in standalone TLS-removal experiments.
//!
//! This intentionally avoids Rust `thread_local!` so experiment lanes can
//! replace per-thread ABI scratch buffers without introducing a `__tls_get_addr`
//! relocation. It is feature-gated because the default ABI path still uses the
//! existing Rust TLS implementation until every tracked source surface has been
//! migrated and artifact-level nm/readelf checks prove the blocker is gone.

use std::sync::Mutex;

use frankenlibc_core::syscall;

pub(crate) struct OwnedTlsCache<T> {
    slots: Mutex<Vec<OwnedTlsSlot<T>>>,
    init: fn() -> T,
}

struct OwnedTlsSlot<T> {
    tid: i32,
    value: T,
}

impl<T> OwnedTlsCache<T>
where
    T: Send,
{
    pub(crate) const fn new(init: fn() -> T) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            init,
        }
    }

    pub(crate) fn with<R>(&'static self, f: impl FnOnce(&mut T) -> R) -> R {
        let tid = syscall::sys_gettid();
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let index = match slots.iter().position(|slot| slot.tid == tid) {
            Some(index) => index,
            None => {
                slots.push(OwnedTlsSlot {
                    tid,
                    value: (self.init)(),
                });
                slots.len() - 1
            }
        };
        f(&mut slots[index].value)
    }
}
