#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

//! Actual native-thread stack ownership and attribute contracts.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use frankenlibc_abi::pthread_abi::*;
use frankenlibc_core::syscall;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct StackAttrApi {
    init: unsafe extern "C" fn(*mut libc::pthread_attr_t) -> i32,
    destroy: unsafe extern "C" fn(*mut libc::pthread_attr_t) -> i32,
    set_size: unsafe extern "C" fn(*mut libc::pthread_attr_t, usize) -> i32,
    set_address: unsafe extern "C" fn(*mut libc::pthread_attr_t, *mut c_void) -> i32,
    set_stack: unsafe extern "C" fn(*mut libc::pthread_attr_t, *mut c_void, usize) -> i32,
    get_stack:
        unsafe extern "C" fn(*const libc::pthread_attr_t, *mut *mut c_void, *mut usize) -> i32,
    get_address: unsafe extern "C" fn(*const libc::pthread_attr_t, *mut *mut c_void) -> i32,
}

impl StackAttrApi {
    fn managed() -> Self {
        Self {
            init: pthread_attr_init,
            destroy: pthread_attr_destroy,
            set_size: pthread_attr_setstacksize,
            set_address: pthread_attr_setstackaddr,
            set_stack: pthread_attr_setstack,
            get_stack: pthread_attr_getstack,
            get_address: pthread_attr_getstackaddr,
        }
    }

    fn host() -> Self {
        use dlsym_oracle::host_fn;
        // Resolve each oracle in libc.so.6 and reject aliases to our own entrypoints.
        unsafe {
            Self {
                init: host_fn(c"pthread_attr_init", pthread_attr_init as *const ()),
                destroy: host_fn(c"pthread_attr_destroy", pthread_attr_destroy as *const ()),
                set_size: host_fn(
                    c"pthread_attr_setstacksize",
                    pthread_attr_setstacksize as *const (),
                ),
                set_address: host_fn(
                    c"pthread_attr_setstackaddr",
                    pthread_attr_setstackaddr as *const (),
                ),
                set_stack: host_fn(c"pthread_attr_setstack", pthread_attr_setstack as *const ()),
                get_stack: host_fn(c"pthread_attr_getstack", pthread_attr_getstack as *const ()),
                get_address: host_fn(
                    c"pthread_attr_getstackaddr",
                    pthread_attr_getstackaddr as *const (),
                ),
            }
        }
    }

    fn snapshot(&self, attr: &libc::pthread_attr_t) -> (usize, usize, usize) {
        let mut base = ptr::null_mut();
        let mut size = 0;
        let mut top = ptr::null_mut();
        unsafe {
            assert_eq!((self.get_stack)(attr, &mut base, &mut size), 0);
            assert_eq!((self.get_address)(attr, &mut top), 0);
        }
        (base as usize, size, top as usize)
    }
}

struct NativeMode(bool);

impl NativeMode {
    fn enter() -> Self {
        Self(pthread_threading_swap_force_native_for_tests())
    }
}

impl Drop for NativeMode {
    fn drop(&mut self) {
        pthread_threading_restore_for_tests(self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StackAttrs {
    address: usize,
    size: usize,
    guard: usize,
    detached: i32,
}

unsafe fn stack_attrs(thread: libc::pthread_t) -> Result<StackAttrs, i32> {
    let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { pthread_getattr_np(thread, &mut attr) };
    if rc != 0 {
        return Err(rc);
    }
    let mut address = ptr::null_mut();
    let mut size = 0;
    let mut guard = 0;
    let mut detached = -1;
    let results = unsafe {
        [
            pthread_attr_getstack(&attr, &mut address, &mut size),
            pthread_attr_getguardsize(&attr, &mut guard),
            pthread_attr_getdetachstate(&attr, &mut detached),
            pthread_attr_destroy(&mut attr),
        ]
    };
    if let Some(error) = results.into_iter().find(|rc| *rc != 0) {
        return Err(error);
    }
    Ok(StackAttrs {
        address: address as usize,
        size,
        guard,
        detached,
    })
}

struct Probe {
    ready: AtomicI32,
    release: AtomicI32,
    result: AtomicI32,
    tid: AtomicI32,
    address: AtomicUsize,
    size: AtomicUsize,
    guard: AtomicUsize,
    local: AtomicUsize,
}

impl Probe {
    fn new() -> Self {
        Self {
            ready: AtomicI32::new(0),
            release: AtomicI32::new(0),
            result: AtomicI32::new(-1),
            tid: AtomicI32::new(0),
            address: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
            guard: AtomicUsize::new(0),
            local: AtomicUsize::new(0),
        }
    }

    fn wait(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while self.ready.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "native child did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

unsafe extern "C" fn probe_stack(arg: *mut c_void) -> *mut c_void {
    let probe = unsafe { &*arg.cast::<Probe>() };
    let local = [0x5au8; 128];
    probe
        .local
        .store(local.as_ptr() as usize, Ordering::Relaxed);
    probe.tid.store(syscall::sys_gettid(), Ordering::Relaxed);
    match unsafe { stack_attrs(pthread_self()) } {
        Ok(attrs) => {
            probe.address.store(attrs.address, Ordering::Relaxed);
            probe.size.store(attrs.size, Ordering::Relaxed);
            probe.guard.store(attrs.guard, Ordering::Relaxed);
            probe.result.store(0, Ordering::Relaxed);
        }
        Err(error) => probe.result.store(error, Ordering::Relaxed),
    }
    probe.ready.store(1, Ordering::Release);
    while probe.release.load(Ordering::Acquire) == 0 {
        syscall::sys_sched_yield();
    }
    std::hint::black_box(&local);
    0x51acusize as *mut c_void
}

unsafe fn run_joinable_probe(attr: *const libc::pthread_attr_t) -> StackAttrs {
    let probe = Probe::new();
    let mut thread = 0;
    assert_eq!(
        unsafe {
            pthread_create(
                &mut thread,
                attr,
                Some(probe_stack),
                (&probe as *const Probe).cast_mut().cast(),
            )
        },
        0
    );
    probe.wait();
    let parent = unsafe { stack_attrs(thread) };
    probe.release.store(1, Ordering::Release);
    let mut result = ptr::null_mut();
    assert_eq!(unsafe { pthread_join(thread, &mut result) }, 0);
    assert_eq!(result as usize, 0x51ac);
    assert_eq!(probe.result.load(Ordering::Acquire), 0);
    let parent = parent.unwrap();
    assert_eq!(parent.address, probe.address.load(Ordering::Acquire));
    assert_eq!(parent.size, probe.size.load(Ordering::Acquire));
    assert_eq!(parent.guard, probe.guard.load(Ordering::Acquire));
    assert_eq!(parent.detached, libc::PTHREAD_CREATE_JOINABLE);
    let local = probe.local.load(Ordering::Acquire);
    assert!(parent.address <= local && local + 128 <= parent.address + parent.size);
    parent
}

struct CallerStack {
    base: *mut c_void,
    total: usize,
    page: usize,
    writable: usize,
}

impl CallerStack {
    fn new() -> Self {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let writable = (512 * 1024 + page - 1) & !(page - 1);
        let total = writable + 2 * page;
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        unsafe {
            assert_eq!(libc::mprotect(base, page, libc::PROT_NONE), 0);
            assert_eq!(
                libc::mprotect(
                    (base as usize + page + writable) as *mut c_void,
                    page,
                    libc::PROT_NONE
                ),
                0
            );
        }
        Self {
            base,
            total,
            page,
            writable,
        }
    }

    fn assert_preserved(&self) {
        let mut residency = vec![0u8; self.total / self.page];
        assert_eq!(
            unsafe { libc::mincore(self.base, self.total, residency.as_mut_ptr()) },
            0
        );
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for address in [
            self.base as usize,
            self.base as usize + self.page + self.writable,
        ] {
            let permissions = maps.lines().find_map(|line| {
                let mut fields = line.split_whitespace();
                let (begin, end) = fields.next()?.split_once('-')?;
                let begin = usize::from_str_radix(begin, 16).ok()?;
                let end = usize::from_str_radix(end, 16).ok()?;
                (begin <= address && address < end).then(|| fields.next().unwrap())
            });
            assert_eq!(permissions, Some("---p"));
        }
    }
}

impl Drop for CallerStack {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.base, self.total) }, 0);
    }
}

#[test]
fn native_stack_borrowed_bounds_and_guards_are_truthful() {
    let _mode = NativeMode::enter();
    let stack = CallerStack::new();
    for (offset, size, guard) in [
        (0, 256 * 1024, 0),
        (3, 256 * 1024 + 17, stack.page + 1),
        (7, 256 * 1024 + 31, usize::MAX),
    ] {
        let address = stack.base as usize + stack.page + 32 + offset;
        unsafe {
            ((address - 1) as *mut u8).write(0x35);
            ((address + size) as *mut u8).write(0x79);
            let mut attr: libc::pthread_attr_t = std::mem::zeroed();
            assert_eq!(pthread_attr_init(&mut attr), 0);
            assert_eq!(
                pthread_attr_setstack(&mut attr, address as *mut c_void, size),
                0
            );
            assert_eq!(pthread_attr_setguardsize(&mut attr, guard), 0);
            let actual = run_joinable_probe(&attr);
            let mut requested_guard = 0;
            assert_eq!(pthread_attr_getguardsize(&attr, &mut requested_guard), 0);
            assert_eq!(pthread_attr_destroy(&mut attr), 0);
            stack.assert_preserved();
            assert_eq!(actual.address, address);
            assert_eq!(actual.size, size);
            assert_eq!(actual.guard, 0);
            assert_eq!(requested_guard, guard);
            assert_eq!(((address - 1) as *const u8).read(), 0x35);
            assert_eq!(((address + size) as *const u8).read(), 0x79);
        }
    }
}

#[test]
fn native_stack_owned_guards_and_default_size_match_actual_storage() {
    let _mode = NativeMode::enter();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        let mut default_size = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut default_size), 0);
        let actual = run_joinable_probe(ptr::null());
        assert_eq!(actual.size, default_size);
        for requested in [0, 1, page + 1] {
            assert_eq!(pthread_attr_setstacksize(&mut attr, 256 * 1024), 0);
            assert_eq!(pthread_attr_setguardsize(&mut attr, requested), 0);
            let actual = run_joinable_probe(&attr);
            assert_eq!(actual.size, 256 * 1024);
            assert_eq!(actual.guard, (requested + page - 1) & !(page - 1));
        }
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn native_stack_foreign_attributes_preserve_stack_ownership() {
    let _mode = NativeMode::enter();
    let stack = CallerStack::new();
    let address = stack.base as usize + stack.page + 32;
    unsafe {
        let mut foreign: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(libc::pthread_attr_init(&mut foreign), 0);
        assert_eq!(libc::pthread_attr_setstacksize(&mut foreign, 256 * 1024), 0);
        assert_eq!(
            libc::pthread_attr_setguardsize(&mut foreign, stack.page + 1),
            0
        );
        // GNU getstack returns a wrapped negative base when only size is set.
        // Such attributes must still request a libc-owned allocation.
        let allocated = run_joinable_probe(&foreign);
        assert_eq!(allocated.size, 256 * 1024);
        assert_eq!(allocated.guard, 2 * stack.page);
        assert_eq!(
            libc::pthread_attr_setstack(&mut foreign, address as *mut c_void, 256 * 1024 + 17),
            0
        );
        let borrowed = run_joinable_probe(&foreign);
        assert_eq!(borrowed.address, address);
        assert_eq!(borrowed.size, 256 * 1024 + 17);
        assert_eq!(borrowed.guard, 0);
        assert_eq!(libc::pthread_attr_destroy(&mut foreign), 0);
        stack.assert_preserved();
    }
}

#[test]
fn native_stack_borrowed_detached_child_leaves_reclamation_to_caller() {
    let _mode = NativeMode::enter();
    let stack = CallerStack::new();
    let address = stack.base as usize + stack.page;
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(
            pthread_attr_setstack(&mut attr, address as *mut c_void, 256 * 1024),
            0
        );
        assert_eq!(pthread_attr_setguardsize(&mut attr, stack.page + 1), 0);
        assert_eq!(
            pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED),
            0
        );
        let probe = Probe::new();
        let mut thread = 0;
        assert_eq!(
            pthread_create(
                &mut thread,
                &attr,
                Some(probe_stack),
                (&probe as *const Probe).cast_mut().cast()
            ),
            0
        );
        probe.wait();
        let actual = stack_attrs(thread);
        let tid = probe.tid.load(Ordering::Acquire);
        probe.release.store(1, Ordering::Release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while syscall::sys_tgkill(syscall::sys_getpid(), tid, 0).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "detached native thread did not exit"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
        assert_eq!(probe.result.load(Ordering::Acquire), 0);
        assert_eq!(
            actual.unwrap(),
            StackAttrs {
                address,
                size: 256 * 1024,
                guard: 0,
                detached: libc::PTHREAD_CREATE_DETACHED,
            }
        );
        stack.assert_preserved();
        (address as *mut u8).write(0xa7);
        assert_eq!((address as *const u8).read(), 0xa7);
    }
}

#[test]
fn native_stack_invalid_ranges_fail_before_publishing_a_thread() {
    let _mode = NativeMode::enter();
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        let address = usize::MAX - 16 * 1024 + 1;
        assert_eq!(
            pthread_attr_setstack(&mut attr, address as *mut c_void, 16 * 1024),
            0
        );
        let mut thread = 0x1234;
        assert_eq!(
            pthread_create(&mut thread, &attr, Some(probe_stack), ptr::null_mut()),
            libc::EINVAL
        );
        assert_eq!(thread, 0x1234);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_setguardsize(&mut attr, usize::MAX), 0);
        assert_eq!(
            pthread_create(&mut thread, &attr, Some(probe_stack), ptr::null_mut()),
            libc::ENOMEM
        );
        assert_eq!(thread, 0x1234);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn native_stack_legacy_address_setter_orders_use_caller_storage() {
    let _mode = NativeMode::enter();
    let stack = CallerStack::new();
    let address = stack.base as usize + stack.page + 35;
    let size = 256 * 1024 + 17;
    let top = address + size;
    let managed = StackAttrApi::managed();
    let host = StackAttrApi::host();
    for address_first in [false, true] {
        let mut attr = unsafe { std::mem::zeroed() };
        let mut oracle = unsafe { std::mem::zeroed() };
        for (api, value) in [(&managed, &mut attr), (&host, &mut oracle)] {
            unsafe {
                assert_eq!((api.init)(value), 0);
                if address_first {
                    assert_eq!((api.set_address)(value, top as *mut c_void), 0);
                    assert_eq!((api.set_size)(value, size), 0);
                } else {
                    assert_eq!((api.set_size)(value, size), 0);
                    assert_eq!((api.set_address)(value, top as *mut c_void), 0);
                }
            }
        }
        assert_eq!(managed.snapshot(&attr), host.snapshot(&oracle));
        assert_eq!(managed.snapshot(&attr), (address, size, top));
        unsafe {
            ((address - 1) as *mut u8).write(0x35);
            (top as *mut u8).write(0x79);
            let actual = run_joinable_probe(&attr);
            assert_eq!(
                (actual.address, actual.size, actual.guard),
                (address, size, 0)
            );
            assert_eq!(((address - 1) as *const u8).read(), 0x35);
            assert_eq!((top as *const u8).read(), 0x79);
            assert_eq!((managed.destroy)(&mut attr), 0);
            assert_eq!((host.destroy)(&mut oracle), 0);
        }
        stack.assert_preserved();
    }
}

#[test]
fn native_stack_mixed_setters_keep_the_high_endpoint() {
    let _mode = NativeMode::enter();
    let stack = CallerStack::new();
    let address = stack.base as usize + stack.page + 39;
    let initial_size = 256 * 1024 + 31;
    let resized = 128 * 1024 + 17;
    let top = address + initial_size;
    let managed = StackAttrApi::managed();
    let host = StackAttrApi::host();
    let mut attr = unsafe { std::mem::zeroed() };
    let mut oracle = unsafe { std::mem::zeroed() };
    for (api, value) in [(&managed, &mut attr), (&host, &mut oracle)] {
        unsafe {
            assert_eq!((api.init)(value), 0);
            assert_eq!(
                (api.set_stack)(value, address as *mut c_void, initial_size),
                0
            );
        }
        assert_eq!(api.snapshot(value), (address, initial_size, top));
        unsafe {
            assert_eq!((api.set_size)(value, resized), 0);
            assert_eq!((api.set_size)(value, 1), libc::EINVAL);
        }
    }
    assert_eq!(managed.snapshot(&attr), host.snapshot(&oracle));
    assert_eq!(managed.snapshot(&attr), (top - resized, resized, top));
    let actual = unsafe { run_joinable_probe(&attr) };
    assert_eq!(
        (actual.address, actual.size, actual.guard),
        (top - resized, resized, 0)
    );
    unsafe {
        assert_eq!((managed.destroy)(&mut attr), 0);
        assert_eq!((host.destroy)(&mut oracle), 0);
    }
    stack.assert_preserved();
}

#[test]
fn legacy_stack_attributes_preserve_zero_and_wrapped_intermediate_bases() {
    let managed = StackAttrApi::managed();
    let host = StackAttrApi::host();
    // These are attribute-only probes: the synthetic addresses are never used
    // to launch a thread. The final valid range must survive setter ordering.
    for top in [512 * 1024usize, 64 * 1024] {
        let mut attr = unsafe { std::mem::zeroed() };
        let mut oracle = unsafe { std::mem::zeroed() };
        for (api, value) in [(&managed, &mut attr), (&host, &mut oracle)] {
            unsafe {
                assert_eq!((api.init)(value), 0);
                assert_eq!((api.set_size)(value, 512 * 1024), 0);
                assert_eq!((api.set_address)(value, top as *mut c_void), 0);
            }
        }
        assert_eq!(managed.snapshot(&attr), host.snapshot(&oracle));
        for (api, value) in [(&managed, &mut attr), (&host, &mut oracle)] {
            unsafe { assert_eq!((api.set_size)(value, 16 * 1024), 0) };
        }
        assert_eq!(managed.snapshot(&attr), host.snapshot(&oracle));
        assert_eq!(managed.snapshot(&attr), (top - 16 * 1024, 16 * 1024, top));
        unsafe {
            assert_eq!((managed.destroy)(&mut attr), 0);
            assert_eq!((host.destroy)(&mut oracle), 0);
        }
    }
}
