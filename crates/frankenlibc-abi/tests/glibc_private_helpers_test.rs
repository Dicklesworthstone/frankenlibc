#![cfg(target_os = "linux")]

//! glibc's GLIBC_PRIVATE allocation helpers, which glibc's own programs and
//! modules link against and which therefore bind to fl's exports under
//! preload: `__libc_scratch_buffer_*` (gencat, pldd, libnss_compat),
//! `__libc_dynarray_*` (getent), `__libc_alloc_buffer_*` and
//! `__open_catalog` (gencat). They used to be always-fail stubs, so
//! `getent initgroups` printed "Could not allocate group list" and gencat
//! could not update a catalog.
//!
//! Each case drives fl's implementation and host glibc's (looked up with
//! dlvsym(..., "GLIBC_PRIVATE")) through the same operations and compares
//! the observable state: return values, lengths, element counts, contents.

use std::ffi::{CString, c_char, c_int, c_void};

fn host<T: Copy>(name: &str) -> T {
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<usize>());
    let lib = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    assert!(!lib.is_null(), "libc.so.6 is loaded");
    let cname = CString::new(name).unwrap();
    let sym = unsafe { libc::dlvsym(lib, cname.as_ptr(), c"GLIBC_PRIVATE".as_ptr()) };
    assert!(!sym.is_null(), "host glibc exports {name}@GLIBC_PRIVATE");
    unsafe { std::mem::transmute_copy(&sym) }
}

#[repr(C)]
struct ScratchBuffer {
    data: *mut c_void,
    length: usize,
    space: Space,
}

#[repr(C, align(16))]
struct Space([u8; 1024]);

impl ScratchBuffer {
    fn new() -> Box<Self> {
        let mut b = Box::new(Self {
            data: std::ptr::null_mut(),
            length: 1024,
            space: Space([0; 1024]),
        });
        b.data = b.space.0.as_mut_ptr().cast();
        b
    }
    fn on_heap(&self) -> bool {
        self.data != self.space.0.as_ptr() as *mut c_void
    }
}

type GrowFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type SetArrayFn = unsafe extern "C" fn(*mut c_void, usize, usize) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);

struct Scratch {
    grow: GrowFn,
    grow_preserve: GrowFn,
    set_array_size: SetArrayFn,
    free: FreeFn,
}

fn scratch_impls() -> [Scratch; 2] {
    [
        Scratch {
            grow: frankenlibc_abi::unistd_abi::__libc_scratch_buffer_grow,
            grow_preserve: frankenlibc_abi::unistd_abi::__libc_scratch_buffer_grow_preserve,
            set_array_size: frankenlibc_abi::unistd_abi::__libc_scratch_buffer_set_array_size,
            free: frankenlibc_abi::malloc_abi::free,
        },
        Scratch {
            grow: host("__libc_scratch_buffer_grow"),
            grow_preserve: host("__libc_scratch_buffer_grow_preserve"),
            set_array_size: host("__libc_scratch_buffer_set_array_size"),
            free: libc::free,
        },
    ]
}

/// One scenario's observations for an implementation.
fn scratch_transcript(imp: &Scratch) -> Vec<String> {
    let mut log = Vec::new();
    let mut b = ScratchBuffer::new();
    let p = &mut *b as *mut ScratchBuffer as *mut c_void;
    unsafe {
        // grow discards; the buffer moves to the heap at twice the size.
        let ok = (imp.grow)(p);
        log.push(format!(
            "grow ok={ok} len={} heap={}",
            b.length,
            b.on_heap()
        ));
        // grow_preserve keeps the bytes.
        for i in 0..b.length {
            *b.data.cast::<u8>().add(i) = (i % 251) as u8;
        }
        let ok = (imp.grow_preserve)(p);
        let kept = (0..2048).all(|i| *b.data.cast::<u8>().add(i) == (i % 251) as u8);
        log.push(format!(
            "grow_preserve ok={ok} len={} kept={kept}",
            b.length
        ));
        // Fits already: nothing changes.
        let ok = (imp.set_array_size)(p, 100, 40);
        log.push(format!("set_array_size small ok={ok} len={}", b.length));
        let ok = (imp.set_array_size)(p, 1000, 10);
        log.push(format!("set_array_size grow ok={ok} len={}", b.length));
        // Overflow fails and leaves the inline buffer behind.
        let ok = (imp.set_array_size)(p, usize::MAX / 2, 3);
        log.push(format!(
            "set_array_size overflow ok={ok} len={} heap={}",
            b.length,
            b.on_heap()
        ));
        // grow_preserve from the inline space copies it out.
        b.space.0[..4].copy_from_slice(b"abcd");
        let ok = (imp.grow_preserve)(p);
        log.push(format!(
            "grow_preserve inline ok={ok} len={} head={:?}",
            b.length,
            std::slice::from_raw_parts(b.data.cast::<u8>(), 4)
        ));
        if b.on_heap() {
            (imp.free)(b.data);
        }
    }
    log
}

#[test]
fn scratch_buffer_matches_host_glibc() {
    let [fl, glibc] = scratch_impls();
    assert_eq!(scratch_transcript(&fl), scratch_transcript(&glibc));
}

#[repr(C)]
struct Dynarray {
    used: usize,
    allocated: usize,
    array: *mut c_void,
}

#[repr(C)]
struct Finalized {
    array: *mut c_void,
    length: usize,
}

type EnlargeFn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int;
type ResizeFn = unsafe extern "C" fn(*mut c_void, usize, *mut c_void, usize) -> c_int;
type FinalizeFn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *mut c_void) -> c_int;

struct Dyn {
    enlarge: EnlargeFn,
    resize: ResizeFn,
    resize_clear: ResizeFn,
    finalize: FinalizeFn,
    free: FreeFn,
}

fn dyn_impls() -> [Dyn; 2] {
    use frankenlibc_abi::unistd_abi as u;
    [
        Dyn {
            enlarge: u::__libc_dynarray_emplace_enlarge,
            resize: u::__libc_dynarray_resize,
            resize_clear: u::__libc_dynarray_resize_clear,
            finalize: u::__libc_dynarray_finalize,
            free: frankenlibc_abi::malloc_abi::free,
        },
        Dyn {
            enlarge: host("__libc_dynarray_emplace_enlarge"),
            resize: host("__libc_dynarray_resize"),
            resize_clear: host("__libc_dynarray_resize_clear"),
            finalize: host("__libc_dynarray_finalize"),
            free: libc::free,
        },
    ]
}

fn dyn_transcript(imp: &Dyn) -> Vec<String> {
    let mut log = Vec::new();
    // A u32 dynarray with a 4-element scratch area, as DYNARRAY_INITIAL_SIZE
    // sets it up.
    let mut scratch = [0u32; 4];
    let scratch_ptr = scratch.as_mut_ptr().cast::<c_void>();
    let mut list = Dynarray {
        used: 0,
        allocated: 4,
        array: scratch_ptr,
    };
    let l = &mut list as *mut Dynarray as *mut c_void;
    unsafe {
        for i in 0..4 {
            *scratch_ptr.cast::<u32>().add(i) = 10 + i as u32;
        }
        list.used = 4;
        let ok = (imp.enlarge)(l, scratch_ptr, 4);
        let moved = list.array != scratch_ptr;
        let kept: Vec<u32> = (0..4).map(|i| *list.array.cast::<u32>().add(i)).collect();
        log.push(format!(
            "enlarge ok={ok} allocated={} moved={moved} kept={kept:?}",
            list.allocated
        ));
        let ok = (imp.enlarge)(l, scratch_ptr, 4);
        log.push(format!(
            "enlarge again ok={ok} allocated={}",
            list.allocated
        ));
        let ok = (imp.resize)(l, 5, scratch_ptr, 4);
        log.push(format!(
            "resize within ok={ok} used={} allocated={}",
            list.used, list.allocated
        ));
        let ok = (imp.resize)(l, 40, scratch_ptr, 4);
        log.push(format!(
            "resize grow ok={ok} used={} allocated={}",
            list.used, list.allocated
        ));
        // Shrinking goes through plain resize: glibc's own resize_clear is
        // only ever called to grow (its dynarray skeleton shrinks inline) and
        // underflows its memset when asked to shrink.
        let ok = (imp.resize)(l, 2, scratch_ptr, 4);
        log.push(format!("resize shrink ok={ok} used={}", list.used));
        let ok = (imp.resize_clear)(l, 60, scratch_ptr, 4);
        let zeros = (2..60).all(|i| *list.array.cast::<u32>().add(i) == 0);
        log.push(format!(
            "resize_clear grow ok={ok} used={} allocated={} zeroed={zeros}",
            list.used, list.allocated
        ));
        let ok = (imp.resize)(l, usize::MAX / 2, scratch_ptr, 4);
        log.push(format!("resize overflow ok={ok} used={}", list.used));
        let mut out = Finalized {
            array: std::ptr::null_mut(),
            length: 0,
        };
        let ok = (imp.finalize)(l, scratch_ptr, 4, (&mut out as *mut Finalized).cast());
        let head: Vec<u32> = (0..2).map(|i| *out.array.cast::<u32>().add(i)).collect();
        log.push(format!(
            "finalize ok={ok} length={} head={head:?}",
            out.length
        ));
        (imp.free)(out.array);

        // An empty list finalizes to NULL/0 and frees its heap array.
        let mut empty = Dynarray {
            used: 0,
            allocated: 4,
            array: scratch_ptr,
        };
        let e = &mut empty as *mut Dynarray as *mut c_void;
        let _ = (imp.enlarge)(e, scratch_ptr, 4);
        let ok = (imp.finalize)(e, scratch_ptr, 4, (&mut out as *mut Finalized).cast());
        log.push(format!(
            "finalize empty ok={ok} null={} length={}",
            out.array.is_null(),
            out.length
        ));
        // A list in the error state (allocated == SIZE_MAX) does not finalize.
        let mut failed = Dynarray {
            used: 0,
            allocated: usize::MAX,
            array: std::ptr::null_mut(),
        };
        let ok = (imp.finalize)(
            (&mut failed as *mut Dynarray).cast(),
            scratch_ptr,
            4,
            (&mut out as *mut Finalized).cast(),
        );
        log.push(format!("finalize failed-list ok={ok}"));
    }
    log
}

#[test]
fn dynarray_matches_host_glibc() {
    let [fl, glibc] = dyn_impls();
    assert_eq!(dyn_transcript(&fl), dyn_transcript(&glibc));
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocBuffer {
    current: usize,
    end: usize,
}

type AllocateFn = unsafe extern "C" fn(usize, *mut *mut c_void) -> AllocBuffer;
type AllocArrayFn = unsafe extern "C" fn(*mut AllocBuffer, usize, usize, usize) -> *mut c_void;
type CopyBytesFn = unsafe extern "C" fn(AllocBuffer, *const c_void, usize) -> AllocBuffer;
type CopyStringFn = unsafe extern "C" fn(AllocBuffer, *const c_char) -> AllocBuffer;

#[test]
fn alloc_buffer_matches_host_glibc() {
    let fl: (AllocateFn, AllocArrayFn, CopyBytesFn, CopyStringFn, FreeFn) = unsafe {
        use frankenlibc_abi::unistd_abi as u;
        (
            std::mem::transmute::<*const (), AllocateFn>(
                u::__libc_alloc_buffer_allocate as *const (),
            ),
            std::mem::transmute::<*const (), AllocArrayFn>(
                u::__libc_alloc_buffer_alloc_array as *const (),
            ),
            std::mem::transmute::<*const (), CopyBytesFn>(
                u::__libc_alloc_buffer_copy_bytes as *const (),
            ),
            std::mem::transmute::<*const (), CopyStringFn>(
                u::__libc_alloc_buffer_copy_string as *const (),
            ),
            frankenlibc_abi::malloc_abi::free,
        )
    };
    let glibc: (AllocateFn, AllocArrayFn, CopyBytesFn, CopyStringFn, FreeFn) = (
        host("__libc_alloc_buffer_allocate"),
        host("__libc_alloc_buffer_alloc_array"),
        host("__libc_alloc_buffer_copy_bytes"),
        host("__libc_alloc_buffer_copy_string"),
        libc::free,
    );
    let run = |(allocate, alloc_array, copy_bytes, copy_string, free): (
        AllocateFn,
        AllocArrayFn,
        CopyBytesFn,
        CopyStringFn,
        FreeFn,
    )| unsafe {
        let mut log = Vec::new();
        let mut block: *mut c_void = std::ptr::null_mut();
        let mut buf = allocate(64, &mut block);
        let base = block as usize;
        log.push(format!(
            "allocate span={} at_block={}",
            buf.end - buf.current,
            buf.current == base
        ));
        let p = alloc_array(&mut buf, 1, 1, 3);
        log.push(format!("bytes at={}", p as usize - base));
        let p = alloc_array(&mut buf, 8, 8, 2);
        log.push(format!(
            "array at={} aligned={}",
            p as usize - base,
            (p as usize).is_multiple_of(8)
        ));
        buf = copy_string(buf, c"hello".as_ptr());
        buf = copy_bytes(buf, b"xyz".as_ptr().cast(), 3);
        log.push(format!("after copies used={}", buf.current - base));
        let text = std::slice::from_raw_parts(block.cast::<u8>().add(19), 9).to_vec();
        log.push(format!("copied={text:?}"));
        let p = alloc_array(&mut buf, 16, 8, 4);
        log.push(format!(
            "overflow null={} failed={}",
            p.is_null(),
            buf == AllocBuffer { current: 0, end: 0 }
        ));
        let after = copy_string(buf, c"z".as_ptr());
        log.push(format!(
            "copy after failure stays failed={}",
            after == AllocBuffer { current: 0, end: 0 }
        ));
        free(block);
        log
    };
    assert_eq!(run(fl), run(glibc));
}
