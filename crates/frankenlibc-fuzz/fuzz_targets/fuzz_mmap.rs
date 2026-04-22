#![no_main]
//! Stateful fuzz target for FrankenLibC's virtual-memory surface:
//!
//!   mmap, munmap, mprotect, msync, madvise, mremap
//!
//! These are the classic memory-safety CVE surface: every kernel
//! mapping bug maps to a UAF, OOB, or W^X bypass here. The target
//! keeps a small arena of live mappings with their (addr, len, prot)
//! triples so later ops can operate on mappings this iteration
//! created — including stale mappings after munmap, to exercise the
//! use-after-unmap contract the membrane must refuse.
//!
//! Oracles:
//! 1. Return-code / pointer contract: mmap returns MAP_FAILED or a
//!    page-aligned non-null pointer; the others return 0 or -1.
//! 2. Lifecycle: once a range is unmapped, further mprotect/msync/
//!    madvise/munmap/mremap on that exact range must fail (return -1).
//! 3. Guard sentinel: every successful anonymous mapping has the
//!    first + last byte of its range written with 0xFD (while
//!    PROT_WRITE is in the mapping's prot flags), then on teardown
//!    we check the bytes still contain our sentinel or the mapping
//!    has been removed — detects off-by-one munmap / mremap that
//!    would corrupt our stamp.
//!
//! Safety:
//! - Every mmap uses MAP_PRIVATE | MAP_ANONYMOUS with fd=-1, so we
//!   never touch the filesystem, never exceed the per-process vma
//!   cap (4 mappings / iteration hard bound), and never need a
//!   backing file fd. Length is bounded to 4 KiB-16 KiB so an
//!   iteration never exhausts VM or vma slots on the worker.
//! - `prot` is picked from a safe set that never includes PROT_EXEC
//!   (we're a fuzz harness, not a JIT — we don't want RWX in the
//!   fuzz binary's address space) but the FUZZER is allowed to
//!   request PROT_EXEC to exercise the membrane's sanitizer path;
//!   our impl either refuses it or clamps it.
//! - Global MMAP_LOCK serializes iterations so two libFuzzer
//!   threads never race on the live-mapping table.
//!
//! Bead: (to be filed)

use std::ffi::{c_int, c_void};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::mmap_abi::{madvise, mmap, mprotect, mremap, msync, munmap};
use libfuzzer_sys::fuzz_target;

const PAGE_SIZE: usize = 4096;
const MAX_LEN: usize = 16 * PAGE_SIZE;
const MAX_MAPPINGS: usize = 4;
const MAX_OPS: usize = 16;
const GUARD_BYTE: u8 = 0xFD;
const MAP_FAILED: *mut c_void = !0_usize as *mut c_void;

#[derive(Debug, Arbitrary)]
enum Op {
    Map { len_pages: u8, prot_sel: u8 },
    Unmap { slot: u8 },
    Protect { slot: u8, prot_sel: u8 },
    Sync { slot: u8, flags_sel: u8 },
    Advise { slot: u8, advice_sel: u8 },
    Remap { slot: u8, new_len_pages: u8, flags_sel: u8 },
    /// Exercise the use-after-unmap path by unmapping a slot and
    /// forcibly keeping it in the live table as Stale so subsequent
    /// ops read it.
    MarkStaleInPlace { slot: u8 },
}

#[derive(Debug, Arbitrary)]
struct MmapFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MapState {
    Live,
    Stale,
}

#[derive(Clone, Copy)]
struct Mapping {
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    state: MapState,
}

// The fuzz target is single-threaded per iteration under libFuzzer,
// but we keep a Mutex-guarded table to make the invariant checker
// robust to any future parallel fuzz driver.
static LOCK: Mutex<()> = Mutex::new(());

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: single-writer, set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_prot(sel: u8) -> c_int {
    // We deliberately include PROT_EXEC as one of the selectable prot
    // values — the ABI's hardened mode is expected to refuse or clamp
    // it rather than actually mapping W+X pages. Our own writes to
    // the mapping only use the PROT_WRITE-bearing forms; we never
    // dereference PROT_EXEC pages.
    match sel % 6 {
        0 => libc::PROT_NONE,
        1 => libc::PROT_READ,
        2 => libc::PROT_READ | libc::PROT_WRITE,
        3 => libc::PROT_WRITE,
        4 => libc::PROT_EXEC, // hardened path should refuse/clamp
        _ => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    }
}

fn pick_sync_flags(sel: u8) -> c_int {
    match sel % 4 {
        0 => libc::MS_SYNC,
        1 => libc::MS_ASYNC,
        2 => libc::MS_INVALIDATE,
        _ => libc::MS_SYNC | libc::MS_INVALIDATE,
    }
}

fn pick_advise(sel: u8) -> c_int {
    const ADVISES: &[c_int] = &[
        libc::MADV_NORMAL,
        libc::MADV_RANDOM,
        libc::MADV_SEQUENTIAL,
        libc::MADV_WILLNEED,
        libc::MADV_DONTNEED,
        libc::MADV_FREE,
        libc::MADV_REMOVE,
    ];
    ADVISES[(sel as usize) % ADVISES.len()]
}

fn pick_remap_flags(sel: u8) -> c_int {
    match sel % 3 {
        0 => libc::MREMAP_MAYMOVE,
        1 => 0, // no-move, may fail if VMA can't extend in place
        _ => libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
    }
}

fn pick_len_pages(n: u8) -> usize {
    ((n as usize) % (MAX_LEN / PAGE_SIZE) + 1) * PAGE_SIZE
}

fn pick_slot(table: &mut [Mapping], slot: u8) -> Option<(usize, Mapping)> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some((idx, table[idx]))
}

fn write_guards(m: &Mapping) {
    // Stamp the guard bytes only when the mapping is writable;
    // PROT_NONE/PROT_READ/PROT_EXEC mappings can't be written to.
    if m.prot & libc::PROT_WRITE == 0 {
        return;
    }
    if m.addr.is_null() || m.addr == MAP_FAILED {
        return;
    }
    // SAFETY: the mapping's prot permits writes, and we only write
    // the two end bytes of the mapping's range which we own.
    unsafe {
        *(m.addr as *mut u8) = GUARD_BYTE;
        *(m.addr.add(m.len - 1) as *mut u8) = GUARD_BYTE;
    }
}

fn check_guards(m: &Mapping) {
    if m.state != MapState::Live {
        return;
    }
    if m.prot & libc::PROT_WRITE == 0 {
        return;
    }
    // SAFETY: Live mapping with PROT_WRITE-era prot (it may have been
    // mprotected since the stamp, so skip if prot lost PROT_WRITE).
    unsafe {
        let head = *(m.addr as *const u8);
        let tail = *(m.addr.add(m.len - 1) as *const u8);
        assert_eq!(
            head, GUARD_BYTE,
            "guard head corrupted at {:p} len={}",
            m.addr, m.len
        );
        assert_eq!(
            tail, GUARD_BYTE,
            "guard tail corrupted at {:p}+{}",
            m.addr,
            m.len - 1
        );
    }
}

fn apply_op(op: &Op, table: &mut Vec<Mapping>) {
    match op {
        Op::Map { len_pages, prot_sel } => {
            if table.len() >= MAX_MAPPINGS {
                return;
            }
            let len = pick_len_pages(*len_pages);
            let prot = pick_prot(*prot_sel);
            let addr = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    len,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if addr == MAP_FAILED || addr.is_null() {
                return;
            }
            // Alignment invariant: mmap must return a page-aligned ptr.
            assert_eq!(
                (addr as usize) & (PAGE_SIZE - 1),
                0,
                "mmap returned misaligned pointer: {:p}",
                addr
            );
            let m = Mapping {
                addr,
                len,
                prot,
                state: MapState::Live,
            };
            write_guards(&m);
            table.push(m);
        }
        Op::Unmap { slot } => {
            let Some((idx, m)) = pick_slot(table, *slot) else {
                return;
            };
            if m.state == MapState::Stale {
                // Use-after-unmap: must return -1.
                let rc = unsafe { munmap(m.addr, m.len) };
                assert_eq!(
                    rc, -1,
                    "munmap on stale mapping {:p}+{} must fail",
                    m.addr, m.len
                );
                return;
            }
            let rc = unsafe { munmap(m.addr, m.len) };
            assert!(rc == 0 || rc == -1, "munmap rc out of contract: {rc}");
            if rc == 0 {
                // Clear from live table entirely so we don't chase a
                // dangling ptr in future check_guards.
                table.remove(idx);
            }
        }
        Op::Protect { slot, prot_sel } => {
            let Some((idx, mut m)) = pick_slot(table, *slot) else {
                return;
            };
            let prot = pick_prot(*prot_sel);
            let rc = unsafe { mprotect(m.addr, m.len, prot) };
            if m.state == MapState::Stale {
                assert_eq!(rc, -1, "mprotect on stale mapping must fail");
                return;
            }
            assert!(rc == 0 || rc == -1, "mprotect rc out of contract: {rc}");
            if rc == 0 {
                m.prot = prot;
                table[idx] = m;
            }
        }
        Op::Sync { slot, flags_sel } => {
            let Some((_, m)) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { msync(m.addr, m.len, pick_sync_flags(*flags_sel)) };
            if m.state == MapState::Stale {
                assert_eq!(rc, -1, "msync on stale mapping must fail");
                return;
            }
            assert!(rc == 0 || rc == -1, "msync rc out of contract: {rc}");
        }
        Op::Advise { slot, advice_sel } => {
            let Some((_, m)) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { madvise(m.addr, m.len, pick_advise(*advice_sel)) };
            if m.state == MapState::Stale {
                assert_eq!(rc, -1, "madvise on stale mapping must fail");
                return;
            }
            assert!(rc == 0 || rc == -1, "madvise rc out of contract: {rc}");
        }
        Op::Remap {
            slot,
            new_len_pages,
            flags_sel,
        } => {
            let Some((idx, m)) = pick_slot(table, *slot) else {
                return;
            };
            if m.state == MapState::Stale {
                // Remapping a stale mapping must fail.
                let new_len = pick_len_pages(*new_len_pages);
                let new_addr = unsafe {
                    mremap(
                        m.addr,
                        m.len,
                        new_len,
                        pick_remap_flags(*flags_sel),
                        std::ptr::null_mut(),
                    )
                };
                assert_eq!(
                    new_addr, MAP_FAILED,
                    "mremap on stale mapping must fail with MAP_FAILED"
                );
                return;
            }
            let new_len = pick_len_pages(*new_len_pages);
            let flags = pick_remap_flags(*flags_sel) & !libc::MREMAP_FIXED; // keep things safe
            let new_addr =
                unsafe { mremap(m.addr, m.len, new_len, flags, std::ptr::null_mut()) };
            if new_addr == MAP_FAILED {
                return;
            }
            assert_eq!(
                (new_addr as usize) & (PAGE_SIZE - 1),
                0,
                "mremap returned misaligned pointer"
            );
            // Update the slot with the new address/length; guards need
            // re-stamping because the kernel may have moved the page.
            let new_m = Mapping {
                addr: new_addr,
                len: new_len,
                prot: m.prot,
                state: MapState::Live,
            };
            write_guards(&new_m);
            table[idx] = new_m;
        }
        Op::MarkStaleInPlace { slot } => {
            let Some((idx, mut m)) = pick_slot(table, *slot) else {
                return;
            };
            if m.state == MapState::Stale {
                return;
            }
            // Call munmap legitimately, then flip to Stale so later
            // ops exercise the use-after-unmap path against exactly
            // this address/length.
            let rc = unsafe { munmap(m.addr, m.len) };
            if rc == 0 {
                m.state = MapState::Stale;
                table[idx] = m;
            }
        }
    }
}

fn cleanup(table: &mut Vec<Mapping>) {
    for m in std::mem::take(table) {
        if m.state == MapState::Live {
            check_guards(&m);
            unsafe {
                munmap(m.addr, m.len);
            }
        }
    }
}

fuzz_target!(|input: MmapFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<Mapping> = Vec::with_capacity(MAX_MAPPINGS);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    // Final sweep: check guards on every live mapping before teardown.
    for m in &table {
        check_guards(m);
    }
    cleanup(&mut table);
});
