//! Signal-safe unwind metadata lookup for the native link map.
//!
//! Readers cannot take the loader locks: a signal may interrupt their owner.
//! Publish complete address records in permanent chunks and reuse retired
//! slots. With the loader's serialized writers, storage follows the peak
//! number of live/staged objects, not the number of dlopen calls. Query never
//! allocates, uses TLS, dereferences the PC, or waits for a writer to finish.

use std::alloc::{Layout, alloc, dealloc};
use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

const CHUNK_SLOTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) link_map: usize,
    pub(super) eh_frame: usize,
}

/// ELF64 GNU layout on x86-64 and AArch64. Neither has EH_DBASE/EH_COUNT.
/// Newer GNU layouts use a reserved word for SFrame; zero flags leave that
/// extension inactive. The caller supplies aligned, complete struct storage.
#[repr(C)]
struct FindObject {
    flags: u64,
    map_start: *mut c_void,
    map_end: *mut c_void,
    link_map: *mut c_void,
    eh_frame: *mut c_void,
    reserved: [u64; 7],
}

impl Record {
    unsafe fn store(self, output: *mut FindObject) {
        // SAFETY: query admits aligned output and the caller supplies its
        // complete ABI size. Scalar volatile stores cannot become an
        // interposed memcpy/memset call, including from a signal handler.
        unsafe {
            (&raw mut (*output).flags).write_volatile(0);
            (&raw mut (*output).map_start).write_volatile(self.start as *mut c_void);
            (&raw mut (*output).map_end).write_volatile(self.end as *mut c_void);
            (&raw mut (*output).link_map).write_volatile(self.link_map as *mut c_void);
            (&raw mut (*output).eh_frame).write_volatile(self.eh_frame as *mut c_void);
            let reserved = (&raw mut (*output).reserved).cast::<u64>();
            for index in 0..7 {
                reserved.add(index).write_volatile(0);
            }
        }
    }
}

#[derive(Debug)]
struct Slot {
    // Reservation is private to writers. Generation zero hides a staged or
    // retired record; a published generation is its never-reused native ID.
    owner: AtomicUsize,
    generation: AtomicUsize,
    start: AtomicUsize,
    end: AtomicUsize,
    link_map: AtomicUsize,
    eh_frame: AtomicUsize,
}

impl Slot {
    const fn new() -> Self {
        Self {
            owner: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
            link_map: AtomicUsize::new(0),
            eh_frame: AtomicUsize::new(0),
        }
    }

    fn reserve(&self, id: usize, record: Record) -> bool {
        if self
            .owner
            .compare_exchange(0, id, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        // Retirement clears generation before releasing owner. Every address
        // word is atomic, including while a reader races with slot reuse.
        self.start.store(record.start, Ordering::SeqCst);
        self.end.store(record.end, Ordering::SeqCst);
        self.link_map.store(record.link_map, Ordering::SeqCst);
        self.eh_frame.store(record.eh_frame, Ordering::SeqCst);
        true
    }

    fn snapshot(&self, address: usize) -> Option<Record> {
        let generation = self.generation.load(Ordering::SeqCst);
        if generation == 0 {
            return None;
        }
        let record = Record {
            start: self.start.load(Ordering::SeqCst),
            end: self.end.load(Ordering::SeqCst),
            link_map: self.link_map.load(Ordering::SeqCst),
            eh_frame: self.eh_frame.load(Ordering::SeqCst),
        };
        // All six operations share a sequentially consistent order with
        // retirement, replacement stores and publication. Seeing any new word
        // therefore entails a changed final generation. Native IDs never
        // repeat, so reload cannot produce ABA. Acquire loads around relaxed
        // payload words alone would not establish this property.
        (generation == self.generation.load(Ordering::SeqCst)
            && record.start <= address
            && address < record.end)
            .then_some(record)
    }

    fn retire(&self) {
        self.generation.store(0, Ordering::SeqCst);
        self.owner.store(0, Ordering::Release);
    }
}

struct Chunk {
    // Immutable after publication. Chunks survive for the process lifetime,
    // so signal readers never need a reclamation/hazard-pointer lock.
    next: *mut Chunk,
    slots: [Slot; CHUNK_SLOTS],
}

struct Index {
    head: AtomicPtr<Chunk>,
}

impl Index {
    const fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn reserve(&self, id: usize, record: Record) -> Option<&Slot> {
        if id == 0 || record.start >= record.end || record.link_map == 0 {
            return None;
        }
        loop {
            let head = self.head.load(Ordering::Acquire);
            let mut cursor = head;
            while !cursor.is_null() {
                // SAFETY: acquire publication exposes a fully initialized,
                // permanently allocated chunk with an immutable next link.
                let chunk = unsafe { &*cursor };
                for slot in &chunk.slots {
                    if slot.reserve(id, record) {
                        return Some(slot);
                    }
                }
                cursor = chunk.next;
            }
            let layout = Layout::new::<Chunk>();
            // SAFETY: the exact nonzero layout is used for initialization and
            // deallocation if this still-private allocation loses a race.
            let allocation = unsafe { alloc(layout) }.cast::<Chunk>();
            if allocation.is_null() {
                return None;
            }
            unsafe {
                allocation.write(Chunk {
                    next: head,
                    slots: [const { Slot::new() }; CHUNK_SLOTS],
                });
            }
            if self
                .head
                .compare_exchange(head, allocation, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // SAFETY: failed publication left this chunk private. No
                // reader can hold it, and its exact allocation is still live.
                unsafe {
                    std::ptr::drop_in_place(allocation);
                    dealloc(allocation.cast(), layout);
                }
            }
            // Successful capacity is permanent and reusable. A staged slot
            // occupies capacity too, so rollback cannot alias another load.
        }
    }

    fn find(&self, address: usize) -> Option<Record> {
        // Snapshot the head once: concurrent growth cannot make this reader
        // chase an ever-growing chain. Every next link is immutable.
        let mut cursor = self.head.load(Ordering::Acquire);
        while !cursor.is_null() {
            // SAFETY: chunks and links remain live and immutable after
            // release publication, including across signal reentry and fork.
            let chunk = unsafe { &*cursor };
            for slot in &chunk.slots {
                if let Some(record) = slot.snapshot(address) {
                    return Some(record);
                }
            }
            cursor = chunk.next;
        }
        None
    }
}

static INDEX: Index = Index::new();

/// Loader Metadata owns this reservation. Publish only after the complete
/// transaction succeeds; drop before the link map or image is destroyed.
/// Writers hold OPERATIONS, and `id` comes from the never-reused native IDs.
#[derive(Debug)]
pub(super) struct Registration {
    slot: &'static Slot,
    id: usize,
}

impl Registration {
    pub(super) fn new(id: usize, record: Record) -> Option<Self> {
        Some(Self {
            slot: INDEX.reserve(id, record)?,
            id,
        })
    }

    pub(super) fn publish(&self) {
        self.slot.generation.store(self.id, Ordering::SeqCst);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.slot.retire();
    }
}

/// Query native metadata without entering either loader, allocator, or TLS.
/// Not-found leaves output untouched. The caller, as with GNU, must retain
/// the object while dereferencing returned link-map/unwind pointers.
///
/// # Safety
/// A non-null result must point to complete writable GNU struct storage.
pub(crate) unsafe fn query(address: *mut c_void, result: *mut c_void) -> bool {
    if result.is_null() || !(result as usize).is_multiple_of(std::mem::align_of::<FindObject>()) {
        return false;
    }
    let Some(record) = INDEX.find(address as usize) else {
        return false;
    };
    // SAFETY: the aligned output has the caller-provided complete ABI size.
    // Allocator-bound lookups cannot be used on an asynchronous signal path.
    unsafe { record.store(result.cast()) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};

    fn record(value: usize) -> Record {
        Record {
            start: value,
            end: value + 16,
            link_map: value + 32,
            eh_frame: value + 48,
        }
    }

    #[test]
    fn pending_and_retired_slots_are_invisible_and_reusable() {
        let index = Index::new();
        let first = index.reserve(1, record(256)).unwrap();
        assert_eq!(index.find(256), None);
        first.generation.store(1, Ordering::SeqCst);
        assert_eq!(index.find(256), Some(record(256)));
        assert_eq!(index.find(271), Some(record(256)));
        assert_eq!(index.find(255), None);
        assert_eq!(index.find(272), None);
        first.retire();
        assert_eq!(index.find(256), None);
        let second = index.reserve(2, record(1024)).unwrap();
        assert!(std::ptr::eq(first, second));
        assert_eq!(index.find(1024), None);
        second.generation.store(2, Ordering::SeqCst);
        assert_eq!(index.find(1024), Some(record(1024)));
        assert_eq!(index.find(256), None);
        second.retire();
    }

    #[test]
    fn unpublished_writer_does_not_block_a_reader() {
        let index = Index::new();
        let staged = index.reserve(1, record(256)).unwrap();
        for _ in 0..100 {
            assert_eq!(index.find(256), None);
        }
        let live = index.reserve(2, record(512)).unwrap();
        live.generation.store(2, Ordering::SeqCst);
        assert_eq!(index.find(512), Some(record(512)));
        staged.retire();
        live.retire();
    }

    #[test]
    fn chunks_grow_only_when_existing_slots_are_reserved() {
        let index = Index::new();
        let slots = (1..=CHUNK_SLOTS + 1)
            .map(|id| index.reserve(id, record(id * 64)).unwrap())
            .collect::<Vec<_>>();
        let head = index.head.load(Ordering::Acquire);
        for slot in slots {
            slot.retire();
        }
        for id in 100..1100 {
            index.reserve(id, record(id * 64)).unwrap().retire();
        }
        assert_eq!(index.head.load(Ordering::Acquire), head);
        // SAFETY: this private index has two permanently allocated chunks.
        unsafe {
            assert!(!(*head).next.is_null());
            assert!((*(*head).next).next.is_null());
        }
    }

    #[test]
    fn concurrent_reuse_never_returns_mixed_address_words() {
        let slot = Arc::new(Slot::new());
        let running = Arc::new(AtomicBool::new(true));
        let ready = Arc::new(Barrier::new(2));
        assert!(slot.reserve(
            1,
            Record {
                start: 0,
                end: 8,
                link_map: 9,
                eh_frame: 10
            }
        ));
        slot.generation.store(1, Ordering::SeqCst);
        let reader_slot = Arc::clone(&slot);
        let reader_running = Arc::clone(&running);
        let reader_ready = Arc::clone(&ready);
        let reader = std::thread::spawn(move || {
            assert_eq!(reader_slot.snapshot(1).unwrap().eh_frame, 10);
            reader_ready.wait();
            while reader_running.load(Ordering::Acquire) {
                if let Some(record) = reader_slot.snapshot(1) {
                    assert_eq!(record.start, 0);
                    assert_eq!(record.end + 1, record.link_map);
                    assert_eq!(record.end + 2, record.eh_frame);
                }
            }
        });
        ready.wait();
        slot.retire();
        for id in 2..100_000 {
            let value = id * 8;
            assert!(slot.reserve(
                id,
                Record {
                    start: 0,
                    end: value,
                    link_map: value + 1,
                    eh_frame: value + 2
                }
            ));
            slot.generation.store(id, Ordering::SeqCst);
            if id % 64 == 0 {
                std::thread::yield_now();
            }
            slot.retire();
        }
        running.store(false, Ordering::Release);
        reader.join().unwrap();
    }

    #[test]
    fn abi_output_has_exact_size_zero_extension_and_canaries() {
        #[repr(C)]
        struct Guarded {
            before: u64,
            output: FindObject,
            after: u64,
        }
        let mut guarded = std::mem::MaybeUninit::<Guarded>::uninit();
        // SAFETY: all-0xa5 is valid for these integers/raw pointers; the guard
        // allocation covers the exact initialized byte count.
        unsafe { guarded.as_mut_ptr().write_bytes(0xa5, 1) };
        let mut guarded = unsafe { guarded.assume_init() };
        let value = Record {
            eh_frame: 0,
            ..record(256)
        };
        unsafe { value.store(&raw mut guarded.output) };
        assert_eq!(std::mem::size_of::<FindObject>(), 96);
        assert_eq!(std::mem::offset_of!(FindObject, eh_frame), 32);
        assert_eq!(guarded.before, 0xa5a5a5a5a5a5a5a5);
        assert_eq!(guarded.after, 0xa5a5a5a5a5a5a5a5);
        assert_eq!(guarded.output.flags, 0);
        assert_eq!(guarded.output.map_start as usize, 256);
        assert_eq!(guarded.output.map_end as usize, 272);
        assert_eq!(guarded.output.link_map as usize, 288);
        assert!(guarded.output.eh_frame.is_null());
        assert_eq!(guarded.output.reserved, [0; 7]);
    }
}
