//! Exercise the production Bloom filter with real allocator observation and
//! rejection. Filter storage must remain optional even under allocator failure.

use frankenlibc_membrane::bloom::PointerBloomFilter;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::{Arc, Barrier};

const PAGE_BYTES: usize = 4096;
const DEFAULT_BITS: usize = 67_108_864;
const DIRECTORY_BYTES: usize = (DEFAULT_BITS / (PAGE_BYTES * 8)) * size_of::<usize>();

#[derive(Clone, Copy, Default)]
struct AllocationState {
    active: bool,
    reject: bool,
    attempts: usize,
    requested_bytes: usize,
    rejected: usize,
    deallocations: usize,
}

thread_local! {
    // Const, destructor-free TLS keeps the allocator hook allocation-free and
    // confines rejection to the test thread running the observed operation.
    static ALLOCATIONS: Cell<AllocationState> = const { Cell::new(AllocationState {
        active: false,
        reject: false,
        attempts: 0,
        requested_bytes: 0,
        rejected: 0,
        deallocations: 0,
    }) };
}

fn reject_allocation(size: usize) -> bool {
    ALLOCATIONS
        .try_with(|cell| {
            let mut state = cell.get();
            if !state.active {
                return false;
            }
            state.attempts += 1;
            state.requested_bytes += size;
            state.rejected += usize::from(state.reject);
            cell.set(state);
            state.reject
        })
        .unwrap_or(false)
}

struct ObservedAllocator;

// SAFETY: accepted requests retain their original System allocator arguments;
// rejected requests return null without modifying any existing allocation.
// The observation hooks only read and write destructor-free thread-local cells.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if reject_allocation(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if reject_allocation(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if reject_allocation(size) {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = ALLOCATIONS.try_with(|cell| {
            let mut state = cell.get();
            if state.active {
                state.deallocations += 1;
                cell.set(state);
            }
        });
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

struct ObservationGuard(PhantomData<*mut ()>);

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        ALLOCATIONS.with(|cell| cell.set(AllocationState::default()));
    }
}

fn observe_allocations<R>(reject: bool, operation: impl FnOnce() -> R) -> (R, AllocationState) {
    ALLOCATIONS.with(|cell| {
        cell.set(AllocationState {
            active: true,
            reject,
            ..AllocationState::default()
        });
    });
    let guard = ObservationGuard(PhantomData);
    let result = operation();
    let state = ALLOCATIONS.with(Cell::get);
    drop(guard);
    (result, state)
}

#[test]
fn default_capacity_commits_only_the_directory_and_touched_pages() {
    let (control, control_allocations) =
        observe_allocations(false, || std::hint::black_box(Box::new([0u8; 17])));
    assert_eq!(control_allocations.attempts, 1, "allocator control");
    assert_eq!(control_allocations.requested_bytes, 17);
    drop(control);

    let (filter, construction) = observe_allocations(false, PointerBloomFilter::new);
    assert_eq!(filter.expected_items(), 4_000_000);
    assert_eq!(filter.num_bits(), DEFAULT_BITS);
    assert_eq!(filter.num_hashes(), 10);
    assert_eq!(construction.attempts, 1);
    assert_eq!(construction.requested_bytes, DIRECTORY_BYTES);

    let (present, query) = observe_allocations(true, || filter.might_contain(0x1000));
    assert!(!present);
    assert_eq!(query.attempts, 0, "empty queries never allocate");

    let (_, first) = observe_allocations(false, || filter.insert(0x1000));
    assert_eq!(first.attempts, 1);
    assert_eq!(first.requested_bytes, PAGE_BYTES);
    let (present, repeated) = observe_allocations(true, || {
        filter.insert(0x1000);
        filter.might_contain(0x1000)
    });
    assert!(present);
    assert_eq!(
        repeated.attempts, 0,
        "warmed insertion and query reuse a page"
    );

    let (_, more) = observe_allocations(false, || {
        for i in 2..102 {
            filter.insert(i * 0x1000);
        }
    });
    assert!(more.attempts <= 100);
    assert_eq!(more.requested_bytes, more.attempts * PAGE_BYTES);
    assert!(
        construction.requested_bytes + first.requested_bytes + more.requested_bytes < 512 * 1024
    );
    for i in 1..102 {
        assert!(filter.might_contain(i * 0x1000));
    }
    assert_eq!(filter.insert_count(), 102);
}

#[test]
fn rejected_page_makes_all_queries_conservative_until_quiesced_clear() {
    let filter = PointerBloomFilter::new();
    let (_, failure) = observe_allocations(true, || filter.insert(0x1000));
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.rejected, 1);
    assert_eq!(failure.requested_bytes, PAGE_BYTES);
    assert_eq!(filter.insert_count(), 1);

    // This includes the missed insertion and unrelated, uninserted pointers.
    for i in 0..4096 {
        assert!(filter.might_contain(i * 0x1000));
    }
    let (_, conservative) = observe_allocations(true, || filter.insert(0x2000));
    assert_eq!(conservative.attempts, 0);
    assert_eq!(filter.insert_count(), 2);

    filter.clear();
    assert_eq!(filter.insert_count(), 0);
    assert!(!filter.might_contain(0x1000));
    assert!(!filter.might_contain(0x2000));
    let (_, recovery) = observe_allocations(false, || filter.insert(0x1000));
    assert_eq!(recovery.attempts, 1);
    assert_eq!(recovery.requested_bytes, PAGE_BYTES);
    assert!(filter.might_contain(0x1000));
    assert!((0..4096).any(|i| !filter.might_contain(i * 0x1000)));
}

#[test]
fn rejected_new_page_also_disables_negative_answers_in_existing_pages() {
    let filter = PointerBloomFilter::new();
    filter.insert(0);
    // These keys occupy separate 512-bit blocks within the same default page.
    // Check reuse through the allocator, then restore the first key alone.
    let (_, shared_page) = observe_allocations(true, || filter.insert(1752));
    assert_eq!(shared_page.attempts, 0);
    filter.clear();
    filter.insert(0);
    assert!(!filter.might_contain(1752));
    assert!(!filter.might_contain(0x1000));

    let (_, failure) = observe_allocations(true, || filter.insert(0x1000));
    assert_eq!(failure.rejected, 1);
    assert_eq!(failure.requested_bytes, PAGE_BYTES);
    assert!(filter.might_contain(0));
    assert!(
        filter.might_contain(1752),
        "unset bit in an already published page"
    );
    assert!(
        filter.might_contain(0x1000),
        "failed first touch in a different page"
    );

    filter.rebuild_from([0, 0x1000]);
    assert!(filter.might_contain(0));
    assert!(filter.might_contain(0x1000));
    assert!(!filter.might_contain(1752));
    assert_eq!(filter.insert_count(), 2);
}

#[test]
fn rejected_rebuild_stays_conservative_and_can_retry() {
    let filter = PointerBloomFilter::new();
    let truth = [0x1000, 0x4000, 0x8000, 0xc000];
    let (_, failure) = observe_allocations(true, || filter.rebuild_from(truth));
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.rejected, 1);
    assert_eq!(failure.requested_bytes, PAGE_BYTES);
    assert_eq!(filter.insert_count(), truth.len() as u64);
    for i in 0..4096 {
        assert!(filter.might_contain(i * 0x1000));
    }

    filter.rebuild_from(truth);
    assert_eq!(filter.insert_count(), truth.len() as u64);
    for ptr in truth {
        assert!(filter.might_contain(ptr));
    }
    assert!((0..4096).any(|i| !filter.might_contain(i * 0x1000)));

    // Rebuilding the same truth set retains every published page. Denying all
    // allocation now must neither abort nor degrade the filter to all-positive.
    let (_, reused) = observe_allocations(true, || filter.rebuild_from(truth));
    assert_eq!(reused.attempts, 0);
    for ptr in truth {
        assert!(filter.might_contain(ptr));
    }
    assert!((0..4096).any(|i| !filter.might_contain(i * 0x1000)));
}

#[test]
fn rejected_directory_remains_conservative_for_its_entire_lifetime() {
    // Reject every allocation, including any unexpected shrink/reallocation
    // during conversion to a boxed directory. Construction must still return.
    let (filter, failure) = observe_allocations(true, PointerBloomFilter::new);
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.rejected, 1);
    assert_eq!(failure.requested_bytes, DIRECTORY_BYTES);
    assert_eq!(filter.num_bits(), DEFAULT_BITS);
    assert_eq!(filter.expected_items(), 4_000_000);

    let (_, unavailable) = observe_allocations(true, || {
        filter.insert(0x1000);
        filter.clear();
        filter.rebuild_from([0x2000, 0x3000]);
    });
    assert_eq!(unavailable.attempts, 0);
    assert_eq!(filter.insert_count(), 2);
    for i in 0..4096 {
        assert!(filter.might_contain(i * 0x1000));
    }

    let recovered = PointerBloomFilter::new();
    assert!(!recovered.might_contain(0x1000));
    recovered.insert(0x1000);
    assert!(recovered.might_contain(0x1000));
}

#[test]
fn simultaneous_first_touch_retains_one_page_and_every_inserted_pointer() {
    const WORKERS: usize = 8;
    const PER_WORKER: usize = 64;
    let filter = Arc::new(PointerBloomFilter::with_capacity(1000, 0.01));
    assert!(filter.num_bits() <= PAGE_BYTES * 8);
    let start = Arc::new(Barrier::new(WORKERS));
    let workers: Vec<_> = (0..WORKERS)
        .map(|worker| {
            let (filter, start) = (Arc::clone(&filter), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                observe_allocations(false, || {
                    let mut every_insert_visible = true;
                    for i in 0..PER_WORKER {
                        let ptr = (worker * PER_WORKER + i + 1) * 0x1000;
                        filter.insert(ptr);
                        every_insert_visible &= filter.might_contain(ptr);
                    }
                    every_insert_visible
                })
            })
        })
        .collect();

    let mut allocated_pages = 0;
    let mut discarded_pages = 0;
    for worker in workers {
        let (every_insert_visible, allocations) = worker.join().expect("inserting thread");
        assert!(every_insert_visible);
        assert_eq!(
            allocations.requested_bytes,
            allocations.attempts * PAGE_BYTES
        );
        allocated_pages += allocations.attempts;
        discarded_pages += allocations.deallocations;
    }
    assert!((1..=WORKERS).contains(&allocated_pages));
    assert_eq!(
        allocated_pages - discarded_pages,
        1,
        "only the winning page is retained"
    );
    assert_eq!(filter.insert_count(), (WORKERS * PER_WORKER) as u64);
    for i in 1..=WORKERS * PER_WORKER {
        assert!(filter.might_contain(i * 0x1000));
    }
}
