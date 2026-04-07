//! Memory allocation.
//!
//! Implements malloc family functions with a multi-tier allocator design:
//! - Small allocations (<=32KB): size-class based slab allocation with thread caches
//! - Large allocations (>32KB): tracked via the large allocator

pub mod allocator;
mod elimination;
pub mod large;
pub mod size_class;
pub mod thread_cache;

pub use allocator::{AllocatorLogLevel, AllocatorLogRecord, MallocState};
pub use elimination::{
    DEFAULT_ELIMINATION_SLOTS, EliminationArray, EliminationExchangeMeta, EliminationOp,
    EliminationOutcome, EliminationSlotStats, EliminationStats, OfferOutcome, TakeOutcome,
};
pub use large::{LargeAllocation, LargeAllocator};
pub use size_class::SizeClass;
pub use thread_cache::ThreadCache;
