//! Thread-local magazine cache for malloc.
//!
//! Each thread maintains a small cache of recently freed objects per size class,
//! reducing contention on the central allocator. This follows a "magazine"
//! design where batches of objects are moved between the thread cache and
//! the central freelist.

use super::size_class::{NUM_SIZE_CLASSES, SizeClassIndex, size_class_index};

/// Maximum number of cached objects per size class per thread.
pub const MAGAZINE_CAPACITY: usize = 64;

/// Per-size-class magazine (stack of free object offsets).
#[derive(Debug, Clone)]
pub struct Magazine {
    /// Stack of free object offsets.
    objects: Vec<usize>,
    /// Maximum capacity.
    capacity: usize,
}

impl Magazine {
    /// Creates a new empty magazine with the given capacity.
    fn new(capacity: usize) -> Self {
        Self {
            objects: Vec::new(),
            capacity,
        }
    }

    /// Attempts to pop a cached object from this magazine.
    fn pop(&mut self) -> Option<usize> {
        self.objects.pop()
    }

    /// Pushes an object into this magazine.
    ///
    /// Returns `true` if the object was cached, `false` if the magazine is full.
    fn push(&mut self, ptr: usize) -> bool {
        if self.objects.len() < self.capacity {
            self.objects.push(ptr);
            true
        } else {
            false
        }
    }

    /// Returns true if the magazine is full.
    fn is_full(&self) -> bool {
        self.objects.len() >= self.capacity
    }

    /// Drains all objects from the magazine, returning them.
    fn drain(&mut self) -> Vec<usize> {
        std::mem::take(&mut self.objects)
    }
}

/// Per-thread cache containing one magazine per size class.
pub struct ThreadCache {
    /// One magazine per size class bin.
    magazines: Vec<Magazine>,
    /// Total number of cached objects across all magazines.
    total_cached: usize,
}

impl ThreadCache {
    /// Creates a new empty thread cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn magazine(&self, index: SizeClassIndex) -> &Magazine {
        &self.magazines[index.get()]
    }

    fn magazine_mut(&mut self, index: SizeClassIndex) -> &mut Magazine {
        &mut self.magazines[index.get()]
    }

    /// Attempts to allocate from the thread cache for the given size class.
    ///
    /// Returns an object offset from the magazine, or `None` if the magazine
    /// is empty (caller should fall back to central allocator).
    pub fn alloc(&mut self, raw_size_class_index: usize) -> Option<usize> {
        let Ok(index) = size_class_index(raw_size_class_index, "ThreadCache::alloc") else {
            return None;
        };
        let result = self.magazine_mut(index).pop();
        if result.is_some() {
            self.total_cached -= 1;
        }
        result
    }

    /// Returns an object to the thread cache for the given size class.
    ///
    /// Returns `true` if the object was cached. Returns `false` if the
    /// magazine is full (caller should return to central allocator instead).
    pub fn dealloc(&mut self, raw_size_class_index: usize, ptr: usize) -> bool {
        let Ok(index) = size_class_index(raw_size_class_index, "ThreadCache::dealloc") else {
            return false;
        };
        let cached = self.magazine_mut(index).push(ptr);
        if cached {
            self.total_cached += 1;
        }
        cached
    }

    /// Returns the total number of cached objects across all magazines.
    pub fn total_cached(&self) -> usize {
        self.total_cached
    }

    /// Drains a specific magazine, returning all cached objects.
    pub fn drain_magazine(&mut self, raw_size_class_index: usize) -> Vec<usize> {
        let Ok(index) = size_class_index(raw_size_class_index, "ThreadCache::drain_magazine")
        else {
            return Vec::new();
        };
        let drained = self.magazine_mut(index).drain();
        self.total_cached -= drained.len();
        drained
    }

    /// Returns true if the magazine for the given size class is full.
    pub fn is_full(&self, raw_size_class_index: usize) -> bool {
        let Ok(index) = size_class_index(raw_size_class_index, "ThreadCache::is_full") else {
            return true;
        };
        self.magazine(index).is_full()
    }
}

impl Default for ThreadCache {
    fn default() -> Self {
        Self {
            magazines: (0..NUM_SIZE_CLASSES)
                .map(|_| Magazine::new(MAGAZINE_CAPACITY))
                .collect(),
            total_cached: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cache_empty() {
        let cache = ThreadCache::new();
        assert_eq!(cache.total_cached(), 0);
    }

    #[test]
    fn test_alloc_empty_returns_none() {
        let mut cache = ThreadCache::new();
        assert!(cache.alloc(0).is_none());
        assert!(cache.alloc(5).is_none());
    }

    #[test]
    fn test_dealloc_and_alloc() {
        let mut cache = ThreadCache::new();
        assert!(cache.dealloc(0, 0x1000));
        assert!(cache.dealloc(0, 0x2000));
        assert_eq!(cache.total_cached(), 2);

        // LIFO order
        assert_eq!(cache.alloc(0), Some(0x2000));
        assert_eq!(cache.alloc(0), Some(0x1000));
        assert!(cache.alloc(0).is_none());
        assert_eq!(cache.total_cached(), 0);
    }

    #[test]
    fn test_different_size_classes() {
        let mut cache = ThreadCache::new();
        assert!(cache.dealloc(0, 0x1000));
        assert!(cache.dealloc(5, 0x2000));

        assert_eq!(cache.alloc(0), Some(0x1000));
        assert!(cache.alloc(0).is_none());
        assert_eq!(cache.alloc(5), Some(0x2000));
        assert!(cache.alloc(5).is_none());
    }

    #[test]
    fn test_magazine_full() {
        let mut cache = ThreadCache::new();
        for i in 0..MAGAZINE_CAPACITY {
            assert!(cache.dealloc(0, i));
        }
        assert!(!cache.dealloc(0, 999)); // Should fail - full
        assert!(cache.is_full(0));
    }

    #[test]
    fn test_out_of_range() {
        let mut cache = ThreadCache::new();
        assert!(cache.alloc(NUM_SIZE_CLASSES).is_none());
        assert!(!cache.dealloc(NUM_SIZE_CLASSES, 0x1000));
    }

    #[test]
    fn test_drain_magazine() {
        let mut cache = ThreadCache::new();
        cache.dealloc(3, 0x1000);
        cache.dealloc(3, 0x2000);
        cache.dealloc(3, 0x3000);

        let drained = cache.drain_magazine(3);
        assert_eq!(drained.len(), 3);
        assert_eq!(cache.total_cached(), 0);
        assert!(cache.alloc(3).is_none());
    }

    #[test]
    fn test_drain_empty_magazine_is_noop() {
        let mut cache = ThreadCache::new();
        let drained = cache.drain_magazine(0);
        assert!(drained.is_empty());
        assert_eq!(cache.total_cached(), 0);
        assert!(cache.alloc(0).is_none());
    }

    #[test]
    fn test_total_cached_matches_magazine_population_under_trace() {
        fn lcg(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            *state
        }

        let mut cache = ThreadCache::new();
        let mut rng = 0x1234_5678_9ABC_DEF0u64;

        for _ in 0..5000 {
            let r = lcg(&mut rng);
            let class = (r as usize) % NUM_SIZE_CLASSES;

            match r % 3 {
                0 => {
                    let ptr = ((r >> 12) as usize) | 0x1000;
                    let _ = cache.dealloc(class, ptr);
                }
                1 => {
                    let _ = cache.alloc(class);
                }
                _ => {
                    let _ = cache.drain_magazine(class);
                }
            }

            let observed: usize = cache.magazines.iter().map(|m| m.objects.len()).sum();
            assert_eq!(cache.total_cached(), observed);
            assert!(cache.total_cached() <= NUM_SIZE_CLASSES * MAGAZINE_CAPACITY);
        }
    }
}
