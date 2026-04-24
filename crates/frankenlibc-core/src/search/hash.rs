//! Linear-probing hash table backing the POSIX `<search.h>`
//! `hcreate`/`hsearch`/`hdestroy` family.
//!
//! Generic over key/value types with caller-supplied hash + equality
//! closures so the abi layer can keep its raw-pointer key storage
//! while delegating the algorithm here.
//!
//! The slot layout is `#[repr(C)]` and the first two fields are
//! `key` and `value`, so when the abi instantiates with key/value
//! types whose memory layout matches POSIX `ENTRY`, a slot pointer
//! cast to `*mut Entry` is well-defined per the C common-prefix
//! rule.

/// One slot in the table. `#[repr(C)]` so abi-side downcasts to
/// POSIX `ENTRY` are valid for matching K/V layouts.
#[repr(C)]
#[derive(Clone)]
pub struct LinearSlot<K, V> {
    pub key: K,
    pub value: V,
    pub occupied: bool,
}

impl<K: Default, V: Default> LinearSlot<K, V> {
    fn empty() -> Self {
        Self {
            key: K::default(),
            value: V::default(),
            occupied: false,
        }
    }
}

/// Linear-probing open-addressed hash table.
pub struct LinearProbeTable<K, V> {
    slots: Vec<LinearSlot<K, V>>,
    capacity: usize,
    len: usize,
}

impl<K: Default + Clone, V: Default + Clone> LinearProbeTable<K, V> {
    /// Pre-allocate `nel` slots. POSIX `hcreate(nel)` requests at
    /// least `nel` capacity; this implementation uses exactly
    /// `max(1, nel)` and never resizes (matches glibc).
    pub fn new(nel: usize) -> Self {
        let capacity = nel.max(1);
        let slots = (0..capacity).map(|_| LinearSlot::empty()).collect();
        Self {
            slots,
            capacity,
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow the slot at `idx` (in-bounds; intended for callers
    /// who got `idx` from `find`/`enter`).
    pub fn slot_at(&self, idx: usize) -> Option<&LinearSlot<K, V>> {
        self.slots.get(idx)
    }

    /// Mutable borrow of the slot at `idx`.
    pub fn slot_mut_at(&mut self, idx: usize) -> Option<&mut LinearSlot<K, V>> {
        self.slots.get_mut(idx)
    }

    /// Raw pointer to the slot at `idx`. Stable for the lifetime of
    /// `self`. Returns `None` if `idx` is out of range.
    pub fn slot_address(&self, idx: usize) -> Option<*const LinearSlot<K, V>> {
        self.slots.get(idx).map(|s| s as *const _)
    }

    /// Search for `key`. Returns `Some(idx)` if found, `None` otherwise.
    pub fn search<H: Fn(&K) -> u64, E: Fn(&K, &K) -> bool>(
        &self,
        key: &K,
        hash: H,
        eq: E,
    ) -> Option<usize> {
        let h = (hash(key) as usize) % self.capacity;
        for i in 0..self.capacity {
            let idx = (h + i) % self.capacity;
            let slot = &self.slots[idx];
            if !slot.occupied {
                return None;
            }
            if eq(&slot.key, key) {
                return Some(idx);
            }
        }
        None
    }

    /// Find existing or insert into the first empty slot encountered.
    /// Returns `Some((idx, was_new))` or `None` when the table is full
    /// and `key` is not already present (matches glibc hsearch(ENTER)).
    pub fn enter<H: Fn(&K) -> u64, E: Fn(&K, &K) -> bool>(
        &mut self,
        key: K,
        value: V,
        hash: H,
        eq: E,
    ) -> Option<(usize, bool)> {
        let h = (hash(&key) as usize) % self.capacity;
        for i in 0..self.capacity {
            let idx = (h + i) % self.capacity;
            let slot = &mut self.slots[idx];
            if !slot.occupied {
                slot.key = key;
                slot.value = value;
                slot.occupied = true;
                self.len += 1;
                return Some((idx, true));
            }
            if eq(&slot.key, &key) {
                return Some((idx, false));
            }
        }
        None
    }
}

/// djb2 hash for null-terminated C strings, exposed because every
/// hsearch user wants the same one.
///
/// Caller passes a function that walks the C string byte-by-byte;
/// no unsafe needed in core since the string-walk happens in the
/// caller's closure.
pub fn djb2_seed() -> u64 {
    5381
}

/// Combine `seed` with byte `c` per the djb2 mixing step.
pub fn djb2_step(seed: u64, c: u8) -> u64 {
    seed.wrapping_mul(33).wrapping_add(c as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(k: &i64) -> u64 {
        // Trivial mixing — exercises the hash-callback API.
        let mut s = djb2_seed();
        for &b in k.to_le_bytes().iter() {
            s = djb2_step(s, b);
        }
        s
    }

    fn eq(a: &i64, b: &i64) -> bool {
        a == b
    }

    #[test]
    fn empty_search_returns_none() {
        let t: LinearProbeTable<i64, u32> = LinearProbeTable::new(8);
        assert!(t.is_empty());
        assert_eq!(t.capacity(), 8);
        assert!(t.search(&42, h, eq).is_none());
    }

    #[test]
    fn enter_then_search() {
        let mut t: LinearProbeTable<i64, u32> = LinearProbeTable::new(16);
        let (idx, new) = t.enter(7, 100, h, eq).unwrap();
        assert!(new);
        assert_eq!(t.len(), 1);
        let found = t.search(&7, h, eq).unwrap();
        assert_eq!(found, idx);
        assert_eq!(t.slot_at(found).unwrap().value, 100);
    }

    #[test]
    fn enter_existing_returns_was_new_false_and_keeps_value() {
        let mut t: LinearProbeTable<i64, u32> = LinearProbeTable::new(16);
        let (idx_a, new_a) = t.enter(7, 100, h, eq).unwrap();
        assert!(new_a);
        let (idx_b, new_b) = t.enter(7, 999, h, eq).unwrap();
        assert!(!new_b);
        assert_eq!(idx_a, idx_b);
        // glibc hsearch(ENTER) ignores new value for existing keys.
        assert_eq!(t.slot_at(idx_a).unwrap().value, 100);
    }

    #[test]
    fn enter_returns_none_when_full() {
        let mut t: LinearProbeTable<i64, u32> = LinearProbeTable::new(2);
        assert!(t.enter(1, 10, h, eq).is_some());
        assert!(t.enter(2, 20, h, eq).is_some());
        assert!(t.enter(3, 30, h, eq).is_none());
    }

    #[test]
    fn slot_addresses_are_stable() {
        let mut t: LinearProbeTable<i64, u32> = LinearProbeTable::new(8);
        let (idx, _) = t.enter(7, 100, h, eq).unwrap();
        let p1 = t.slot_address(idx).unwrap();
        // Subsequent operations don't reallocate (Vec is pre-sized).
        let _ = t.enter(11, 200, h, eq);
        let _ = t.search(&7, h, eq);
        let p2 = t.slot_address(idx).unwrap();
        assert_eq!(p1, p2, "slot pointers must stay stable");
    }
}
