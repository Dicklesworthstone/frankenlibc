//! Bounded FIFO duplicate-reply storage for a UDP service transport.
//!
//! Enabling a cache reserves its entire storage. Lookup and insertion neither
//! allocate nor retain borrowed packet/response buffers. A key contains the
//! peer address/port and the complete request, including credentials; reusing
//! an XID for different arguments must not disclose or replay another result.
//! Service-registration generations invalidate old replies without mutation
//! of a transport whose operation gate is held by another thread.

use std::mem::size_of;

// A cache is an application-requested optimization, not an unbounded remotely
// driven allocator. Refuse configurations above this per-transport byte budget
// with ENOMEM at the ABI boundary, before reserving or touching their storage.
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Peer {
    pub address: u32,
    pub port: u16,
}

#[derive(Clone, Copy, Default)]
struct Slot {
    peer: Peer,
    generation: u64,
    request_len: usize,
    reply_len: usize,
    occupied: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CacheError {
    InvalidSize,
    NoMemory,
}

pub(super) struct ReplyCache {
    slots: Vec<Slot>,
    bytes: Vec<u8>,
    packet_size: usize,
    next: usize,
}

impl ReplyCache {
    pub fn new(count: usize, packet_size: usize) -> Result<Self, CacheError> {
        if count == 0 || packet_size == 0 {
            return Err(CacheError::InvalidSize);
        }
        let stride = packet_size.checked_mul(2).ok_or(CacheError::NoMemory)?;
        let footprint = stride.checked_add(size_of::<Slot>())
            .and_then(|n| n.checked_mul(count)).ok_or(CacheError::NoMemory)?;
        if footprint > MAX_CACHE_BYTES {
            return Err(CacheError::NoMemory);
        }
        let mut slots = Vec::new();
        slots.try_reserve_exact(count).map_err(|_| CacheError::NoMemory)?;
        slots.resize(count, Slot::default());
        let mut bytes = Vec::new();
        let length = stride * count; // bounded above by the checked footprint
        bytes.try_reserve_exact(length).map_err(|_| CacheError::NoMemory)?;
        bytes.resize(length, 0);
        Ok(Self { slots, bytes, packet_size, next: 0 })
    }

    fn index(&self, peer: Peer, generation: u64, request: &[u8]) -> Option<usize> {
        if request.len() > self.packet_size {
            return None;
        }
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            if !slot.occupied || slot.peer != peer || slot.generation != generation
                || slot.request_len != request.len() {
                return None;
            }
            let start = index * self.packet_size * 2;
            (self.bytes[start..start + request.len()] == *request).then_some(index)
        })
    }

    pub fn lookup(&self, peer: Peer, generation: u64, request: &[u8]) -> Option<&[u8]> {
        let index = self.index(peer, generation, request)?;
        let start = (index * 2 + 1) * self.packet_size;
        Some(&self.bytes[start..start + self.slots[index].reply_len])
    }

    /// Store only a fully encoded response. Oversized data leaves the cache
    /// unchanged. Replacing a reply to the same request consumes no FIFO slot.
    pub fn remember(&mut self, peer: Peer, generation: u64, request: &[u8], reply: &[u8]) -> bool {
        if request.len() > self.packet_size || reply.len() > self.packet_size {
            return false;
        }
        let index = self.index(peer, generation, request).unwrap_or_else(|| {
            let index = self.next;
            self.next = (self.next + 1) % self.slots.len();
            index
        });
        let start = index * self.packet_size * 2;
        self.bytes[start..start + request.len()].copy_from_slice(request);
        let start = start + self.packet_size;
        self.bytes[start..start + reply.len()].copy_from_slice(reply);
        self.slots[index] = Slot {
            peer, generation, request_len: request.len(), reply_len: reply.len(), occupied: true,
        };
        true
    }
}
