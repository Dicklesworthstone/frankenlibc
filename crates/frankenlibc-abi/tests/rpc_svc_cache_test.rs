//! Execute the exact storage engine used by release RPC transports. ABI modules
//! are excluded from the library unit-test build, so this is an integration test.
#[path = "../src/rpc_svc_cache.rs"]
mod cache;
use cache::{CacheError, Peer, ReplyCache};

const A: Peer = Peer { address: 0x0100007f, port: 1000 };
const B: Peer = Peer { address: 0x0100007f, port: 1001 };

#[test]
fn replay_owns_request_and_reply_bytes() {
    let mut cache = ReplyCache::new(2, 32).unwrap();
    let mut request = b"request".to_vec();
    let mut reply = b"response".to_vec();
    assert!(cache.remember(A, 1, &request, &reply));
    request.fill(0); reply.fill(0);
    assert_eq!(cache.lookup(A, 1, b"request"), Some(b"response".as_slice()));
}
#[test]
fn peers_and_entire_requests_are_distinct() {
    let mut cache = ReplyCache::new(4, 32).unwrap();
    cache.remember(A, 1, b"xid-args-user1", b"first");
    assert_eq!(cache.lookup(B, 1, b"xid-args-user1"), None);
    assert_eq!(cache.lookup(A, 1, b"xid-args-user2"), None);
    assert_eq!(cache.lookup(A, 1, b"xid-newargs-user1"), None);
    assert_eq!(cache.lookup(Peer { address: 2, ..A }, 1, b"xid-args-user1"), None);
}
#[test]
fn service_generation_invalidates_cached_results() {
    let mut cache = ReplyCache::new(2, 8).unwrap();
    cache.remember(A, 9, b"call", b"old");
    assert_eq!(cache.lookup(A, 10, b"call"), None);
    cache.remember(A, 10, b"call", b"new");
    assert_eq!(cache.lookup(A, 10, b"call"), Some(b"new".as_slice()));
}
#[test]
fn fifo_eviction_is_not_changed_by_a_hit() {
    let mut cache = ReplyCache::new(2, 8).unwrap();
    cache.remember(A, 0, b"1", b"one");
    cache.remember(A, 0, b"2", b"two");
    assert!(cache.lookup(A, 0, b"1").is_some());
    cache.remember(A, 0, b"3", b"three");
    assert_eq!(cache.lookup(A, 0, b"1"), None);
    assert_eq!(cache.lookup(A, 0, b"2"), Some(b"two".as_slice()));
    assert_eq!(cache.lookup(A, 0, b"3"), Some(b"three".as_slice()));
}
#[test]
fn replacing_a_reply_preserves_other_entries() {
    let mut cache = ReplyCache::new(2, 8).unwrap();
    cache.remember(A, 0, b"1", b"one");
    cache.remember(A, 0, b"2", b"two");
    cache.remember(A, 0, b"1", b"new-one");
    assert_eq!(cache.lookup(A, 0, b"2"), Some(b"two".as_slice()));
    assert_eq!(cache.lookup(A, 0, b"1"), Some(b"new-one".as_slice()));
    cache.remember(A, 0, b"3", b"three");
    assert_eq!(cache.lookup(A, 0, b"1"), None);
}
#[test]
fn oversized_packets_do_not_consume_or_mutate_a_slot() {
    let mut cache = ReplyCache::new(1, 4).unwrap();
    cache.remember(A, 0, b"1234", b"5678");
    assert!(!cache.remember(A, 0, b"12345", b"0"));
    assert!(!cache.remember(A, 0, b"0", b"12345"));
    assert_eq!(cache.lookup(A, 0, b"12345"), None);
    assert_eq!(cache.lookup(A, 0, b"1234"), Some(b"5678".as_slice()));
}
#[test]
fn invalid_and_overflowing_allocations_are_rejected() {
    assert!(matches!(ReplyCache::new(0, 8), Err(CacheError::InvalidSize)));
    assert!(matches!(ReplyCache::new(1, 0), Err(CacheError::InvalidSize)));
    for (count, size) in [(usize::MAX, 8), (2, usize::MAX), (65536, 65536)] {
        assert!(matches!(ReplyCache::new(count, size), Err(CacheError::NoMemory)));
    }
}
#[test]
fn repeated_wraparound_returns_exact_latest_window() {
    let mut cache = ReplyCache::new(7, 8).unwrap();
    for n in 0u64..2048 {
        let key = n.to_ne_bytes();
        let value = (n ^ 0x0123456789abcdef).to_ne_bytes();
        assert!(cache.remember(A, 0, &key, &value));
        for live in n.saturating_sub(6)..=n {
            let expected = (live ^ 0x0123456789abcdef).to_ne_bytes();
            assert_eq!(cache.lookup(A, 0, &live.to_ne_bytes()), Some(expected.as_slice()));
        }
        if n >= 7 { assert!(cache.lookup(A, 0, &(n-7).to_ne_bytes()).is_none()); }
    }
}
