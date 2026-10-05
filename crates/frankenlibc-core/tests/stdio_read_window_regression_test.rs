//! Regression coverage for the read-window implementation already on main.
//! These tests use read_window/consume_window rather than the superseded
//! prepare_abi_read_window API from the earlier, uncommitted patch bundle.

use frankenlibc_core::stdio::{BufMode, OpenFlags, StdioStream};

fn input() -> StdioStream {
    let mut stream = StdioStream::with_mode(
        8,
        OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        },
        BufMode::Full,
    );
    assert_eq!(stream.fill_read_buffer(b"0123456789\n"), 11);
    assert_eq!(stream.buffered_read(1), b"0");
    stream
}

#[test]
fn inline_and_ordinary_reads_share_one_cursor() {
    let mut stream = input();
    assert_eq!(stream.read_window(), Some(b"123456789\n".as_slice()));
    assert_eq!(stream.offset(), 1);
    stream.consume_window(3);
    assert_eq!(stream.offset(), 4);
    assert_eq!(stream.buffered_read(2), b"45");
    assert_eq!(stream.offset(), 6);
    assert_eq!(stream.read_window(), Some(b"6789\n".as_slice()));
    stream.consume_window(5);
    assert!(stream.read_window().is_none());
    assert_eq!(stream.offset(), 11);
    assert!(!stream.is_eof());
    assert!(!stream.is_error());
}

#[test]
fn empty_and_oversized_consumption_cannot_advance_beyond_buffered_input() {
    let mut stream = input();
    stream.consume_window(0);
    assert_eq!(stream.offset(), 1);
    assert_eq!(stream.readable_buffered(), 10);
    // consume_window deliberately clamps; pointer validation belongs to the ABI.
    stream.consume_window(usize::MAX);
    assert_eq!(stream.offset(), 11);
    assert_eq!(stream.readable_buffered(), 0);
    stream.consume_window(usize::MAX);
    assert_eq!(stream.offset(), 11);
    assert!(stream.buffered_read(1).is_empty());
    assert!(!stream.is_eof());
}

#[test]
fn repeated_window_inspection_never_consumes_input() {
    let mut stream = input();
    let start = stream.read_window().unwrap().as_ptr();
    for _ in 0..32 {
        assert_eq!(stream.read_window(), Some(b"123456789\n".as_slice()));
        assert_eq!(stream.read_window().unwrap().as_ptr(), start);
        assert_eq!(stream.offset(), 1);
    }
    stream.consume_window(1);
    assert_eq!(stream.read_window(), Some(b"23456789\n".as_slice()));
    assert_eq!(stream.offset(), 2);
}

#[test]
fn nested_ungetc_keeps_bytes_visible_in_lifo_order() {
    let mut stream = input();
    stream.consume_window(2);
    assert_eq!(stream.offset(), 3);
    let before = stream.readable_buffered();
    assert!(stream.ungetc(b'Z'));
    assert_eq!(stream.read_window(), Some(b"Z3456789\n".as_slice()));
    assert_eq!(stream.readable_buffered(), before + 1);
    assert!(stream.ungetc(b'Y'));
    assert_eq!(stream.read_window(), Some(b"YZ3456789\n".as_slice()));
    assert_eq!(stream.readable_buffered(), before + 2);
    assert_eq!(stream.offset(), 1);
    stream.consume_window(1);
    assert_eq!(stream.buffered_read(2), b"Z3");
    assert_eq!(stream.offset(), 4);
}

#[test]
fn queued_pushback_precedes_the_main_window_without_losing_bytes() {
    let mut stream = input();
    stream.pushback_read_bytes(b"abcdefgh");
    assert!(stream.read_window().is_none());
    assert_eq!(stream.buffered_read(5), b"abcde");
    stream.pushback_read_bytes(b"WXYZ");
    assert!(stream.read_window().is_none());
    assert_eq!(stream.readable_buffered(), 17);
    assert_eq!(stream.buffered_read(7), b"WXYZfgh");
    assert_eq!(stream.read_window(), Some(b"123456789\n".as_slice()));
    assert_eq!(stream.buffered_read(2), b"12");
    assert_eq!(stream.offset(), 15);
}

#[test]
fn seek_preparation_discards_pushback_and_refill_exposes_only_new_bytes() {
    let mut stream = input();
    stream.consume_window(2);
    assert!(stream.ungetc(b'Z'));
    stream.pushback_read_bytes(b"queued");
    assert!(stream.prepare_seek().is_empty());
    stream.set_offset(100);
    assert!(stream.read_window().is_none());
    assert_eq!(stream.readable_buffered(), 0);
    assert_eq!(stream.fill_read_buffer(b"new"), 3);
    assert_eq!(stream.read_window(), Some(b"new".as_slice()));
    stream.consume_window(2);
    assert_eq!(stream.buffered_read(1), b"w");
    assert_eq!(stream.offset(), 103);
}

#[test]
fn pending_output_and_memory_backing_do_not_publish_a_read_window() {
    let mut stream = input();
    stream.consume_window(2);
    assert!(stream.prepare_seek().is_empty());
    assert!(stream.fast_putc(b'x'));
    assert!(stream.read_window().is_none());
    assert_eq!(stream.pending_flush(), b"x");
    let mut memory = StdioStream::new_mem_fixed(
        b"abc".to_vec(),
        3,
        OpenFlags {
            readable: true,
            ..Default::default()
        },
    );
    assert!(memory.read_window().is_none());
    assert_eq!(memory.mem_read(2), b"ab");
    assert!(memory.read_window().is_none());
}

#[test]
fn ungetc_after_buffer_exhaustion_clears_eof_and_restores_one_byte() {
    let mut stream = input();
    stream.consume_window(10);
    stream.set_eof();
    assert!(stream.ungetc(b'Q'));
    assert!(!stream.is_eof());
    assert_eq!(stream.read_window(), Some(b"Q".as_slice()));
    assert_eq!(stream.offset(), 10);
    stream.consume_window(1);
    assert!(stream.read_window().is_none());
    assert_eq!(stream.offset(), 11);
    assert!(!stream.is_eof());
}
