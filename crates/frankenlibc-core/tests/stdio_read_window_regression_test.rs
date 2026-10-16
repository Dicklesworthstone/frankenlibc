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

fn memory_input(bytes: &[u8]) -> StdioStream {
    StdioStream::new_mem_fixed(
        bytes.to_vec(),
        bytes.len(),
        OpenFlags {
            readable: true,
            ..Default::default()
        },
    )
}

#[test]
fn memory_delimited_reads_set_eof_only_after_a_failed_read() {
    use frankenlibc_core::stdio::ReadUntil;
    for bytes in [b"".as_slice(), b"tail", b"a\0b", b"last\n"] {
        let mut stream = memory_input(bytes);
        let mut output = Vec::new();
        let result = stream.read_until_delim(b'\n', &mut output);
        assert_eq!(output, bytes);
        assert_eq!(stream.offset(), bytes.len() as i64);
        assert!(!stream.is_error());
        if bytes.ends_with(b"\n") {
            assert_eq!(result, ReadUntil::Found);
            assert!(
                !stream.is_eof(),
                "a delimiter at the end does not probe EOF"
            );
            output.clear();
            assert_eq!(stream.read_until_delim(b'\n', &mut output), ReadUntil::Eof);
            assert!(output.is_empty());
        } else {
            assert_eq!(result, ReadUntil::Eof);
        }
        assert!(stream.is_eof());
        stream.clear_err();
        assert!(!stream.is_eof());
        output.clear();
        assert_eq!(stream.read_until_delim(b'\n', &mut output), ReadUntil::Eof);
        assert!(stream.is_eof() && output.is_empty());
    }
}

#[test]
fn memory_bounded_reads_distinguish_exact_fill_from_eof() {
    use frankenlibc_core::stdio::ReadUntil;
    for length in 0..9 {
        for capacity in 0..12 {
            let bytes = vec![b'x'; length];
            let mut stream = memory_input(&bytes);
            let mut output = vec![0xa5; capacity + 2];
            let (count, result) = stream.read_into_slice(b'\n', &mut output[1..1 + capacity]);
            assert_eq!(count, length.min(capacity));
            assert!(output[1..1 + count].iter().all(|b| *b == b'x'));
            assert_eq!(output[0], 0xa5);
            assert!(output[1 + count..].iter().all(|b| *b == 0xa5));
            assert_eq!(stream.offset(), count as i64);
            assert_eq!(stream.is_eof(), capacity > length, "{length}/{capacity}");
            assert_eq!(
                result,
                if capacity > length {
                    ReadUntil::Eof
                } else {
                    ReadUntil::NeedRefill
                }
            );
            assert!(!stream.is_error());
        }
    }
}

#[test]
fn memory_delimiter_wins_over_capacity_and_end_of_backing() {
    use frankenlibc_core::stdio::ReadUntil;
    for bytes in [b"a\n".as_slice(), b"a\nrest"] {
        for capacity in [2, 3, 12] {
            let mut stream = memory_input(bytes);
            let mut output = vec![0xa5; capacity];
            assert_eq!(
                stream.read_into_slice(b'\n', &mut output),
                (2, ReadUntil::Found)
            );
            assert_eq!(&output[..2], b"a\n");
            assert!(output[2..].iter().all(|b| *b == 0xa5));
            assert!(!stream.is_eof());
        }
    }
}

#[test]
fn memory_eof_recovers_through_pushback_and_seek_for_both_readers() {
    use frankenlibc_core::stdio::ReadUntil;
    for bounded in [false, true] {
        let mut stream = memory_input(b"abc");
        let mut output = Vec::new();
        assert_eq!(stream.read_until_delim(b'\n', &mut output), ReadUntil::Eof);
        assert!(stream.is_eof());
        assert!(stream.ungetc(b'\n'));
        assert!(!stream.is_eof());
        if bounded {
            let mut output = [0; 2];
            assert_eq!(
                stream.read_into_slice(b'\n', &mut output),
                (1, ReadUntil::Found)
            );
            assert_eq!(output[0], b'\n');
        } else {
            output.clear();
            assert_eq!(
                stream.read_until_delim(b'\n', &mut output),
                ReadUntil::Found
            );
            assert_eq!(output, b"\n");
        }
        assert!(!stream.is_eof());
        output.clear();
        assert_eq!(stream.read_until_delim(b'\n', &mut output), ReadUntil::Eof);
        assert!(stream.is_eof());
        assert_eq!(stream.mem_seek(0, 0), 0);
        assert!(!stream.is_eof());
        assert_eq!(stream.mem_read(3), b"abc");
        assert!(!stream.is_eof());
        assert!(stream.mem_read(1).is_empty());
        assert!(stream.is_eof());
    }
}

#[test]
fn delimited_read_error_and_descriptor_refill_are_not_eof_observations() {
    use frankenlibc_core::stdio::ReadUntil;
    let mut output = Vec::new();
    let mut stream = StdioStream::new_mem_fixed(
        vec![1],
        1,
        OpenFlags {
            writable: true,
            ..Default::default()
        },
    );
    assert_eq!(stream.read_until_delim(b'\n', &mut output), ReadUntil::Eof);
    assert!(stream.is_error());
    assert!(!stream.is_eof());
    let mut stream = StdioStream::new(
        8,
        OpenFlags {
            readable: true,
            ..Default::default()
        },
    );
    assert_eq!(stream.fill_read_buffer(b"abc"), 3);
    assert_eq!(
        stream.read_until_delim(b'\n', &mut output),
        ReadUntil::NeedRefill
    );
    assert_eq!(output, b"abc");
    assert!(!stream.is_eof());
}
