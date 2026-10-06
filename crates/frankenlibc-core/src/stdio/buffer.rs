//! Buffered I/O engine.
//!
//! Clean-room implementation of POSIX stdio buffering semantics.
//! Three modes: fully-buffered (_IOFBF), line-buffered (_IOLBF),
//! and unbuffered (_IONBF).
//!
//! Reference: POSIX.1-2024 setvbuf, ISO C11 7.21.3
//!
//! Design: the buffer is a bounded ring with explicit read/write cursors.
//! Monotonic state tracking prevents illegal mode transitions after I/O
//! has occurred (POSIX: setvbuf must be called before any I/O).

use std::borrow::Cow;

/// Default buffer size (POSIX BUFSIZ).
pub const BUFSIZ: usize = 8192;

/// Buffering mode constants matching POSIX `_IOFBF`, `_IOLBF`, `_IONBF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufMode {
    /// Fully buffered: flush when buffer is full.
    Full,
    /// Line buffered: flush on newline or buffer full.
    Line,
    /// Unbuffered: no buffering, immediate I/O.
    None,
}

/// POSIX constant values for setvbuf mode argument.
pub const IOFBF: i32 = 0;
pub const IOLBF: i32 = 1;
pub const IONBF: i32 = 2;

impl BufMode {
    /// Convert from POSIX integer constant.
    pub fn from_posix(mode: i32) -> Option<BufMode> {
        match mode {
            IOFBF => Some(BufMode::Full),
            IOLBF => Some(BufMode::Line),
            IONBF => Some(BufMode::None),
            _ => Option::None,
        }
    }
}

/// Stream buffer state for a single direction (read or write).
///
/// Invariants:
/// - `read_pos <= read_filled <= capacity`
/// - `write_len <= capacity`
/// - `data.len() == 0 || data.len() == capacity`
/// - non-empty readable/writable state implies materialized `data`
#[derive(Debug)]
pub struct StreamBuffer {
    data: Vec<u8>,
    /// Logical buffer capacity reported to callers.
    capacity: usize,
    /// Current read cursor position.
    read_pos: usize,
    /// Number of valid bytes available for read buffering.
    read_filled: usize,
    /// Number of valid bytes staged for write flushing.
    write_len: usize,
    /// Buffering mode.
    mode: BufMode,
    /// Whether any I/O has occurred (disables setvbuf changes per POSIX).
    io_started: bool,
}

impl StreamBuffer {
    /// Create a new buffer with the given mode and capacity.
    pub fn new(mode: BufMode, capacity: usize) -> Self {
        let cap = if matches!(mode, BufMode::None) {
            0
        } else {
            capacity.max(1)
        };
        Self {
            data: Vec::new(),
            capacity: cap,
            read_pos: 0,
            read_filled: 0,
            write_len: 0,
            mode,
            io_started: false,
        }
    }

    /// Create a fully-buffered buffer with default BUFSIZ.
    pub fn default_full() -> Self {
        Self::new(BufMode::Full, BUFSIZ)
    }

    /// Create a line-buffered buffer with default BUFSIZ.
    pub fn default_line() -> Self {
        Self::new(BufMode::Line, BUFSIZ)
    }

    /// Create an unbuffered "buffer" (zero-size).
    pub fn unbuffered() -> Self {
        Self::new(BufMode::None, 0)
    }

    /// Current buffering mode.
    pub fn mode(&self) -> BufMode {
        self.mode
    }

    /// Buffer capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Change buffering mode and optionally resize.
    ///
    /// Returns `false` if I/O has already occurred (POSIX disallows this).
    pub fn set_mode(&mut self, mode: BufMode, size: usize) -> bool {
        if self.io_started {
            return false;
        }
        self.mode = mode;
        let cap = if matches!(mode, BufMode::None) {
            0
        } else {
            size.max(1)
        };
        self.capacity = cap;
        self.data.clear();
        self.read_pos = 0;
        self.read_filled = 0;
        self.write_len = 0;
        true
    }

    /// `setvbuf(f, NULL, _IOFBF|_IOLBF, ..)` on a stream already in use: glibc
    /// only flips the mode, keeping the buffer and whatever it holds, so do
    /// the same (an unbuffered stream gains `size` bytes of storage, allocated
    /// by the next buffered operation).
    pub fn switch_mode_in_place(&mut self, mode: BufMode, size: usize) {
        if matches!(mode, BufMode::None) {
            return;
        }
        if self.capacity == 0 {
            self.capacity = size.max(1);
        }
        self.mode = mode;
    }

    /// [`set_mode`](Self::set_mode) for a stream already in use, after the
    /// caller synced it (glibc's `_IO_SETBUF`): staged output must have been
    /// written, and unread input still buffered is discarded, as glibc's
    /// `_IO_setb` does when the descriptor could not seek back over it.
    /// Returns false if output is still staged.
    pub fn rebuild_after_sync(&mut self, mode: BufMode, size: usize) -> bool {
        if self.write_len != 0 {
            return false;
        }
        let started = self.io_started;
        self.io_started = false;
        let ok = self.set_mode(mode, size);
        self.io_started = started;
        ok
    }

    // -----------------------------------------------------------------------
    // Write-side operations
    // -----------------------------------------------------------------------

    /// Buffer a write. Returns the bytes that should be flushed immediately
    /// (may be empty if buffering absorbs them) and the bytes actually buffered.
    ///
    /// Caller must flush the returned flush slice to the underlying fd.
    pub fn write<'a>(&mut self, data: &'a [u8]) -> WriteResult<'a> {
        self.io_started = true;

        match self.mode {
            BufMode::None => {
                // Unbuffered: all bytes must be written immediately.
                WriteResult {
                    buffered: 0,
                    flush_needed: true,
                    flush_data: Cow::Borrowed(data),
                    flushed_from_buffer: 0,
                }
            }
            BufMode::Full => self.write_full(data),
            BufMode::Line => self.write_line(data),
        }
    }

    /// Fast single-byte append for the common Full-buffered, has-space case.
    ///
    /// Returns `true` iff the byte was appended with NO flush needed — i.e. the mode
    /// is `Full` and there is room for one more byte. This is BYTE-IDENTICAL to
    /// `write(&[byte])` when that returns `flush_needed = false` (the `data.len() <=
    /// remaining` branch of `write_full`): same `data[write_len] = byte`, same
    /// `write_len += 1`, same `io_started = true`. Every other case (Line/None mode,
    /// or a full buffer that would flush) returns `false` so the caller takes the
    /// full `write` path unchanged.
    #[inline]
    pub fn fast_putc(&mut self, byte: u8) -> bool {
        if !matches!(self.mode, BufMode::Full) || self.write_len >= self.capacity {
            return false;
        }
        self.io_started = true;
        self.ensure_storage();
        self.data[self.write_len] = byte;
        self.write_len += 1;
        true
    }

    /// Fast single-byte read from the buffer: returns the next buffered byte and advances
    /// the read cursor, or `None` when the read buffer is exhausted (caller refills on the
    /// slow path). Identical to `read(1)` for the in-buffer case.
    #[inline]
    pub fn fast_getc(&mut self) -> Option<u8> {
        if self.read_pos < self.read_filled {
            let b = self.data[self.read_pos];
            self.read_pos += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Fast `puts` body: append `body` followed by a single `'\n'` IFF a Full-buffered
    /// stream has room for ALL of `body.len() + 1` (no flush) — byte-identical to
    /// `write(body)` then `write(b"\n")` when neither flushes. Atomic (all-or-nothing) so
    /// a partial body+newline never lands on the fast path. `false` ⇒ caller's full path.
    #[inline]
    pub fn fast_write_line(&mut self, body: &[u8]) -> bool {
        let need = body.len() + 1;
        if !matches!(self.mode, BufMode::Full)
            || need > self.capacity.saturating_sub(self.write_len)
        {
            return false;
        }
        self.io_started = true;
        self.ensure_storage();
        if !body.is_empty() {
            self.data[self.write_len..self.write_len + body.len()].copy_from_slice(body);
        }
        self.data[self.write_len + body.len()] = b'\n';
        self.write_len += need;
        true
    }

    /// Fast bulk read of exactly `dst.len()` bytes IFF they are all already in the read
    /// buffer. Copies + advances the cursor and returns `true`; returns `false` (caller
    /// refills on the slow path) when fewer than `dst.len()` bytes are buffered. Identical
    /// to `read(dst.len())` for the all-buffered case.
    #[inline]
    pub fn fast_read(&mut self, dst: &mut [u8]) -> bool {
        if dst.len() > self.read_filled.saturating_sub(self.read_pos) {
            return false;
        }
        dst.copy_from_slice(&self.data[self.read_pos..self.read_pos + dst.len()]);
        self.read_pos += dst.len();
        true
    }

    /// Fast multi-byte append for the common Full-buffered, fits-without-flush case.
    /// BYTE-IDENTICAL to `write(data)` when it returns `flush_needed = false` (the
    /// `data.len() <= remaining` branch of `write_full`). Returns `false` (caller takes
    /// the full `write` path) for Line/None mode or a write that would overflow → flush.
    #[inline]
    pub fn fast_write(&mut self, data: &[u8]) -> bool {
        if !matches!(self.mode, BufMode::Full)
            || data.len() > self.capacity.saturating_sub(self.write_len)
        {
            return false;
        }
        self.io_started = true;
        if !data.is_empty() {
            self.ensure_storage();
            self.data[self.write_len..self.write_len + data.len()].copy_from_slice(data);
        }
        self.write_len += data.len();
        true
    }

    /// Get any pending buffered write data that needs flushing.
    pub fn pending_write_data(&self) -> &[u8] {
        if self.write_len == 0 {
            &[]
        } else {
            &self.data[..self.write_len]
        }
    }

    /// Mark write buffer as flushed (reset position).
    pub fn mark_flushed(&mut self) {
        self.write_len = 0;
    }

    /// The write buffer as `(base address, bytes staged, capacity)` for a
    /// Full-buffered buffer whose storage exists: what glibc exposes as
    /// `_IO_write_base`, `_IO_write_ptr - _IO_write_base` and
    /// `_IO_buf_end - _IO_buf_base`, in Full or Line mode (a Line window is
    /// published with `_IO_write_end == _IO_write_ptr`, as glibc does, so
    /// every inline `putc` still reaches `__overflow` and its newline flush).
    /// `None` in None mode and before the first buffered write materialises
    /// the storage. The storage is allocated once at full capacity and is
    /// only replaced by `set_mode` (before any I/O) or `rebuild_after_sync`
    /// (setvbuf after I/O); both run under the stream lock, whose release
    /// republishes the window, so a published address is never stale.
    pub fn write_window(&self) -> Option<(usize, usize, usize)> {
        if matches!(self.mode, BufMode::None)
            || self.capacity == 0
            || self.data.len() < self.capacity
        {
            return None;
        }
        Some((self.data.as_ptr() as usize, self.write_len, self.capacity))
    }

    /// Account for bytes the caller stored in place through
    /// [`write_window`](Self::write_window): the staged length becomes `used`
    /// if that only grows it within capacity. Returns the bytes added.
    pub fn commit_write(&mut self, used: usize) -> usize {
        if used <= self.write_len || used > self.capacity {
            return 0;
        }
        let added = used - self.write_len;
        self.write_len = used;
        self.io_started = true;
        added
    }

    // -----------------------------------------------------------------------
    // Read-side operations
    // -----------------------------------------------------------------------

    /// Attempt to read `count` bytes from the buffer.
    ///
    /// Returns the bytes available. If empty, the caller should refill
    /// from the underlying fd.
    pub fn read(&mut self, count: usize) -> &[u8] {
        self.io_started = true;
        let available = self.read_filled.saturating_sub(self.read_pos);
        let take = count.min(available);
        let slice = &self.data[self.read_pos..self.read_pos + take];
        self.read_pos += take;
        slice
    }

    /// Number of buffered bytes available for reading.
    pub fn readable(&self) -> usize {
        self.read_filled.saturating_sub(self.read_pos)
    }

    /// Peek the readable bytes without consuming them.
    ///
    /// Returns the same bytes a subsequent [`read`](Self::read) would, but
    /// leaves the read cursor untouched so the caller can scan the slice
    /// (e.g. for a delimiter) and then [`consume`](Self::consume) exactly the
    /// number of bytes it wants.
    pub fn peek(&self) -> &[u8] {
        &self.data[self.read_pos..self.read_filled]
    }

    /// Advance the read cursor by `n` bytes (clamped to the filled region).
    ///
    /// Pairs with [`peek`](Self::peek) for read-until-delimiter scanning.
    pub fn consume(&mut self, n: usize) {
        self.io_started = true;
        self.read_pos = (self.read_pos + n).min(self.read_filled);
    }

    /// Fill the read buffer with data from an external source.
    /// Resets position to 0. Returns the number of bytes accepted.
    pub fn fill(&mut self, data: &[u8]) -> usize {
        let take = data.len().min(self.capacity);
        if take > 0 {
            self.ensure_storage();
        }
        self.data[..take].copy_from_slice(&data[..take]);
        self.read_pos = 0;
        self.read_filled = take;
        take
    }

    /// Push a single byte back into the read buffer (for ungetc).
    ///
    /// Returns `true` on success, `false` if no space available.
    pub fn unget(&mut self, byte: u8) -> bool {
        if self.read_pos > 0 {
            self.read_pos -= 1;
            self.data[self.read_pos] = byte;
            true
        } else if self.read_filled < self.capacity {
            self.ensure_storage();
            // Shift buffer right by 1 to make room.
            if self.read_filled > 0 {
                self.data.copy_within(0..self.read_filled, 1);
            }
            self.data[0] = byte;
            self.read_filled += 1;
            true
        } else {
            false
        }
    }

    /// Reset the buffer (discard all pending data).
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.read_filled = 0;
        self.write_len = 0;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    // Inlined: the per-byte fast paths (fast_putc, fast_write) call it on
    // every byte, and out of line it was 11% of a putc loop for one compare.
    #[inline]
    fn ensure_storage(&mut self) {
        if self.data.len() < self.capacity {
            self.grow_storage();
        }
    }

    #[cold]
    #[inline(never)]
    fn grow_storage(&mut self) {
        self.data.resize(self.capacity, 0);
    }

    fn write_full<'a>(&mut self, data: &'a [u8]) -> WriteResult<'a> {
        let remaining = self.capacity.saturating_sub(self.write_len);
        if data.len() <= remaining {
            // Fits entirely in the buffer.
            if !data.is_empty() {
                self.ensure_storage();
                self.data[self.write_len..self.write_len + data.len()].copy_from_slice(data);
            }
            self.write_len += data.len();
            WriteResult {
                buffered: data.len(),
                flush_needed: false,
                flush_data: Cow::Borrowed(&[]),
                flushed_from_buffer: 0,
            }
        } else {
            // glibc's split (`_IO_new_file_xsputn`): top the buffer up to
            // capacity, flush that full buffer, write whole blocks of what is
            // left directly (all of it when the block is under 128 bytes), and
            // keep the tail buffered. The flush points are observable: fl used
            // to write the old buffer plus ALL of `data` and buffer nothing, so
            // a program's stdout and stderr sharing a pipe interleaved at
            // different places than under glibc.
            let block = self.capacity;
            let rest = data.len() - remaining;
            let direct = if block >= 128 {
                rest - rest % block
            } else {
                rest
            };
            let flush_end = remaining + direct;
            let flushed_from_buffer = self.write_len;
            let flush_data = if flushed_from_buffer == 0 {
                Cow::Borrowed(&data[..flush_end])
            } else {
                let mut flush = Vec::with_capacity(self.write_len + flush_end);
                flush.extend_from_slice(&self.data[..self.write_len]);
                flush.extend_from_slice(&data[..flush_end]);
                Cow::Owned(flush)
            };
            // The tail is shorter than a block, so it fits. If the flush fails
            // the caller discards it with `mark_flushed`, as for line mode.
            let tail = &data[flush_end..];
            if !tail.is_empty() {
                self.ensure_storage();
                self.data[..tail.len()].copy_from_slice(tail);
            }
            self.write_len = tail.len();
            WriteResult {
                buffered: tail.len(),
                flush_needed: true,
                flush_data,
                flushed_from_buffer,
            }
        }
    }

    fn write_line<'a>(&mut self, data: &'a [u8]) -> WriteResult<'a> {
        // Materialise the storage on the first line-buffered write even when
        // nothing stays staged, so the stream can publish its (glibc-style,
        // `_IO_write_end == _IO_write_ptr`) write window right after the
        // `__overflow` that {fmt} uses to force the buffer into existence.
        self.ensure_storage();
        if self.write_len == 0 && data.last().copied() == Some(b'\n') {
            return WriteResult {
                buffered: 0,
                flush_needed: true,
                flush_data: Cow::Borrowed(data),
                flushed_from_buffer: 0,
            };
        }

        // Find the last newline in the data.
        let last_nl = data.iter().rposition(|&b| b == b'\n');

        match last_nl {
            Some(nl_pos) => {
                let flush_end = nl_pos + 1;
                let remainder = &data[flush_end..];

                // If the remainder exceeds buffer capacity, we cannot buffer it
                // without losing data. Fall back to flushing the entire write.
                if remainder.len() > self.capacity {
                    return self.write_full(data);
                }

                // Flush everything up to and including the last newline.
                let flushed_from_buffer = self.write_len;
                let flush_data = if flushed_from_buffer == 0 {
                    Cow::Borrowed(&data[..flush_end])
                } else {
                    let mut flush = Vec::with_capacity(self.write_len + flush_end);
                    flush.extend_from_slice(&self.data[..self.write_len]);
                    flush.extend_from_slice(&data[..flush_end]);
                    Cow::Owned(flush)
                };
                self.write_len = 0;

                // Buffer the remainder after the newline.
                if !remainder.is_empty() {
                    self.ensure_storage();
                    self.data[..remainder.len()].copy_from_slice(remainder);
                }
                self.write_len = remainder.len();

                WriteResult {
                    buffered: remainder.len(),
                    flush_needed: true,
                    flush_data,
                    flushed_from_buffer,
                }
            }
            None => {
                // No newline: just buffer (full-buffer style).
                self.write_full(data)
            }
        }
    }
}

/// Result of a buffered write operation.
#[derive(Debug)]
pub struct WriteResult<'a> {
    /// How many bytes were retained in the buffer.
    pub buffered: usize,
    /// Whether the caller must write `flush_data` to the fd now.
    pub flush_needed: bool,
    /// Bytes that must be flushed to the fd.
    pub flush_data: Cow<'a, [u8]>,
    /// Bytes in `flush_data` that came from previous buffered writes.
    pub flushed_from_buffer: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    /// glibc's overflow split: fill to capacity, flush the full buffer plus
    /// whole blocks of the rest, buffer the tail (4096-byte buffer as glibc
    /// gives a pipe or ext4 file).
    #[test]
    fn full_overflow_splits_like_glibc() {
        let mut b = StreamBuffer::new(BufMode::Full, 4096);
        let head = vec![b'a'; 4000];
        assert!(!b.write(&head).flush_needed);
        let next = vec![b'b'; 297];
        let r = b.write(&next);
        assert!(r.flush_needed);
        assert_eq!(r.flushed_from_buffer, 4000);
        assert_eq!(r.flush_data.len(), 4096, "flush exactly the full buffer");
        assert_eq!(r.buffered, 201);
        drop(r);
        assert_eq!(b.pending_write_data(), &[b'b'; 201][..]);

        // 96 pending + 10000: 4000 tops up, 4096 more go direct, 1904 wait.
        let mut b = StreamBuffer::new(BufMode::Full, 4096);
        b.write(&[b'x'; 96]);
        let big = vec![b'y'; 10000];
        let r = b.write(&big);
        assert_eq!(r.flush_data.len(), 96 + 4000 + 4096);
        assert_eq!(r.buffered, 1904);

        // Under 128 bytes of block, glibc writes the whole rest directly.
        let mut b = StreamBuffer::new(BufMode::Full, 16);
        b.write(&[b'x'; 10]);
        let r = b.write(&[b'y'; 50]);
        assert_eq!(r.flush_data.len(), 60);
        assert_eq!(r.buffered, 0);
    }

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    #[test]
    fn test_full_buffer_absorbs_small_writes() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let result = buf.write(b"hello");
        assert!(!result.flush_needed);
        assert_eq!(result.buffered, 5);
        assert_eq!(buf.pending_write_data(), b"hello");
    }

    #[test]
    fn test_full_buffer_flushes_on_overflow() {
        let mut buf = StreamBuffer::new(BufMode::Full, 8);
        let _ = buf.write(b"abcd");
        let result = buf.write(b"efghijklmn");
        assert!(result.flush_needed);
        assert_eq!(result.flush_data.as_ref(), b"abcdefghijklmn");
    }

    #[test]
    fn test_line_buffer_flushes_on_newline() {
        let mut buf = StreamBuffer::new(BufMode::Line, 64);
        let result = buf.write(b"hello\nworld");
        assert!(result.flush_needed);
        assert_eq!(result.flush_data.as_ref(), b"hello\n");
        assert_eq!(buf.pending_write_data(), b"world");
    }

    #[test]
    fn test_line_buffer_trailing_newline_empty_pending_flushes_directly() {
        let mut buf = StreamBuffer::new(BufMode::Line, 64);
        let result = buf.write(b"metric=value status=ok\n");
        assert!(result.flush_needed);
        assert_eq!(result.buffered, 0);
        assert_eq!(result.flushed_from_buffer, 0);
        assert_eq!(result.flush_data.as_ref(), b"metric=value status=ok\n");
        assert!(buf.pending_write_data().is_empty());
    }

    #[test]
    fn test_line_buffer_no_newline_buffers() {
        let mut buf = StreamBuffer::new(BufMode::Line, 64);
        let result = buf.write(b"hello");
        assert!(!result.flush_needed);
        assert_eq!(buf.pending_write_data(), b"hello");
    }

    #[test]
    fn test_unbuffered_always_flushes() {
        let mut buf = StreamBuffer::unbuffered();
        let result = buf.write(b"hello");
        assert!(result.flush_needed);
        assert_eq!(result.flush_data.as_ref(), b"hello");
        assert_eq!(result.buffered, 0);
    }

    #[test]
    fn test_read_from_filled_buffer() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        buf.fill(b"hello world");
        let data = buf.read(5);
        assert_eq!(data, b"hello");
        let data2 = buf.read(6);
        assert_eq!(data2, b" world");
    }

    #[test]
    fn test_unget_byte() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        buf.fill(b"ello");
        // Read one byte.
        let _ = buf.read(1);
        // Push it back.
        assert!(buf.unget(b'e'));
        let data = buf.read(4);
        assert_eq!(data, b"ello");
    }

    #[test]
    fn test_set_mode_before_io() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        assert!(buf.set_mode(BufMode::Line, 128));
        assert_eq!(buf.mode(), BufMode::Line);
        assert_eq!(buf.capacity(), 128);
    }

    #[test]
    fn test_set_mode_reuses_existing_allocation_when_capacity_fits() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let original_ptr = buf.data.as_ptr();

        assert!(buf.set_mode(BufMode::Line, 32));

        assert_eq!(buf.mode(), BufMode::Line);
        assert_eq!(buf.capacity(), 32);
        assert_eq!(buf.data.as_ptr(), original_ptr);
        assert_eq!(buf.readable(), 0);
        assert!(buf.pending_write_data().is_empty());
        assert!(buf.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_set_mode_after_io_fails() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let _ = buf.write(b"x");
        assert!(!buf.set_mode(BufMode::Line, 128));
    }

    #[test]
    fn test_switch_mode_in_place_keeps_staged_bytes() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let _ = buf.write(b"abc");
        buf.switch_mode_in_place(BufMode::Line, 4096);
        assert_eq!(buf.mode(), BufMode::Line);
        assert_eq!(buf.capacity(), 64);
        assert_eq!(buf.pending_write_data(), b"abc");
        // None is not an in-place switch: the stream must be synced first.
        buf.switch_mode_in_place(BufMode::None, 0);
        assert_eq!(buf.mode(), BufMode::Line);
    }

    #[test]
    fn test_switch_mode_in_place_gives_unbuffered_stream_storage() {
        let mut buf = StreamBuffer::new(BufMode::None, 0);
        let _ = buf.write(b"x");
        buf.switch_mode_in_place(BufMode::Full, 512);
        assert_eq!(buf.mode(), BufMode::Full);
        assert_eq!(buf.capacity(), 512);
        assert!(!buf.write(b"yz").flush_needed);
        assert_eq!(buf.pending_write_data(), b"yz");
    }

    #[test]
    fn test_rebuild_after_sync_requires_drained_output() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let _ = buf.write(b"abc");
        assert!(!buf.rebuild_after_sync(BufMode::None, 0));
        assert_eq!(buf.pending_write_data(), b"abc");
        buf.mark_flushed();
        assert!(buf.rebuild_after_sync(BufMode::None, 0));
        assert_eq!(buf.mode(), BufMode::None);
        assert_eq!(buf.capacity(), 0);
        // Still a stream in use: a later set_mode is refused as before.
        assert!(!buf.set_mode(BufMode::Full, 64));
    }

    #[test]
    fn test_rebuild_after_sync_discards_unread_input() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        buf.fill(b"unread input");
        let _ = buf.read(2);
        assert!(buf.rebuild_after_sync(BufMode::Full, 128));
        assert_eq!(buf.readable(), 0);
        assert_eq!(buf.capacity(), 128);
    }

    #[test]
    fn test_bufmode_from_posix() {
        assert_eq!(BufMode::from_posix(0), Some(BufMode::Full));
        assert_eq!(BufMode::from_posix(1), Some(BufMode::Line));
        assert_eq!(BufMode::from_posix(2), Some(BufMode::None));
        assert_eq!(BufMode::from_posix(3), Option::None);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_set_mode_before_io_resets_state(
            initial_mode in prop_oneof![Just(BufMode::Full), Just(BufMode::Line), Just(BufMode::None)],
            target_mode in prop_oneof![Just(BufMode::Full), Just(BufMode::Line), Just(BufMode::None)],
            initial_capacity in 0usize..128,
            target_size in 0usize..128,
            prefill in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let mut buf = StreamBuffer::new(initial_mode, initial_capacity);
            let _ = buf.fill(&prefill);

            let changed = buf.set_mode(target_mode, target_size);

            let expected_capacity = if matches!(target_mode, BufMode::None) {
                0
            } else {
                target_size.max(1)
            };

            prop_assert!(changed);
            prop_assert_eq!(buf.mode(), target_mode);
            prop_assert_eq!(buf.capacity(), expected_capacity);
            prop_assert_eq!(buf.readable(), 0);
            prop_assert!(buf.pending_write_data().is_empty());
        }

        #[test]
        fn prop_full_mode_buffers_without_flush_when_capacity_allows(
            cap in 1usize..128,
            data in proptest::collection::vec(any::<u8>(), 0..128)
        ) {
            prop_assume!(data.len() <= cap);

            let mut buf = StreamBuffer::new(BufMode::Full, cap);
            let result = buf.write(&data);

            prop_assert!(!result.flush_needed);
            prop_assert_eq!(result.buffered, data.len());
            prop_assert_eq!(buf.pending_write_data(), data.as_slice());
        }

        #[test]
        fn prop_line_mode_flushes_through_last_newline(
            data in proptest::collection::vec(any::<u8>(), 0..128)
        ) {
            let mut buf = StreamBuffer::new(BufMode::Line, data.len().max(1) + 1);
            let result = buf.write(&data);
            let last_nl = data.iter().rposition(|b| *b == b'\n');

            match last_nl {
                Some(index) => {
                    prop_assert!(result.flush_needed);
                    prop_assert_eq!(result.flush_data.as_ref(), &data[..=index]);
                    prop_assert_eq!(buf.pending_write_data(), &data[index + 1..]);
                }
                None => {
                    prop_assert!(!result.flush_needed);
                    prop_assert!(result.flush_data.is_empty());
                    prop_assert_eq!(buf.pending_write_data(), data.as_slice());
                }
            }
        }

        #[test]
        fn prop_unbuffered_mode_always_requests_immediate_flush(
            data in proptest::collection::vec(any::<u8>(), 0..128)
        ) {
            let mut buf = StreamBuffer::unbuffered();
            let result = buf.write(&data);

            prop_assert!(result.flush_needed);
            prop_assert_eq!(result.buffered, 0);
            prop_assert_eq!(result.flush_data.as_ref(), data.as_slice());
        }
    }
}
