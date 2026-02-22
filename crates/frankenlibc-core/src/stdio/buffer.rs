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
/// - `pos <= filled <= data.len()`
/// - `data.len() <= capacity` (capacity is fixed at creation)
#[derive(Debug)]
pub struct StreamBuffer {
    data: Vec<u8>,
    /// Current read/write position in the buffer.
    pos: usize,
    /// Number of valid bytes in the buffer (for read buffers).
    filled: usize,
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
            data: vec![0u8; cap],
            pos: 0,
            filled: 0,
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
        self.data.len()
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
        self.data = vec![0u8; cap];
        self.pos = 0;
        self.filled = 0;
        true
    }

    // -----------------------------------------------------------------------
    // Write-side operations
    // -----------------------------------------------------------------------

    /// Buffer a write. Returns the bytes that should be flushed immediately
    /// (may be empty if buffering absorbs them) and the bytes actually buffered.
    ///
    /// Caller must flush the returned flush slice to the underlying fd.
    pub fn write(&mut self, data: &[u8]) -> WriteResult {
        self.io_started = true;

        match self.mode {
            BufMode::None => {
                // Unbuffered: all bytes must be written immediately.
                WriteResult {
                    buffered: 0,
                    flush_needed: true,
                    flush_data: data.to_vec(),
                }
            }
            BufMode::Full => self.write_full(data),
            BufMode::Line => self.write_line(data),
        }
    }

    /// Get any pending buffered write data that needs flushing.
    pub fn pending_write_data(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    /// Mark write buffer as flushed (reset position).
    pub fn mark_flushed(&mut self) {
        self.pos = 0;
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
        let available = self.filled - self.pos;
        let take = count.min(available);
        let slice = &self.data[self.pos..self.pos + take];
        self.pos += take;
        slice
    }

    /// Number of buffered bytes available for reading.
    pub fn readable(&self) -> usize {
        self.filled.saturating_sub(self.pos)
    }

    /// Fill the read buffer with data from an external source.
    /// Resets position to 0.
    pub fn fill(&mut self, data: &[u8]) {
        let take = data.len().min(self.data.len());
        self.data[..take].copy_from_slice(&data[..take]);
        self.pos = 0;
        self.filled = take;
    }

    /// Push a single byte back into the read buffer (for ungetc).
    ///
    /// Returns `true` on success, `false` if no space available.
    pub fn unget(&mut self, byte: u8) -> bool {
        if self.pos > 0 {
            self.pos -= 1;
            self.data[self.pos] = byte;
            true
        } else if self.filled < self.data.len() {
            // Shift buffer right by 1 to make room.
            if self.filled > 0 {
                self.data.copy_within(0..self.filled, 1);
            }
            self.data[0] = byte;
            self.filled += 1;
            true
        } else {
            false
        }
    }

    /// Reset the buffer (discard all pending data).
    pub fn reset(&mut self) {
        self.pos = 0;
        self.filled = 0;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn write_full(&mut self, data: &[u8]) -> WriteResult {
        let remaining = self.data.len().saturating_sub(self.pos);
        if data.len() <= remaining {
            // Fits entirely in the buffer.
            self.data[self.pos..self.pos + data.len()].copy_from_slice(data);
            self.pos += data.len();
            WriteResult {
                buffered: data.len(),
                flush_needed: false,
                flush_data: Vec::new(),
            }
        } else {
            // Buffer is full — flush existing + overflow.
            let mut flush = Vec::with_capacity(self.pos + data.len());
            flush.extend_from_slice(&self.data[..self.pos]);
            flush.extend_from_slice(data);
            self.pos = 0;
            WriteResult {
                buffered: 0,
                flush_needed: true,
                flush_data: flush,
            }
        }
    }

    fn write_line(&mut self, data: &[u8]) -> WriteResult {
        // Find the last newline in the data.
        let last_nl = data.iter().rposition(|&b| b == b'\n');

        match last_nl {
            Some(nl_pos) => {
                let flush_end = nl_pos + 1;
                let remainder = &data[flush_end..];

                // If the remainder exceeds buffer capacity, we cannot buffer it
                // without losing data. Fall back to flushing the entire write.
                if remainder.len() > self.data.len() {
                    return self.write_full(data);
                }

                // Flush everything up to and including the last newline.
                let mut flush = Vec::with_capacity(self.pos + flush_end);
                flush.extend_from_slice(&self.data[..self.pos]);
                flush.extend_from_slice(&data[..flush_end]);
                self.pos = 0;

                // Buffer the remainder after the newline.
                self.data[..remainder.len()].copy_from_slice(remainder);
                self.pos = remainder.len();

                WriteResult {
                    buffered: remainder.len(),
                    flush_needed: true,
                    flush_data: flush,
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
pub struct WriteResult {
    /// How many bytes were retained in the buffer.
    pub buffered: usize,
    /// Whether the caller must write `flush_data` to the fd now.
    pub flush_needed: bool,
    /// Bytes that must be flushed to the fd.
    pub flush_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        assert_eq!(&result.flush_data, b"abcdefghijklmn");
    }

    #[test]
    fn test_line_buffer_flushes_on_newline() {
        let mut buf = StreamBuffer::new(BufMode::Line, 64);
        let result = buf.write(b"hello\nworld");
        assert!(result.flush_needed);
        assert_eq!(&result.flush_data, b"hello\n");
        assert_eq!(buf.pending_write_data(), b"world");
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
        assert_eq!(&result.flush_data, b"hello");
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
    fn test_set_mode_after_io_fails() {
        let mut buf = StreamBuffer::new(BufMode::Full, 64);
        let _ = buf.write(b"x");
        assert!(!buf.set_mode(BufMode::Line, 128));
    }

    #[test]
    fn test_bufmode_from_posix() {
        assert_eq!(BufMode::from_posix(0), Some(BufMode::Full));
        assert_eq!(BufMode::from_posix(1), Some(BufMode::Line));
        assert_eq!(BufMode::from_posix(2), Some(BufMode::None));
        assert_eq!(BufMode::from_posix(3), Option::None);
    }

    proptest! {
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
                    prop_assert_eq!(&result.flush_data, &data[..=index]);
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
            prop_assert_eq!(result.flush_data, data);
        }
    }
}
