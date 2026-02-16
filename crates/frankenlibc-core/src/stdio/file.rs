//! FILE stream state management.
//!
//! Clean-room implementation of the POSIX FILE abstraction.
//! Manages file descriptor, buffering, flags, and position.
//!
//! Reference: POSIX.1-2024 fopen, ISO C11 7.21.5
//!
//! Design: `StdioStream` is the safe Rust model of a C `FILE`.
//! The ABI layer wraps these in a registry and hands out opaque
//! pointers to C callers. No raw FILE* from glibc is used internally.

use super::buffer::{BUFSIZ, BufMode, StreamBuffer};

// ---------------------------------------------------------------------------
// Stream flags
// ---------------------------------------------------------------------------

/// File open mode flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    pub readable: bool,
    pub writable: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub binary: bool,
    pub exclusive: bool,
}

/// Runtime stream state flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamFlags {
    pub eof: bool,
    pub error: bool,
    /// True if any read or write has occurred.
    pub io_started: bool,
}

// ---------------------------------------------------------------------------
// Mode parsing
// ---------------------------------------------------------------------------

/// Parse a POSIX fopen mode string (e.g. "r", "w+", "rb", "a+b").
///
/// Returns `None` if the mode string is invalid.
pub fn parse_mode(mode: &[u8]) -> Option<OpenFlags> {
    if mode.is_empty() {
        return None;
    }

    let mut flags = OpenFlags::default();
    let mut pos = 0;

    // Base mode character.
    match mode[pos] {
        b'r' => {
            flags.readable = true;
        }
        b'w' => {
            flags.writable = true;
            flags.create = true;
            flags.truncate = true;
        }
        b'a' => {
            flags.writable = true;
            flags.create = true;
            flags.append = true;
        }
        _ => return None,
    }
    pos += 1;

    // Modifiers: '+', 'b', 'x' in any order.
    while pos < mode.len() {
        match mode[pos] {
            b'+' => {
                flags.readable = true;
                flags.writable = true;
            }
            b'b' => flags.binary = true,
            b'x' => flags.exclusive = true,
            _ => return None,
        }
        pos += 1;
    }

    Some(flags)
}

/// Convert open flags to POSIX O_* flag bits.
pub fn flags_to_oflags(flags: &OpenFlags) -> i32 {
    let mut oflags = 0i32;

    if flags.readable && flags.writable {
        oflags |= 2; // O_RDWR
    } else if flags.writable {
        oflags |= 1; // O_WRONLY
    }
    // O_RDONLY is 0, so readable-only needs no flag.

    if flags.create {
        oflags |= 0o100; // O_CREAT
    }
    if flags.truncate {
        oflags |= 0o1000; // O_TRUNC
    }
    if flags.append {
        oflags |= 0o2000; // O_APPEND
    }
    if flags.exclusive {
        oflags |= 0o200; // O_EXCL
    }

    oflags
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// POSIX FILE stream.
///
/// Holds the file descriptor, buffer, and stream state. This type lives
/// entirely in safe Rust. The ABI layer allocates these on the heap and
/// manages a registry mapping opaque `FILE*` pointers to stream IDs.
#[derive(Debug)]
pub struct StdioStream {
    /// Underlying file descriptor (-1 if closed).
    fd: i32,
    /// I/O buffer.
    buffer: StreamBuffer,
    /// How the file was opened.
    open_flags: OpenFlags,
    /// Runtime state (eof, error).
    flags: StreamFlags,
    /// Logical file position (for seekable streams).
    offset: i64,
    /// One-byte pushback for ungetc (layered on top of buffer).
    ungetc_byte: Option<u8>,
}

impl StdioStream {
    fn advance_offset(&mut self, bytes: usize) {
        let inc = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.offset = self.offset.saturating_add(inc);
    }

    fn rewind_offset_one(&mut self) {
        self.offset = self.offset.saturating_sub(1);
    }

    /// Create a new stream for the given fd with default buffering.
    pub fn new(fd: i32, open_flags: OpenFlags) -> Self {
        let buf_mode = if fd <= 2 {
            // stdin/stdout are line-buffered by default; stderr unbuffered.
            if fd == 2 {
                BufMode::None
            } else {
                BufMode::Line
            }
        } else {
            BufMode::Full
        };
        Self {
            fd,
            buffer: StreamBuffer::new(buf_mode, BUFSIZ),
            open_flags,
            flags: StreamFlags::default(),
            offset: 0,
            ungetc_byte: None,
        }
    }

    /// Create a stream wrapping an existing fd with specified buffering.
    pub fn with_mode(fd: i32, open_flags: OpenFlags, buf_mode: BufMode) -> Self {
        Self {
            fd,
            buffer: StreamBuffer::new(buf_mode, BUFSIZ),
            open_flags,
            flags: StreamFlags::default(),
            offset: 0,
            ungetc_byte: None,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Get the underlying file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Check if the stream is readable.
    pub fn is_readable(&self) -> bool {
        self.open_flags.readable
    }

    /// Check if the stream is writable.
    pub fn is_writable(&self) -> bool {
        self.open_flags.writable
    }

    /// Check if EOF has been reached.
    pub fn is_eof(&self) -> bool {
        self.flags.eof
    }

    /// Check if an error has occurred.
    pub fn is_error(&self) -> bool {
        self.flags.error
    }

    /// Clear EOF and error indicators.
    pub fn clear_err(&mut self) {
        self.flags.eof = false;
        self.flags.error = false;
    }

    /// Set the EOF indicator.
    pub fn set_eof(&mut self) {
        self.flags.eof = true;
    }

    /// Set the error indicator.
    pub fn set_error(&mut self) {
        self.flags.error = true;
    }

    /// Current logical file offset.
    pub fn offset(&self) -> i64 {
        self.offset
    }

    /// Set the logical offset (after a successful lseek).
    pub fn set_offset(&mut self, off: i64) {
        self.offset = off;
    }

    /// Get the current buffering mode.
    pub fn buf_mode(&self) -> BufMode {
        self.buffer.mode()
    }

    // -----------------------------------------------------------------------
    // Buffering control
    // -----------------------------------------------------------------------

    /// Change the buffering mode (POSIX setvbuf).
    ///
    /// Must be called before any I/O. Returns false if too late.
    pub fn set_buffering(&mut self, mode: BufMode, size: usize) -> bool {
        self.buffer.set_mode(mode, size)
    }

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    /// Buffer a write. Returns bytes that need to be flushed to the fd.
    ///
    /// Caller is responsible for actually writing `flush_data` to fd.
    pub fn buffer_write(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.open_flags.writable {
            self.flags.error = true;
            return Vec::new();
        }
        self.flags.io_started = true;
        let result = self.buffer.write(data);
        self.advance_offset(data.len());
        if result.flush_needed {
            result.flush_data
        } else {
            Vec::new()
        }
    }

    /// Get any pending write data that needs flushing.
    pub fn pending_flush(&self) -> &[u8] {
        self.buffer.pending_write_data()
    }

    /// Mark the write buffer as successfully flushed.
    pub fn mark_flushed(&mut self) {
        self.buffer.mark_flushed();
    }

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    /// Read from the internal buffer. Returns available bytes.
    ///
    /// If empty, caller should call `fill_read_buffer` then retry.
    pub fn buffered_read(&mut self, count: usize) -> Vec<u8> {
        if count == 0 {
            return Vec::new();
        }
        if !self.open_flags.readable {
            self.flags.error = true;
            return Vec::new();
        }
        self.flags.io_started = true;

        let mut result = Vec::new();
        let mut remaining = count;

        // First, return ungetc byte if present.
        if let Some(b) = self.ungetc_byte.take() {
            result.push(b);
            remaining -= 1;
            if remaining == 0 {
                return result;
            }
        }

        // Then read from buffer.
        let data = self.buffer.read(remaining);
        result.extend_from_slice(data);
        self.advance_offset(result.len());
        result
    }

    /// Number of bytes available for reading without I/O.
    pub fn readable_buffered(&self) -> usize {
        self.ungetc_byte.is_some() as usize + self.buffer.readable()
    }

    /// Fill the read buffer with externally-fetched data.
    pub fn fill_read_buffer(&mut self, data: &[u8]) {
        self.buffer.fill(data);
    }

    /// Push a byte back (ungetc). Returns false if already one pushed back.
    pub fn ungetc(&mut self, byte: u8) -> bool {
        let pushed = if self.ungetc_byte.is_some() {
            // Try the buffer's unget.
            self.buffer.unget(byte)
        } else {
            self.ungetc_byte = Some(byte);
            true
        };

        if pushed {
            self.flags.eof = false; // POSIX: ungetc clears EOF
            self.rewind_offset_one();
        }
        pushed
    }

    // -----------------------------------------------------------------------
    // Seeking
    // -----------------------------------------------------------------------

    /// Prepare for a seek: discard read buffer and flush writes.
    ///
    /// Returns pending write data that must be flushed before the seek.
    pub fn prepare_seek(&mut self) -> Vec<u8> {
        self.ungetc_byte = None;
        self.buffer.reset();
        self.flags.eof = false;
        let pending = self.buffer.pending_write_data().to_vec();
        self.buffer.mark_flushed();
        pending
    }

    // -----------------------------------------------------------------------
    // Close
    // -----------------------------------------------------------------------

    /// Prepare for close: returns pending write data.
    pub fn prepare_close(&mut self) -> Vec<u8> {
        let pending = self.buffer.pending_write_data().to_vec();
        self.buffer.mark_flushed();
        pending
    }

    /// Check if the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.fd < 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mode_read() {
        let f = parse_mode(b"r").unwrap();
        assert!(f.readable);
        assert!(!f.writable);
        assert!(!f.append);
    }

    #[test]
    fn test_parse_mode_write() {
        let f = parse_mode(b"w").unwrap();
        assert!(!f.readable);
        assert!(f.writable);
        assert!(f.truncate);
        assert!(f.create);
    }

    #[test]
    fn test_parse_mode_append_plus() {
        let f = parse_mode(b"a+").unwrap();
        assert!(f.readable);
        assert!(f.writable);
        assert!(f.append);
    }

    #[test]
    fn test_parse_mode_binary() {
        let f = parse_mode(b"rb").unwrap();
        assert!(f.readable);
        assert!(f.binary);
    }

    #[test]
    fn test_parse_mode_exclusive() {
        let f = parse_mode(b"wx").unwrap();
        assert!(f.writable);
        assert!(f.exclusive);
    }

    #[test]
    fn test_parse_mode_invalid() {
        assert!(parse_mode(b"").is_none());
        assert!(parse_mode(b"z").is_none());
    }

    #[test]
    fn test_stream_write_buffer() {
        let flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        let flush = s.buffer_write(b"hello");
        assert!(flush.is_empty()); // fully buffered, not full yet
        assert_eq!(s.pending_flush(), b"hello");
    }

    #[test]
    fn test_stream_read_ungetc() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        s.fill_read_buffer(b"ello");
        assert!(s.ungetc(b'h'));
        let data = s.buffered_read(5);
        assert_eq!(&data, b"hello");
    }

    #[test]
    fn test_stream_offset_tracks_reads_and_writes() {
        let write_flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let mut writer = StdioStream::new(3, write_flags);
        assert_eq!(writer.offset(), 0);
        let _ = writer.buffer_write(b"hello");
        assert_eq!(writer.offset(), 5);
        let _ = writer.buffer_write(b" world");
        assert_eq!(writer.offset(), 11);

        let read_flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut reader = StdioStream::new(3, read_flags);
        reader.fill_read_buffer(b"abcdef");
        let first = reader.buffered_read(2);
        assert_eq!(&first, b"ab");
        assert_eq!(reader.offset(), 2);
        let second = reader.buffered_read(4);
        assert_eq!(&second, b"cdef");
        assert_eq!(reader.offset(), 6);
    }

    #[test]
    fn test_ungetc_rewinds_offset() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        s.fill_read_buffer(b"abc");
        let first = s.buffered_read(2);
        assert_eq!(&first, b"ab");
        assert_eq!(s.offset(), 2);
        assert!(s.ungetc(b'b'));
        assert_eq!(s.offset(), 1);
        let replay = s.buffered_read(2);
        assert_eq!(&replay, b"bc");
        assert_eq!(s.offset(), 3);
    }

    #[test]
    fn test_stream_eof_clear() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        s.set_eof();
        assert!(s.is_eof());
        s.clear_err();
        assert!(!s.is_eof());
    }

    #[test]
    fn test_stream_stderr_unbuffered() {
        let flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let s = StdioStream::new(2, flags);
        assert_eq!(s.buf_mode(), BufMode::None);
    }

    #[test]
    fn test_stream_stdout_line_buffered() {
        let flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let s = StdioStream::new(1, flags);
        assert_eq!(s.buf_mode(), BufMode::Line);
    }

    #[test]
    fn test_flags_to_oflags_write_create_trunc() {
        let f = parse_mode(b"w").unwrap();
        let o = flags_to_oflags(&f);
        assert_ne!(o & 1, 0); // O_WRONLY
        assert_ne!(o & 0o100, 0); // O_CREAT
        assert_ne!(o & 0o1000, 0); // O_TRUNC
    }

    #[test]
    fn test_flags_to_oflags_read_write() {
        let f = parse_mode(b"r+").unwrap();
        let o = flags_to_oflags(&f);
        assert_ne!(o & 2, 0); // O_RDWR
    }
}
