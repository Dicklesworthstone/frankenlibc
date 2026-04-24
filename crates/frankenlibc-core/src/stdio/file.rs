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

use super::buffer::{BUFSIZ, BufMode, StreamBuffer, WriteResult};

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
    pub cloexec: bool,
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

    // Modifiers: '+', 'b', 'x', 'e', 'm', 'c' in any order.
    // glibc accepts 'e' (O_CLOEXEC), 'm' (mmap), 'c' (cancel-safe), 'x' (exclusive).
    // Reject invalid modifiers like 'r', 'w', 'a' in non-primary position.
    while pos < mode.len() {
        match mode[pos] {
            b'+' => {
                flags.readable = true;
                flags.writable = true;
            }
            b'b' => flags.binary = true,
            b'x' => flags.exclusive = true,
            b'e' => flags.cloexec = true,
            b'm' | b'c' => {} // Accepted but no-op on Linux
            // Reject 'r', 'w', 'a' in modifier position (e.g., "rw", "ar").
            // Also reject any other unknown characters.
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
    if flags.cloexec {
        oflags |= 0o2000000; // O_CLOEXEC
    }

    oflags
}

// ---------------------------------------------------------------------------
// Memory backing for fmemopen / open_memstream
// ---------------------------------------------------------------------------

/// Memory backing for memory-based stdio streams.
///
/// `Fixed` is for `fmemopen`: a position-tracked buffer with a fixed maximum
/// size. `Dynamic` is for `open_memstream`: a growable write buffer.
#[derive(Debug)]
pub enum MemBacking {
    /// `fmemopen`: position-tracked fixed-size buffer.
    Fixed {
        /// The backing data (capacity == max size).
        data: Vec<u8>,
        /// Current read/write position.
        pos: usize,
        /// Logical end of valid content (for reads and NUL termination).
        content_end: usize,
    },
    /// `open_memstream`: dynamically growing write buffer.
    Dynamic {
        /// The backing data (grows on write past end).
        data: Vec<u8>,
        /// Current write position.
        pos: usize,
    },
}

impl MemBacking {
    /// Write data at the current position. Returns bytes actually written.
    pub fn write(&mut self, src: &[u8]) -> usize {
        match self {
            MemBacking::Fixed {
                data,
                pos,
                content_end,
            } => {
                let avail = data.len().saturating_sub(*pos);
                let n = src.len().min(avail);
                if n > 0 {
                    data[*pos..*pos + n].copy_from_slice(&src[..n]);
                    *pos += n;
                    if *pos > *content_end {
                        *content_end = *pos;
                    }
                }
                n
            }
            MemBacking::Dynamic { data, pos } => {
                let Some(end) = pos.checked_add(src.len()) else {
                    return 0;
                };
                if end > data.len() {
                    if data.try_reserve(end - data.len()).is_err() {
                        return 0;
                    }
                    data.resize(end, 0);
                }
                data[*pos..end].copy_from_slice(src);
                *pos = end;
                src.len()
            }
        }
    }

    /// Read up to `count` bytes from the current position. Returns the data read.
    pub fn read(&mut self, count: usize) -> Vec<u8> {
        match self {
            MemBacking::Fixed {
                data,
                pos,
                content_end,
            } => {
                let avail = (*content_end).saturating_sub(*pos);
                let n = count.min(avail);
                if n == 0 {
                    return Vec::new();
                }
                let result = data[*pos..*pos + n].to_vec();
                *pos += n;
                result
            }
            MemBacking::Dynamic { data, pos } => {
                let avail = data.len().saturating_sub(*pos);
                let n = count.min(avail);
                if n == 0 {
                    return Vec::new();
                }
                let result = data[*pos..*pos + n].to_vec();
                *pos += n;
                result
            }
        }
    }

    /// Seek to a new position. `whence`: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END.
    /// Returns the new position on success, or `None` on invalid seek.
    pub fn seek(&mut self, offset: i64, whence: i32) -> Option<i64> {
        let (size, pos) = match self {
            MemBacking::Fixed {
                data,
                pos,
                content_end,
            } => {
                let sz = if whence == 2 {
                    *content_end
                } else {
                    data.len()
                };
                (sz, pos)
            }
            MemBacking::Dynamic { data, pos } => (data.len(), pos),
        };

        let base = match whence {
            0 => 0i64,        // SEEK_SET
            1 => *pos as i64, // SEEK_CUR
            2 => size as i64, // SEEK_END
            _ => return None,
        };

        let new_pos = base.checked_add(offset)?;
        if new_pos < 0 {
            return None;
        }

        let new_pos = new_pos as usize;
        // For Fixed, clamp to buffer size; for Dynamic, allow within data length
        match self {
            MemBacking::Fixed { data, .. } => {
                if new_pos > data.len() {
                    return None;
                }
            }
            MemBacking::Dynamic { .. } => {
                // Allow seeking beyond end; open_memstream semantics grow on write.
            }
        }

        match self {
            MemBacking::Fixed { pos: p, .. } => *p = new_pos,
            MemBacking::Dynamic { pos: p, .. } => *p = new_pos,
        }
        Some(new_pos as i64)
    }

    /// Current position.
    pub fn position(&self) -> usize {
        match self {
            MemBacking::Fixed { pos, .. } | MemBacking::Dynamic { pos, .. } => *pos,
        }
    }

    /// Current data slice (for open_memstream sync).
    pub fn data(&self) -> &[u8] {
        match self {
            MemBacking::Fixed {
                data, content_end, ..
            } => &data[..*content_end],
            MemBacking::Dynamic { data, .. } => data.as_slice(),
        }
    }

    /// Clone the data as a new Vec (for returning to C caller via malloc).
    pub fn data_clone(&self) -> Vec<u8> {
        self.data().to_vec()
    }
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
    /// Underlying file descriptor (-1 if closed, -2 if memory-backed).
    fd: i32,
    /// I/O buffer (used for fd-backed streams only).
    buffer: StreamBuffer,
    /// How the file was opened.
    open_flags: OpenFlags,
    /// Runtime state (eof, error).
    flags: StreamFlags,
    /// Logical file position (for seekable streams).
    offset: i64,
    /// One-byte pushback for ungetc (layered on top of buffer).
    ungetc_byte: Option<u8>,
    /// Optional memory backing for fmemopen/open_memstream.
    mem_backing: Option<MemBacking>,
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
            mem_backing: None,
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
            mem_backing: None,
        }
    }

    /// Create a memory-backed stream for `fmemopen`.
    ///
    /// If `data` is provided (user buffer), it becomes the fixed backing.
    /// `content_len` is the initial amount of valid content for reading.
    pub fn new_mem_fixed(data: Vec<u8>, content_len: usize, open_flags: OpenFlags) -> Self {
        let cl = content_len.min(data.len());
        // For write modes without append, position starts at 0.
        // For append mode, position starts at content_end.
        let pos = if open_flags.append { cl } else { 0 };
        Self {
            fd: -2, // sentinel: memory-backed
            buffer: StreamBuffer::new(BufMode::None, 0),
            open_flags,
            flags: StreamFlags::default(),
            offset: pos as i64,
            ungetc_byte: None,
            mem_backing: Some(MemBacking::Fixed {
                data,
                pos,
                content_end: cl,
            }),
        }
    }

    /// Create a dynamically-growing memory stream for `open_memstream`.
    pub fn new_mem_dynamic() -> Self {
        Self {
            fd: -2,
            buffer: StreamBuffer::new(BufMode::None, 0),
            open_flags: OpenFlags {
                writable: true,
                ..Default::default()
            },
            flags: StreamFlags::default(),
            offset: 0,
            ungetc_byte: None,
            mem_backing: Some(MemBacking::Dynamic {
                data: Vec::new(),
                pos: 0,
            }),
        }
    }

    /// Create a dynamic memory-backed stream with custom open flags.
    /// Used by fopencookie where the mode determines read/write permissions.
    pub fn new_mem_dynamic_with_flags(open_flags: OpenFlags) -> Self {
        Self {
            fd: -2,
            buffer: StreamBuffer::new(BufMode::None, 0),
            open_flags,
            flags: StreamFlags::default(),
            offset: 0,
            ungetc_byte: None,
            mem_backing: Some(MemBacking::Dynamic {
                data: Vec::new(),
                pos: 0,
            }),
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

    /// Buffer a write and return the buffering outcome.
    ///
    /// Caller is responsible for flushing `flush_data` and advancing the
    /// logical offset by the number of bytes accepted for this call.
    pub fn buffer_write(&mut self, data: &[u8]) -> Option<WriteResult> {
        if !self.open_flags.writable {
            self.flags.error = true;
            return None;
        }
        self.flags.io_started = true;
        self.flags.eof = false;
        Some(self.buffer.write(data))
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
                self.advance_offset(result.len());
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
    /// Returns the number of bytes actually buffered.
    pub fn fill_read_buffer(&mut self, data: &[u8]) -> usize {
        self.buffer.fill(data)
    }

    /// Total capacity of the internal buffer.
    pub fn buffer_capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Push a byte back (ungetc). Returns false if already one pushed back.
    pub fn ungetc(&mut self, byte: u8) -> bool {
        let pushed = if let Some(existing) = self.ungetc_byte {
            // Push the existing byte into the buffer, and replace ungetc_byte
            // with the new byte, maintaining LIFO order.
            if self.buffer.unget(existing) {
                self.ungetc_byte = Some(byte);
                true
            } else {
                false
            }
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
        let pending = self.buffer.pending_write_data().to_vec();
        self.ungetc_byte = None;
        self.buffer.reset();
        self.flags.eof = false;
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
        self.fd < 0 && self.mem_backing.is_none()
    }

    // -----------------------------------------------------------------------
    // Memory-backed stream operations
    // -----------------------------------------------------------------------

    /// Check if this stream is memory-backed (fmemopen/open_memstream).
    pub fn is_mem_backed(&self) -> bool {
        self.mem_backing.is_some()
    }

    /// Write data to a memory-backed stream. Returns bytes written.
    /// For fd-backed streams, returns 0 (caller should use buffer_write).
    pub fn mem_write(&mut self, data: &[u8]) -> usize {
        if !self.open_flags.writable {
            self.flags.error = true;
            return 0;
        }
        self.flags.io_started = true;
        self.flags.eof = false;
        if let Some(ref mut backing) = self.mem_backing {
            let n = backing.write(data);
            self.offset = backing.position() as i64;
            n
        } else {
            0
        }
    }

    /// Read data from a memory-backed stream. Returns data read.
    /// For fd-backed streams, returns empty (caller should use buffered_read).
    pub fn mem_read(&mut self, count: usize) -> Vec<u8> {
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

        // Handle ungetc byte first.
        if let Some(b) = self.ungetc_byte.take() {
            result.push(b);
            remaining -= 1;
            if remaining == 0 {
                if let Some(ref backing) = self.mem_backing {
                    self.offset = backing.position() as i64;
                } else {
                    self.advance_offset(1);
                }
                return result;
            }
        }

        if let Some(ref mut backing) = self.mem_backing {
            let data = backing.read(remaining);
            if data.len() < remaining {
                self.flags.eof = true;
            }
            result.extend(data);
            self.offset = backing.position() as i64;
        }
        result
    }

    /// Seek within a memory-backed stream.
    /// Returns the new position on success, or -1 on failure.
    pub fn mem_seek(&mut self, offset: i64, whence: i32) -> i64 {
        self.ungetc_byte = None;
        self.flags.eof = false;
        if let Some(ref mut backing) = self.mem_backing {
            if let Some(new_pos) = backing.seek(offset, whence) {
                self.offset = new_pos;
                new_pos
            } else {
                -1
            }
        } else {
            -1
        }
    }

    /// Get a reference to the memory backing data (for open_memstream sync).
    pub fn mem_data(&self) -> Option<&[u8]> {
        self.mem_backing.as_ref().map(|b| b.data())
    }

    /// Clone the memory backing data (for returning to C caller).
    pub fn mem_data_clone(&self) -> Option<Vec<u8>> {
        self.mem_backing.as_ref().map(|b| b.data_clone())
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
        assert!(parse_mode(b"rw").is_none());
        assert!(parse_mode(b"ar").is_none());
    }

    #[test]
    fn test_stream_write_buffer() {
        let flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        let result = s.buffer_write(b"hello").expect("write ok");
        assert!(!result.flush_needed);
        assert!(result.flush_data.is_empty()); // fully buffered, not full yet
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
        let first = writer.buffer_write(b"hello").expect("write ok");
        assert!(!first.flush_needed);
        writer.set_offset(writer.offset().saturating_add(first.buffered as i64));
        assert_eq!(writer.offset(), 5);
        let second = writer.buffer_write(b" world").expect("write ok");
        assert!(!second.flush_needed);
        writer.set_offset(writer.offset().saturating_add(second.buffered as i64));
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
    fn test_ungetc_single_byte_read_restores_offset() {
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
        let replay = s.buffered_read(1);
        assert_eq!(&replay, b"b");
        assert_eq!(s.offset(), 2);
    }

    #[test]
    fn test_prepare_seek_flushes_pending_writes_and_clears_read_state() {
        let flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        let result = s.buffer_write(b"buffered").expect("write ok");
        assert!(!result.flush_needed);
        assert_eq!(s.pending_flush(), b"buffered");

        assert!(s.ungetc(b'w'));
        assert!(s.readable_buffered() > 0);
        s.set_eof();

        let pending = s.prepare_seek();
        assert_eq!(&pending, b"buffered");
        assert!(s.pending_flush().is_empty());
        assert_eq!(s.readable_buffered(), 0);
        assert!(!s.is_eof());
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

    // -----------------------------------------------------------------------
    // MemBacking tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mem_backing_fixed_write_read() {
        let mut b = MemBacking::Fixed {
            data: vec![0u8; 32],
            pos: 0,
            content_end: 0,
        };
        assert_eq!(b.write(b"hello"), 5);
        assert_eq!(b.position(), 5);
        // Seek back to start.
        assert_eq!(b.seek(0, 0), Some(0));
        let out = b.read(5);
        assert_eq!(&out, b"hello");
        assert_eq!(b.position(), 5);
    }

    #[test]
    fn test_mem_backing_fixed_write_at_capacity() {
        let mut b = MemBacking::Fixed {
            data: vec![0u8; 4],
            pos: 0,
            content_end: 0,
        };
        // Writing more than capacity truncates.
        assert_eq!(b.write(b"abcdef"), 4);
        assert_eq!(b.data(), b"abcd");
    }

    #[test]
    fn test_mem_backing_fixed_read_past_content_end() {
        let mut b = MemBacking::Fixed {
            data: vec![0u8; 32],
            pos: 0,
            content_end: 3,
        };
        // Only 3 bytes of content available.
        let out = b.read(10);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn test_mem_backing_dynamic_write_grows() {
        let mut b = MemBacking::Dynamic {
            data: Vec::new(),
            pos: 0,
        };
        assert_eq!(b.write(b"hello"), 5);
        assert_eq!(b.write(b" world"), 6);
        assert_eq!(b.data(), b"hello world");
        assert_eq!(b.position(), 11);
    }

    #[test]
    fn test_mem_read_short_sets_eof() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(b"hi".to_vec(), 2, flags);
        let data = s.mem_read(4);
        assert_eq!(&data, b"hi");
        assert!(s.is_eof(), "EOF should be set after short mem_read");
    }

    #[test]
    fn test_mem_read_ungetc_updates_offset() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(b"ab".to_vec(), 2, flags);
        let first = s.mem_read(1);
        assert_eq!(&first, b"a");
        assert_eq!(s.offset(), 1);
        assert!(s.ungetc(b'a'));
        assert_eq!(s.offset(), 0);
        let replay = s.mem_read(1);
        assert_eq!(&replay, b"a");
        assert_eq!(s.offset(), 1);
    }

    #[test]
    fn test_mem_backing_dynamic_overwrite() {
        let mut b = MemBacking::Dynamic {
            data: Vec::new(),
            pos: 0,
        };
        b.write(b"hello world");
        // Seek to position 5 and overwrite.
        assert_eq!(b.seek(5, 0), Some(5));
        b.write(b"_RUST");
        assert_eq!(b.data(), b"hello_RUSTd");
    }

    #[test]
    fn test_mem_backing_dynamic_seek_past_end_grows_on_write() {
        let mut b = MemBacking::Dynamic {
            data: Vec::new(),
            pos: 0,
        };
        b.write(b"hi");
        // Seek past end and write; gap should be zero-filled.
        assert_eq!(b.seek(5, 0), Some(5));
        b.write(b"!");
        assert_eq!(b.data(), b"hi\0\0\0!");
    }

    #[test]
    fn test_mem_backing_dynamic_huge_seek_write_fails_without_panic() {
        let mut b = MemBacking::Dynamic {
            data: Vec::new(),
            pos: 0,
        };
        assert_eq!(b.seek(i64::MAX, 0), Some(i64::MAX));
        assert_eq!(b.write(b"!"), 0);
        assert!(b.data().is_empty());
        assert_eq!(b.position(), i64::MAX as usize);
    }

    #[test]
    fn test_mem_backing_seek_set_cur_end() {
        let mut b = MemBacking::Fixed {
            data: vec![0u8; 10],
            pos: 0,
            content_end: 5,
        };
        // SEEK_SET
        assert_eq!(b.seek(3, 0), Some(3));
        assert_eq!(b.position(), 3);
        // SEEK_CUR
        assert_eq!(b.seek(2, 1), Some(5));
        assert_eq!(b.position(), 5);
        // SEEK_END (relative to content_end for Fixed)
        assert_eq!(b.seek(-2, 2), Some(3));
        assert_eq!(b.position(), 3);
    }

    #[test]
    fn test_mem_backing_seek_invalid() {
        let mut b = MemBacking::Fixed {
            data: vec![0u8; 10],
            pos: 0,
            content_end: 5,
        };
        // Negative resulting position.
        assert_eq!(b.seek(-1, 0), None);
        // Past buffer size.
        assert_eq!(b.seek(11, 0), None);
        // Invalid whence.
        assert_eq!(b.seek(0, 99), None);
    }

    #[test]
    fn test_mem_backing_data_clone() {
        let b = MemBacking::Fixed {
            data: vec![1, 2, 3, 4, 5],
            pos: 0,
            content_end: 3,
        };
        let cloned = b.data_clone();
        assert_eq!(&cloned, &[1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // StdioStream memory-backed tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stream_mem_fixed_write_read_cycle() {
        let data = vec![0u8; 64];
        let flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(data, 0, flags);
        assert!(s.is_mem_backed());
        assert!(!s.is_closed());

        // Write.
        assert_eq!(s.mem_write(b"POSIX"), 5);
        assert_eq!(s.offset(), 5);

        // Seek back.
        assert_eq!(s.mem_seek(0, 0), 0);

        // Read.
        let out = s.mem_read(5);
        assert_eq!(&out, b"POSIX");
    }

    #[test]
    fn test_stream_mem_fixed_read_only() {
        let data = b"Hello, World!".to_vec();
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(data, 13, flags);

        let out = s.mem_read(5);
        assert_eq!(&out, b"Hello");

        // Writing should fail (not writable).
        assert_eq!(s.mem_write(b"x"), 0);
        assert!(s.is_error());
    }

    #[test]
    fn test_stream_mem_fixed_append_position() {
        let mut data = b"abc".to_vec();
        data.resize(16, 0);
        let flags = OpenFlags {
            writable: true,
            append: true,
            ..Default::default()
        };
        let s = StdioStream::new_mem_fixed(data, 3, flags);
        // Append mode: position starts at content_end.
        assert_eq!(s.offset(), 3);
    }

    #[test]
    fn test_stream_mem_dynamic_write_and_data() {
        let mut s = StdioStream::new_mem_dynamic();
        assert!(s.is_mem_backed());

        assert_eq!(s.mem_write(b"dynamic"), 7);
        assert_eq!(s.mem_write(b" stream"), 7);
        assert_eq!(s.offset(), 14);

        let data = s.mem_data().unwrap();
        assert_eq!(data, b"dynamic stream");
    }

    #[test]
    fn test_stream_mem_dynamic_data_clone() {
        let mut s = StdioStream::new_mem_dynamic();
        s.mem_write(b"test");
        let cloned = s.mem_data_clone().unwrap();
        assert_eq!(&cloned, b"test");
    }

    #[test]
    fn test_stream_mem_seek_resets_eof() {
        let data = vec![0u8; 8];
        let flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(data, 0, flags);
        s.set_eof();
        assert!(s.is_eof());
        s.mem_seek(0, 0);
        assert!(!s.is_eof());
    }

    #[test]
    fn test_stream_mem_read_sets_eof() {
        let data = b"ab".to_vec();
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(data, 2, flags);
        let out = s.mem_read(2);
        assert_eq!(&out, b"ab");
        // Next read at end should set EOF.
        let out2 = s.mem_read(1);
        assert!(out2.is_empty());
        assert!(s.is_eof());
    }

    #[test]
    fn test_stream_fd_not_mem_backed() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let s = StdioStream::new(3, flags);
        assert!(!s.is_mem_backed());
        assert!(s.mem_data().is_none());
    }
}
