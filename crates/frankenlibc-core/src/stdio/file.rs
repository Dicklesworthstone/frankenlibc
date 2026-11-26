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

use std::collections::VecDeque;

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
    /// GNU fopen's `c` modifier keeps descriptor I/O out of cancellation points.
    pub no_cancel: bool,
}

/// Runtime stream state flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamFlags {
    pub eof: bool,
    pub error: bool,
    /// True if any read or write has occurred.
    pub io_started: bool,
    /// Direction of the most recent I/O operation: true if it was a write,
    /// false if a read. Only meaningful when `io_started` is set. Drives
    /// `__freading`/`__fwriting` parity with glibc.
    pub last_write: bool,
    /// Stream orientation for `fwide`: 0 = unset, >0 = wide, <0 = byte.
    /// Sticky once set to a non-zero value.
    pub orientation: i32,
    /// `__fsetlocking` mode: false = FSETLOCKING_INTERNAL (the default), true =
    /// FSETLOCKING_BYCALLER.
    pub locking_bycaller: bool,
    /// Whether the fd can seek, probed once by the ABI: 0 = not yet known,
    /// 1 = seekable, 2 = not (pipe, socket, terminal).
    pub seekability: u8,
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

    // Modifiers, as glibc reads them: only the next six characters are
    // examined, a ',' (the ",ccs=" charset suffix) ends them, '+', 'b', 'x',
    // 'e', 'm', 'c' have meaning, and ANY other character is ignored --
    // "rt" (sed opens scripts with it), "rw", "r b" all open fine there.
    // Rejecting them made sed -f fail with EINVAL.
    while pos < mode.len() && pos < 7 {
        match mode[pos] {
            b',' => break,
            b'+' => {
                flags.readable = true;
                flags.writable = true;
            }
            b'b' => flags.binary = true,
            b'x' => flags.exclusive = true,
            b'e' => flags.cloexec = true,
            b'c' => flags.no_cancel = true,
            _ => {} // 'm': no-op here; anything else is ignored
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

/// Position and input buffering for a fixed, externally owned memory stream.
///
/// The ABI supplies bounded copies through closures: this model never borrows
/// caller memory across calls. Output buffering belongs to `StdioStream`; a
/// write here represents bytes actually delivered by its flush callback.
#[derive(Debug)]
pub struct FixedMemCursor {
    capacity: usize,
    position: usize,
    content_end: usize,
    append: bool,
    input_start: usize,
    input: Vec<u8>,
}

impl FixedMemCursor {
    pub fn new(capacity: usize, content_end: usize, append: bool) -> Self {
        Self::with_input_buffer(capacity, content_end, append, Vec::new())
    }

    pub fn with_input_buffer(
        capacity: usize,
        content_end: usize,
        append: bool,
        mut input: Vec<u8>,
    ) -> Self {
        input.clear();
        let content_end = content_end.min(capacity);
        Self {
            capacity,
            position: if append { content_end } else { 0 },
            content_end,
            append,
            input_start: 0,
            input,
        }
    }

    pub fn take_input_buffer(&mut self) -> Vec<u8> {
        self.input_start = 0;
        let mut buf = std::mem::take(&mut self.input);
        buf.clear();
        buf
    }

    /// Reset cursor state in place while keeping its pooled `input` buffer
    /// allocation (bounded to `64 KiB` so large transient buffers are released).
    #[inline]
    pub fn reset(&mut self, capacity: usize, content_end: usize, append: bool) {
        if self.input.capacity() > 64 * 1024 {
            self.input = Vec::new();
        } else {
            self.input.clear();
        }
        let content_end = content_end.min(capacity);
        self.capacity = capacity;
        self.position = if append { content_end } else { 0 };
        self.content_end = content_end;
        self.append = append;
        self.input_start = 0;
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn content_end(&self) -> usize {
        self.content_end
    }

    pub fn discard_input(&mut self) {
        self.input.clear();
    }

    /// A zero-distance seek preserves prefetched input, as on a cookie FILE.
    /// Other seeks invalidate it. The fixed capacity bounds SEEK_SET/CUR;
    /// SEEK_END is relative to the current logical extent.
    pub fn seek(&mut self, offset: i64, whence: i32) -> Option<usize> {
        let base = match whence {
            0 => 0,
            1 => i64::try_from(self.position).ok()?,
            2 => i64::try_from(self.content_end).ok()?,
            _ => return None,
        };
        let next = usize::try_from(base.checked_add(offset)?).ok()?;
        if next > self.capacity {
            return None;
        }
        if next != self.position {
            self.discard_input();
        }
        self.position = next;
        Some(next)
    }

    /// Copy input using a direct `Vec<u8>` refill callback (avoiding redundant
    /// zero-initialization before overwriting). Only a refill reads caller
    /// storage in buffered mode; unbuffered reads retain no snapshot.
    /// Fast buffered slice probe for single-threaded `fread` hits: if `len`
    /// bytes are already present in `self.input` at `self.position`, advances
    /// `self.position` by `len` and returns that contiguous slice without call overhead.
    #[inline(always)]
    pub fn try_take_buffered(&mut self, len: usize) -> Option<&[u8]> {
        let start = self.position.checked_sub(self.input_start)?;
        let end = start.checked_add(len)?;
        if end <= self.input.len() {
            self.position += len;
            Some(&self.input[start..end])
        } else {
            None
        }
    }

    #[inline]
    pub fn read_with_refill(
        &mut self,
        dst: &mut [u8],
        delimiter: Option<u8>,
        prefetch: usize,
        mut refill_into: impl FnMut(usize, usize, &mut Vec<u8>),
    ) -> usize {
        if delimiter.is_none()
            && let Some(start) = self.position.checked_sub(self.input_start)
            && let Some(end) = start.checked_add(dst.len())
            && end <= self.input.len()
        {
            dst.copy_from_slice(&self.input[start..end]);
            self.position += dst.len();
            return dst.len();
        }
        let mut written = 0;
        while written < dst.len() && self.position < self.content_end {
            let buffered = self.position.checked_sub(self.input_start);
            if buffered.is_none_or(|i| i >= self.input.len()) {
                self.input_start = self.position;
                let count = prefetch.max(1).min(self.content_end - self.position);
                self.input.clear();
                refill_into(self.position, count, &mut self.input);
                if self.input.len() > count {
                    self.input.truncate(count);
                }
                if self.input.is_empty() {
                    break;
                }
            }
            let start = self.position - self.input_start;
            let count = (dst.len() - written).min(self.input.len() - start);
            let bytes = &self.input[start..start + count];
            let stop = delimiter.and_then(|d| bytes.iter().position(|&b| b == d));
            let count = stop.map_or(count, |i| i + 1);
            dst[written..written + count].copy_from_slice(&bytes[..count]);
            self.position += count;
            written += count;
            if stop.is_some() {
                break;
            }
        }
        written
    }

    /// Copy input, optionally stopping after a delimiter. Only a refill reads
    /// caller storage in buffered mode; unbuffered reads retain no snapshot.
    pub fn read_into(
        &mut self,
        dst: &mut [u8],
        delimiter: Option<u8>,
        prefetch: usize,
        mut copy_from: impl FnMut(usize, &mut [u8]),
    ) -> usize {
        self.read_with_refill(dst, delimiter, prefetch, |start, count, input| {
            input.resize(count, 0);
            copy_from(start, input);
        })
    }

    /// Commit one output callback, touching only its byte range and any
    /// required terminator. Caller edits outside that range remain intact.
    pub fn write(&mut self, src: &[u8], mut copy_to: impl FnMut(usize, &[u8])) -> usize {
        self.discard_input();
        let start = if self.append {
            self.content_end
        } else {
            self.position
        };
        let count = src.len().min(self.capacity.saturating_sub(start));
        let needs_nul = src.last() != Some(&0);
        // On a short write, there must still be room for the terminator at
        // the starting position. A one-byte buffer cannot accept "abc".
        if count == 0
            || (count < src.len()
                && self.capacity.saturating_sub(self.position) <= usize::from(needs_nul))
        {
            return 0;
        }
        copy_to(start, &src[..count]);
        self.position = start + count;
        if self.position > self.content_end {
            self.content_end = self.position;
            if needs_nul {
                if self.content_end < self.capacity {
                    copy_to(self.content_end, &[0]);
                } else if !self.append {
                    copy_to(self.capacity - 1, &[0]);
                }
            }
        }
        count
    }
}

/// Memory backing for memory-based stdio streams.
///
/// `Fixed` is for `fmemopen`: a position-tracked buffer with a fixed maximum
/// size. `Dynamic` and `WideDynamic` are growable byte/wide write buffers.
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
    /// `open_wmemstream`: positions and storage are wchar_t elements, not
    /// bytes in a multibyte encoding. Retain the tail across backward seeks.
    WideDynamic { data: Vec<u32>, pos: usize },
}

/// Make a forward seek visible to a later flush or close, even when no
/// output follows it. Retained elements preceding the new extent survive.
fn extend_memstream<T: Default + Copy>(data: &mut Vec<T>, extent: usize) -> Result<(), i32> {
    if extent > data.len() {
        data.try_reserve(extent - data.len())
            .map_err(|_| crate::errno::ENOMEM)?;
        data.resize(extent, T::default());
    }
    Ok(())
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
            // Byte I/O is not admitted on a wide-oriented memory stream.
            MemBacking::WideDynamic { .. } => 0,
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
            MemBacking::WideDynamic { .. } => Vec::new(),
        }
    }

    /// Peek the remaining readable bytes from the current position without
    /// advancing it. Pairs with [`consume`](Self::consume) for scanning.
    pub fn peek(&self) -> &[u8] {
        match self {
            MemBacking::Fixed {
                data,
                pos,
                content_end,
            } => {
                let start = (*pos).min(*content_end);
                &data[start..*content_end]
            }
            MemBacking::Dynamic { data, pos } => {
                let start = (*pos).min(data.len());
                &data[start..]
            }
            MemBacking::WideDynamic { .. } => &[],
        }
    }

    /// Advance the read position by `n` bytes (clamped to the readable end).
    pub fn consume(&mut self, n: usize) {
        match self {
            MemBacking::Fixed {
                pos, content_end, ..
            } => {
                *pos = (*pos + n).min(*content_end);
            }
            MemBacking::Dynamic { data, pos } => {
                *pos = (*pos + n).min(data.len());
            }
            MemBacking::WideDynamic { .. } => {}
        }
    }

    /// Seek to a new position. `whence`: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END.
    pub fn seek(&mut self, offset: i64, whence: i32) -> Option<i64> {
        self.try_seek(offset, whence).ok()
    }

    fn try_seek(&mut self, offset: i64, whence: i32) -> Result<i64, i32> {
        use crate::errno::EINVAL;

        let base = match whence {
            0 => 0,
            1 => self.position(),
            // GNU growing streams use the current output position for SEEK_END.
            // The older tail remains in storage after a backward seek.
            2 => match self {
                Self::Fixed { content_end, .. } => *content_end,
                _ => self.position(),
            },
            _ => return Err(EINVAL),
        };
        let position = i64::try_from(base)
            .ok()
            .and_then(|base| base.checked_add(offset))
            .ok_or(EINVAL)?;
        let next = usize::try_from(position).map_err(|_| EINVAL)?;
        match self {
            Self::Fixed {
                pos, content_end, ..
            } => {
                if next > *content_end {
                    return Err(EINVAL);
                }
                *pos = next;
            }
            Self::Dynamic { data, pos } => {
                extend_memstream(data, next)?;
                *pos = next;
            }
            Self::WideDynamic { data, pos } => {
                extend_memstream(data, next)?;
                *pos = next;
            }
        }
        Ok(position)
    }

    /// Current position.
    pub fn position(&self) -> usize {
        match self {
            MemBacking::Fixed { pos, .. }
            | MemBacking::Dynamic { pos, .. }
            | MemBacking::WideDynamic { pos, .. } => *pos,
        }
    }

    /// Current data slice (for open_memstream sync).
    pub fn data(&self) -> &[u8] {
        match self {
            MemBacking::Fixed {
                data, content_end, ..
            } => &data[..*content_end],
            MemBacking::Dynamic { data, .. } => data.as_slice(),
            MemBacking::WideDynamic { .. } => &[],
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

/// Outcome of one [`StdioStream::read_until_delim`] step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadUntil {
    /// The delimiter was found and consumed into the output buffer.
    Found,
    /// The available buffered data was drained without finding the delimiter;
    /// an fd-backed caller should refill the buffer before calling again.
    NeedRefill,
    /// No more data is available (EOF / memory backing exhausted).
    Eof,
}

/// Wide input backup is independent of the external byte encoding. Keep one
/// character inline so the guaranteed first pushback never needs allocation;
/// further successful pushes are returned in last-in-first-out order.
#[derive(Debug, Default)]
struct WidePushback {
    first: Option<(u32, u8)>,
    rest: Vec<(u32, u8)>,
    /// External-byte position adjustment for representable characters only.
    bytes: usize,
}

impl WidePushback {
    fn push(&mut self, value: u32, width: u8) -> bool {
        let Some(bytes) = self.bytes.checked_add(usize::from(width)) else {
            return false;
        };
        if let Some(previous) = self.first {
            if self.rest.try_reserve(1).is_err() {
                return false;
            }
            self.rest.push(previous);
        }
        self.first = Some((value, width));
        self.bytes = bytes;
        true
    }

    fn pop(&mut self) -> Option<(u32, u8)> {
        let entry = self.first.take()?;
        self.first = self.rest.pop();
        self.bytes -= usize::from(entry.1);
        Some(entry)
    }

    fn clear(&mut self) {
        self.first = None;
        self.rest.clear();
        self.bytes = 0;
    }
}

/// Wide output remains in characters until a flush chooses its transliteration
/// locale. Its encoded batch and acknowledged prefix belong to the stream, so
/// cancellation cannot lose or replay bytes already delivered to the fd.
///
/// GNU wide streams retain the complete character batch on an ordinary write
/// error, even if a prefix reached the fd. A later retry converts that batch
/// again using its then-current locale. Cancellation instead leaves the encoded
/// cursor intact for a cleanup handler to finish the suffix.
#[derive(Debug, Default)]
struct WideOutputBuffer {
    initialized: bool,
    user_supplied: bool,
    characters: VecDeque<u32>,
    encoded: Vec<u8>,
    encoded_characters: usize,
    consumed: usize,
}

impl WideOutputBuffer {
    fn clear(&mut self) {
        self.characters.clear();
        self.retry();
    }

    fn retry(&mut self) {
        self.encoded.clear();
        self.encoded_characters = 0;
        self.consumed = 0;
    }

    fn append_character(
        destination: &mut Vec<u8>,
        codec: crate::iconv::MultibyteCodec,
        value: u32,
        utf8_transliteration: bool,
    ) -> Result<(), i32> {
        let mut encoded = [0u8; 6];
        if let Some(length) = codec.encode(value, &mut encoded) {
            destination
                .try_reserve(length)
                .map_err(|_| crate::errno::ENOMEM)?;
            destination.extend_from_slice(&encoded[..length]);
            return Ok(());
        }

        let mut replacement = crate::iconv::transliteration(value, utf8_transliteration);
        // The table supplies ASCII characters, not external bytes. Preflight
        // the whole replacement before encoding it (notably for EBCDIC).
        if !replacement
            .iter()
            .all(|&byte| codec.encode(u32::from(byte), &mut encoded).is_some())
        {
            replacement = b"?";
        }
        for &byte in replacement {
            let length = codec
                .encode(u32::from(byte), &mut encoded)
                .ok_or(crate::errno::EILSEQ)?;
            destination
                .try_reserve(length)
                .map_err(|_| crate::errno::ENOMEM)?;
            destination.extend_from_slice(&encoded[..length]);
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        codec: crate::iconv::MultibyteCodec,
        utf8_transliteration: bool,
    ) -> Result<(), i32> {
        if self.encoded_characters != 0 || self.characters.is_empty() {
            return Ok(());
        }
        for &value in &self.characters {
            if let Err(error) =
                Self::append_character(&mut self.encoded, codec, value, utf8_transliteration)
            {
                // No descriptor I/O happened: keep the original characters
                // and discard this incomplete conversion transaction.
                self.retry();
                return Err(error);
            }
        }
        self.encoded_characters = self.characters.len();
        if self.encoded.is_empty() {
            // Empty transliterations still consume their source characters.
            self.consume(0);
        }
        Ok(())
    }

    fn consume(&mut self, count: usize) -> usize {
        let acknowledged = count.min(self.encoded.len().saturating_sub(self.consumed));
        self.consumed += acknowledged;
        if self.consumed == self.encoded.len() && self.encoded_characters != 0 {
            // A caller may have appended characters after staging this batch.
            // Commit only the source prefix represented by these bytes.
            drop(self.characters.drain(..self.encoded_characters));
            self.retry();
        }
        acknowledged
    }

    fn pending_offset(
        &self,
        codec: crate::iconv::MultibyteCodec,
        utf8_transliteration: bool,
    ) -> usize {
        let width = if let Some(width) = codec.fixed_width() {
            self.characters.len().saturating_mul(width)
        } else {
            let mut encoded = [0u8; 6];
            self.characters.iter().fold(0usize, |total, &value| {
                let width = if let Some(length) = codec.encode(value, &mut encoded) {
                    length
                } else {
                    let mut replacement =
                        crate::iconv::transliteration(value, utf8_transliteration);
                    // Match physical output's whole-replacement preflight,
                    // without allocating or staging bytes during ftell.
                    if !replacement
                        .iter()
                        .all(|&byte| codec.encode(u32::from(byte), &mut encoded).is_some())
                    {
                        replacement = b"?";
                    }
                    replacement.iter().fold(0usize, |length, &byte| {
                        length.saturating_add(
                            codec.encode(u32::from(byte), &mut encoded).unwrap_or(0),
                        )
                    })
                };
                total.saturating_add(width)
            })
        };
        // offset already includes acknowledged descriptor bytes. An ordinary
        // error resets consumed because GNU will replay the retained batch.
        width.saturating_sub(self.consumed)
    }
}

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
    /// Conversion engine fixed when the ABI first orients this stream wide.
    wide_codec: Option<crate::iconv::MultibyteCodec>,
    /// Deferred characters and cancellation-safe conversion state for fd output.
    wide_output: WideOutputBuffer,
    /// Logical file position (for seekable streams), excluding unacknowledged
    /// wide output. Narrow buffered writes are already included.
    offset: i64,
    /// One-byte pushback for ungetc (layered on top of buffer).
    ungetc_byte: Option<u8>,
    /// Overflow pushback and bytes returned by scanner or wide-read rollback.
    read_pushback: VecDeque<u8>,
    /// Complete wchar_t values pushed by ungetwc, before any external bytes.
    wide_pushback: WidePushback,
    /// Optional memory backing for fmemopen/open_memstream.
    mem_backing: Option<MemBacking>,
    /// Bytes accepted into the modelled `BUFSIZ` stdio buffer since the last
    /// flush on a `MemBacking::Fixed` (`fmemopen`) stream (bd-lamxlj).
    mem_pending_write: usize,
    /// Bytes accepted into the modelled `BUFSIZ` stdio buffer beyond the fixed
    /// backing capacity since the last flush on a `MemBacking::Fixed` stream.
    /// Reported as a flush error (`EOF`, `ferror`) on `fflush`/`fseek`/`fclose`.
    mem_pending_overflow: usize,
    /// Opaque token naming the C `FILE` this stream is published through
    /// (0: none). The ABI layer uses it to find the handle whose glibc read
    /// window mirrors [`read_window`](Self::read_window).
    c_handle: usize,
}

impl StdioStream {
    /// Whether descriptor reads/writes may act on a pending thread cancellation.
    /// This follows the stream, including after buffering-mode changes.
    pub fn cancellation_enabled(&self) -> bool {
        !self.open_flags.no_cancel
    }

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
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: 0,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: None,
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    /// Create a stream wrapping an existing fd with specified buffering.
    pub fn with_mode(fd: i32, open_flags: OpenFlags, buf_mode: BufMode) -> Self {
        Self {
            fd,
            buffer: StreamBuffer::new(buf_mode, BUFSIZ),
            open_flags,
            flags: StreamFlags::default(),
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: 0,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: None,
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    /// Reset a recycled `StdioStream` in place for a fresh `fmemopen` lifecycle.
    #[inline]
    pub fn reset_for_fmemopen(&mut self, open_flags: OpenFlags, offset: i64, c_handle: usize) {
        self.fd = -1;
        self.buffer.reset_for_reuse(BufMode::Full, BUFSIZ);
        self.open_flags = open_flags;
        self.flags = StreamFlags {
            orientation: -1,
            ..StreamFlags::default()
        };
        self.wide_codec = None;
        self.wide_output.clear();
        self.wide_output.initialized = false;
        self.wide_output.user_supplied = false;
        self.offset = offset;
        self.ungetc_byte = None;
        self.read_pushback.clear();
        self.wide_pushback.clear();
        self.mem_backing = None;
        self.mem_pending_write = 0;
        self.mem_pending_overflow = 0;
        self.c_handle = c_handle;
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
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: pos as i64,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: Some(MemBacking::Fixed {
                data,
                pos,
                content_end: cl,
            }),
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    /// Create a read-only memory stream that carries NO data internally.
    ///
    /// Used by fmemopen read-only mode (bd-rv2gv6): the content lives in the
    /// registered `FastFixedMemRead` cursor (which owns its own copy), and ALL
    /// reads — fast path and fallback — are served from that cursor. The
    /// stream's `mem_backing` is present only for seek/ftell position tracking
    /// (`content_end` drives clamping; `data` is empty because the generic
    /// mem-read path is unreachable for properly registered streams).
    ///
    /// This eliminates the 4 KiB stream-side copy per fmemopen open
    /// (bd-rv2gv6: the copy was redundant with the cursor's copy).
    pub fn new_mem_fixed_readonly(content_len: usize, open_flags: OpenFlags) -> Self {
        let pos = if open_flags.append { content_len } else { 0 };
        Self {
            fd: -2,
            buffer: StreamBuffer::new(BufMode::None, 0),
            open_flags,
            flags: StreamFlags::default(),
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: pos as i64,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: Some(MemBacking::Fixed {
                data: Vec::new(),
                pos,
                content_end: content_len,
            }),
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    /// Orientation as glibc reports it in `FILE::_mode`: explicit orientation,
    /// or byte (-1) once any byte I/O happened on an unoriented stream.
    pub fn effective_orientation(&self) -> i32 {
        if self.flags.orientation == 0 && self.flags.io_started {
            -1
        } else {
            self.flags.orientation
        }
    }

    /// Bind an immutable conversion engine once. Later locale selections,
    /// seeks, and buffering changes cannot replace a wide stream's encoding.
    pub fn bind_wide_codec(&mut self, codec: crate::iconv::MultibyteCodec) {
        self.wide_codec.get_or_insert(codec);
    }

    #[must_use]
    pub fn wide_codec(&self) -> Option<crate::iconv::MultibyteCodec> {
        self.wide_codec
    }

    /// Give a [`Self::new_mem_fixed_readonly`] stream its bytes.
    ///
    /// That constructor leaves the generic backing empty because the ABI's
    /// fast cursor owns the bytes, but not every operation goes through the
    /// cursor (`fscanf`, for one), and the generic read then indexed an empty
    /// buffer and panicked across the FFI boundary (process abort). The ABI
    /// calls this when it hands the stream back to the generic path; it is a
    /// no-op once the data is present.
    pub fn materialize_mem_fixed_data(&mut self, bytes: &[u8]) {
        if let Some(MemBacking::Fixed {
            data, content_end, ..
        }) = &mut self.mem_backing
            && data.is_empty()
            && *content_end > 0
        {
            let n = (*content_end).min(bytes.len());
            data.extend_from_slice(&bytes[..n]);
            data.resize(*content_end, 0);
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
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: 0,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: Some(MemBacking::Dynamic {
                data: Vec::new(),
                pos: 0,
            }),
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    /// Create a wide memory stream whose seek/tell offsets count wchar_t
    /// elements. Values are stored verbatim, independently of LC_CTYPE.
    pub fn new_mem_wide_dynamic() -> Self {
        let mut stream = Self::new_mem_dynamic();
        stream.mem_backing = Some(MemBacking::WideDynamic {
            data: Vec::new(),
            pos: 0,
        });
        stream.flags.orientation = 1;
        stream
    }

    /// Create a dynamic memory-backed stream with custom open flags.
    /// Used by fopencookie where the mode determines read/write permissions.
    pub fn new_mem_dynamic_with_flags(open_flags: OpenFlags) -> Self {
        Self {
            fd: -2,
            buffer: StreamBuffer::new(BufMode::None, 0),
            open_flags,
            flags: StreamFlags::default(),
            wide_codec: None,
            wide_output: WideOutputBuffer::default(),
            offset: 0,
            ungetc_byte: None,
            read_pushback: VecDeque::new(),
            wide_pushback: WidePushback::default(),
            c_handle: 0,
            mem_backing: Some(MemBacking::Dynamic {
                data: Vec::new(),
                pos: 0,
            }),
            mem_pending_write: 0,
            mem_pending_overflow: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Get the underlying file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Seekability of the fd as last recorded (see [`StreamFlags::seekability`]).
    pub fn seekability(&self) -> u8 {
        self.flags.seekability
    }

    /// Record the fd's seekability (1 seekable, 2 not).
    pub fn set_seekability(&mut self, value: u8) {
        self.flags.seekability = value;
    }

    /// Whether writes append (`"a"`/`"a+"`, O_APPEND): the kernel, not the
    /// stream's position, decides where written bytes land.
    pub fn is_appending(&self) -> bool {
        self.open_flags.append
    }

    /// Check if the stream is readable.
    pub fn is_readable(&self) -> bool {
        self.open_flags.readable
    }

    /// Check if the stream is writable.
    pub fn is_writable(&self) -> bool {
        self.open_flags.writable
    }

    /// Check if the stream was opened with truncation semantics.
    pub fn is_truncating(&self) -> bool {
        self.open_flags.truncate
    }

    /// True iff the most recent I/O operation on this stream was a read.
    /// (False before any operation.) Used by `__freading`.
    pub fn last_was_read(&self) -> bool {
        self.flags.io_started && !self.flags.last_write
    }

    /// True iff the most recent I/O operation on this stream was a write.
    /// (False before any operation.) Used by `__fwriting`.
    pub fn last_was_write(&self) -> bool {
        self.flags.io_started && self.flags.last_write
    }

    /// `fwide` semantics: if the orientation is still unset and `mode` is
    /// non-zero, fix it (wide for mode > 0, byte for mode < 0); orientation is
    /// sticky thereafter. Returns the resulting orientation (>0 wide, <0 byte,
    /// 0 unset).
    pub fn set_orientation(&mut self, mode: i32) -> i32 {
        // Byte I/O on an unoriented stream fixes it as byte-oriented (glibc:
        // `fwide(fp, 0)` after `putc` returns -1, and `fwide(fp, 1)` cannot
        // switch it afterwards).
        if self.flags.orientation == 0 && self.flags.io_started {
            self.flags.orientation = -1;
        }
        if self.flags.orientation == 0 && mode != 0 {
            self.flags.orientation = if mode > 0 { 1 } else { -1 };
        }
        self.flags.orientation
    }

    /// `__fpurge`: discard all buffered data — unread input and unflushed
    /// output, plus any pushed-back bytes — without writing it out.
    ///
    /// The logical offset already counts buffered writes and excludes unread
    /// read-ahead, so it moves back to the descriptor's offset, as glibc's
    /// ftell reports after `__fpurge`: before the discarded writes (gnulib
    /// test-fpurge expects 4 after `fflush` at 4 then 2 purged bytes), and past
    /// the discarded read-ahead.
    pub fn purge(&mut self) {
        let pending = self.buffer.pending_write_data().len() as i64;
        let unread = self.unread_bytes_for_position() as i64;
        self.offset = self.offset - pending + unread;
        self.buffer.reset();
        self.wide_output.clear();
        self.ungetc_byte = None;
        self.read_pushback.clear();
        self.wide_pushback.clear();
    }

    /// Whether the caller owns synchronization of ordinary stream operations.
    #[inline]
    pub fn locking_bycaller(&self) -> bool {
        self.flags.locking_bycaller
    }

    /// `__fsetlocking`: FSETLOCKING_QUERY(0) only reports the current locking
    /// mode; INTERNAL(1)/BYCALLER(2) change it. Returns the mode that was in
    /// effect BEFORE the call (glibc returns the previous mode on a set and the
    /// current mode on a query), encoded as 1 (INTERNAL) or 2 (BYCALLER).
    pub fn set_locking(&mut self, typ: i32) -> i32 {
        let prev = if self.flags.locking_bycaller { 2 } else { 1 };
        match typ {
            1 => self.flags.locking_bycaller = false, // FSETLOCKING_INTERNAL
            2 => self.flags.locking_bycaller = true,  // FSETLOCKING_BYCALLER
            _ => {}                                   // FSETLOCKING_QUERY / other
        }
        prev
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
        if self.wide_output.initialized {
            return false;
        }
        self.buffer.set_mode(mode, size)
    }

    /// `setvbuf` on a stream already in use, which glibc accepts. With
    /// `keep_buffer` (no caller buffer, Full or Line) the mode flips in place
    /// and buffered bytes stay; otherwise the caller has synced the stream
    /// (flushed staged output, given back unread input it could) and the
    /// buffer is rebuilt. Returns false if output is still staged.
    pub fn rebuffer(&mut self, mode: BufMode, size: usize, keep_buffer: bool) -> bool {
        if keep_buffer && !matches!(mode, BufMode::None) {
            self.buffer.switch_mode_in_place(mode, size);
            return true;
        }
        if !self.buffer.pending_write_data().is_empty()
            || !self.wide_output.characters.is_empty()
            || !self.wide_output.encoded.is_empty()
        {
            return false;
        }
        let eof = self.flags.eof;
        let _ = self.prepare_seek();
        self.flags.eof = eof;
        let accepted = self.buffer.rebuild_after_sync(mode, size);
        if accepted {
            self.wide_output.initialized = false;
        }
        accepted
    }

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    /// Capacity of the independent wide buffer, in wchar_t elements.
    /// GNU uses one wide slot per byte of owned storage, but caller-provided
    /// storage contributes one slot per rounded-up wchar_t. Unbuffered output
    /// still needs one character for conversion.
    #[must_use]
    pub fn wide_output_capacity(&self) -> usize {
        let bytes = self.buffer.capacity();
        if self.wide_output.user_supplied {
            bytes.div_ceil(std::mem::size_of::<u32>()).max(1)
        } else {
            bytes.max(1)
        }
    }

    /// Record ownership after a successful setvbuf buffer replacement.
    /// A NULL-buffer mode change preserves the previous ownership.
    pub fn set_wide_buffer_user_supplied(&mut self, user_supplied: bool) {
        self.wide_output.user_supplied = user_supplied;
    }

    /// Whether descriptor I/O has materialized this stream's logical wide buffer.
    #[must_use]
    pub fn wide_output_initialized(&self) -> bool {
        self.wide_output.initialized
    }

    /// Record primary wide-buffer initialization before descriptor input.
    /// Wide pushback alone does not initialize this buffer.
    pub fn mark_wide_buffer_initialized(&mut self) {
        self.wide_output.initialized = true;
    }

    /// Number of queued wchar_t values, including a partially written batch.
    /// GNU retains the complete batch until its descriptor write succeeds.
    #[must_use]
    pub fn pending_wide_output(&self) -> usize {
        self.wide_output.characters.len()
    }

    /// Queue as many wide characters as fit without converting or flushing.
    /// The ABI chooses line-buffer boundaries and flushes a full buffer.
    /// None means permission failure. For nonempty input with available room,
    /// Some(0) means allocation failure; both failures set the stream error.
    pub fn buffer_wide_write(&mut self, data: &[u32]) -> Option<usize> {
        if !self.open_flags.writable {
            self.flags.error = true;
            return None;
        }
        let room = self
            .wide_output_capacity()
            .saturating_sub(self.wide_output.characters.len());
        let count = room.min(data.len());
        if self.wide_output.characters.try_reserve(count).is_err() {
            self.flags.error = true;
            return Some(0);
        }
        self.wide_output
            .characters
            .extend(data[..count].iter().copied());
        self.wide_output.initialized = true;
        self.flags.io_started = true;
        self.flags.last_write = true;
        self.flags.eof = false;
        // setvbuf must observe wide I/O even before external bytes exist.
        // An empty narrow write marks use without staging or allocating bytes.
        let _ = self.buffer.write(&[]);
        Some(count)
    }

    /// Convert the queued batch through the FILE's immutable external codec,
    /// selecting transliteration from the locale active at physical conversion.
    /// An already staged suffix survives cancellation without reconversion.
    /// Failed conversion leaves all source characters available for retry.
    pub fn prepare_wide_flush(&mut self, utf8_transliteration: bool) -> Result<(), i32> {
        let codec = self
            .wide_codec
            .unwrap_or(crate::iconv::MultibyteCodec::Ascii);
        let result = self.wide_output.prepare(codec, utf8_transliteration);
        if result.is_err() {
            self.flags.error = true;
        }
        result
    }

    /// Remaining external bytes of the staged wide batch. The stream owns this
    /// slice across cancellable writes, including partially written characters.
    #[must_use]
    pub fn pending_wide_flush(&self) -> &[u8] {
        &self.wide_output.encoded[self.wide_output.consumed..]
    }

    /// Commit a descriptor's acknowledged prefix before another cancellation
    /// point. Only complete batch delivery consumes its original characters.
    pub fn consume_wide_flushed_prefix(&mut self, count: usize) {
        let acknowledged = self.wide_output.consume(count);
        self.advance_offset(acknowledged);
    }

    /// An ordinary GNU write error retains and later reencodes the complete
    /// wchar batch, including any prefix the descriptor accepted. Cancellation
    /// must not call this: cleanup resumes at the retained encoded cursor.
    pub fn retry_wide_flush(&mut self) {
        self.wide_output.retry();
    }

    /// Pending byte-position adjustment without flushing or materializing
    /// conversion. GNU fixed-width streams count source wchar_t units times
    /// their width, even when transliteration expands them. Variable-width
    /// streams measure conversion under the current locale without staging
    /// bytes. Acknowledged staged bytes already contribute to offset.
    #[must_use]
    pub fn pending_wide_offset(&self, utf8_transliteration: bool) -> usize {
        let codec = self
            .wide_codec
            .unwrap_or(crate::iconv::MultibyteCodec::Ascii);
        self.wide_output.pending_offset(codec, utf8_transliteration)
    }

    /// Buffer a write and return the buffering outcome.
    ///
    /// Caller is responsible for flushing `flush_data` and advancing the
    /// logical offset by the number of bytes accepted for this call.
    pub fn buffer_write<'a>(&mut self, data: &'a [u8]) -> Option<WriteResult<'a>> {
        if !self.open_flags.writable {
            self.flags.error = true;
            return None;
        }
        self.flags.io_started = true;
        self.flags.last_write = true;
        self.flags.eof = false;
        Some(self.buffer.write(data))
    }

    /// Fast single-byte buffered write for the common case (Full-buffered fd stream
    /// with room). Returns `true` iff the byte was appended with no flush — exactly
    /// the `buffer_write(&[byte])` path that returns `WriteResult { flush_needed:
    /// false, .. }`, PLUS the caller's usual `set_offset(offset + 1)`. Returns `false`
    /// (caller falls back to the full `buffer_write` + flush path, unchanged) for a
    /// non-writable, mem-backed, Line/unbuffered, or full-buffer stream. Sets the same
    /// flags as `buffer_write` so observable state is byte-identical.
    #[inline]
    pub fn fast_putc(&mut self, byte: u8) -> bool {
        if !self.open_flags.writable || self.is_mem_backed() {
            return false;
        }
        if self.buffer.fast_putc(byte) {
            self.flags.io_started = true;
            self.flags.last_write = true;
            self.flags.eof = false;
            self.offset = self.offset.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Fast multi-byte buffered write (bulk sibling of `fast_putc`): appends `data` iff a
    /// Full-buffered fd stream has room for all of it (no flush) — byte-identical to the
    /// no-flush `buffer_write(data)` path plus the caller's `set_offset(offset + len)`.
    /// Returns `false` (caller falls back to the full path) otherwise.
    #[inline]
    pub fn fast_write(&mut self, data: &[u8]) -> bool {
        if !self.open_flags.writable || self.is_mem_backed() {
            return false;
        }
        if self.buffer.fast_write(data) {
            self.flags.io_started = true;
            self.flags.last_write = true;
            self.flags.eof = false;
            self.offset = self.offset.saturating_add(data.len() as i64);
            true
        } else {
            false
        }
    }

    /// Like `fast_write`, but also buffers non-newline bytes on `BufMode::Line` streams.
    #[inline]
    pub fn fast_write_line_or_full(&mut self, data: &[u8]) -> bool {
        if !self.open_flags.writable || self.is_mem_backed() {
            return false;
        }
        if self.buffer.fast_write_line_or_full(data) {
            self.flags.io_started = true;
            self.flags.last_write = true;
            self.flags.eof = false;
            self.offset = self.offset.saturating_add(data.len() as i64);
            true
        } else {
            false
        }
    }

    /// Fast single-byte buffered read for the common case: returns `Some(byte)` iff a byte
    /// is already in the read buffer for a clean readable fd stream — reusing
    /// `buffered_read_into` (which advances the cursor/offset and clears `last_write`).
    /// Returns `None` (caller falls back to the full path: refill / ungetc / transition /
    /// mem) for an empty buffer, a write-pending stream, pending ungetc/pushback, a
    /// mem-backed or non-readable stream. The C read/write-transition contract guarantees
    /// the buffer is in a clean read state here.
    #[inline]
    pub fn fast_getc(&mut self) -> Option<u8> {
        if !self.open_flags.readable
            || self.is_mem_backed()
            || self.flags.last_write
            || self.ungetc_byte.is_some()
            || !self.read_pushback.is_empty()
        {
            return None;
        }
        // Lean in-buffer read mirroring `buffered_read_into`'s effects for the buffered
        // single-byte case (io_started=true, last_write=false, offset+1), skipping its
        // dst-slice machinery and the redundant gates already checked above. `None` ⇒
        // buffer exhausted ⇒ caller refills on the slow path.
        match self.buffer.fast_getc() {
            Some(b) => {
                self.flags.io_started = true;
                self.flags.last_write = false;
                self.advance_offset(1);
                Some(b)
            }
            None => None,
        }
    }

    /// Fast `puts`: append `body` + `'\n'` iff a Full-buffered fd stream has room for all
    /// of it (no flush) — byte-identical to `buffer_write(body)` then `buffer_write(b"\n")`
    /// plus the offset bump. Returns `false` (caller's full path) otherwise.
    #[inline]
    pub fn fast_puts(&mut self, body: &[u8]) -> bool {
        if !self.open_flags.writable || self.is_mem_backed() {
            return false;
        }
        if self.buffer.fast_write_line(body) {
            self.flags.io_started = true;
            self.flags.last_write = true;
            self.flags.eof = false;
            self.offset = self.offset.saturating_add(body.len() as i64 + 1);
            true
        } else {
            false
        }
    }

    /// The buffered, not yet consumed bytes a caller may read in place: what
    /// glibc exposes as `[_IO_read_ptr, _IO_read_end)`, which the inline
    /// `getc_unlocked` and gnulib's freadahead/freadptr/freadseek read and
    /// advance directly. `None` unless the stream is a readable fd stream in a
    /// clean read state (no pending write, no pushed-back bytes, which must be
    /// returned first) with bytes buffered. The slice stays valid until the
    /// stream is next modified.
    pub fn read_window(&self) -> Option<&[u8]> {
        if !self.open_flags.readable
            || self.is_mem_backed()
            || self.flags.last_write
            || self.flags.orientation > 0
            || self.ungetc_byte.is_some()
            || !self.read_pushback.is_empty()
        {
            return None;
        }
        let window = self.buffer.peek();
        (!window.is_empty()).then_some(window)
    }

    /// Whether the C handle reports this stream as buffered (`_IO_UNBUFFERED`
    /// clear): an fd-backed stream in Full or Line mode, as glibc reports it.
    /// Code poking glibc's FILE fills such a stream's buffer in place ({fmt}
    /// does once the bit is clear, after an `__overflow` that must leave a
    /// [`write_window`](Self::write_window) behind), so memory-backed streams,
    /// which never publish one, stay reported as unbuffered.
    pub fn reports_buffered(&self) -> bool {
        !self.is_mem_backed() && !matches!(self.buffer.mode(), BufMode::None)
    }

    /// Whether this stream can ever publish a [`write_window`](Self::write_window):
    /// a writable stream [reported as buffered](Self::reports_buffered).
    pub fn write_window_capable(&self) -> bool {
        self.open_flags.writable && self.reports_buffered() && self.flags.orientation <= 0
    }

    /// The write buffer a caller may fill in place, as `(base address, bytes
    /// staged, capacity)`: what glibc exposes as `[_IO_write_base,
    /// _IO_write_ptr, _IO_write_end)`, which the inline `putc_unlocked` fills
    /// directly. `None` unless the stream is [`write_window_capable`] and in
    /// write mode (its last operation wrote), so a read-mode stream keeps only
    /// its read window. Bytes stored in place are accounted for by
    /// [`commit_write_window`](Self::commit_write_window).
    ///
    /// [`write_window_capable`]: Self::write_window_capable
    pub fn write_window(&self) -> Option<(usize, usize, usize)> {
        if !self.write_window_capable() || !self.flags.last_write {
            return None;
        }
        self.buffer.write_window()
    }

    /// Account for the caller having filled the write window up to `used`
    /// bytes from its base (see [`write_window`](Self::write_window)).
    pub fn commit_write_window(&mut self, used: usize) {
        let added = self.buffer.commit_write(used);
        if added == 0 {
            return;
        }
        self.flags.io_started = true;
        self.flags.last_write = true;
        self.flags.eof = false;
        let _ = self.set_orientation(-1);
        self.offset = self.offset.saturating_add(added as i64);
    }

    /// The opaque C handle token set by [`set_c_handle`](Self::set_c_handle).
    #[inline]
    pub fn c_handle(&self) -> usize {
        self.c_handle
    }

    /// Record the C `FILE` handle token this stream is published through.
    pub fn set_c_handle(&mut self, handle: usize) {
        self.c_handle = handle;
    }

    /// Account for the first `n` bytes of [`read_window`](Self::read_window)
    /// having been consumed in place by the caller.
    pub fn consume_window(&mut self, n: usize) {
        let n = n.min(self.buffer.readable());
        if n == 0 {
            return;
        }
        self.buffer.consume(n);
        self.flags.io_started = true;
        self.flags.last_write = false;
        let _ = self.set_orientation(-1);
        self.advance_offset(n);
    }

    /// Fast bulk buffered read (bulk sibling of `fast_getc`): fills `dst` entirely iff all
    /// `dst.len()` bytes are already buffered for a clean readable fd stream (no refill).
    /// Mirrors `buffered_read_into`'s io_started/last_write/offset effects. Returns `false`
    /// (caller falls back to the full path) otherwise.
    #[inline]
    pub fn fast_read(&mut self, dst: &mut [u8]) -> bool {
        if !self.open_flags.readable
            || self.is_mem_backed()
            || self.flags.last_write
            || self.ungetc_byte.is_some()
            || !self.read_pushback.is_empty()
        {
            return false;
        }
        if self.buffer.fast_read(dst) {
            self.flags.io_started = true;
            self.flags.last_write = false;
            self.advance_offset(dst.len());
            true
        } else {
            false
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

    /// Remove an acknowledged write prefix without changing the logical
    /// position, which already includes all buffered output. Call this before
    /// a following descriptor write can cancel or fail, so cleanup cannot
    /// replay bytes already accepted by the kernel.
    pub fn consume_flushed_prefix(&mut self, count: usize) {
        self.buffer.consume_flushed_prefix(count);
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
        self.flags.last_write = false;

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

        while remaining > 0 {
            let Some(b) = self.read_pushback.pop_front() else {
                break;
            };
            result.push(b);
            remaining -= 1;
        }
        if remaining == 0 {
            self.advance_offset(result.len());
            return result;
        }

        // Then read from buffer.
        let data = self.buffer.read(remaining);
        result.extend_from_slice(data);
        self.advance_offset(result.len());
        result
    }

    /// Zero-allocation sibling of [`buffered_read`](Self::buffered_read): fills
    /// `dst` from the ungetc byte, pushback queue, then the read buffer, and
    /// returns the number of bytes written. Behaviour is byte-for-byte identical
    /// to `buffered_read(dst.len())` followed by a copy into `dst` — but it writes
    /// straight into the caller's buffer, so `fread` no longer allocates a
    /// throwaway `Vec` per call (which, in the shipped `libc.so`, would route
    /// through the security-membrane allocator at ~100 ns each).
    pub fn buffered_read_into(&mut self, dst: &mut [u8]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        if !self.open_flags.readable {
            self.flags.error = true;
            return 0;
        }
        self.flags.io_started = true;
        self.flags.last_write = false;

        let mut w = 0usize;

        if let Some(b) = self.ungetc_byte.take() {
            dst[w] = b;
            w += 1;
            if w == dst.len() {
                self.advance_offset(w);
                return w;
            }
        }

        while w < dst.len() {
            let Some(b) = self.read_pushback.pop_front() else {
                break;
            };
            dst[w] = b;
            w += 1;
        }
        if w == dst.len() {
            self.advance_offset(w);
            return w;
        }

        let data = self.buffer.read(dst.len() - w);
        let n = data.len();
        dst[w..w + n].copy_from_slice(data);
        w += n;
        self.advance_offset(w);
        w
    }

    /// Number of bytes available for reading without I/O.
    pub fn readable_buffered(&self) -> usize {
        self.ungetc_byte.is_some() as usize + self.read_pushback.len() + self.buffer.readable()
    }

    /// Bytes by which the backend cursor leads the logical input position.
    /// Wide backup may contain values that cannot be externally encoded. Those
    /// values have no invented byte width, and are still returned verbatim.
    /// This is position bookkeeping, not a count of bytes available to fread.
    pub fn unread_bytes_for_position(&self) -> usize {
        self.readable_buffered()
            .saturating_add(self.wide_pushback.bytes)
    }

    /// Whether a wide read must consume a complete pushed-back character
    /// before touching any external bytes, including ASCII fast paths.
    pub fn has_wide_pushback(&self) -> bool {
        self.wide_pushback.first.is_some()
    }

    /// Push a wchar_t without converting it into the FILE's external encoding.
    /// The bound codec is used only to retain byte-position accounting for
    /// representable characters. The position while backup is pending is
    /// unspecified; draining all backup restores the pre-push position.
    /// WEOF and allocation failures leave input and status unchanged.
    pub fn ungetwc(&mut self, value: u32) -> bool {
        if value == u32::MAX {
            return false;
        }
        let mut encoded = [0; 6];
        let width = self
            .wide_codec
            .and_then(|codec| codec.encode(value, &mut encoded))
            .unwrap_or(0) as u8;
        if !self.wide_pushback.push(value, width) {
            return false;
        }
        self.offset = self.offset.saturating_sub(i64::from(width));
        self.flags.io_started = true;
        self.flags.eof = false;
        true
    }

    /// Read one complete pushed-back wide value without decoding, descriptor
    /// I/O or allocation. Sticky errors remain set, as for ordinary input.
    pub fn read_wide_pushback(&mut self) -> Option<u32> {
        let (value, width) = self.wide_pushback.pop()?;
        self.offset = self.offset.saturating_add(i64::from(width));
        self.flags.io_started = true;
        self.flags.last_write = false;
        Some(value)
    }

    /// Stage externally-fetched bytes so subsequent reads see them first.
    ///
    /// Used by scanf-family entrypoints after they bulk-read from a
    /// non-seekable fd and parse only a prefix. Unlike `ungetc`, this does not
    /// alter the logical offset; callers set the post-parse offset explicitly.
    pub fn pushback_read_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        for &byte in bytes.iter().rev() {
            self.read_pushback.push_front(byte);
        }
        self.flags.eof = false;
    }

    /// Return a previously consumed byte sequence in its original order.
    ///
    /// Buffered fd reads normally rewind in place without allocation. A
    /// character crossing a refill, or a memory stream without an I/O buffer,
    /// uses the pushback queue when the single-byte path has no more room.
    /// `preserve_eof` distinguishes an incomplete decoded prefix at EOF from
    /// an explicit unget operation, which must clear EOF.
    pub fn unread_bytes(&mut self, bytes: &[u8], preserve_eof: bool) {
        let was_eof = self.flags.eof;
        if !bytes.is_empty() && (self.ungetc_byte.is_some() || !self.read_pushback.is_empty()) {
            if let Some(byte) = self.ungetc_byte.take() {
                self.read_pushback.push_front(byte);
            }
            self.pushback_read_bytes(bytes);
            self.offset = self
                .offset
                .saturating_sub(i64::try_from(bytes.len()).unwrap_or(i64::MAX));
            if preserve_eof && was_eof {
                self.flags.eof = true;
            }
            return;
        }
        for index in (0..bytes.len()).rev() {
            if !self.ungetc(bytes[index]) {
                if let Some(byte) = self.ungetc_byte.take() {
                    self.read_pushback.push_front(byte);
                }
                self.pushback_read_bytes(&bytes[..=index]);
                self.offset = self
                    .offset
                    .saturating_sub(i64::try_from(index + 1).unwrap_or(i64::MAX));
                break;
            }
        }
        if preserve_eof && was_eof {
            self.flags.eof = true;
        }
    }

    /// Rewind a memory-backed stream by `unconsumed` bytes after a bulk scanf
    /// read over-read the backing.
    ///
    /// `read_stream_for_scanf` consumes a whole chunk but `scanf` only parses a
    /// prefix; the unparsed tail must be made available to the next read on the
    /// same stream (glibc consumes exactly what it parses). No-op for fd-backed
    /// streams, whose buffer/offset integration is tracked separately
    /// (bd-2g7oyh.180).
    pub fn scanf_rewind_mem(&mut self, unconsumed: usize) {
        if unconsumed == 0 {
            return;
        }
        if let Some(ref mut backing) = self.mem_backing {
            // SEEK_CUR by the unconsumed count; mem_read already advanced pos
            // past it, so this lands exactly on the first unparsed byte.
            backing.seek(-(unconsumed as i64), 1);
            self.offset = backing.position() as i64;
            self.flags.eof = false;
        }
    }

    /// Append bytes into `out` up to and including the first occurrence of
    /// `delim`, consuming exactly that many bytes from the read buffer /
    /// memory backing — never reading past the delimiter.
    ///
    /// This is the bulk primitive behind `getdelim`/`getline`: it lets the ABI
    /// layer read a whole line under a single registry lock and a single policy
    /// decision, instead of one `fgetc` (lock + policy decision + 1-byte `Vec`
    /// allocation) per character. Refilling fd-backed streams from the
    /// descriptor is left to the caller (signalled by [`ReadUntil::NeedRefill`]),
    /// because that path lives in the ABI layer alongside the membrane policy.
    /// On allocation failure, the bytes that did not fit remain unread.
    pub fn read_until_delim(
        &mut self,
        delim: u8,
        out: &mut Vec<u8>,
    ) -> Result<ReadUntil, std::collections::TryReserveError> {
        if !self.open_flags.readable {
            self.flags.error = true;
            return Ok(ReadUntil::Eof);
        }
        self.flags.io_started = true;
        self.flags.last_write = false;

        // Reserve before consuming any source, including pushback: a failed
        // allocation must not silently discard the next unread byte.
        if let Some(b) = self.ungetc_byte {
            out.try_reserve(1)?;
            self.ungetc_byte = None;
            out.push(b);
            self.advance_offset(1);
            if b == delim {
                return Ok(ReadUntil::Found);
            }
        }

        while let Some(&b) = self.read_pushback.front() {
            out.try_reserve(1)?;
            let _ = self.read_pushback.pop_front();
            out.push(b);
            self.advance_offset(1);
            if b == delim {
                return Ok(ReadUntil::Found);
            }
        }

        if let Some(backing) = self.mem_backing.as_mut() {
            let rem = backing.peek();
            if rem.is_empty() {
                self.flags.eof = true;
                return Ok(ReadUntil::Eof);
            }
            let outcome = match crate::string::mem::memchr(rem, delim, rem.len()) {
                Some(k) => {
                    out.try_reserve(k + 1)?;
                    out.extend_from_slice(&rem[..=k]);
                    backing.consume(k + 1);
                    ReadUntil::Found
                }
                None => {
                    let n = rem.len();
                    out.try_reserve(n)?;
                    out.extend_from_slice(rem);
                    backing.consume(n);
                    // Unlike a bounded read, getdelim keeps looking until
                    // the delimiter or an attempted read past the end. The
                    // final unterminated line therefore sets EOF immediately.
                    self.flags.eof = true;
                    ReadUntil::Eof
                }
            };
            self.offset = backing.position() as i64;
            Ok(outcome)
        } else {
            let buffered = self.buffer.peek();
            if buffered.is_empty() {
                return Ok(ReadUntil::NeedRefill);
            }
            let outcome = match crate::string::mem::memchr(buffered, delim, buffered.len()) {
                Some(k) => {
                    out.try_reserve(k + 1)?;
                    out.extend_from_slice(&buffered[..=k]);
                    self.buffer.consume(k + 1);
                    self.advance_offset(k + 1);
                    ReadUntil::Found
                }
                None => {
                    let n = buffered.len();
                    out.try_reserve(n)?;
                    out.extend_from_slice(buffered);
                    self.buffer.consume(n);
                    self.advance_offset(n);
                    ReadUntil::NeedRefill
                }
            };
            Ok(outcome)
        }
    }

    /// Fill `dst` with bytes up to and including the first `delim`, or until
    /// `dst` is full — whichever comes first — consuming exactly the bytes
    /// written. Returns `(bytes_written_this_call, outcome)`.
    ///
    /// Zero-allocation, length-bounded sibling of [`read_until_delim`]: the bulk
    /// primitive behind `fgets`, which previously read one byte at a time via
    /// `buffered_read(1)` — a 1-byte `Vec` allocation per character. Writes
    /// straight into the caller's destination (e.g. the C `char*`), so a whole
    /// line copies with zero heap traffic. fd-backed refill is the caller's job
    /// (signalled by [`ReadUntil::NeedRefill`]); the caller stops once `dst` is
    /// full regardless of the outcome.
    pub fn read_into_slice(&mut self, delim: u8, dst: &mut [u8]) -> (usize, ReadUntil) {
        if dst.is_empty() {
            return (0, ReadUntil::NeedRefill);
        }
        if !self.open_flags.readable {
            self.flags.error = true;
            return (0, ReadUntil::Eof);
        }
        self.flags.io_started = true;
        self.flags.last_write = false;

        let mut written = 0usize;

        // A pending ungetc byte is logically first (mirrors buffered_read).
        if let Some(b) = self.ungetc_byte.take() {
            dst[written] = b;
            written += 1;
            self.advance_offset(1);
            if b == delim {
                return (written, ReadUntil::Found);
            }
            if written == dst.len() {
                return (written, ReadUntil::NeedRefill);
            }
        }

        while written < dst.len() {
            let Some(b) = self.read_pushback.pop_front() else {
                break;
            };
            dst[written] = b;
            written += 1;
            self.advance_offset(1);
            if b == delim {
                return (written, ReadUntil::Found);
            }
        }
        if written == dst.len() {
            return (written, ReadUntil::NeedRefill);
        }

        let limit = dst.len() - written;

        if let Some(backing) = self.mem_backing.as_mut() {
            let rem = backing.peek();
            let rem_len = rem.len();
            if rem_len == 0 {
                self.flags.eof = true;
                return (written, ReadUntil::Eof);
            }
            let scan_len = rem_len.min(limit);
            let (n, found) = match crate::string::mem::memchr(rem, delim, scan_len) {
                Some(k) => (k + 1, true),
                None => (scan_len, false),
            };
            dst[written..written + n].copy_from_slice(&rem[..n]);
            backing.consume(n);
            self.offset = backing.position() as i64;
            written += n;
            let outcome = if found {
                ReadUntil::Found
            } else if written == dst.len() {
                // Filling the caller's request is not an attempt past EOF,
                // even when its last byte is the last byte of the backing.
                ReadUntil::NeedRefill
            } else {
                self.flags.eof = true;
                ReadUntil::Eof
            };
            (written, outcome)
        } else {
            let buffered = self.buffer.peek();
            if buffered.is_empty() {
                return (written, ReadUntil::NeedRefill);
            }
            let scan_len = buffered.len().min(limit);
            let (n, found) = match crate::string::mem::memchr(buffered, delim, scan_len) {
                Some(k) => (k + 1, true),
                None => (scan_len, false),
            };
            dst[written..written + n].copy_from_slice(&buffered[..n]);
            self.buffer.consume(n);
            self.advance_offset(n);
            written += n;
            let outcome = if found {
                ReadUntil::Found
            } else {
                ReadUntil::NeedRefill
            };
            (written, outcome)
        }
    }

    /// ASCII-only wide-line fast path for `fgetws`.
    ///
    /// This consumes bytes only when the currently buffered data can complete a
    /// valid `fgetws` result without decoding: either a newline is present before
    /// `dst` fills, or `dst` fills with ASCII bytes. If the buffer starts with a
    /// multibyte character or holds only an incomplete ASCII prefix, it returns
    /// `None` without advancing the stream so the caller can use the normal
    /// `fgetwc` decoder.
    pub fn read_ascii_line_into_wide(&mut self, dst: &mut [u32]) -> Option<(usize, ReadUntil)> {
        if self.has_wide_pushback() {
            return None;
        }
        if dst.is_empty() {
            return Some((0, ReadUntil::NeedRefill));
        }
        if !self.open_flags.readable {
            self.flags.error = true;
            return Some((0, ReadUntil::Eof));
        }
        if self.is_mem_backed() || self.ungetc_byte.is_some() || !self.read_pushback.is_empty() {
            return None;
        }

        let buffered = self.buffer.peek();
        if buffered.is_empty() {
            return Some((0, ReadUntil::NeedRefill));
        }

        let limit = dst.len().min(buffered.len());
        for i in 0..limit {
            let byte = buffered[i];
            if byte >= 0x80 {
                return None;
            }
            dst[i] = byte as u32;
            if byte == b'\n' {
                let n = i + 1;
                self.flags.io_started = true;
                self.flags.last_write = false;
                self.buffer.consume(n);
                self.advance_offset(n);
                return Some((n, ReadUntil::Found));
            }
        }

        if limit == dst.len() {
            self.flags.io_started = true;
            self.flags.last_write = false;
            self.buffer.consume(limit);
            self.advance_offset(limit);
            return Some((limit, ReadUntil::NeedRefill));
        }

        None
    }

    /// Reserve the read buffer before consuming descriptor input, leaving
    /// buffered bytes and cursor positions unchanged.
    pub fn try_reserve_read_buffer(&mut self) -> Result<(), std::collections::TryReserveError> {
        self.buffer.try_reserve_storage()
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

    /// Push a byte back (ungetc), growing overflow storage when necessary.
    /// Returns false if that storage cannot be allocated, without consuming input.
    pub fn ungetc(&mut self, byte: u8) -> bool {
        // Like glibc, back the read position up over the byte just consumed
        // (storing `byte` there; a seek discards the buffer, so the slot is
        // never re-read as file data) instead of parking it aside: the
        // pushed-back byte then stays inside the read window, which gnulib's
        // freadahead counts (`ungetc` must leave its value unchanged).
        let in_buffer = self.ungetc_byte.is_none()
            && self.read_pushback.is_empty()
            && !self.is_mem_backed()
            && !self.flags.last_write
            && self.buffer.readable() < self.buffer.capacity()
            && self.buffer.unget(byte);
        let pushed = if in_buffer {
            true
        } else if let Some(existing) = self.ungetc_byte {
            // Keep the older side byte before any queued scanner/wide-read
            // rollback. Moving it into the ordinary buffer is safe only when
            // no queue precedes that buffer; otherwise it would be reordered.
            let buffered = self.read_pushback.is_empty()
                && !self.is_mem_backed()
                && !self.flags.last_write
                && self.buffer.unget(existing);
            if !buffered {
                if self.read_pushback.try_reserve(1).is_err() {
                    return false;
                }
                self.read_pushback.push_front(existing);
            }
            self.ungetc_byte = Some(byte);
            true
        } else {
            self.ungetc_byte = Some(byte);
            true
        };

        if pushed {
            self.flags.io_started = true;
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
    /// Returns pending narrow write data that must be flushed before the seek.
    /// Wide output must be converted and drained by the ABI first; this method
    /// deliberately retains any unresolved wide batch instead of losing it.
    pub fn prepare_seek(&mut self) -> Vec<u8> {
        let pending = self.buffer.pending_write_data().to_vec();
        self.ungetc_byte = None;
        self.read_pushback.clear();
        self.wide_pushback.clear();
        self.buffer.reset();
        self.flags.eof = false;
        self.buffer.mark_flushed();
        pending
    }

    // -----------------------------------------------------------------------
    // Close
    // -----------------------------------------------------------------------

    /// Prepare for close: returns pending narrow write data. The ABI must
    /// separately flush wide output; unresolved wide characters are retained.
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
        self.flags.last_write = true;
        self.flags.eof = false;
        if let Some(ref mut backing) = self.mem_backing {
            let n = backing.write(data);
            if self.open_flags.truncate
                && let MemBacking::Fixed { data, pos, .. } = backing
                && *pos == data.len()
                && !data.is_empty()
            {
                let last = data.len() - 1;
                data[last] = 0;
            }
            if matches!(backing, MemBacking::Fixed { .. }) {
                let next_pending = self.mem_pending_write.saturating_add(data.len());
                if n == data.len() && self.mem_pending_overflow == 0 {
                    self.mem_pending_write = next_pending % BUFSIZ;
                    self.offset = backing.position() as i64;
                    return data.len();
                }
                if next_pending <= BUFSIZ {
                    self.mem_pending_write = next_pending;
                    self.mem_pending_overflow =
                        self.mem_pending_overflow.saturating_add(data.len() - n);
                    self.offset =
                        backing.position().saturating_add(self.mem_pending_overflow) as i64;
                    return data.len();
                }
                // Write exceeds glibc's 8192-byte (`BUFSIZ`) FILE buffer: flush
                // immediately and report the short write / overflow at write time.
                self.mem_pending_write = 0;
                self.mem_pending_overflow = 0;
                self.flags.error = true;
                self.offset = backing.position() as i64;
                return n;
            }
            self.offset = backing.position() as i64;
            n
        } else {
            0
        }
    }

    /// Write complete wide elements without an intermediate byte encoding.
    /// None identifies a different stream kind; a short result is an output
    /// failure. Allocation failure preserves the prior contents and position.
    pub fn mem_write_wide(&mut self, source: &[u32]) -> Option<usize> {
        let Some(MemBacking::WideDynamic { data, pos }) = &mut self.mem_backing else {
            return None;
        };
        if !self.open_flags.writable {
            self.flags.error = true;
            return Some(0);
        }
        if source.is_empty() {
            return Some(0);
        }
        let Some(end) = pos.checked_add(source.len()) else {
            self.flags.error = true;
            return Some(0);
        };
        if end > data.len() {
            if data.try_reserve(end - data.len()).is_err() {
                self.flags.error = true;
                return Some(0);
            }
            data.resize(end, 0);
        }
        data[*pos..end].copy_from_slice(source);
        *pos = end;
        self.offset = end as i64;
        self.flags.io_started = true;
        self.flags.last_write = true;
        self.flags.eof = false;
        Some(source.len())
    }

    /// Flush staged writes on a memory-backed stream (`bd-lamxlj`).
    ///
    /// Returns `false` (and sets `error` + clamps `offset` to the backing
    /// position) if bytes buffered in the modelled `BUFSIZ` window overflowed a
    /// `MemBacking::Fixed` (`fmemopen`) stream since the last flush.
    pub fn mem_flush(&mut self) -> bool {
        self.mem_pending_write = 0;
        if self.mem_pending_overflow > 0 {
            self.mem_pending_overflow = 0;
            if let Some(ref backing) = self.mem_backing {
                self.offset = backing.position() as i64;
            }
            self.flags.error = true;
            false
        } else {
            true
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
        self.flags.last_write = false;

        let mut result = Vec::new();
        let mut remaining = count;

        // Handle ungetc byte first.
        if let Some(b) = self.ungetc_byte.take() {
            result.push(b);
            remaining -= 1;
            if remaining == 0 {
                self.advance_offset(result.len());
                return result;
            }
        }

        while remaining > 0 {
            let Some(byte) = self.read_pushback.pop_front() else {
                break;
            };
            result.push(byte);
            remaining -= 1;
        }
        if remaining == 0 {
            self.advance_offset(result.len());
            return result;
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

    /// Zero-allocation sibling of [`mem_read`](Self::mem_read): fills `dst` from
    /// the ungetc byte then the memory backing, returning the number of bytes
    /// written. Byte-for-byte identical to `mem_read(dst.len())` + copy, but
    /// writes straight into the caller's buffer (no per-`fread` `Vec`).
    pub fn mem_read_into(&mut self, dst: &mut [u8]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        if !self.open_flags.readable {
            self.flags.error = true;
            return 0;
        }
        self.flags.io_started = true;
        self.flags.last_write = false;

        let mut w = 0usize;

        if let Some(b) = self.ungetc_byte.take() {
            dst[w] = b;
            w += 1;
            if w == dst.len() {
                self.advance_offset(w);
                return w;
            }
        }

        while w < dst.len() {
            let Some(byte) = self.read_pushback.pop_front() else {
                break;
            };
            dst[w] = byte;
            w += 1;
        }
        if w == dst.len() {
            self.advance_offset(w);
            return w;
        }

        let mut hit_eof = false;
        if let Some(ref mut backing) = self.mem_backing {
            // peek + consume is zero-copy (the owned `backing.read` would allocate);
            // copying the slice ends the immutable borrow before `consume`.
            let avail = backing.peek();
            let want = dst.len() - w;
            let n = avail.len().min(want);
            dst[w..w + n].copy_from_slice(&avail[..n]);
            hit_eof = n < want;
            backing.consume(n);
            w += n;
            self.offset = backing.position() as i64;
        }
        if hit_eof {
            self.flags.eof = true;
        }
        w
    }

    /// Seek within a memory-backed stream.
    /// Returns the new position on success, or -1 on failure.
    pub fn mem_seek(&mut self, offset: i64, whence: i32) -> i64 {
        self.try_mem_seek(offset, whence).unwrap_or(-1)
    }

    /// Preserve the cause of a failed seek for the public FILE entrypoints.
    pub fn try_mem_seek(&mut self, offset: i64, whence: i32) -> Result<i64, i32> {
        if !self.mem_flush() {
            return Err(crate::errno::ENOSPC);
        }
        // Queued pushback precedes the backing's physical position. A relative
        // seek starts at the logical position, then discards that pushback.
        let (offset, whence) = if whence == 1 {
            let position = self
                .offset
                .checked_add(offset)
                .ok_or(crate::errno::EINVAL)?;
            (position, 0)
        } else {
            (offset, whence)
        };
        let backing = self.mem_backing.as_mut().ok_or(crate::errno::EINVAL)?;
        let position = backing.try_seek(offset, whence)?;
        self.ungetc_byte = None;
        self.read_pushback.clear();
        self.wide_pushback.clear();
        self.flags.eof = false;
        self.offset = position;
        Ok(position)
    }

    /// Get a reference to the memory backing data (for open_memstream sync).
    pub fn mem_data(&self) -> Option<&[u8]> {
        self.mem_backing.as_ref().map(|b| b.data())
    }

    /// Wide storage for publication by open_wmemstream's ABI owner. The
    /// current position may precede its retained tail after a backward seek.
    pub fn mem_wide_data(&self) -> Option<&[u32]> {
        match self.mem_backing.as_ref()? {
            MemBacking::WideDynamic { data, .. } => Some(data),
            _ => None,
        }
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

    fn deferred_wide_stream(codec: crate::iconv::MultibyteCodec, bytes: usize) -> StdioStream {
        let mut stream = StdioStream::new(7, parse_mode(b"w+").unwrap());
        assert!(stream.set_buffering(BufMode::Full, bytes));
        stream.set_wide_buffer_user_supplied(true);
        assert_eq!(stream.set_orientation(1), 1);
        stream.bind_wide_codec(codec);
        stream
    }

    #[test]
    fn wide_output_admission_counts_characters_and_checks_permissions() {
        let mut owned = StdioStream::new(6, parse_mode(b"w").unwrap());
        assert_eq!(owned.wide_output_capacity(), BUFSIZ);
        assert!(owned.set_buffering(BufMode::Full, 9));
        assert_eq!(owned.wide_output_capacity(), 9);
        owned.set_wide_buffer_user_supplied(true);
        assert_eq!(owned.wide_output_capacity(), 3);
        owned.reset_for_fmemopen(parse_mode(b"w+").unwrap(), 0, 0);
        assert_eq!(owned.wide_output_capacity(), BUFSIZ);

        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 9);
        assert_eq!(stream.wide_output_capacity(), 3);
        assert!(!stream.wide_output_initialized());
        // Newlines are deliberately retained: the ABI chooses line flushes.
        assert_eq!(
            stream.buffer_wide_write(&[0x41, 0x0a, 0x20ac, 0x42]),
            Some(3)
        );
        assert_eq!(stream.buffer_wide_write(&[0x43]), Some(0));
        assert_eq!(stream.pending_wide_output(), 3);
        assert!(stream.wide_output_initialized());
        assert!(stream.last_was_write());
        assert!(stream.pending_flush().is_empty());
        assert_eq!(stream.offset(), 0);
        assert!(!stream.set_buffering(BufMode::None, 0));

        let mut readonly = StdioStream::new(8, parse_mode(b"r").unwrap());
        assert_eq!(readonly.buffer_wide_write(&[0x0301]), None);
        assert!(readonly.is_error());
        assert!(!readonly.wide_output_initialized());
        assert_eq!(readonly.pending_wide_output(), 0);
        let unbuffered = StdioStream::with_mode(9, parse_mode(b"w").unwrap(), BufMode::None);
        assert_eq!(unbuffered.wide_output_capacity(), 1);

        let mut input = StdioStream::new(10, parse_mode(b"r").unwrap());
        input.set_orientation(1);
        assert!(input.ungetwc(0x41));
        assert!(input.last_was_read());
        assert!(!input.wide_output_initialized());
        assert_eq!(input.read_wide_pushback(), Some(0x41));
        assert!(!input.wide_output_initialized());
        input.mark_wide_buffer_initialized();
        assert!(input.wide_output_initialized());
        assert!(input.rebuffer(BufMode::Full, 32, false));
        assert!(input.last_was_read());
        assert!(!input.wide_output_initialized());
    }

    #[test]
    fn wide_output_conversion_uses_flush_locale_and_bound_codec() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 16);
        assert_eq!(stream.buffer_wide_write(&[0x20ac, 0x0301, 0xa9]), Some(3));
        assert!(stream.pending_wide_flush().is_empty());
        assert_eq!(stream.pending_wide_offset(false), 3);
        // GNU ASCII output: Euro and copyright expand in both C locales;
        // the combining acute mark disappears only under C.UTF-8.
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"EUR?(C)");
        stream.retry_wide_flush();
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Utf8);
        assert_eq!(stream.prepare_wide_flush(true), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"EUR(C)");
        assert_eq!(stream.pending_wide_output(), 3);
        stream.consume_wide_flushed_prefix(6);
        assert_eq!(stream.offset(), 6);
        assert_eq!(stream.pending_wide_output(), 0);
    }

    #[test]
    fn wide_output_partial_acknowledgement_retains_cancellation_suffix() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Utf8, 16);
        assert_eq!(stream.buffer_wide_write(&[0x20ac, 0x41]), Some(2));
        assert_eq!(stream.prepare_wide_flush(true), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"\xe2\x82\xacA");
        stream.consume_wide_flushed_prefix(1);
        assert_eq!(stream.offset(), 1);
        assert_eq!(stream.pending_wide_offset(false), 3);
        assert_eq!(stream.pending_wide_output(), 2);
        // A cleanup flush resumes mid-character without encoding it again.
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"\x82\xacA");
        stream.consume_wide_flushed_prefix(2);
        assert_eq!(stream.pending_wide_flush(), b"A");
        assert_eq!(stream.pending_wide_output(), 2);
        stream.consume_wide_flushed_prefix(1);
        assert_eq!(stream.offset(), 4);
        assert_eq!(stream.pending_wide_offset(false), 0);
        assert_eq!(stream.pending_wide_output(), 0);
        assert!(stream.pending_wide_flush().is_empty());
    }

    #[test]
    fn wide_output_write_error_replays_the_complete_character_batch() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 16);
        assert_eq!(stream.buffer_wide_write(&[0x41, 0x42, 0x43]), Some(3));
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        stream.consume_wide_flushed_prefix(1);
        assert_eq!(stream.pending_wide_flush(), b"BC");
        stream.retry_wide_flush();
        assert_eq!(stream.offset(), 1);
        assert_eq!(stream.pending_wide_output(), 3);
        assert_eq!(stream.pending_wide_offset(false), 3);
        assert_eq!(stream.prepare_wide_flush(true), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"ABC");
        stream.consume_wide_flushed_prefix(3);
        assert_eq!(stream.offset(), 4);
        assert_eq!(stream.pending_wide_output(), 0);
    }

    #[test]
    fn wide_output_empty_transliterations_commit_without_descriptor_bytes() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 16);
        stream.set_offset(12);
        stream.set_eof();
        assert_eq!(stream.buffer_wide_write(&[0x0301, 0x0301]), Some(2));
        assert!(!stream.is_eof());
        assert!(stream.last_was_write());
        assert_eq!(stream.prepare_wide_flush(true), Ok(()));
        assert_eq!(stream.pending_wide_output(), 0);
        assert!(stream.pending_wide_flush().is_empty());
        assert_eq!(stream.offset(), 12);
        stream.consume_wide_flushed_prefix(usize::MAX);
        assert_eq!(stream.offset(), 12);
    }

    #[test]
    fn wide_output_purge_and_rebuffer_preserve_acknowledged_progress() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Utf8, 16);
        assert_eq!(stream.buffer_wide_write(&[0x20ac, 0x41]), Some(2));
        assert!(!stream.rebuffer(BufMode::None, 0, false));
        assert!(stream.rebuffer(BufMode::Line, 64, true));
        assert_eq!(stream.wide_output_capacity(), 4);
        assert_eq!(stream.prepare_wide_flush(true), Ok(()));
        stream.consume_wide_flushed_prefix(1);
        stream.purge();
        assert_eq!(stream.offset(), 1);
        assert_eq!(stream.pending_wide_output(), 0);
        assert!(stream.pending_wide_flush().is_empty());
        assert!(stream.wide_output_initialized());
        assert!(stream.rebuffer(BufMode::Full, 32, false));
        assert!(!stream.wide_output_initialized());
        assert_eq!(stream.wide_output_capacity(), 8);
        assert_eq!(stream.buffer_wide_write(&[0x20ac]), Some(1));
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"\xe2\x82\xac");

        stream.reset_for_fmemopen(parse_mode(b"r").unwrap(), 4, 99);
        assert_eq!(stream.pending_wide_output(), 0);
        assert!(stream.pending_wide_flush().is_empty());
        assert!(!stream.wide_output_initialized());
        assert_eq!(stream.offset(), 4);
    }

    #[test]
    fn wide_output_appended_characters_survive_an_earlier_batch_commit() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 16);
        assert_eq!(stream.buffer_wide_write(&[0x41]), Some(1));
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.buffer_wide_write(&[0x42, 0x43]), Some(2));
        assert_eq!(stream.pending_wide_flush(), b"A");
        stream.consume_wide_flushed_prefix(1);
        assert_eq!(stream.pending_wide_output(), 2);
        assert_eq!(stream.offset(), 1);
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"BC");
        stream.consume_wide_flushed_prefix(2);
        assert_eq!(stream.offset(), 3);
        assert_eq!(stream.pending_wide_output(), 0);
    }

    #[test]
    fn wide_output_position_uses_external_codec_widths_without_conversion() {
        for (codec, characters, expected_c, expected_utf8) in [
            (
                crate::iconv::MultibyteCodec::Ascii,
                vec![0x20ac, 0x0301],
                2,
                2,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"ISO-8859-1").unwrap(),
                vec![0xe9, 0x20ac, 0],
                3,
                3,
            ),
            (
                crate::iconv::MultibyteCodec::Utf8,
                vec![0xe9, 0x20ac, 0],
                6,
                6,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"UTF-16LE").unwrap(),
                vec![0x20ac, 0x1f642, 0],
                8,
                8,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"UCS-2BE").unwrap(),
                vec![0x20ac, 0x0301, 0x41],
                6,
                6,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"UTF-32LE").unwrap(),
                vec![0x20ac, 0x0301, 0x41],
                12,
                12,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"SHIFT_JIS").unwrap(),
                vec![0x20ac, 0x0301, 0x41],
                5,
                4,
            ),
            (
                crate::iconv::MultibyteCodec::for_stream(b"GBK").unwrap(),
                vec![0x20ac, 0x0301, 0x41],
                3,
                2,
            ),
        ] {
            let mut stream = deferred_wide_stream(codec, 16);
            assert_eq!(
                stream.buffer_wide_write(&characters),
                Some(characters.len())
            );
            assert_eq!(stream.pending_wide_offset(false), expected_c);
            assert_eq!(stream.pending_wide_offset(true), expected_utf8);
            assert_eq!(stream.pending_wide_offset(false), expected_c);
            assert_eq!(stream.pending_wide_output(), characters.len());
            assert!(stream.pending_wide_flush().is_empty());
            assert_eq!(stream.offset(), 0);
        }
    }

    #[test]
    fn wide_output_seek_and_close_preparation_do_not_drop_unflushed_characters() {
        let mut stream = deferred_wide_stream(crate::iconv::MultibyteCodec::Ascii, 16);
        assert_eq!(stream.buffer_wide_write(&[0x41, 0x42]), Some(2));
        assert!(stream.prepare_seek().is_empty());
        assert_eq!(stream.pending_wide_output(), 2);
        assert!(stream.prepare_close().is_empty());
        assert_eq!(stream.pending_wide_output(), 2);
        assert_eq!(stream.prepare_wide_flush(false), Ok(()));
        assert_eq!(stream.pending_wide_flush(), b"AB");
        stream.consume_wide_flushed_prefix(2);
        assert!(stream.prepare_seek().is_empty());
        assert_eq!(stream.pending_wide_output(), 0);
        assert_eq!(stream.offset(), 2);
    }

    #[test]
    fn memory_seek_cur_accounts_for_pending_pushback() {
        let flags = parse_mode(b"r").unwrap();
        for (relative, position, suffix) in [
            (-1, 3, b"def".as_slice()),
            (0, 4, b"ef".as_slice()),
            (1, 5, b"f".as_slice()),
        ] {
            let mut stream = StdioStream::new_mem_fixed(b"abcdef".to_vec(), 6, flags);
            assert_eq!(stream.mem_read(6), b"abcdef");
            stream.unread_bytes(b"XY", false);
            assert_eq!(stream.offset(), 4);
            assert_eq!(stream.mem_seek(relative, 1), position);
            assert_eq!(stream.offset(), position);
            assert_eq!(stream.mem_read(suffix.len()), suffix);
            assert_eq!(stream.offset(), 6);
        }

        let mut stream = StdioStream::new_mem_fixed(b"abcdef".to_vec(), 6, flags);
        assert_eq!(stream.mem_read(6), b"abcdef");
        stream.unread_bytes(b"XY", false);
        assert_eq!(stream.mem_seek(i64::MAX, 1), -1);
        assert_eq!(stream.offset(), 4);
        assert_eq!(
            stream.mem_read(2),
            b"XY",
            "a failed seek preserves pushback"
        );
        assert_eq!(stream.offset(), 6);
    }

    #[test]
    fn wide_backup_preserves_values_order_position_and_sticky_errors() {
        for codec in [
            crate::iconv::MultibyteCodec::Ascii,
            crate::iconv::MultibyteCodec::Utf8,
        ] {
            let mut stream = StdioStream::new(7, parse_mode(b"r").unwrap());
            stream.set_orientation(1);
            stream.bind_wide_codec(codec);
            stream.fill_read_buffer(b"AB");
            assert_eq!(stream.buffered_read(1), b"A");
            stream.set_eof();
            stream.set_error();
            let position = stream.offset();

            let values = [0x41, 0x20ac, 0xd800, 0x8000_0000, 0, 0x7fff_ffff];
            for (index, value) in values.into_iter().enumerate() {
                assert!(stream.ungetwc(value));
                assert!(!stream.is_eof());
                assert!(stream.is_error());
                if index == 0 {
                    assert_eq!(
                        stream.wide_pushback.rest.capacity(),
                        0,
                        "one guaranteed pushback uses inline storage"
                    );
                }
            }
            let pending_position = stream.offset();
            assert!(!stream.ungetwc(u32::MAX));
            assert_eq!(stream.offset(), pending_position);
            for value in values.into_iter().rev() {
                assert_eq!(stream.read_wide_pushback(), Some(value));
                assert!(stream.is_error());
            }
            assert_eq!(stream.read_wide_pushback(), None);
            assert_eq!(stream.offset(), position);
            assert_eq!(stream.buffered_read(1), b"B");
            assert_eq!(stream.offset(), 2);
        }
    }

    #[test]
    fn wide_backup_precedes_ascii_fast_reads_and_byte_rollback() {
        let mut stream = StdioStream::new(7, parse_mode(b"r").unwrap());
        stream.set_orientation(1);
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Ascii);
        stream.fill_read_buffer(b"AB\n");
        assert_eq!(stream.buffered_read(1), b"A");
        stream.unread_bytes(b"A", false);
        assert!(stream.ungetwc(0x20ac));
        let mut line = [0; 3];
        assert!(stream.read_ascii_line_into_wide(&mut line).is_none());
        assert_eq!(stream.offset(), 0);
        assert_eq!(stream.read_wide_pushback(), Some(0x20ac));
        assert_eq!(stream.buffered_read(1), b"A");
        assert_eq!(
            stream.read_ascii_line_into_wide(&mut line),
            Some((2, ReadUntil::Found))
        );
        assert_eq!(&line[..2], &[u32::from(b'B'), u32::from(b'\n')]);
    }

    #[test]
    fn wide_backup_is_discarded_by_purge_seek_and_stream_reuse() {
        let mut stream = StdioStream::new(7, parse_mode(b"r").unwrap());
        stream.set_orientation(1);
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Ascii);
        stream.fill_read_buffer(b"ABC");
        assert_eq!(stream.buffered_read(1), b"A");
        assert!(stream.ungetwc(u32::from(b'A')));
        assert!(stream.ungetwc(0xd800));
        stream.purge();
        assert!(!stream.has_wide_pushback());
        assert_eq!(stream.offset(), 3);
        assert!(stream.buffered_read(1).is_empty());

        assert!(stream.ungetwc(0x8000_0000));
        let _ = stream.prepare_seek();
        stream.set_offset(8);
        assert_eq!(stream.read_wide_pushback(), None);
        assert_eq!(stream.offset(), 8);

        assert!(stream.ungetwc(0x20ac));
        stream.reset_for_fmemopen(parse_mode(b"r").unwrap(), 4, 99);
        assert!(!stream.has_wide_pushback());
        assert_eq!(stream.offset(), 4);
        assert_eq!(stream.unread_bytes_for_position(), 0);
    }

    #[test]
    fn failed_memory_seek_retains_wide_backup() {
        let mut stream = StdioStream::new_mem_fixed(b"AB".to_vec(), 2, parse_mode(b"r").unwrap());
        stream.set_orientation(1);
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Ascii);
        assert_eq!(stream.mem_read(1), b"A");
        assert!(stream.ungetwc(0x20ac));
        assert_eq!(stream.mem_seek(-1, 0), -1);
        assert_eq!(stream.read_wide_pushback(), Some(0x20ac));
        assert_eq!(stream.offset(), 1);
        assert_eq!(stream.mem_read(1), b"B");
        assert!(stream.ungetwc(0xd800));
        assert_eq!(stream.mem_seek(0, 0), 0);
        assert_eq!(stream.read_wide_pushback(), None);
        assert_eq!(stream.mem_read(1), b"A");
    }

    #[test]
    fn wide_codec_is_bound_once_and_survives_seek() {
        let mut stream = StdioStream::new(7, parse_mode(b"r").unwrap());
        assert!(stream.wide_codec().is_none());
        stream.set_orientation(1);
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Utf8);
        stream.bind_wide_codec(crate::iconv::MultibyteCodec::Ascii);
        let _ = stream.prepare_seek();
        assert_eq!(stream.effective_orientation(), 1);
        assert!(matches!(
            stream.wide_codec(),
            Some(crate::iconv::MultibyteCodec::Utf8)
        ));
    }

    #[test]
    fn memory_wide_pushback_preserves_multiple_characters_and_offsets() {
        let bytes = "é€X".as_bytes();
        for bulk in [false, true] {
            let mut stream =
                StdioStream::new_mem_fixed(bytes.to_vec(), bytes.len(), parse_mode(b"r").unwrap());
            assert_eq!(stream.mem_read(bytes.len()), bytes);
            assert_eq!(stream.offset(), bytes.len() as i64);
            stream.unread_bytes(b"X", false);
            stream.unread_bytes("€".as_bytes(), false);
            stream.unread_bytes("é".as_bytes(), false);
            assert_eq!(stream.offset(), 0);
            let mut actual = [0; 6];
            for (index, byte) in actual.iter_mut().enumerate() {
                if bulk {
                    assert_eq!(stream.mem_read_into(std::slice::from_mut(byte)), 1);
                } else {
                    *byte = stream.mem_read(1)[0];
                }
                assert_eq!(stream.offset(), (index + 1) as i64);
            }
            assert_eq!(&actual, bytes);
            assert!(stream.mem_read(1).is_empty());
            assert!(stream.is_eof());
        }
    }

    #[test]
    fn incomplete_character_rollback_retains_eof_but_explicit_unget_clears_it() {
        let mut stream = StdioStream::new_mem_fixed(vec![0xe2, 0x82], 2, parse_mode(b"r").unwrap());
        assert_eq!(stream.mem_read(3), [0xe2, 0x82]);
        assert!(stream.is_eof());
        stream.unread_bytes(&[0xe2, 0x82], true);
        assert_eq!(stream.offset(), 0);
        assert!(stream.is_eof());
        stream.unread_bytes(b"A", false);
        assert!(!stream.is_eof());
        assert_eq!(stream.mem_read(3), [b'A', 0xe2, 0x82]);
        assert_eq!(stream.offset(), 2);
    }

    #[test]
    fn wide_pushback_survives_a_read_buffer_refill() {
        let mut stream = StdioStream::with_mode(7, parse_mode(b"r").unwrap(), BufMode::Full);
        stream.fill_read_buffer(b"ab");
        assert_eq!(stream.buffered_read(2), b"ab");
        stream.fill_read_buffer(b"cd");
        assert_eq!(stream.buffered_read(2), b"cd");
        stream.unread_bytes(b"abcd", false);
        assert_eq!(stream.offset(), 0);
        assert_eq!(stream.buffered_read(4), b"abcd");
        assert_eq!(stream.offset(), 4);
    }

    #[test]
    fn fixed_cursor_refills_and_preserves_only_prefetched_input() {
        let mut source = *b"abcdef";
        let mut cursor = FixedMemCursor::new(source.len(), source.len(), false);
        let mut byte = [0];
        let read = |cursor: &mut FixedMemCursor, source: &[u8], byte: &mut [u8]| {
            cursor.read_into(byte, None, 3, |start, dst| {
                dst.copy_from_slice(&source[start..start + dst.len()]);
            })
        };
        source[0] = b'X';
        assert_eq!(read(&mut cursor, &source, &mut byte), 1);
        assert_eq!(byte, *b"X");
        source[1..].fill(b'Y');
        assert_eq!(cursor.seek(0, 1), Some(1));
        let mut tail = [0; 5];
        assert_eq!(read(&mut cursor, &source, &mut tail), 5);
        assert_eq!(&tail, b"bcYYY");
        assert_eq!(cursor.seek(0, 0), Some(0));
        assert_eq!(read(&mut cursor, &source, &mut byte), 1);
        assert_eq!(byte, *b"X");
        assert_eq!(cursor.seek(-1, 0), None);
        assert_eq!(cursor.seek(i64::MAX, 1), None);
        assert_eq!(cursor.seek(0, 99), None);
        assert_eq!(cursor.position(), 1);
    }

    #[test]
    fn fixed_cursor_output_preserves_unwritten_storage_and_bounded_seeks() {
        let mut source = [b'Z'; 8];
        let mut cursor = FixedMemCursor::new(source.len(), 0, false);
        assert_eq!(cursor.seek(3, 0), Some(3));
        assert_eq!(
            cursor.write(b"AB", |start, bytes| {
                source[start..start + bytes.len()].copy_from_slice(bytes);
            }),
            2
        );
        assert_eq!(&source, b"ZZZAB\0ZZ");
        assert_eq!(cursor.seek(4, 2), None);
        assert_eq!(cursor.position(), 5);
        assert_eq!(cursor.seek(3, 2), Some(8));
        assert_eq!(
            cursor.write(b"X", |_, _| panic!("full buffer must not be touched")),
            0
        );
        let mut empty = FixedMemCursor::new(0, 0, false);
        assert_eq!(
            empty.read_into(&mut [0], None, 1, |_, _| panic!("empty input")),
            0
        );
        assert_eq!(empty.write(b"X", |_, _| panic!("empty output")), 0);
    }

    #[test]
    fn fixed_cursor_read_with_refill_recycles_buffer_without_leaking_stale_bytes() {
        let mut backing = Vec::with_capacity(4096);
        backing.extend_from_slice(b"stale-secret-bytes");
        let source = b"hello\nworld!";
        let mut cursor =
            FixedMemCursor::with_input_buffer(source.len(), source.len(), false, backing);
        let mut first_line = [0u8; 16];
        let n = cursor.read_with_refill(&mut first_line, Some(b'\n'), 4096, |start, count, buf| {
            assert!(buf.is_empty());
            assert!(buf.capacity() >= 4096);
            buf.extend_from_slice(&source[start..start + count]);
        });
        assert_eq!(&first_line[..n], b"hello\n");

        let mut rest = [0u8; 16];
        let m = cursor.read_with_refill(&mut rest, None, 4096, |_, _, _| {
            panic!("prefetched input must serve remaining bytes without refill");
        });
        assert_eq!(&rest[..m], b"world!");

        let recycled = cursor.take_input_buffer();
        assert!(recycled.is_empty());
        assert!(recycled.capacity() >= 4096);
    }

    #[test]
    fn committed_read_window_sets_sticky_byte_orientation() {
        let mut stream = StdioStream::new(
            3,
            OpenFlags {
                readable: true,
                ..Default::default()
            },
        );
        assert_eq!(stream.fill_read_buffer(b"abc"), 3);
        stream.consume_window(0);
        assert_eq!(stream.set_orientation(0), 0);
        stream.consume_window(2);
        assert_eq!(stream.flags.orientation, -1);
        assert_eq!(stream.set_orientation(1), -1);
        assert_eq!(stream.offset(), 2);
        assert_eq!(stream.read_window(), Some(b"c".as_slice()));
    }

    #[test]
    fn committed_write_window_sets_sticky_byte_orientation() {
        let mut stream = StdioStream::new(
            3,
            OpenFlags {
                writable: true,
                ..Default::default()
            },
        );
        assert!(stream.buffer_write(b"a").is_some());
        stream.set_offset(1);
        let (_, used, capacity) = stream.write_window().unwrap();
        assert_eq!(used, 1);
        assert!(capacity > used);
        stream.commit_write_window(used + 1);
        assert_eq!(stream.flags.orientation, -1);
        assert_eq!(stream.set_orientation(1), -1);
        assert_eq!(stream.offset(), 2);
        stream.commit_write_window(used + 1);
        assert_eq!(
            stream.offset(),
            2,
            "repeated absorption must not double count"
        );
    }

    #[test]
    fn wide_streams_do_not_publish_byte_windows() {
        let mut stream = StdioStream::new(
            3,
            OpenFlags {
                readable: true,
                writable: true,
                ..Default::default()
            },
        );
        assert_eq!(stream.set_orientation(1), 1);
        assert_eq!(stream.fill_read_buffer(b"abc"), 3);
        assert!(stream.read_window().is_none());
        assert!(!stream.write_window_capable());
        assert_eq!(stream.set_orientation(-1), 1);
    }

    #[test]
    fn test_parse_mode_read() {
        let f = parse_mode(b"r").unwrap();
        assert!(f.readable);
        assert!(!f.writable);
        assert!(!f.append);
    }

    #[test]
    fn no_cancel_mode_follows_the_open_stream() {
        let normal = StdioStream::new(7, parse_mode(b"r+").unwrap());
        assert!(normal.cancellation_enabled());
        let mut suppressed = StdioStream::new(7, parse_mode(b"r+ce").unwrap());
        assert!(!suppressed.cancellation_enabled());
        assert!(suppressed.set_buffering(BufMode::None, 0));
        assert!(!suppressed.cancellation_enabled());
        assert!(!parse_mode(b"r,ccs=UTF-8").unwrap().no_cancel);
        assert!(!parse_mode(b"rbbbbbbc").unwrap().no_cancel);
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
        // Only an empty mode or a bad first character is invalid.
        assert!(parse_mode(b"").is_none());
        assert!(parse_mode(b"z").is_none());
        assert!(parse_mode(b"tr").is_none());
    }

    /// glibc ignores unknown modifier characters ("rt", "rw", "r b"), reads
    /// at most six of them, and stops at the ",ccs=" suffix. Verified against
    /// glibc 2.43 fopen: "rt", "rbt", "rq", "rw", "ar", "r b", "r,ccs=UTF-8"
    /// all open; "rw" is read-only.
    #[test]
    fn test_parse_mode_ignores_unknown_modifiers_like_glibc() {
        let rt = parse_mode(b"rt").unwrap();
        assert!(rt.readable && !rt.writable);
        let rw = parse_mode(b"rw").unwrap();
        assert!(rw.readable && !rw.writable && !rw.truncate);
        let ar = parse_mode(b"ar").unwrap();
        assert!(ar.writable && ar.append && !ar.readable);
        assert!(parse_mode(b"r b").unwrap().binary);
        let ccs = parse_mode(b"r,ccs=UTF-8").unwrap();
        assert!(ccs.readable && !ccs.writable);
        // '+' after the comma is part of the charset name, not a modifier.
        assert!(!parse_mode(b"r,ccs=+").unwrap().writable);
        // Only six modifier characters are read: a '+' in the seventh is not.
        assert!(!parse_mode(b"rqqqqqq+").unwrap().writable);
        assert!(parse_mode(b"rqqqqq+").unwrap().writable);
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
    fn test_partial_flush_commits_prefix_before_stream_reuse() {
        let flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let mut stream = StdioStream::new(3, flags);
        assert!(!stream.buffer_write(b"prefix:suffix").unwrap().flush_needed);
        stream.set_offset(13);

        // A write has acknowledged exactly "prefix:" before the next write
        // can cancel. Reusing the stream must expose only the unsent suffix.
        stream.consume_flushed_prefix(7);
        assert_eq!(stream.pending_flush(), b"suffix");
        assert_eq!(stream.offset(), 13);
        assert!(!stream.buffer_write(b":next").unwrap().flush_needed);
        stream.set_offset(18);
        assert_eq!(stream.pending_flush(), b"suffix:next");

        stream.consume_flushed_prefix(0);
        assert_eq!(stream.pending_flush(), b"suffix:next");
        stream.consume_flushed_prefix(11);
        assert!(stream.pending_flush().is_empty());
        assert_eq!(stream.offset(), 18);
        assert!(!stream.buffer_write(b"fresh").unwrap().flush_needed);
        assert_eq!(stream.pending_flush(), b"fresh");
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
    fn test_stream_pushback_read_bytes_preserves_order_and_offset() {
        let flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new(3, flags);
        s.fill_read_buffer(b"tail");
        let prefix = s.buffered_read(2);
        assert_eq!(&prefix, b"ta");
        assert_eq!(s.offset(), 2);

        s.pushback_read_bytes(b"abc");
        s.set_offset(1);
        let data = s.buffered_read(5);
        assert_eq!(&data, b"abcil");
        assert_eq!(s.offset(), 6);
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
    fn test_mem_backing_dynamic_forward_seek_extends_before_write() {
        let mut backing = MemBacking::Dynamic {
            data: Vec::new(),
            pos: 0,
        };
        backing.write(b"hi");
        assert_eq!(backing.seek(5, 0), Some(5));
        assert_eq!(backing.data(), b"hi\0\0\0");
        assert_eq!(backing.write(b"!"), 1);
        assert_eq!(backing.data(), b"hi\0\0\0!");
    }

    #[test]
    fn test_unallocatable_memory_seek_preserves_position_and_contents() {
        let mut byte = StdioStream::new_mem_dynamic();
        byte.mem_write(b"abc");
        assert_eq!(byte.try_mem_seek(i64::MAX, 0), Err(crate::errno::ENOMEM));
        assert_eq!(byte.offset(), 3);
        assert_eq!(byte.mem_data(), Some(b"abc".as_slice()));
        assert_eq!(byte.mem_write(b"!"), 1);
        assert_eq!(byte.mem_data(), Some(b"abc!".as_slice()));

        let mut wide = StdioStream::new_mem_wide_dynamic();
        wide.mem_write_wide(&[0x20ac]);
        assert_eq!(wide.try_mem_seek(i64::MAX, 0), Err(crate::errno::ENOMEM));
        assert_eq!(wide.offset(), 1);
        assert_eq!(wide.mem_wide_data(), Some([0x20ac].as_slice()));
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
    fn test_stream_mem_failed_seek_preserves_eof() {
        let data = vec![0u8; 8];
        let flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let mut s = StdioStream::new_mem_fixed(data, 0, flags);
        s.set_eof();
        assert_eq!(s.mem_seek(9, 0), -1);
        assert!(s.is_eof());
        assert_eq!(s.offset(), 0);
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

    #[test]
    fn test_fixed_cursor_reset_and_stream_reset_for_fmemopen() {
        let mut cursor = FixedMemCursor::new(16, 16, false);
        let src1 = *b"0123456789abcdef";
        let mut dst = [0u8; 4];
        assert_eq!(
            cursor.read_with_refill(&mut dst, None, 16, |start, count, out| {
                out.extend_from_slice(&src1[start..start + count]);
            }),
            4
        );
        assert_eq!(&dst, b"0123");
        // Second buffered read hits the inline fast path without invoking refill.
        assert_eq!(
            cursor.read_with_refill(&mut dst, None, 16, |_, _, _| {
                panic!("buffered read should not refill");
            }),
            4
        );
        assert_eq!(&dst, b"4567");

        // Reset cursor in place for a smaller stream and verify clean state.
        cursor.reset(5, 5, false);
        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.content_end(), 5);
        let src2 = *b"hello";
        let mut dst6 = [0u8; 6];
        assert_eq!(
            cursor.read_with_refill(&mut dst6, None, 16, |start, count, out| {
                out.extend_from_slice(&src2[start..start + count]);
            }),
            5
        );
        assert_eq!(&dst6[..5], b"hello");

        let ro_flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        let mut stream = StdioStream::with_mode(-1, ro_flags, BufMode::Full);
        stream.set_eof();
        stream.set_error();
        let _ = stream.ungetc(b'X');
        stream.reset_for_fmemopen(ro_flags, 0, 0x1234);
        assert!(!stream.is_eof());
        assert!(!stream.is_error());
        assert_eq!(stream.effective_orientation(), -1);
        assert_eq!(stream.c_handle(), 0x1234);
        assert_eq!(stream.offset(), 0);
    }
}
