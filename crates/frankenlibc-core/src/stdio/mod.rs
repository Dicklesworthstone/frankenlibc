//! Standard I/O operations.
//!
//! Implements `<stdio.h>` functions: formatted output, formatted input,
//! file operations, and buffered I/O.
//!
//! Architecture:
//! - `buffer` — buffered I/O engine (Full/Line/Unbuffered modes)
//! - `file` — FILE stream state management, mode parsing
//! - `printf` — printf format string parser and renderers
//! - `scanf` — scanf format string parser (implementation pending)

pub mod buffer;
pub mod file;
pub mod printf;
pub mod scanf;

pub use buffer::{BUFSIZ, BufMode, StreamBuffer};
pub use file::{MemBacking, OpenFlags, StdioStream, flags_to_oflags, parse_mode};
pub use printf::{
    FormatArg, FormatFlags, FormatSegment, FormatSpec, LengthMod, Precision, ValueArgKind, Width,
    format_char, format_float, format_pointer, format_signed, format_str, format_unsigned,
    parse_format_spec, parse_format_string,
};
pub use scanf::{ScanResult, ScanValue, parse_scanf_format, scan_input};
