//! Buffered stream frontends for the native loader.
//!
//! FILE pointers returned by a native fopen/fdopen must be consumed through
//! the same ABI stream registry, including functions obtained with dlsym.
//! Bind the existing implementations rather than importing a host FILE ABI
//! or adding a second stream registry. Native preemption is handled by the
//! caller before this runtime fallback; backend/mode policy is unchanged.

use crate::stdio_abi as stdio;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") { "GLIBC_2.17" } else { "GLIBC_2.2.5" };
    // The existing fmemopen frontend implements the post-2.22 contract,
    // including zero-sized streams. Do not alias the incompatible old ABI.
    let introduced = if name == "fmemopen" { "GLIBC_2.22" } else { baseline };
    if version.is_some_and(|version| version != introduced) { return None; }
    // Preserve each frontend's actual ABI (including C-unwind) by taking its
    // address directly. Do not fabricate a signature-erasing call wrapper.
    let function = match name {
        "fopen" => stdio::fopen as *const (),
        "fdopen" => stdio::fdopen as *const (),
        "freopen" => stdio::freopen as *const (),
        "fclose" => stdio::fclose as *const (),
        "fread" => stdio::fread as *const (),
        "fwrite" => stdio::fwrite as *const (),
        "fgetc" => stdio::fgetc as *const (),
        "fputc" => stdio::fputc as *const (),
        "fgets" => stdio::fgets as *const (),
        "fputs" => stdio::fputs as *const (),
        "ungetc" => stdio::ungetc as *const (),
        "fseek" => stdio::fseek as *const (),
        "ftell" => stdio::ftell as *const (),
        "rewind" => stdio::rewind as *const (),
        "feof" => stdio::feof as *const (),
        "ferror" => stdio::ferror as *const (),
        "clearerr" => stdio::clearerr as *const (),
        "fflush" => stdio::fflush as *const (),
        "setbuf" => stdio::setbuf as *const (),
        "setvbuf" => stdio::setvbuf as *const (),
        "fileno" => stdio::fileno as *const (),
        "flockfile" => stdio::flockfile as *const (),
        "ftrylockfile" => stdio::ftrylockfile as *const (),
        "funlockfile" => stdio::funlockfile as *const (),
        "fmemopen" => stdio::fmemopen as *const (),
        "open_memstream" => stdio::open_memstream as *const (),
        "getline" => stdio::getline as *const (),
        "getdelim" | "__getdelim" => stdio::getdelim as *const (),
        "printf" => stdio::printf as *const (),
        "vprintf" => stdio::vprintf as *const (),
        "fprintf" => stdio::fprintf as *const (),
        "vfprintf" => stdio::vfprintf as *const (),
        "snprintf" => stdio::snprintf as *const (),
        "vsnprintf" => stdio::vsnprintf as *const (),
        "sprintf" => stdio::sprintf as *const (),
        "vsprintf" => stdio::vsprintf as *const (),
        "asprintf" => stdio::asprintf as *const (),
        "vasprintf" => stdio::vasprintf as *const (),
        // These are addresses of FILE* variables, not FILE* values or
        // function pointers. GCC's inline vprintf reads stdout directly.
        "stdin" => (&raw mut stdio::stdin) as *const (),
        "stdout" => (&raw mut stdio::stdout) as *const (),
        "stderr" => (&raw mut stdio::stderr) as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
