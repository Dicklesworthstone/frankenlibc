//! Buffered stream frontends for the native loader.
//!
//! FILE pointers returned by a native fopen/fdopen must be consumed through
//! the same ABI stream registry, including functions obtained with dlsym.
//! Bind the existing implementations rather than importing a host FILE ABI
//! or adding a second stream registry. Native preemption is handled by the
//! caller before this runtime fallback; backend/mode policy is unchanged.

use crate::{isoc_abi as isoc, stdio_abi as stdio};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    let introduced = match name {
        // The existing frontend implements the post-2.22 contract, including
        // zero-sized streams. Do not alias the incompatible old fmemopen ABI.
        "fmemopen" => "GLIBC_2.22",
        // C headers redirect scanf calls to these names. The C99 namespace
        // predates AArch64's baseline, while C23 postdates both baselines.
        "__isoc99_scanf" | "__isoc99_fscanf" | "__isoc99_sscanf" | "__isoc99_vscanf"
        | "__isoc99_vfscanf" | "__isoc99_vsscanf"
            if cfg!(target_arch = "x86_64") =>
        {
            "GLIBC_2.7"
        }
        "__isoc23_scanf" | "__isoc23_fscanf" | "__isoc23_sscanf" | "__isoc23_vscanf"
        | "__isoc23_vfscanf" | "__isoc23_vsscanf" => "GLIBC_2.38",
        _ => baseline,
    };
    if version.is_some_and(|version| version != introduced) {
        return None;
    }
    // Preserve each frontend's actual ABI (including C-unwind) by taking its
    // address directly. Do not fabricate a signature-erasing call wrapper.
    let function = match name {
        "fopen" => stdio::fopen as *const (),
        "fopen64" => stdio::fopen64 as *const (),
        "fdopen" => stdio::fdopen as *const (),
        "freopen" => stdio::freopen as *const (),
        "freopen64" => stdio::freopen64 as *const (),
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
        "fseeko" => stdio::fseeko as *const (),
        "ftello" => stdio::ftello as *const (),
        "fseeko64" => stdio::fseeko64 as *const (),
        "ftello64" => stdio::ftello64 as *const (),
        "fgetpos" => stdio::fgetpos as *const (),
        "fsetpos" => stdio::fsetpos as *const (),
        "fgetpos64" => stdio::fgetpos64 as *const (),
        "fsetpos64" => stdio::fsetpos64 as *const (),
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
        "scanf" => stdio::scanf as *const (),
        "fscanf" => stdio::fscanf as *const (),
        "sscanf" => stdio::sscanf as *const (),
        "vscanf" => stdio::vscanf as *const (),
        "vfscanf" => stdio::vfscanf as *const (),
        "vsscanf" => stdio::vsscanf as *const (),
        "__isoc99_scanf" => stdio::__isoc99_scanf as *const (),
        "__isoc99_fscanf" => stdio::__isoc99_fscanf as *const (),
        "__isoc99_sscanf" => stdio::__isoc99_sscanf as *const (),
        "__isoc99_vscanf" => stdio::__isoc99_vscanf as *const (),
        "__isoc99_vfscanf" => stdio::__isoc99_vfscanf as *const (),
        "__isoc99_vsscanf" => stdio::__isoc99_vsscanf as *const (),
        "__isoc23_scanf" => isoc::__isoc23_scanf as *const (),
        "__isoc23_fscanf" => isoc::__isoc23_fscanf as *const (),
        "__isoc23_sscanf" => isoc::__isoc23_sscanf as *const (),
        "__isoc23_vscanf" => isoc::__isoc23_vscanf as *const (),
        "__isoc23_vfscanf" => isoc::__isoc23_vfscanf as *const (),
        "__isoc23_vsscanf" => isoc::__isoc23_vsscanf as *const (),
        // These are addresses of FILE* variables, not FILE* values or
        // function pointers. GCC's inline vprintf reads stdout directly.
        "stdin" => (&raw mut stdio::stdin) as *const (),
        "stdout" => (&raw mut stdio::stdout) as *const (),
        "stderr" => (&raw mut stdio::stderr) as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
