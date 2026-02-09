//! glibc_rust core crate.
//!
//! This crate introduces the first version of a Transparent Safety Membrane (TSM)
//! substrate at the libc ABI boundary.
#![allow(clippy::missing_safety_doc)]

pub mod safety;

use std::ffi::c_void;

use safety::{
    CopyDecision, CopyDisposition, PointerFacts, classify_pointer, decide_copy, global_registry,
};

/// Preview entrypoint for TSM-mediated memcpy semantics.
///
/// This symbol is intentionally namespaced until the project flips to real libc
/// symbol exports.
///
/// # Safety
///
/// - `dst` and `src` must be valid for reads/writes for the resulting number of
///   copied bytes under C ABI expectations.
/// - The membrane may clamp the requested length if metadata is available.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_memcpy_preview(
    dst: *mut c_void,
    src: *const c_void,
    requested_len: usize,
) -> *mut c_void {
    if requested_len == 0 {
        return dst;
    }

    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    let registry = global_registry();
    let src_facts: PointerFacts = classify_pointer(registry, src);
    let dst_facts: PointerFacts = classify_pointer(registry, dst.cast_const());

    let decision = decide_copy(requested_len, src_facts, dst_facts);

    let copy_len = match decision {
        CopyDecision {
            disposition: CopyDisposition::Allow,
            effective_len,
            ..
        }
        | CopyDecision {
            disposition: CopyDisposition::Repair,
            effective_len,
            ..
        } => effective_len,
        CopyDecision {
            disposition: CopyDisposition::Deny,
            ..
        } => 0,
    };

    if copy_len == 0 {
        return dst;
    }

    // SAFETY: We validated non-null pointers above; caller retains the C ABI
    // contract for pointer validity. The membrane only constrains length.
    unsafe {
        std::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), copy_len);
    }

    dst
}

/// Preview entrypoint for TSM-mediated malloc.
///
/// Allocates memory via system allocator and registers it with the membrane.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_malloc_preview(size: usize) -> *mut c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }

    // Use system allocator for preview
    let layout = match std::alloc::Layout::from_size_align(size, 16) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = unsafe { std::alloc::alloc(layout) }.cast::<c_void>();

    if !ptr.is_null() {
        global_registry().register_allocation(ptr, size, 1);
    }

    ptr
}

/// Preview entrypoint for TSM-mediated free.
///
/// Frees memory via system allocator and updates membrane state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_free_preview(ptr: *mut c_void, size_hint: usize) {
    if ptr.is_null() {
        return;
    }

    let registry = global_registry();
    let facts = classify_pointer(registry, ptr);

    if facts.temporal == safety::TemporalState::Valid {
        registry.mark_freed(ptr);
        // We need the size to deallocate safely with Rust allocator.
        // In real TSM, we track it. Here we use the hint or lookup.
        let size = facts.remaining.unwrap_or(size_hint);
        if size > 0 {
            let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
            unsafe { std::alloc::dealloc(ptr.cast::<u8>(), layout) };
        }
    }
}

/// Preview entrypoint for TSM-mediated calloc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_calloc_preview(nmemb: usize, size: usize) -> *mut c_void {
    let total = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => return std::ptr::null_mut(),
    };
    if total == 0 {
        return std::ptr::null_mut();
    }

    let layout = match std::alloc::Layout::from_size_align(total, 16) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<c_void>();

    if !ptr.is_null() {
        global_registry().register_allocation(ptr, total, 1);
    }
    ptr
}

/// Preview entrypoint for TSM-mediated realloc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_realloc_preview(
    ptr: *mut c_void,
    new_size: usize,
    old_size_hint: usize,
) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { glibc_rust_malloc_preview(new_size) };
    }
    if new_size == 0 {
        unsafe { glibc_rust_free_preview(ptr, old_size_hint) };
        return std::ptr::null_mut();
    }

    let registry = global_registry();
    let _facts = classify_pointer(registry, ptr);

    // If we don't know the size, we can't safely realloc with Rust allocator API
    // because `realloc` requires old layout.
    // We rely on old_size_hint if metadata is missing/partial.
    let old_size = if let Some(meta) = registry.lookup_containing(ptr) {
        meta.len
    } else {
        old_size_hint
    };

    if old_size == 0 {
        return std::ptr::null_mut(); // Cannot realloc unknown ptr safely in preview
    }

    let old_layout = match std::alloc::Layout::from_size_align(old_size, 16) {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };
    let new_ptr =
        unsafe { std::alloc::realloc(ptr.cast::<u8>(), old_layout, new_size) }.cast::<c_void>();

    if !new_ptr.is_null() {
        registry.mark_freed(ptr); // Mark old as freed (even if same addr, conceptually new generation)
        registry.register_allocation(new_ptr, new_size, 2);
    }

    new_ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcpy_preview_zero_len_returns_dst() {
        let mut dst = [0_u8; 4];
        let src = [1_u8, 2_u8, 3_u8, 4_u8];

        // SAFETY: test uses valid pointers and len=0.
        let result = unsafe {
            glibc_rust_memcpy_preview(
                dst.as_mut_ptr().cast::<c_void>(),
                src.as_ptr().cast::<c_void>(),
                0,
            )
        };

        assert_eq!(result, dst.as_mut_ptr().cast::<c_void>());
        assert_eq!(dst, [0_u8; 4]);
    }

    #[test]
    fn memcpy_preview_copies_when_valid() {
        let mut dst = [0_u8; 4];
        let src = [1_u8, 2_u8, 3_u8, 4_u8];

        // SAFETY: test uses valid pointers and bounded len.
        let _result = unsafe {
            glibc_rust_memcpy_preview(
                dst.as_mut_ptr().cast::<c_void>(),
                src.as_ptr().cast::<c_void>(),
                src.len(),
            )
        };

        assert_eq!(dst, src);
    }
}
