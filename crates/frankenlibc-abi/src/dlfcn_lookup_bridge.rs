//! Per-object lookup entries retain native provenance across compiler tail calls.
//!
//! A shared return-PC-only entry loses the importing DSO when its last C
//! operation is `return dlsym(...)`. Keep the real return PC (another native
//! caller still wins), but supply the importing object's never-reused ID as
//! fallback. No global/thread-local "last caller" state is involved.

use super::super::{Mapping, raw_syscall};
use std::sync::OnceLock;

const SLOT: usize = 64;
const LENGTH: usize = 4096;

#[derive(Debug)]
pub(in super::super) struct BoundCalls {
    origin: usize,
    mapping: OnceLock<Option<Mapping>>,
}

impl BoundCalls {
    pub(in super::super) fn new(origin: usize) -> Self {
        Self {
            origin,
            mapping: OnceLock::new(),
        }
    }

    /// Outer None is an unrelated symbol; inner None is a recognized refusal.
    /// Allocate at most one RX page, only when this DSO actually uses lookup.
    pub(super) fn address(&self, name: &str, version: Option<&str>) -> Option<Option<u64>> {
        let index = match name {
            "dlsym" => 0,
            "dlvsym" => 1,
            _ => return None,
        };
        if super::resolver_address(name, version).is_none() {
            return Some(None);
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let mapping = self.mapping.get_or_init(|| build(self.origin));
            Some(
                mapping
                    .as_ref()
                    .and_then(|mapping| mapping.base.checked_add(index * SLOT))
                    .map(|a| a as u64),
            )
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = index;
            Some(super::resolver_address(name, version))
        }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn build(origin: usize) -> Option<Mapping> {
    // SAFETY: a fresh anonymous mapping; no executable permission while writing.
    let base = unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            LENGTH,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .ok()?;
    let mapping = Mapping {
        base: base as usize,
        len: LENGTH,
    };
    let targets = [
        super::bound_dlsym_entry as *const () as usize,
        super::bound_dlvsym_entry as *const () as usize,
    ];
    for (index, target) in targets.into_iter().enumerate() {
        let bytes = machine_code(index, origin as u64, target as u64);
        if bytes.len() > SLOT {
            return None;
        }
        // SAFETY: both slots are disjoint, in bounds and not yet published.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(index * SLOT), bytes.len())
        };
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: synchronize only the freshly written, mapped instruction slots.
    unsafe {
        synchronize_instruction_cache(base as usize, 2 * SLOT)
    };
    // SAFETY: the guard owns this entire mapping; it is never writable again.
    unsafe { raw_syscall::sys_mprotect(base, LENGTH, libc::PROT_READ | libc::PROT_EXEC) }.ok()?;
    Some(mapping)
}

#[cfg(target_arch = "x86_64")]
fn machine_code(index: usize, origin: u64, target: u64) -> Vec<u8> {
    // ENDBR64; mov argument-register,[rsp]; mov origin-register,imm64;
    // mov rax,target; jmp rax. There is no synthetic return frame to unwind.
    // dlsym: caller in rdx, origin in rcx; dlvsym: caller in rcx, origin in r8.
    let mut code = vec![
        0xf3,
        0x0f,
        0x1e,
        0xfa,
        0x48,
        0x8b,
        if index == 0 { 0x14 } else { 0x0c },
        0x24,
    ];
    code.extend_from_slice(if index == 0 {
        &[0x48, 0xb9]
    } else {
        &[0x49, 0xb8]
    });
    code.extend_from_slice(&origin.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&target.to_le_bytes());
    code.extend_from_slice(&[0xff, 0xe0]);
    code
}

#[cfg(target_arch = "aarch64")]
fn machine_code(index: usize, origin: u64, target: u64) -> Vec<u8> {
    // BTI c; mov caller,lr; ldr origin,literal; ldr x16,target; br x16;
    // nop for aligned 64-bit literals. x0..x2 are otherwise untouched.
    let words: [u32; 6] = [
        0xd503245f,
        if index == 0 { 0xaa1e03e2 } else { 0xaa1e03e3 },
        if index == 0 { 0x58000083 } else { 0x58000084 },
        0x580000b0,
        0xd61f0200,
        0xd503201f,
    ];
    let mut code = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    code.extend_from_slice(&origin.to_le_bytes());
    code.extend_from_slice(&target.to_le_bytes());
    code
}

#[cfg(target_arch = "aarch64")]
unsafe fn synchronize_instruction_cache(start: usize, length: usize) {
    let ctr: u64;
    // SAFETY: CTR_EL0 describes user-accessible cache line sizes on Linux.
    unsafe {
        std::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nostack, preserves_flags))
    };
    let dline = 4usize << ((ctr >> 16) & 15);
    let iline = 4usize << (ctr & 15);
    for address in ((start & !(dline - 1))..start + length).step_by(dline) {
        // SAFETY: cache maintenance covers only this live mapping.
        unsafe {
            std::arch::asm!("dc cvau, {address}", address = in(reg) address, options(nostack, preserves_flags))
        };
    }
    // SAFETY: publish data-cache writes before instruction-cache invalidation.
    unsafe { std::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    for address in ((start & !(iline - 1))..start + length).step_by(iline) {
        // SAFETY: invalidate the same newly written instruction range.
        unsafe {
            std::arch::asm!("ic ivau, {address}", address = in(reg) address, options(nostack, preserves_flags))
        };
    }
    // SAFETY: subsequent execution observes the new immutable instructions.
    unsafe { std::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
}
