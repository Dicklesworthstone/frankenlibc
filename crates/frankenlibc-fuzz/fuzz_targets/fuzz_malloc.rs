#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: fuzz malloc/free sequences
    // Parse data as a sequence of alloc/free/realloc operations
    if data.len() < 4 {
        return;
    }

    let arena = frankenlibc_membrane::ptr_validator::ValidationPipeline::new();
    let mut allocations = Vec::new();

    for chunk in data.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let op = chunk[0] % 3;
        let size = u16::from_le_bytes([chunk[1], chunk[2]]) as usize;

        match op {
            0 => {
                // Allocate
                if let Some(ptr) = arena.arena.allocate(size.max(1).min(65536)) {
                    allocations.push(ptr);
                }
            }
            1 => {
                // Free
                if let Some(ptr) = allocations.pop() {
                    let _ = arena.arena.free(ptr);
                }
            }
            _ => {
                // Validate random existing allocation
                if let Some(&ptr) = allocations.last() {
                    let _ = arena.validate(ptr as usize);
                }
            }
        }
    }

    // Clean up
    for ptr in allocations {
        let _ = arena.arena.free(ptr);
    }
});
