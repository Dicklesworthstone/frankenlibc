#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the validation pipeline with arbitrary pointer values
    if data.len() < 8 {
        return;
    }

    let pipeline = frankenlibc_membrane::ptr_validator::ValidationPipeline::new();

    for chunk in data.chunks(8) {
        if chunk.len() < 8 {
            break;
        }
        let addr = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3],
            chunk[4], chunk[5], chunk[6], chunk[7],
        ]) as usize;

        // Should never panic regardless of input
        let outcome = pipeline.validate(addr);
        let _ = outcome.can_read();
        let _ = outcome.can_write();
    }
});
