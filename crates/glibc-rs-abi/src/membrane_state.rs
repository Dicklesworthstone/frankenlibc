//! Global state for the Transparent Safety Membrane.
//!
//! This module holds the singleton `ValidationPipeline` instance used by
//! all ABI entrypoints (`malloc`, `string`, etc.). This ensures that
//! allocations made by `malloc` are visible to the validation logic used
//! by `memcpy` and other functions.

use std::sync::OnceLock;

use glibc_rs_membrane::ptr_validator::ValidationPipeline;

/// Global validation pipeline instance.
///
/// This singleton manages the allocation arena, bloom filter, page oracle,
/// and runtime math kernel for the entire process.
#[allow(dead_code)]
pub(crate) fn global_pipeline() -> &'static ValidationPipeline {
    static PIPELINE: OnceLock<ValidationPipeline> = OnceLock::new();
    PIPELINE.get_or_init(ValidationPipeline::new)
}
