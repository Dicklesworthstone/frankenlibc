//! Test the exact production scheduler without exporting libc symbols into
//! the Rust test harness. ABI modules are intentionally absent in --lib tests.
#[path = "../src/aio_scheduler.rs"]
mod scheduler;
