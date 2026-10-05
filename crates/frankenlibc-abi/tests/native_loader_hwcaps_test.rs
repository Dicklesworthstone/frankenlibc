//! Compile the native-loader cache and CPU-policy tests outside the ABI's
//! cfg(not(test)) modules. No exported libc symbols are linked into this test.
#[path = "../src/dlfcn_cache.rs"]
mod cache;
