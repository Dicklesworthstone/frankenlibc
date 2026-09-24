//! Compile private native-loader search/cache tests despite dlfcn_abi being
//! excluded from the ABI crate's unit-test build to avoid symbol interposition.
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]

#[allow(dead_code)]
#[path = "../src/dlfcn_search.rs"]
mod search;
