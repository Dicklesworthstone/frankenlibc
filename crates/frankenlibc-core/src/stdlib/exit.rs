//! Process termination functions.

use std::sync::Mutex;

use crate::syscall;

// Global list of atexit handlers
static ATEXIT_HANDLERS: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

pub fn exit(status: i32) -> ! {
    // 1. Run atexit handlers in reverse order
    // We must unlock the mutex before running handlers to avoid deadlock if a handler calls exit() or atexit().
    let handlers = if let Ok(mut lock) = ATEXIT_HANDLERS.lock() {
        let mut extracted = Vec::new();
        std::mem::swap(&mut *lock, &mut extracted);
        extracted
    } else {
        Vec::new()
    };

    // Handlers are stored in registration order. Standard says reverse order.
    // Vec::pop() gives reverse order.
    for handler in handlers.into_iter().rev() {
        handler();
    }

    // 2. Flush stdio buffers (TODO: wire up stdio flushing)

    // 3. Terminate process
    // Use a raw syscall to avoid recursion through our interposed `exit` ABI.
    syscall::sys_exit_group(status)
}
pub fn atexit(func: extern "C" fn()) -> i32 {
    if let Ok(mut handlers) = ATEXIT_HANDLERS.lock() {
        handlers.push(func);
        0
    } else {
        -1
    }
}
