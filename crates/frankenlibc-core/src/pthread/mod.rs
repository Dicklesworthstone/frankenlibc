//! POSIX threads.
//!
//! Implements `<pthread.h>` constants and validators for thread management,
//! mutexes, condition variables, reader-writer locks, and thread-local storage.

#[allow(unsafe_code)]
pub mod cond;
pub mod mutex;
pub mod rwlock;
#[allow(unsafe_code)]
pub mod thread;
pub mod tls;

pub use cond::{
    CondvarData, PTHREAD_COND_CLOCK_MONOTONIC, PTHREAD_COND_CLOCK_REALTIME, condvar_broadcast,
    condvar_destroy, condvar_init, condvar_signal, condvar_timedwait, condvar_wait,
};
pub use mutex::{
    PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE,
};
pub use rwlock::{
    PTHREAD_RWLOCK_DEFAULT_NP, PTHREAD_RWLOCK_PREFER_READER_NP,
    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, PTHREAD_RWLOCK_PREFER_WRITER_NP,
};
pub use thread::{
    THREAD_DETACHED, THREAD_FINISHED, THREAD_JOINED, THREAD_RUNNING, THREAD_STARTING, ThreadHandle,
};
#[cfg(target_arch = "x86_64")]
pub use thread::{create_thread, detach_thread, join_thread, self_tid};
#[cfg(target_arch = "x86_64")]
pub use tls::{pthread_getspecific, pthread_setspecific};
pub use tls::{pthread_key_create, pthread_key_delete};
