//! POSIX threads.
//!
//! Implements `<pthread.h>` constants and validators for thread management,
//! mutexes, condition variables, reader-writer locks, and thread-local storage.

pub mod cond;
pub mod mutex;
pub mod rwlock;
#[allow(unsafe_code)]
pub mod thread;
pub mod tls;

pub use cond::{PTHREAD_COND_CLOCK_MONOTONIC, PTHREAD_COND_CLOCK_REALTIME};
pub use mutex::{
    PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE,
};
pub use rwlock::{
    PTHREAD_RWLOCK_DEFAULT_NP, PTHREAD_RWLOCK_PREFER_READER_NP,
    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, PTHREAD_RWLOCK_PREFER_WRITER_NP,
};
pub use thread::{
    THREAD_DETACHED, THREAD_FINISHED, THREAD_JOINED, THREAD_RUNNING, THREAD_STARTING, ThreadHandle,
    create_thread, detach_thread, join_thread, self_tid,
};
pub use tls::{
    pthread_getspecific, pthread_key_create, pthread_key_delete, pthread_setspecific,
};
