//! Resource limits for exact execution: a process-wide budget of gate
//! threads shared by concurrent jobs, and each job's own share.
//!
//! - `ENCOMPUTE_EXACT_THREADS`: gate threads the whole process may run at
//!   once (default: the machine's logical cores).
//! - `ENCOMPUTE_EXACT_WORKERS`: threads one job may use (default: the
//!   budget, at most 8).
//!
//! A job takes what is free, at least one thread (waiting if none is), and
//! returns it when done: one expensive job cannot starve the others, and
//! the evaluator never runs more gate threads than its budget.

use std::sync::{Condvar, Mutex, OnceLock};

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Threads the process may run gates on at once.
pub fn total_threads() -> usize {
    env_usize("ENCOMPUTE_EXACT_THREADS").unwrap_or_else(cores)
}

/// Threads one job may use.
pub fn job_workers() -> usize {
    env_usize("ENCOMPUTE_EXACT_WORKERS")
        .unwrap_or_else(|| total_threads().min(8))
        .min(total_threads())
}

struct Budget {
    free: Mutex<usize>,
    cv: Condvar,
}

fn budget() -> &'static Budget {
    static B: OnceLock<Budget> = OnceLock::new();
    B.get_or_init(|| Budget {
        free: Mutex::new(total_threads()),
        cv: Condvar::new(),
    })
}

/// Threads held by a job; returned on drop.
pub struct Permit {
    pub threads: usize,
}

/// Takes up to `want` threads (at least one; waits while none is free).
pub fn acquire(want: usize) -> Permit {
    let b = budget();
    let mut free = b.free.lock().unwrap_or_else(|p| p.into_inner());
    while *free == 0 {
        free = b.cv.wait(free).unwrap_or_else(|p| p.into_inner());
    }
    let threads = want.max(1).min(*free);
    *free -= threads;
    Permit { threads }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let b = budget();
        *b.free.lock().unwrap_or_else(|p| p.into_inner()) += self.threads;
        b.cv.notify_all();
    }
}
