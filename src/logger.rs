//! Tiny logger mirroring the reference implementation's semantics:
//! `debug` is silent in production, everything else always prints.

use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_debug(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { println!($($arg)*) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::logger::debug_enabled() { println!($($arg)*) }
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}
