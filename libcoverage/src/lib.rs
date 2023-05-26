//! `libcoverage` is a static library implementing the LLVM Sanitizer Coverage hooks.
//!
//! It initializes the guards and global counters.
//! Multiple environment variables are available to control how the fuzzee behaves.

#![warn(
    clippy::semicolon_if_nothing_returned,
    missing_copy_implementations,
    missing_debug_implementations,
    noop_method_call,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    variant_size_differences
)]

use fuzzer_protocol::{run_server, COVERAGE_COUNTERS};
use std::env;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Once;

// https://github.com/AFLplusplus/AFLplusplus/blob/3b799c09cd68bb68b26784261f1fbaa3e737c747/custom_mutators/libfuzzer/FuzzerTracePC.cpp#L533
// https://clang.llvm.org/docs/SanitizerCoverage.html

static IS_INITIALIZED: Once = Once::new();

// The guards are [start, stop).
// This function will be called at least once per DSO and may be called
// more than once with the same values of start/stop.
//
// This callback is inserted by the compiler as a module constructor
// into every DSO. `start` and `stop` correspond to the
// beginning and end of the section with the guards for the entire
// binary (executable or DSO). The callback will be called at least
// once per DSO and may be called multiple times with the same parameters.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, end: *mut u32) {
    // Ensure Rust panic cannot traverse the FFI boundary as this would be UB
    let _ = std::panic::catch_unwind(move || {
        // This function will be called multiple times, if there are multiple DSOs.
        // So it needs to handle being called with different `start` and `end` values.

        let is_initialized = *start != 0;
        if env::var("FUZZEE_STARTUP_DEBUG").is_ok() {
            let count = end.offset_from(start);
            eprintln!(
                "Initializing {} guards at {:p}{} for a total of {}",
                count,
                start,
                if is_initialized {
                    " (already initialized)"
                } else {
                    ""
                },
                GUARD_ID.load(Ordering::SeqCst) + {
                    if is_initialized {
                        0
                    } else {
                        count as u32
                    }
                },
            );
        }

        static GUARD_ID: AtomicU32 = AtomicU32::new(1);

        // already initialized
        if is_initialized {
            return;
        }

        // empty range
        if start == end {
            return;
        }

        while start != end {
            let id = GUARD_ID.fetch_add(1, Ordering::SeqCst);
            *start = id;
            // get address of next element
            start = start.offset(1);
        }

        if let Err(err) = COVERAGE_COUNTERS.set_size(GUARD_ID.load(Ordering::SeqCst)) {
            eprintln!("{err}");
            std::process::exit(70);
        }

        // Do program global initialization
        IS_INITIALIZED.call_once(|| {
            eprintln!("Initialize __sanitizer_cov_trace_pc_guard_init");

            // Install an exit handler
            let status = libc::atexit(shutdown);
            if status != 0 {
                eprintln!("atexit failed");
                std::process::exit(71);
            }

            if let Ok(addr) = env::var("FUZZEE_LISTEN_ADDR") {
                eprintln!("Starting fuzzee server on {addr}");
                std::thread::spawn(move || run_server(addr.parse().unwrap()));
            }
        });
    });
}

// This callback is inserted by the compiler on every edge in the
// control flow (some optimizations apply).
// Typically, the compiler will emit the code like this:
//
// ```c
//    if(*guard)
//      __sanitizer_cov_trace_pc_guard(guard);
// ```
//
// But for large functions it will emit a simple call:
//
// ```c
//    __sanitizer_cov_trace_pc_guard(guard);
// ```
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard_variable: *mut u32) {
    // Ensure Rust panic cannot traverse the FFI boundary as this would be UB
    let _ = std::panic::catch_unwind(|| {
        let guard_id = *guard_variable;
        COVERAGE_COUNTERS.inc(guard_id);
    });
}

extern "C" fn shutdown() {
    if env::var("FUZZEE_COUNTER_ON_EXIT").is_ok() {
        let counters = COVERAGE_COUNTERS.get_values();
        eprintln!("{counters:?}");
    }
    eprintln!("Shutdown coverage-impl");
}
