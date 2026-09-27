//! The evaluator's worker frame protocol (`tag u8 | len u64 LE | payload`)
//! and the job reply inside a frame: a frame claiming more bytes than
//! follow is an error, never an allocation of the claimed size.
#![no_main]
use encompute_evaluator::pool::{read_frame, split_execute_reply};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    while let Ok(Some((_, payload))) = read_frame(&mut r) {
        assert!(payload.len() <= data.len());
        let _ = split_execute_reply(&payload);
    }
});
