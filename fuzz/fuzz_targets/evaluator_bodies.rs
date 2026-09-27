//! Evaluator HTTP bodies, as the routes hand them to the engine: program
//! uploads (`.eir`), evaluation-key envelopes, job input envelopes and key
//! IDs, on the mock backend. The first byte picks the route.
#![no_main]
use std::sync::OnceLock;

use encompute_evaluator::engine::{Engine, Local};
use encompute_evaluator::Backends;
use libfuzzer_sys::fuzz_target;

static EV: OnceLock<encompute_fuzz::MockEvaluator> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let ev = EV.get_or_init(encompute_fuzz::mock_evaluator);
    let Some((&route, body)) = data.split_first() else {
        return;
    };
    match route % 4 {
        0 => {
            // A fresh engine each time: programs are never evicted.
            if let Ok(text) = std::str::from_utf8(body) {
                let _ = Local::new(Backends::MOCK).add_program(text);
            }
        }
        1 => {
            let _ = ev.engine.register_keys(&ev.program_id, body);
        }
        2 => {
            let _ = ev.engine.execute(&ev.program_id, body);
        }
        _ => {
            let _ = ev
                .engine
                .has_key(&ev.program_id, &String::from_utf8_lossy(body));
        }
    }
});
