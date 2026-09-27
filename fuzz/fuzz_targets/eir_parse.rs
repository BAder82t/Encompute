//! `.eir` program text (`encompute_ir::parse`): never panics; anything
//! accepted prints back to the same program.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(p) = encompute_ir::parse(text) {
        let again = encompute_ir::parse(&p.to_string()).expect("printed program parses");
        assert_eq!(again, p);
    }
});
