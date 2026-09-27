//! Fuzz smoke tests for the `.eir` text parser: thousands of mutated
//! programs must never panic, must finish quickly, and anything accepted
//! must print back to itself. Resource limits: huge dimensions, value
//! numbers, lines and constants are typed errors, not allocations.

mod fuzz_support;

use std::time::Duration;

use encompute_ir::{parse, Code};
use fuzz_support::{run, within};

const SEEDS: &[&str] = &[
    include_str!("../../../examples/09_differential_privacy/fedavg.eir"),
    include_str!("../../../examples/06_confidentiality_policy/training.eir"),
    include_str!("../../../examples/04_execution_receipts/adult.eir"),
    include_str!("../../../examples/07_attested_key_release/step.eir"),
    include_str!("../../../benches/exact/mixed.eir"),
    include_str!("../../../benches/exact/lookup_small.eir"),
    include_str!("../../../benches/exact/branch_logic.eir"),
    "encompute 0.1\nprogram m precision 0.001 verification required\n\
     %0 = input \"x\" [-1.0, 1.0] : secret vector<2>\n\
     %1 = const [1.0, 2.0, 3.0, 4.0] : public matrix<2x2>\n\
     %2 = matvec %1, %0 : secret vector<2>\n\
     %3 = poly %2 [0.5, 0.25, 0.125] : secret vector<2>\n\
     %4 = sum %3 : secret scalar\n%5 = sigmoid %4 : secret scalar\n\
     output \"y\" = %5 public\n",
];

fn seeds() -> Vec<Vec<u8>> {
    SEEDS.iter().map(|s| s.as_bytes().to_vec()).collect()
}

#[test]
fn seeds_parse() {
    for s in SEEDS {
        let p = parse(s).unwrap();
        assert_eq!(parse(&p.to_string()).unwrap(), p);
    }
}

#[test]
fn mutated_programs_never_panic_and_round_trip() {
    run("eir", &seeds(), 6000, Duration::from_secs(2), |bytes| {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return;
        };
        if let Ok(p) = parse(text) {
            let printed = p.to_string();
            let again = parse(&printed).expect("printed program parses");
            assert_eq!(again, p, "round trip");
        }
    });
}

fn program(body: &str) -> String {
    format!("encompute 0.1\nprogram p precision 0.001\n{body}")
}

#[test]
fn huge_dimensions_are_refused_without_allocating() {
    let limit = Duration::from_secs(2);
    for (ty, code) in [
        ("secret vector<18446744073709551615>", Code::Unsupported),
        ("secret vector<18446744073709551616>", Code::Parse),
        ("secret vector<32769>", Code::Unsupported),
        ("secret matrix<4294967296x4294967296>", Code::Unsupported),
        (
            "secret matrix<18446744073709551615x18446744073709551615>",
            Code::Unsupported,
        ),
        ("secret matrix<99999999999999999999999x2>", Code::Parse),
    ] {
        let src = program(&format!(
            "%0 = input \"x\" [-1.0, 1.0] : {ty}\noutput \"y\" = %0\n"
        ));
        let e = within(limit, || parse(&src)).unwrap_err();
        assert_eq!(e.code, code, "{ty}: {e}");
    }
    let src = program(
        "%0 = const [1.0] : public matrix<4294967296x4294967296>\n\
         %1 = input \"x\" [-1.0, 1.0] : secret scalar\noutput \"y\" = %1\n",
    );
    let e = within(limit, || parse(&src)).unwrap_err();
    assert_eq!(e.code, Code::Unsupported, "{e}");
}

#[test]
fn huge_numbers_are_typed_errors() {
    let limit = Duration::from_secs(2);
    for body in [
        "%4294967296 = input \"x\" [-1.0, 1.0] : secret scalar\n",
        "%18446744073709551616 = input \"x\" [-1.0, 1.0] : secret scalar\n",
        "%0 = input \"x\" [-1.0, 1.0] : secret scalar\n%1 = neg %4294967295 : secret scalar\n",
        "%0 = input \"x\" [-1e999, 1.0] : secret scalar\n",
        "%0 = input \"x\" [NaN, 1.0] : secret scalar\n",
        "%0 = input \"x\" [0.0, 255.0] : secret u8\n%1 = shl %0 18446744073709551615 : secret u8\n",
        "%0 = input \"x\" [0.0, 255.0] : secret u8\n%1 = shl %0 4294967296 : secret u8\n",
    ] {
        let src = program(&format!("{body}output \"y\" = %0\n"));
        let e = within(limit, || parse(&src)).unwrap_err();
        assert!(
            matches!(e.code, Code::Parse | Code::Type | Code::MissingRange),
            "{body}: {e}"
        );
    }
    let aggregate = |tail: &str| {
        program(&format!(
            "party \"a\" \"A\"\n%0 = input \"x\" [-1.0, 1.0] : secret vector<2>\n\
             output \"y\" = %0 to \"a\"\naggregate \"y\" sum {tail}\n"
        ))
    };
    for tail in [
        "minimum 18446744073709551616 colluding 1 clip [-1.0, 1.0] scale 1 modulus 40",
        "minimum 3 colluding 1 clip [-1.0, 1.0] scale 1 modulus 4294967296",
        "minimum 3 colluding 1 clip [-1.0, 1.0, 2.0] scale 1 modulus 40",
    ] {
        let e = within(limit, || parse(&aggregate(tail))).unwrap_err();
        assert!(!e.message.is_empty(), "{tail}: {e}");
    }
}

#[test]
fn large_inputs_parse_in_bounded_time() {
    // A constant of 32768 values, and one with a million (refused).
    let ok: Vec<String> = (0..32768).map(|i| format!("{}.5", i % 7)).collect();
    let src = program(&format!(
        "%0 = input \"x\" [-1.0, 1.0] : secret vector<32768>\n\
         %1 = const [{}] : public vector<32768>\n%2 = mul %0, %1 : secret vector<32768>\n\
         output \"y\" = %2\n",
        ok.join(", ")
    ));
    within(Duration::from_secs(10), || parse(&src)).unwrap();
    let many = vec!["1.0"; 1_000_000].join(",");
    let src = program(&format!(
        "%0 = const [{many}] : public vector<1000000>\noutput \"y\" = %0\n"
    ));
    let e = within(Duration::from_secs(10), || parse(&src)).unwrap_err();
    assert_eq!(e.code, Code::Unsupported, "{e}");
    // 20000 chained operations.
    let mut body = String::from("%0 = input \"x\" [-1.0, 1.0] : secret scalar\n");
    for i in 1..20000 {
        body.push_str(&format!("%{i} = neg %{} : secret scalar\n", i - 1));
    }
    body.push_str("output \"y\" = %19999\n");
    within(Duration::from_secs(10), || parse(&program(&body))).unwrap();
    // A megabyte line of brackets, quotes and one very long name.
    for junk in [
        "[".repeat(1 << 20),
        "\"".repeat(1 << 20),
        "a".repeat(1 << 20),
    ] {
        let e = within(Duration::from_secs(10), || parse(&program(&junk))).unwrap_err();
        assert_eq!(e.code, Code::Parse, "{e}");
        let src = format!("encompute 0.1\nprogram {junk} precision 0.1\n");
        let e = within(Duration::from_secs(10), || parse(&src)).unwrap_err();
        assert!(!e.message.is_empty(), "{e}");
    }
}

#[test]
fn truncated_programs_are_refused() {
    for s in SEEDS {
        for cut in (0..s.len()).step_by(7) {
            if !s.is_char_boundary(cut) {
                continue;
            }
            let _ = within(Duration::from_secs(1), || parse(&s[..cut]));
        }
    }
    assert_eq!(parse("").unwrap_err().code, Code::Parse);
    assert_eq!(parse("encompute 0.1\n").unwrap_err().code, Code::Parse);
}
