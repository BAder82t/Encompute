//! Semantic transcripts: deterministic, bound to every semantic
//! detail, and replaying to exactly the plan's results.

use encompute_backend::{ExactClient, ExactEvaluator, PlainExactClient, PlainExactEvaluator};
use encompute_exact::{
    compile, evaluate_exact, evaluate_exact_observed, semantic_transcript, ExecutionContext,
    TranscriptObserver,
};
use encompute_ir::{evaluate, Builder, CmpOp, Code, Elem, Inputs, LogicOp, Program, Range};
use encompute_verification::transcript::ProofOp;
use encompute_verification::{ReferenceTranscriptEvaluator, SemanticTranscript};

mod gen;

const SPEC: &str = "abababababababababababababababababababababababababababababababab";

/// The eligibility example, with knobs for mutation tests.
fn eligible(threshold: f64, cmp: CmpOp, risk_type: Elem, logic: LogicOp, swap: bool) -> Program {
    let mut b = Builder::new("eligible", 1e-3).unwrap();
    let age = b
        .input_exact("age", Elem::U8, Some(Range::new(0.0, 120.0)))
        .unwrap();
    let risk = b
        .input_exact("risk", risk_type, Some(Range::new(0.0, 1000.0)))
        .unwrap();
    let k = b.constant_exact(Elem::U8, threshold).unwrap();
    let adult = b.cmp(CmpOp::Ge, age, k).unwrap();
    let k650 = b.constant_exact(risk_type, 650.0).unwrap();
    let ok = b.cmp(cmp, risk, k650).unwrap();
    let both = b.logic(logic, adult, ok).unwrap();
    let fee_hi = b.constant_exact(Elem::U8, 25.0).unwrap();
    let fee_lo = b.constant_exact(Elem::U8, 5.0).unwrap();
    let fee = if swap {
        b.select(both, fee_lo, fee_hi).unwrap()
    } else {
        b.select(both, fee_hi, fee_lo).unwrap()
    };
    b.output("eligible", both).unwrap();
    b.output("fee", fee).unwrap();
    b.finish().unwrap()
}

fn base() -> Program {
    eligible(18.0, CmpOp::Lt, Elem::U16, LogicOp::And, false)
}

fn transcript(p: &Program) -> SemanticTranscript {
    semantic_transcript(&compile(p).unwrap().plan, SPEC)
}

fn run_mock(p: &Program, inputs: &Inputs) -> Vec<i128> {
    let plan = compile(p).unwrap().plan;
    let client = PlainExactClient::new(5);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let cts = plan
        .inputs
        .iter()
        .map(|i| {
            ev.load(
                i.elem,
                &client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let outs = evaluate_exact(&ev, &plan, cts).unwrap();
    plan.outputs
        .iter()
        .zip(outs)
        .map(|(o, ct)| client.decrypt(o.elem, &ev.store(&ct).unwrap()).unwrap())
        .collect()
}

fn replay(t: &SemanticTranscript, inputs: &Inputs) -> Vec<i128> {
    let xs: Vec<i128> = t
        .inputs
        .iter()
        .map(|i| inputs[&i.name][0] as i128)
        .collect();
    ReferenceTranscriptEvaluator::evaluate(t, &xs).unwrap()
}

#[test]
fn listing_and_structure() {
    let t = transcript(&base());
    let listing = t.listing();
    assert!(listing.contains("INPUT"), "{listing}");
    assert!(
        listing.contains("GE_CONST") && listing.contains("LT_CONST"),
        "{listing}"
    );
    assert!(
        listing.contains("SELECT") && listing.contains(": bool"),
        "{listing}"
    );
    assert_eq!(t.outputs.len(), 2);
    assert_eq!(
        ProofOp::from_code(ProofOp::Select.code()),
        Some(ProofOp::Select)
    );
    // Every opcode has a distinct code.
    let mut codes: Vec<u16> = ProofOp::ALL.iter().map(|o| o.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), ProofOp::ALL.len());
}

/// Pinned: a change here means every transcript hash changed. Only allowed
/// with a transcript-version bump (ADR-008). Same value on every platform.
#[test]
fn fixture_hash_is_stable_across_platforms() {
    let t = transcript(&base());
    assert_eq!(
        t.id().hex(),
        "036efc9940b41db2c6c04d316a687511c97e61465a9f1d035f90f3fbb1fd12c2",
        "transcript hash changed:\n{}",
        String::from_utf8(t.canonical_bytes().unwrap()).unwrap()
    );
}

#[test]
fn deterministic_across_compilations() {
    let (a, b) = (transcript(&base()), transcript(&base()));
    assert_eq!(a, b);
    assert_eq!(a.id(), b.id());
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    // The spec is part of the transcript.
    let other = semantic_transcript(&compile(&base()).unwrap().plan, &"cd".repeat(32));
    assert_ne!(other.id(), a.id());
}

#[test]
fn every_semantic_change_changes_the_hash() {
    let h = |p: Program| transcript(&p).id();
    let orig = h(base());
    let mutants = [
        (
            "18 → 19",
            eligible(19.0, CmpOp::Lt, Elem::U16, LogicOp::And, false),
        ),
        (
            "< → <=",
            eligible(18.0, CmpOp::Le, Elem::U16, LogicOp::And, false),
        ),
        (
            "u16 → u32",
            eligible(18.0, CmpOp::Lt, Elem::U32, LogicOp::And, false),
        ),
        (
            "and → or",
            eligible(18.0, CmpOp::Lt, Elem::U16, LogicOp::Or, false),
        ),
        (
            "select branches swapped",
            eligible(18.0, CmpOp::Lt, Elem::U16, LogicOp::And, true),
        ),
    ];
    for (what, p) in mutants {
        assert_ne!(h(p), orig, "{what}");
    }
    // Output bound to another register.
    let mut t = transcript(&base());
    t.outputs[0].register = 0;
    assert_ne!(t.id(), orig, "output register");
    // Operand order.
    let mut t = transcript(&base());
    let e = t
        .entries
        .iter_mut()
        .find(|e| e.op == ProofOp::Select)
        .unwrap();
    e.operands.swap(1, 2);
    assert_ne!(t.id(), orig, "operand order");
}

#[test]
fn strict_parsing() {
    let t = transcript(&base());
    let bytes = t.canonical_bytes().unwrap();
    assert_eq!(SemanticTranscript::from_bytes(&bytes).unwrap(), t);
    let text = String::from_utf8(bytes).unwrap();
    let bad = |s: String, what: &str| {
        assert_eq!(
            SemanticTranscript::from_bytes(s.as_bytes())
                .unwrap_err()
                .code,
            Code::Transcript,
            "{what}"
        );
    };
    bad(
        text.replace("\"transcript_version\":1", "\"transcript_version\":2"),
        "version",
    );
    bad(
        text.replace("EncomputeProofTranscriptV1", "Other"),
        "format",
    );
    bad(text.replace("\"op\":1,", "\"op\":999,"), "unknown opcode");
    bad(
        text.replace("\"value\":\"18\"", "\"value\":\"018\""),
        "non-canonical constant",
    );
    bad(
        text.replace("\"value\":\"18\"", "\"value\":\"300\""),
        "constant outside u8",
    );
    bad(
        text.replacen("{\"entries\"", "{\"extra\":1,\"entries\"", 1),
        "unknown field",
    );
    bad(text[..text.len() / 2].to_owned(), "truncated");
    let mutate = |f: &dyn Fn(&mut SemanticTranscript), what: &str| {
        let mut m = t.clone();
        f(&mut m);
        bad(
            String::from_utf8(m.canonical_bytes().unwrap()).unwrap(),
            what,
        );
    };
    mutate(&|m| m.entries[2].operands[0] = 9, "forward reference");
    mutate(
        &|m| m.entries[4].operands.pop().map(|_| ()).unwrap(),
        "missing operand",
    );
    mutate(&|m| m.entries[4].operands.push(0), "extra operand");
    mutate(
        &|m| {
            // An input index smuggled onto a non-INPUT entry.
            let p = m.entries[0].params.clone();
            m.entries[4].params = p;
        },
        "parameter of another opcode",
    );
    mutate(&|m| m.entries[2].params.clear(), "missing constant");
    mutate(
        &|m| m.entries[4].ty = encompute_verification::transcript::ExactType(Elem::U8),
        "ill-typed result",
    );
    mutate(
        &|m| m.outputs[0].ty = encompute_verification::transcript::ExactType(Elem::U8),
        "output type",
    );
}

#[test]
fn no_runtime_values_in_transcripts() {
    // The transcript is built from the plan alone; running the program on
    // distinctive inputs cannot change or enter it.
    let p = base();
    let plan = compile(&p).unwrap().plan;
    let client = PlainExactClient::new(1);
    let ev = PlainExactEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let cts = vec![
        ev.load(Elem::U8, &client.encrypt(Elem::U8, 97).unwrap())
            .unwrap(),
        ev.load(Elem::U16, &client.encrypt(Elem::U16, 913).unwrap())
            .unwrap(),
    ];
    let mut obs = TranscriptObserver::default();
    let ctx = ExecutionContext {
        spec_id: SPEC.into(),
    };
    evaluate_exact_observed(&ev, &plan, cts, &ctx, &mut obs).unwrap();
    let observed = obs.into_transcript().unwrap();
    // The observer records exactly the plan-derived transcript.
    assert_eq!(observed, semantic_transcript(&plan, SPEC));
    let text = String::from_utf8(observed.canonical_bytes().unwrap()).unwrap();
    assert!(!text.contains("97") && !text.contains("913"), "{text}");
}

/// Random plans over every width and op: the transcript replays to exactly
/// the plan's results on the mock and the clear interpreter.
/// `ENCOMPUTE_EXACT_PROGRAMS` sets the count (nightly: 10 000+).
#[test]
fn random_plans_replay_exactly() {
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    use std::cell::Cell;
    let n = gen::programs(512);
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: n,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let (plans, cases) = (Cell::new(0u32), Cell::new(0u64));
    runner
        .run(
            &(gen::arb_program(), proptest::prelude::any::<u64>()),
            |((p, decl), seed)| {
                let Ok(c) = compile(&p) else {
                    return Ok(());
                };
                let t = semantic_transcript(&c.plan, SPEC);
                plans.set(plans.get() + 1);
                for case in 0..6 {
                    let inputs = gen::inputs_for(&decl, case, seed);
                    let want = run_mock(&p, &inputs);
                    proptest::prop_assert_eq!(replay(&t, &inputs), want.clone(), "{}", p);
                    let clear: Vec<i128> = c
                        .plan
                        .outputs
                        .iter()
                        .map(|o| evaluate(&p, &inputs).unwrap()[&o.name][0] as i128)
                        .collect();
                    proptest::prop_assert_eq!(clear, want);
                    cases.set(cases.get() + 1);
                }
                Ok(())
            },
        )
        .unwrap();
    eprintln!(
        "transcript replay: {} plans, {} cases, all exact",
        plans.get(),
        cases.get()
    );
}

/// Building and hashing a transcript is negligible next to FHE evaluation.
#[test]
fn transcript_generation_is_cheap() {
    let plan = compile(&base()).unwrap().plan;
    let t0 = std::time::Instant::now();
    for _ in 0..1000 {
        let t = semantic_transcript(&plan, SPEC);
        std::hint::black_box(t.id());
    }
    let per = t0.elapsed() / 1000;
    eprintln!(
        "transcript of {} instructions: {per:?} to build and hash",
        plan.instrs.len()
    );
    // The same program takes about 2 s to evaluate on TFHE-rs.
    assert!(per < std::time::Duration::from_millis(20), "{per:?}");
}
