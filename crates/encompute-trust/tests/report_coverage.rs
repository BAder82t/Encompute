//! A satisfied trust report must not read as more than it covers (risk
//! R-04): a program without confidentiality declarations has no policy to
//! verify, a caller can require evidence of a run, and the report lists
//! what it covered and what was not present.

use encompute_trust::{ReportOptions, Status, TrustGraph};

const PLAIN: &str = "encompute 0.1
program plain precision 0.001
%0 = input \"x\" [0.0, 10.0] : secret u8
%1 = const [3.0] : public u8
%2 = ge %0, %1 : secret bool
output \"y\" = %2
";

const DECLARED: &str = "encompute 0.1
program owned precision 0.001 purpose \"x\"
party \"p\" \"P\"
asset \"a\" dataset owners [\"p\"] readers [\"p\"] purposes [\"x\"] release owner_only
%0 = input \"v\" [0.0, 10.0] asset \"a\" : secret u8
%1 = const [3.0] : public u8
%2 = ge %0, %1 : secret bool
output \"y\" = %2 to \"p\"
";

fn graph(eir: &str) -> TrustGraph {
    let mut g = TrustGraph::new();
    g.add_program(eir).unwrap();
    g
}

fn status(r: &encompute_trust::TrustReport, row: &str) -> Status {
    r.rows.iter().find(|x| x.name == row).unwrap().status
}

#[test]
fn a_program_without_declarations_has_no_policy_to_verify() {
    let r = graph(PLAIN).report(&ReportOptions::default()).unwrap();
    assert_eq!(status(&r, "Program"), Status::Verified);
    assert_eq!(status(&r, "Policy"), Status::NotPresent);
    // A declared policy is still verified.
    let mut g = graph(DECLARED);
    let _ = &mut g;
    let r = g.report(&ReportOptions::default()).unwrap();
    assert_eq!(status(&r, "Policy"), Status::Verified);
}

#[test]
fn a_report_lists_what_it_covered_and_what_was_not_present() {
    let r = graph(PLAIN).report(&ReportOptions::default()).unwrap();
    assert!(r.satisfied, "{r}");
    assert_eq!(r.covered, ["Evidence", "Program"]);
    assert!(r.not_present.iter().any(|x| x == "Policy"));
    assert!(r.not_present.iter().any(|x| x == "Execution"));
    let text = r.to_string();
    assert!(text.contains("COVERS     Evidence, Program"), "{text}");
    assert!(text.contains("NOT PRESENT"), "{text}");
}

#[test]
fn requiring_a_run_refuses_a_report_with_no_execution_aggregation_or_training() {
    let opts = ReportOptions {
        require_run: true,
        ..ReportOptions::default()
    };
    let r = graph(PLAIN).report(&opts).unwrap();
    assert!(!r.satisfied, "{r}");
    assert!(
        r.unmet.iter().any(|u| u.contains("no evidence of a run")),
        "{:?}",
        r.unmet
    );
    // Without the requirement the same bundle satisfies (library default).
    assert!(
        graph(PLAIN)
            .report(&ReportOptions::default())
            .unwrap()
            .satisfied
    );
}

/// A receipt from the mock backend, which encrypts nothing, signed by a
/// trusted evaluator key (risk R-11).
fn mock_execution() -> (TrustGraph, String) {
    use encompute_verification::{
        EvaluatorSigner, ExecutionReceipt, VerificationEvidence, RECEIPT_VERSION,
    };
    use sha2::{Digest, Sha256};
    let text = encompute_ir::parse(PLAIN).unwrap().to_string();
    let program_id: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s = EvaluatorSigner::from_seed(&[5; 32]);
    let h = |c: char| c.to_string().repeat(64);
    let receipt = ExecutionReceipt {
        version: RECEIPT_VERSION,
        execution_id: "00000000-0000-4000-8000-000000000001".into(),
        spec_id: h('1'),
        program_id,
        plan_id: h('2'),
        parameter_set_id: h('3'),
        key_id: h('4'),
        request_commitment: h('5'),
        output_commitment: h('6'),
        scheme: "BinFHE".into(),
        backend: "mock".into(),
        backend_version: "0".into(),
        transcript_hash: None,
        evaluator_id: s.identity().evaluator_id(),
        evidence: VerificationEvidence::None,
        attestation: None,
        grant_digest: None,
    }
    .sign(&s)
    .unwrap();
    let mut g = graph(PLAIN);
    g.add_execution_receipt(receipt).unwrap();
    (g, s.identity().public_key_hex())
}

#[test]
fn a_mock_backend_execution_is_not_verified_evidence_unless_allowed() {
    let (g, key) = mock_execution();
    let anchors = encompute_trust::Anchors {
        evaluators: [key].into_iter().collect(),
        ..Default::default()
    };
    // Default: the row fails, and it does not count as a run.
    let r = g
        .report(&ReportOptions {
            anchors: anchors.clone(),
            require_run: true,
            ..ReportOptions::default()
        })
        .unwrap();
    assert_eq!(status(&r, "Execution"), Status::Failed, "{r}");
    assert!(!r.satisfied);
    let row = r.rows.iter().find(|x| x.name == "Execution").unwrap();
    assert!(
        row.details.iter().any(|d| d.contains("mock backend")),
        "{:?}",
        row.details
    );
    // Allowed explicitly (development, tests): verified, with a note.
    let r = g
        .report(&ReportOptions {
            anchors,
            require_run: true,
            allow_mock: true,
            ..ReportOptions::default()
        })
        .unwrap();
    assert_eq!(status(&r, "Execution"), Status::Verified, "{r}");
    assert!(r.satisfied, "{r}");
    let row = r.rows.iter().find(|x| x.name == "Execution").unwrap();
    assert!(
        row.details.iter().any(|d| d.contains("not encrypted")),
        "{:?}",
        row.details
    );
}
