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
