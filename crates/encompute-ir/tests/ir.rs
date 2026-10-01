use encompute_ir::{evaluate, parse, Builder, Code, Inputs, Program, Range, Shape, ValueId};
use proptest::prelude::*;

fn logistic() -> Program {
    let mut b = Builder::new("score", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let w = b.constant(Shape::Vector(3), vec![0.5, -0.25, 2.0]).unwrap();
    let bias = b.constant(Shape::Scalar, vec![0.1]).unwrap();
    let z = b.dot(w, x).unwrap();
    let z = b.add(z, bias).unwrap();
    let y = b.sigmoid(z).unwrap();
    b.output("score", y).unwrap();
    b.finish().unwrap()
}

#[test]
fn prints_the_documented_form() {
    let text = logistic().to_string();
    assert_eq!(
        text,
        "encompute 0.1\n\
         program score precision 0.001\n\
         %0 = input \"x\" [-1.0, 1.0] : secret vector<3>\n\
         %1 = const [0.5, -0.25, 2.0] : public vector<3>\n\
         %2 = const [0.1] : public scalar\n\
         %3 = dot %1, %0 : secret scalar\n\
         %4 = add %3, %2 : secret scalar\n\
         %5 = sigmoid %4 : secret scalar\n\
         output \"score\" = %5\n"
    );
    assert_eq!(parse(&text).unwrap(), logistic());
}

#[test]
fn evaluates_reference_semantics() {
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, 0.0, -0.5]);
    let out = evaluate(&logistic(), &inputs).unwrap();
    let z: f64 = 0.5 - 1.0 + 0.1;
    assert!((out["score"][0] - 1.0 / (1.0 + (-z).exp())).abs() < 1e-15);
}

#[test]
fn matvec_and_broadcast() {
    let mut b = Builder::new("m", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-2.0, 2.0))
        .unwrap();
    let s = b.input("s", Shape::Scalar, Range::new(0.0, 1.0)).unwrap();
    let m = b
        .constant(Shape::Matrix(2, 3), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        .unwrap();
    let y = b.matvec(m, x).unwrap();
    let y = b.mul(y, s).unwrap();
    let p = b.poly(y, vec![1.0, 0.0, 2.0]).unwrap();
    b.output("y", p).unwrap();
    let prog = b.finish().unwrap();
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, -1.0, 2.0]);
    inputs.insert("s".into(), vec![0.5]);
    let out = evaluate(&prog, &inputs).unwrap();
    // m·x = [5, 11], ·0.5 = [2.5, 5.5], 1 + 2y² = [13.5, 61.5]
    assert_eq!(out["y"], vec![13.5, 61.5]);
    assert_eq!(parse(&prog.to_string()).unwrap(), prog);
}

#[test]
fn rejects_out_of_range_and_missing_inputs() {
    let p = logistic();
    let mut inputs = Inputs::new();
    inputs.insert("x".into(), vec![1.0, 0.0, -1.5]);
    assert_eq!(evaluate(&p, &inputs).unwrap_err().code, Code::BadInput);
    assert_eq!(
        evaluate(&p, &Inputs::new()).unwrap_err().code,
        Code::BadInput
    );
    inputs.insert("x".into(), vec![0.0, 0.0, 0.0]);
    inputs.insert("y".into(), vec![0.0]);
    assert_eq!(evaluate(&p, &inputs).unwrap_err().code, Code::BadInput);
}

#[test]
fn type_rules() {
    let mut b = Builder::new("t", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let y = b
        .input("y", Shape::Vector(4), Range::new(-1.0, 1.0))
        .unwrap();
    let c = b.constant(Shape::Scalar, vec![1.0]).unwrap();
    let m = b.constant(Shape::Matrix(2, 4), vec![0.0; 8]).unwrap();
    assert_eq!(b.add(x, y).unwrap_err().code, Code::Type);
    assert_eq!(b.dot(x, y).unwrap_err().code, Code::Type);
    assert_eq!(b.add(c, c).unwrap_err().code, Code::Type, "public-only op");
    assert_eq!(b.matvec(m, x).unwrap_err().code, Code::Type);
    assert_eq!(b.add(m, x).unwrap_err().code, Code::Type);
    assert_eq!(b.matvec(x, y).unwrap_err().code, Code::Unsupported);
    assert_eq!(b.poly(x, vec![1.0]).unwrap_err().code, Code::Type);
    assert_eq!(b.ty(ValueId(99)).unwrap_err().code, Code::Type);
    assert_eq!(
        b.input("z", Shape::Scalar, Range::new(1.0, 1.0))
            .unwrap_err()
            .code,
        Code::MissingRange
    );
    assert_eq!(
        b.input("x", Shape::Scalar, Range::new(0.0, 1.0))
            .unwrap_err()
            .code,
        Code::Type,
        "duplicate"
    );
    assert_eq!(
        b.output("out", c).unwrap_err().code,
        Code::Type,
        "public output"
    );
    assert!(Builder::new("bad name", 1e-3).is_err());
    assert!(Builder::new("p", 0.0).is_err());
    assert_eq!(b.finish().unwrap_err().code, Code::Type, "no outputs");
}

#[test]
fn parse_errors_carry_line_numbers() {
    let bad = "encompute 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, 1.0] : secret vector<2>\n%1 = neg %0 : secret scalar\noutput \"y\" = %1\n";
    let e = parse(bad).unwrap_err();
    assert_eq!(e.code, Code::Parse);
    assert!(e.message.starts_with("line 4:"), "{}", e.message);

    let bad =
        "encompute 0.1\nprogram p precision 0.1\n%1 = input \"x\" [0.0, 1.0] : secret scalar\n";
    assert!(parse(bad).unwrap_err().message.contains("expected %0"));
    assert_eq!(parse("encompute 0.2\n").unwrap_err().code, Code::Parse);
    let bad = "encompute 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, 1.0] : secret scalar\n%1 = frob %0 : secret scalar\n";
    assert!(parse(bad).unwrap_err().message.contains("unknown op"));
    let bad =
        "encompute 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, inf] : secret scalar\n";
    assert_eq!(parse(bad).unwrap_err().code, Code::Parse);
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let src = format!("# model\n\n{}\n# end\n", logistic());
    assert_eq!(parse(&src).unwrap(), logistic());
}

/// Random well-typed programs built through the checked builder.
fn arb_program() -> impl Strategy<Value = Program> {
    let finite = -1e6f64..1e6;
    (
        1usize..6,
        prop::collection::vec((0u8..9, any::<u32>(), any::<u32>(), finite.clone()), 1..25),
        prop::collection::vec(finite, 8),
    )
        .prop_map(|(n, steps, pool)| {
            let mut b = Builder::new("p", 1e-4).unwrap();
            let v = b
                .input("v", Shape::Vector(n), Range::new(-3.0, 3.5))
                .unwrap();
            let s = b.input("s", Shape::Scalar, Range::new(-0.5, 1e-3)).unwrap();
            let mut secrets = vec![v, s];
            for (kind, i, j, x) in steps {
                let a = secrets[i as usize % secrets.len()];
                let other = secrets[j as usize % secrets.len()];
                let r = match kind {
                    0 => b.add(a, other),
                    1 => b.sub(a, other),
                    2 => b.mul(a, other),
                    3 => b.neg(a),
                    4 => b.sum(a),
                    5 => b.sigmoid(a),
                    6 => b.poly(a, vec![x, pool[0], pool[1]]),
                    7 => {
                        let c = b
                            .constant(
                                Shape::Vector(n),
                                pool.iter().cycle().take(n).copied().collect(),
                            )
                            .unwrap();
                        b.dot(c, a)
                    }
                    _ => {
                        let c = b
                            .constant(
                                Shape::Matrix(2, n),
                                pool.iter().cycle().take(2 * n).copied().collect(),
                            )
                            .unwrap();
                        b.matvec(c, a)
                    }
                };
                if let Ok(id) = r {
                    secrets.push(id);
                }
            }
            let last = *secrets.last().unwrap();
            b.output("out", last).unwrap();
            b.output("v_copy", v).unwrap();
            b.finish().unwrap()
        })
}

proptest! {
    #[test]
    fn print_parse_round_trip(p in arb_program()) {
        let text = p.to_string();
        let back = parse(&text).unwrap();
        prop_assert_eq!(&back, &p);
        prop_assert_eq!(back.to_string(), text);
    }
}

#[test]
fn oversized_shapes_are_rejected_before_allocation() {
    let mut b = Builder::new("p", 1e-3).unwrap();
    let e = b
        .input("x", Shape::Vector(1 << 40), Range::new(0.0, 1.0))
        .unwrap_err();
    assert_eq!(e.code, Code::Unsupported);
    let text = "encompute 0.1\nprogram p precision 0.1\n%0 = const [1.0] : public matrix<4294967297x4294967297>\n";
    assert!(parse(text).is_err());
    let text = "encompute 0.1\nprogram p precision 0.1\n%0 = input \"x\" [0.0, 1.0] : secret vector<99999999999>\n";
    assert_eq!(parse(text).unwrap_err().code, Code::Unsupported);
}

fn valid_text() -> String {
    let mut b = Builder::new("fuzz", 1e-3).unwrap();
    let x = b
        .input("x", Shape::Vector(3), Range::new(-1.0, 1.0))
        .unwrap();
    let m = b
        .constant(Shape::Matrix(2, 3), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        .unwrap();
    let y = b.matvec(m, x).unwrap();
    let z = b.poly(y, vec![0.5, 1.0, -0.25]).unwrap();
    let s = b.sum(z).unwrap();
    let t = b.sigmoid(s).unwrap();
    b.output("t", t).unwrap();
    b.finish().unwrap().to_string()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The parser returns an error, never panics, on arbitrary input.
    #[test]
    fn parse_never_panics_on_arbitrary_text(s in ".{0,400}") {
        let _ = parse(&s);
    }

    /// Nor on valid programs with random edits.
    #[test]
    fn parse_never_panics_on_mutations(
        edits in prop::collection::vec((any::<usize>(), 0u8..3, any::<char>()), 1..8)
    ) {
        let mut chars: Vec<char> = valid_text().chars().collect();
        for (pos, kind, c) in edits {
            let i = pos % (chars.len() + 1);
            match kind {
                0 if i < chars.len() => { chars[i] = c; }
                1 => chars.insert(i, c),
                _ if i < chars.len() => { chars.remove(i); }
                _ => {}
            }
        }
        let text: String = chars.into_iter().collect();
        if let Ok(p) = parse(&text) {
            // Whatever parses must print and re-parse identically.
            prop_assert_eq!(parse(&p.to_string()).unwrap(), p);
        }
    }
}

#[test]
fn every_code_round_trips_and_is_unique() {
    let mut seen = std::collections::HashSet::new();
    for c in Code::ALL {
        assert_eq!(Code::parse(c.as_str()), Some(c));
        assert!(seen.insert(c.as_str()), "duplicate {c}");
    }
}

/// The governance block from ENC2701 (public-sector governed projects) is
/// complete, in order, and each code is documented in docs/errors.md.
#[test]
fn the_governance_codes_are_the_2701_block() {
    let block: Vec<&str> = Code::ALL
        .iter()
        .map(|c| c.as_str())
        .filter(|s| s.starts_with("ENC27"))
        .collect();
    // 2701..=2730 is one contiguous block: the base (2701..=2718), privacy
    // scopes and aggregates (2719..=2722), residency and operators
    // (2723..=2726) and the evidence bundle (2727..=2730).
    let expected: Vec<String> = (2701..=2730).map(|n| format!("ENC{n}")).collect();
    assert_eq!(block, expected);
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/errors.md"),
    )
    .unwrap();
    for c in expected {
        assert!(
            doc.contains(&format!("| {c} |")),
            "docs/errors.md lacks {c}"
        );
    }
    assert_eq!(Code::GovernanceAuthorizationMissing.as_str(), "ENC2701");
    assert_eq!(Code::GovernanceReleaseTicket.as_str(), "ENC2712");
    assert_eq!(Code::GovernanceBrokerStateRollback.as_str(), "ENC2713");
    assert_eq!(Code::GovernanceAuthorizationLimit.as_str(), "ENC2714");
    assert_eq!(Code::GovernanceCustody.as_str(), "ENC2715");
    assert_eq!(Code::GovernanceAuditorSeparation.as_str(), "ENC2716");
    assert_eq!(Code::GovernanceRevocationHead.as_str(), "ENC2717");
    assert_eq!(Code::GovernanceCheckpointWitness.as_str(), "ENC2718");
    assert_eq!(Code::GovernancePrivacyScope.as_str(), "ENC2719");
    assert_eq!(Code::GovernancePrivacyAllocation.as_str(), "ENC2720");
    assert_eq!(Code::GovernanceAggregateDeclaration.as_str(), "ENC2721");
    assert_eq!(Code::GovernanceAggregateLayout.as_str(), "ENC2722");
    assert_eq!(Code::GovernanceLocationEvidence.as_str(), "ENC2723");
    assert_eq!(Code::GovernancePlacementChange.as_str(), "ENC2724");
    assert_eq!(Code::GovernanceOperatorSeparation.as_str(), "ENC2725");
    assert_eq!(Code::GovernanceClientPlacement.as_str(), "ENC2726");
    assert_eq!(Code::GovernanceBundleMalformed.as_str(), "ENC2727");
    assert_eq!(Code::GovernanceBundleUnverified.as_str(), "ENC2728");
    assert_eq!(Code::GovernanceBundlePlaintext.as_str(), "ENC2729");
    assert_eq!(Code::GovernanceBundleLimit.as_str(), "ENC2730");
}

fn with_forms(forms: &str) -> String {
    format!(
        "encompute 0.1\nprogram eligible precision 0.001 purpose \"eligibility\"\n\
         party \"tax\" \"Tax\"\nparty \"ben\" \"Benefits\"\n\
         asset \"income\" dataset owners [\"tax\"] readers [\"ben\"] purposes [\"eligibility\"] release allowed_parties{forms}\n\
         %0 = input \"x\" [0.0, 120.0] asset \"income\" : secret u8\n\
         %1 = const [18.0] : public u8\n\
         %2 = ge %0, %1 : secret bool\n\
         output \"out\" = %2 to \"ben\"\n"
    )
}

/// `release R forms [..]` parses into the asset's forms, prints back
/// canonically and round-trips; without it there are no forms.
#[test]
fn release_forms_round_trip() {
    use encompute_ir::confidentiality::ReleaseForm;
    let none = encompute_ir::parse(&with_forms("")).unwrap();
    assert_eq!(none.confidentiality().unwrap().assets[0].policy.forms, None);
    assert!(!none.to_string().contains("forms"));
    for (text, forms) in [
        (" forms [boolean]", vec![ReleaseForm::Boolean]),
        (
            " forms [bounded_category 4, boolean]",
            vec![ReleaseForm::Boolean, ReleaseForm::BoundedCategory { max: 4 }],
        ),
        (
            " forms [aggregate, dp_aggregate, derived_artifact]",
            vec![
                ReleaseForm::Aggregate,
                ReleaseForm::DpAggregate,
                ReleaseForm::DerivedArtifact,
            ],
        ),
        (" forms []", vec![]),
        (
            " forms [dp_aggregate] derive [model aggregate_only to [\"ben\"]] privacy unit \"person\" epsilon 1.0 delta 1e-6",
            vec![ReleaseForm::DpAggregate],
        ),
    ] {
        let p = encompute_ir::parse(&with_forms(text)).unwrap();
        let got = &p.confidentiality().unwrap().assets[0].policy.forms;
        assert_eq!(got, &Some(forms.into_iter().collect()), "{text}");
        let printed = p.to_string();
        let q = encompute_ir::parse(&printed).unwrap();
        assert_eq!(p, q, "{printed}");
        assert_eq!(printed, q.to_string());
    }
}

#[test]
fn malformed_release_forms_are_refused() {
    for bad in [
        " forms [bool]",
        " forms [boolean, boolean]",
        " forms [bounded_category]",
        " forms [bounded_category -1]",
        " forms [boolean",
    ] {
        let e = encompute_ir::parse(&with_forms(bad)).unwrap_err();
        assert_eq!(e.code, Code::Parse, "{bad}: {e:?}");
    }
    let e = encompute_ir::parse(&with_forms(
        " forms [bounded_category 2, bounded_category 5]",
    ))
    .unwrap_err();
    assert_eq!(e.code, Code::PolicyDeclaration, "{e:?}");
}

/// Forms join by intersection (a bounded category at the lower maximum),
/// and `forms_within` is "at least as strict".
#[test]
fn release_forms_meet_and_within() {
    use encompute_ir::confidentiality::{forms_within, meet_forms, ReleaseForm as F};
    use std::collections::BTreeSet;
    let s = |x: &[F]| Some(x.iter().copied().collect::<BTreeSet<F>>());
    assert_eq!(meet_forms(&None, &None), None);
    assert_eq!(meet_forms(&s(&[F::Boolean]), &None), s(&[F::Boolean]));
    assert_eq!(
        meet_forms(
            &s(&[F::Boolean, F::BoundedCategory { max: 9 }, F::Aggregate]),
            &s(&[F::BoundedCategory { max: 3 }, F::Aggregate, F::DpAggregate])
        ),
        s(&[F::BoundedCategory { max: 3 }, F::Aggregate])
    );
    assert_eq!(meet_forms(&s(&[F::Boolean]), &s(&[F::Aggregate])), s(&[]));
    assert!(forms_within(&None, &None));
    assert!(forms_within(&s(&[F::Boolean]), &None));
    assert!(!forms_within(&None, &s(&[F::Boolean])));
    assert!(forms_within(
        &s(&[F::BoundedCategory { max: 2 }]),
        &s(&[F::BoundedCategory { max: 3 }])
    ));
    assert!(!forms_within(
        &s(&[F::BoundedCategory { max: 4 }]),
        &s(&[F::BoundedCategory { max: 3 }])
    ));
    assert!(!forms_within(&s(&[F::Aggregate]), &s(&[F::DpAggregate])));
    assert!(forms_within(&s(&[]), &s(&[F::Boolean])));
}
