//! Aggregation boundaries (ADR-012): lowering `aggregate` declarations, the
//! derived policy, and every declaration that must be refused.

use encompute_analysis::confidentiality::analyze;
use encompute_ir::confidentiality::{AggregationFunction, OutputRelease, PartyId, Release};
use encompute_ir::{parse, Code};

/// Three hospitals, each owning a gradient that may leave only in
/// aggregate, to the coordinator.
fn fedavg(body: &str, aggregate: &str) -> String {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"disease-training\"\n\
         party \"hospital-a\" \"Hospital A\"\nparty \"hospital-b\" \"Hospital B\"\n\
         party \"hospital-c\" \"Hospital C\"\nparty \"hospital-d\" \"Hospital D\"\n\
         party \"coordinator\" \"Coordinator\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"disease-training\"] release aggregate_only\n"
        ));
    }
    s.push_str(
        "%0 = input \"ga\" [-1.0, 1.0] asset \"gradient-a\" : secret vector<8>\n\
         %1 = input \"gb\" [-1.0, 1.0] asset \"gradient-b\" : secret vector<8>\n\
         %2 = input \"gc\" [-1.0, 1.0] asset \"gradient-c\" : secret vector<8>\n",
    );
    s.push_str(body);
    s.push_str(aggregate);
    s
}

const SUM: &str = "%3 = add %0, %1 : secret vector<8>\n%4 = add %3, %2 : secret vector<8>\n";
const OUT: &str = "output \"global_gradient\" = %4 to \"coordinator\"\n";
const AGG: &str =
    "aggregate \"global_gradient\" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 1024 modulus 32\n";

fn code(text: &str) -> Code {
    match parse(text) {
        Err(e) => e.code,
        Ok(p) => analyze(&p).unwrap_err().code,
    }
}

#[test]
fn aggregate_only_needs_the_boundary() {
    // Without the declaration, revealing the sum is ENC1905.
    assert_eq!(
        code(&fedavg(&format!("{SUM}{OUT}"), "")),
        Code::AggregationRequired
    );
    // With it, the aggregate reaches the coordinator.
    let text = fedavg(&format!("{SUM}{OUT}"), AGG);
    let p = parse(&text).unwrap();
    assert_eq!(p.to_string(), text, "canonical text");
    let r = analyze(&p).unwrap().unwrap();
    let b = &r.aggregations[0];
    assert_eq!(b.function, AggregationFunction::Sum);
    assert_eq!(b.vector_len, 8);
    assert_eq!(
        b.contributions
            .iter()
            .map(|k| k.party.as_str())
            .collect::<Vec<_>>(),
        ["hospital-a", "hospital-b", "hospital-c"]
    );
    assert_eq!(b.contribution_policy.release, Release::AggregateOnly);
    // Derived policy: owners and purposes inherited, released only to the
    // parties every contribution allows; not public.
    let a = &b.aggregate_policy;
    assert_eq!(a.owners.len(), 3);
    assert_eq!(a.release, Release::AllowedParties);
    assert_eq!(
        a.audience,
        Some([PartyId::new("coordinator").unwrap()].into())
    );
    assert_eq!(a.purposes, Some(["disease-training".to_string()].into()));
    assert_eq!(
        b.recipient,
        OutputRelease::Party(PartyId::new("coordinator").unwrap())
    );
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("differential privacy")));
    assert!(r
        .flows
        .iter()
        .any(|f| f.to == "aggregate:global_gradient" && f.ops == ["secure_aggregation"]));
}

#[test]
fn the_aggregate_is_not_public_or_for_anyone() {
    let public = OUT.replace("to \"coordinator\"", "public");
    assert_eq!(
        code(&fedavg(&format!("{SUM}{public}"), AGG)),
        Code::PublicRelease
    );
    let other = OUT.replace("coordinator", "hospital-a");
    assert_eq!(
        code(&fedavg(&format!("{SUM}{other}"), AGG)),
        Code::UnauthorizedParty
    );
    // Sealed is fine.
    let sealed = OUT.replace(" to \"coordinator\"", "");
    assert!(analyze(&parse(&fedavg(&format!("{SUM}{sealed}"), AGG)).unwrap()).is_ok());
}

#[test]
fn only_sums_of_one_input_per_party() {
    // A product is not an aggregate.
    let mul = "%3 = add %0, %1 : secret vector<8>\n%4 = mul %3, %2 : secret vector<8>\n";
    assert_eq!(
        code(&fedavg(&format!("{mul}{OUT}"), AGG)),
        Code::AggregationPlan
    );
    // One party counted twice.
    let twice = "%3 = add %0, %1 : secret vector<8>\n%4 = add %3, %0 : secret vector<8>\n";
    assert_eq!(
        code(&fedavg(&format!("{twice}{OUT}"), AGG)),
        Code::AggregationPlan
    );
    // A "sum" of one party's gradient alone.
    let alone = "%3 = add %0, %1 : secret vector<8>\n%4 = add %3, %2 : secret vector<8>\n";
    let one = format!("{alone}output \"global_gradient\" = %0 to \"coordinator\"\n");
    assert_eq!(code(&fedavg(&one, AGG)), Code::AggregationPlan);
    // Minimum above the number of parties, or below 2.
    assert_eq!(
        code(&fedavg(
            &format!("{SUM}{OUT}"),
            &AGG.replace("minimum 3", "minimum 4")
        )),
        Code::AggregationPlan
    );
    assert_eq!(
        code(&fedavg(
            &format!("{SUM}{OUT}"),
            &AGG.replace("minimum 3", "minimum 1")
        )),
        Code::AggregationPlan
    );
    // An output that does not exist.
    assert_eq!(
        code(&fedavg(
            &format!("{SUM}{OUT}"),
            &AGG.replace("global_gradient", "nope")
        )),
        Code::AggregationPlan
    );
    // Two assets of one party.
    let text = fedavg(&format!("{SUM}{OUT}"), AGG)
        .replace("owners [\"hospital-c\"]", "owners [\"hospital-a\"]");
    assert_eq!(code(&text), Code::AggregationPlan);
}

#[test]
fn owners_must_permit_aggregate_release() {
    let text = fedavg(&format!("{SUM}{OUT}"), AGG).replacen(
        "release aggregate_only",
        "release owner_only",
        1,
    );
    assert_eq!(code(&text), Code::Declassification);
}

#[test]
fn quantization_overflow_is_a_compile_error() {
    // 3 x 2048 levels = 6144 >= 2^12.
    let small = AGG.replace("modulus 32", "modulus 12");
    let e = parse(&fedavg(&format!("{SUM}{OUT}"), &small))
        .map(|p| analyze(&p).unwrap_err())
        .unwrap();
    assert_eq!(e.code, Code::AggregationOverflow);
    assert!(
        e.message.contains("maximum aggregate 6144"),
        "{}",
        e.message
    );
    // 2^13 fits.
    assert!(analyze(
        &parse(&fedavg(
            &format!("{SUM}{OUT}"),
            &AGG.replace("modulus 32", "modulus 13")
        ))
        .unwrap()
    )
    .is_ok());
    // Bad codecs.
    for bad in ["clip [1.0, -1.0]", "scale 0", "modulus 65", "modulus 7"] {
        let a = match bad.split_once(' ').unwrap().0 {
            "clip" => AGG.replace("clip [-1.0, 1.0]", bad),
            "scale" => AGG.replace("scale 1024", bad),
            _ => AGG.replace("modulus 32", bad),
        };
        assert_eq!(
            code(&fedavg(&format!("{SUM}{OUT}"), &a)),
            Code::AggregationPlan,
            "{bad}"
        );
    }
}

#[test]
fn clipping_is_never_hidden() {
    let text = fedavg(
        &format!("{SUM}{OUT}"),
        &AGG.replace("clip [-1.0, 1.0]", "clip [-0.5, 0.5]"),
    );
    let r = analyze(&parse(&text).unwrap()).unwrap().unwrap();
    assert_eq!(
        r.warnings
            .iter()
            .filter(|w| w.contains("clips each value"))
            .count(),
        3,
        "{:?}",
        r.warnings
    );
}

#[test]
fn codec_round_trip() {
    let k = encompute_ir::confidentiality::FixedPointCodec {
        clip_min: -1.0,
        clip_max: 1.0,
        scale: 1024,
        modulus_bits: 32,
    };
    assert_eq!(k.levels(), 2048);
    assert_eq!(k.encode(-1.0), 0);
    assert_eq!(k.encode(1.0), 2048);
    assert_eq!(k.encode(5.0), 2048, "clipped");
    assert_eq!(k.encode(f64::NAN), 0);
    let xs = [0.123, -0.456, 0.789];
    let sum: u64 = xs.iter().map(|&x| k.encode(x)).sum();
    let back = k.decode_sum(sum as i64, 3);
    assert!((back - xs.iter().sum::<f64>()).abs() <= 3.0 * k.resolution() + 1e-12);
}

/// The declared collusion bound sets the protocol threshold; bounds the
/// parties cannot meet are refused.
#[test]
fn collusion_bound_sets_the_threshold() {
    let with = |minimum: usize, colluding: usize| {
        fedavg(
            &format!("{SUM}{OUT}"),
            &AGG.replace(
                "minimum 3 colluding 1",
                &format!("minimum {minimum} colluding {colluding}"),
            ),
        )
    };
    let t = |text: String| {
        analyze(&parse(&text).unwrap())
            .unwrap()
            .unwrap()
            .aggregations[0]
            .threshold
    };
    assert_eq!(t(with(3, 1)), 3);
    assert_eq!(t(with(2, 0)), 2);
    // Two of three may be released, but one colluding party forces all three.
    assert_eq!(t(with(2, 1)), 3);
    assert_eq!(t(with(3, 2)), 3, "unanimity tolerates n - 1 colluders");
    assert_eq!(code(&with(3, 3)), Code::AggregationPlan);
    assert_eq!(code(&with(2, 3)), Code::AggregationPlan);
}

/// Release-boundary detection (ADR-013): revealing a budgeted asset needs a
/// DP mechanism; sealed values are internal and cost nothing.
#[test]
fn privacy_budgets_need_a_mechanism_at_the_release_boundary() {
    let budgeted = |dp: &str| {
        fedavg(&format!("{SUM}{OUT}"), &format!("{}{dp}\n", AGG.trim_end())).replace(
            "release aggregate_only",
            "release aggregate_only privacy unit \"patient\" epsilon 3.0 delta 1e-6",
        )
    };
    // Released without noise: refused.
    assert_eq!(code(&budgeted("")), Code::PrivacyPolicy);
    // With the mechanism: a privacy release charging all three budgets.
    let dp = " dp discrete_gaussian clip_norm 1.0 noise_multiplier 1.2";
    let text = budgeted(dp);
    let p = parse(&text).unwrap();
    assert_eq!(p.to_string(), text, "canonical text");
    let r = analyze(&p).unwrap().unwrap();
    assert_eq!(r.privacy_releases.len(), 1);
    assert_eq!(r.privacy_releases[0].charged.len(), 3);
    assert!(r.warnings.iter().any(|w| w.contains("each patient")));
    // Sealed: internal, nothing charged, no mechanism needed.
    let sealed = budgeted("").replace(" to \"coordinator\"", "");
    let r = analyze(&parse(&sealed).unwrap()).unwrap().unwrap();
    assert!(r.privacy_releases.is_empty());
    // Invalid budgets and mechanisms.
    for bad in ["epsilon 0.0", "epsilon -1.0"] {
        let t = budgeted(dp).replace("epsilon 3.0", bad);
        assert_eq!(code(&t), Code::PrivacyPolicy, "{bad}");
    }
    let t = budgeted(dp).replace("delta 1e-6", "delta 1.0");
    assert_eq!(code(&t), Code::PrivacyPolicy);
    let t = budgeted(dp).replace("noise_multiplier 1.2", "noise_multiplier 0.0");
    assert_eq!(code(&t), Code::PrivacyPolicy, "no noise, no privacy");
    // A clip range not containing zero.
    let t = budgeted(dp).replace("clip [-1.0, 1.0]", "clip [0.5, 1.0]");
    assert_eq!(code(&t), Code::PrivacyPolicy);
    // The privacy policy ID changes with the mechanism or a budget.
    let id = |t: &str| {
        encompute_verification::PrivacyPolicyId::of(parse(t).unwrap().confidentiality().unwrap())
            .unwrap()
            .hex()
    };
    assert_ne!(
        id(&text),
        id(&text.replace("noise_multiplier 1.2", "noise_multiplier 1.3"))
    );
    assert_ne!(
        id(&text),
        id(&text.replacen("epsilon 3.0", "epsilon 4.0", 1))
    );
}

#[test]
fn privacy_presets() {
    use encompute_ir::confidentiality::{privacy_preset, PrivacyUnit};
    let (b, m) = privacy_preset("strong", PrivacyUnit::Patient).unwrap();
    assert_eq!(
        (b.epsilon, b.delta, m.noise_multiplier, m.clip_norm),
        (3.0, 1e-6, 6.0, 1.0)
    );
    assert!(
        privacy_preset("maximum", PrivacyUnit::Record)
            .unwrap()
            .0
            .epsilon
            < b.epsilon
    );
    assert_eq!(
        privacy_preset("weak", PrivacyUnit::Record)
            .unwrap_err()
            .code,
        Code::PrivacyPolicy
    );
}
