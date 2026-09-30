//! Release forms (governed projects, release classes): an asset's owners
//! may limit the forms anything released from it takes (a boolean, a
//! bounded category, an aggregate, a differentially private aggregate, a
//! derived artifact). Forms join by intersection; a released output must
//! provably take an allowed form (ENC1907). A program never declares a
//! weaker policy than the one its owner registered (`refines`).

use std::collections::BTreeSet;

use encompute_analysis::confidentiality::{analyze, output_forms, refines, Policy};
use encompute_ir::confidentiality::{AssetPolicy, PartyId, Release, ReleaseForm as F};
use encompute_ir::{parse, Code};

/// One tax asset with `forms`, an output computed by `body` (over `%0`,
/// the age, and `%1`, a constant 18) as `%2`, released to benefits.
fn eligibility(forms: &str, body: &str) -> String {
    format!(
        "encompute 0.1\nprogram eligible precision 0.001 purpose \"eligibility\"\n\
         party \"tax\" \"Tax\"\nparty \"ben\" \"Benefits\"\n\
         asset \"income\" dataset owners [\"tax\"] readers [\"ben\"] purposes [\"eligibility\"] release allowed_parties{forms}\n\
         %0 = input \"x\" [0.0, 120.0] asset \"income\" : secret u8\n\
         %1 = const [18.0] : public u8\n\
         {body}\
         output \"out\" = %2 to \"ben\"\n"
    )
}

const BOOL: &str = "%2 = ge %0, %1 : secret bool\n";
const VALUE: &str = "%2 = add %0, %1 : secret u8\n";

fn code(text: &str) -> Option<Code> {
    match parse(text) {
        Err(e) => Some(e.code),
        Ok(p) => analyze(&p).err().map(|e| e.code),
    }
}

#[test]
fn value_output_from_boolean_only_does_not_compile_1907() {
    // A comparison is a boolean: released.
    assert_eq!(code(&eligibility(" forms [boolean]", BOOL)), None);
    // The value itself is not.
    assert_eq!(
        code(&eligibility(" forms [boolean]", VALUE)),
        Some(Code::ReleaseForm)
    );
    let p = parse(&eligibility(" forms [boolean]", VALUE)).unwrap();
    let e = analyze(&p).unwrap_err();
    assert!(e.message.contains("boolean"), "{}", e.message);
    // Without forms nothing changes.
    assert_eq!(code(&eligibility("", VALUE)), None);
    // Kept sealed, the value releases nothing.
    assert_eq!(
        code(&eligibility(" forms [boolean]", VALUE).replace(" to \"ben\"", "")),
        None
    );
}

#[test]
fn bounded_category_range_within_max() {
    // The smaller of the age and 3 lies in [0, 3].
    let text = eligibility(
        " forms [bounded_category 3]",
        "%2 = min %0, %1 : secret u8\n",
    )
    .replace("const [18.0]", "const [3.0]");
    assert_eq!(code(&text), None, "{text}");
    // The range [0, 3] is not within a bound of 2.
    assert_eq!(
        code(&text.replace("bounded_category 3", "bounded_category 2")),
        Some(Code::ReleaseForm)
    );
    // A boolean is a category bounded by 1.
    assert_eq!(
        code(&eligibility(" forms [bounded_category 1]", BOOL)),
        None
    );
    // An unbounded value (the age, up to 120) is not a small category.
    assert_eq!(
        code(&eligibility(" forms [bounded_category 100]", VALUE)),
        Some(Code::ReleaseForm)
    );
    assert_eq!(
        code(&eligibility(" forms [bounded_category 255]", VALUE)),
        None
    );
    // The forms each output is released in: a boolean is one; an integer
    // is a bounded category only under a bound its sources declared.
    let forms = |text: &str| output_forms(&parse(text).unwrap()).unwrap().unwrap()["out"].clone();
    assert_eq!(forms(&eligibility("", BOOL)), BTreeSet::from([F::Boolean]));
    assert_eq!(forms(&eligibility("", VALUE)), BTreeSet::new());
    assert_eq!(
        forms(&text),
        BTreeSet::from([F::BoundedCategory { max: 3 }])
    );
    assert_eq!(
        forms(&eligibility(" forms [bounded_category 5]", BOOL)),
        BTreeSet::from([F::BoundedCategory { max: 1 }])
    );
}

/// Three agencies each contribute a count; the forms of each count.
fn counts(forms: &str, dp: &str) -> String {
    let mut s = String::from(
        "encompute 0.1\nprogram total precision 0.001 purpose \"statistics\"\n\
         party \"a\" \"A\"\nparty \"b\" \"B\"\nparty \"c\" \"C\"\nparty \"stats\" \"Statistics\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"count-{x}\" dataset owners [\"{x}\"] readers [\"stats\"] purposes [\"statistics\"] \
             release aggregate_only{forms}\n"
        ));
    }
    s.push_str(
        "%0 = input \"ca\" [0.0, 1.0] asset \"count-a\" : secret scalar\n\
         %1 = input \"cb\" [0.0, 1.0] asset \"count-b\" : secret scalar\n\
         %2 = input \"cc\" [0.0, 1.0] asset \"count-c\" : secret scalar\n\
         %3 = add %0, %1 : secret scalar\n%4 = add %3, %2 : secret scalar\n\
         output \"total\" = %4 to \"stats\"\n",
    );
    s.push_str(&format!(
        "aggregate \"total\" sum minimum 3 colluding 1 clip [0.0, 1.0] scale 1024 modulus 32{dp}\n"
    ));
    s
}

const DP: &str = " dp discrete_gaussian clip_norm 1.0 noise_multiplier 1.2";

#[test]
fn aggregate_forms_need_the_boundary_and_dp_forms_need_noise() {
    assert_eq!(code(&counts(" forms [aggregate]", "")), None);
    assert_eq!(
        code(&counts(" forms [dp_aggregate]", "")),
        Some(Code::ReleaseForm)
    );
    assert_eq!(code(&counts(" forms [dp_aggregate]", DP)), None);
    // A DP aggregate is an aggregate.
    assert_eq!(code(&counts(" forms [aggregate]", DP)), None);
    assert_eq!(
        code(&counts(" forms [boolean]", "")),
        Some(Code::ReleaseForm)
    );
    let p = parse(&counts("", DP)).unwrap();
    let f = output_forms(&p).unwrap().unwrap();
    assert_eq!(f["total"], BTreeSet::from([F::Aggregate, F::DpAggregate]));
}

#[test]
fn join_intersects_forms() {
    let p = parse(&eligibility(" forms [boolean, aggregate]", BOOL)).unwrap();
    let a = &p.confidentiality().unwrap().assets[0];
    let mut other = a.clone();
    other.policy.forms = Some([F::Boolean, F::BoundedCategory { max: 3 }].into());
    let joined = Policy::of_asset(a).join(&Policy::of_asset(&other));
    assert_eq!(joined.forms, Some([F::Boolean].into()));
    let open = Policy::public().join(&Policy::of_asset(a));
    assert_eq!(open.forms, a.policy.forms);
    // Two sources whose forms do not meet release nothing at all.
    other.policy.forms = Some([F::Aggregate].into());
    let mut x = a.clone();
    x.policy.forms = Some([F::Boolean].into());
    let none = Policy::of_asset(&x).join(&Policy::of_asset(&other));
    assert_eq!(none.forms, Some(BTreeSet::new()));
}

fn registered() -> AssetPolicy {
    let p = parse(&eligibility(" forms [boolean, bounded_category 4]", BOOL)).unwrap();
    p.confidentiality().unwrap().assets[0].policy.clone()
}

#[test]
fn program_weaker_than_registered_refused() {
    let r = registered();
    refines(&r, &r, "eligibility").unwrap();
    // Stricter is fine.
    let mut s = r.clone();
    s.release = Release::OwnerOnly;
    s.readers.clear();
    s.forms = Some([F::BoundedCategory { max: 2 }].into());
    refines(&s, &r, "eligibility").unwrap();
    type Weaken = (&'static str, Code, Box<dyn Fn(&mut AssetPolicy)>);
    let cases: Vec<Weaken> = vec![
        (
            "release",
            Code::Declassification,
            Box::new(|x| x.release = Release::Public),
        ),
        (
            "readers",
            Code::Declassification,
            Box::new(|x| {
                x.readers.insert(PartyId::new("tax").unwrap());
            }),
        ),
        (
            "owners",
            Code::Declassification,
            Box::new(|x| {
                x.owners.insert(PartyId::new("ben").unwrap());
            }),
        ),
        (
            "purposes",
            Code::PurposeViolation,
            Box::new(|x| {
                x.purposes.insert("marketing".into());
            }),
        ),
        (
            "forms (absent)",
            Code::ReleaseForm,
            Box::new(|x| x.forms = None),
        ),
        (
            "forms (wider)",
            Code::ReleaseForm,
            Box::new(|x| x.forms = Some([F::BoundedCategory { max: 5 }].into())),
        ),
        (
            "forms (other)",
            Code::ReleaseForm,
            Box::new(|x| x.forms = Some([F::Aggregate].into())),
        ),
        (
            "derive",
            Code::Declassification,
            Box::new(|x| {
                x.derive.insert(
                    encompute_ir::confidentiality::AssetKind::Model,
                    encompute_ir::confidentiality::DerivePermission {
                        release: Release::AllowedParties,
                        to: [PartyId::new("ben").unwrap()].into(),
                    },
                );
            }),
        ),
        (
            "privacy",
            Code::Declassification,
            Box::new(|x| {
                x.privacy = Some(encompute_ir::confidentiality::PrivacyBudget {
                    unit: encompute_ir::confidentiality::PrivacyUnit::Organization,
                    epsilon: 1.0,
                    delta: 1e-6,
                })
            }),
        ),
    ];
    for (what, c, weaken) in cases {
        let mut d = r.clone();
        weaken(&mut d);
        assert_eq!(
            refines(&d, &r, "eligibility").unwrap_err().code,
            c,
            "{what}"
        );
    }
    // Another purpose than the job's, even one the owner registered.
    let mut two = r.clone();
    two.purposes.insert("statistics".into());
    refines(&r, &two, "eligibility").unwrap();
    assert_eq!(
        refines(&two, &two, "eligibility").unwrap_err().code,
        Code::PurposeViolation
    );
    // A purpose the owner did not register.
    assert_eq!(
        refines(&r, &r, "statistics").unwrap_err().code,
        Code::PurposeViolation
    );
}
