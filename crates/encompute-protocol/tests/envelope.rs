use encompute_ir::Code;
use encompute_protocol::{open, Envelope, Expect, Header, Kind};
use proptest::prelude::*;

fn header(kind: Kind) -> Header {
    Header {
        governance_id: None,
        kind,
        scheme: "CKKS".into(),
        backend: "openfhe".into(),
        backend_version: "1.5.1".into(),
        parameter_set_id: "p1".into(),
        program_id: Some("prog1".into()),
        key_id: Some("k1".into()),
        items: vec![],
    }
}

fn expect(kind: Kind) -> Expect<'static> {
    Expect {
        governance_id: None,
        kind,
        scheme: "CKKS",
        backend: "openfhe",
        backend_version: "1.5.1",
        parameter_set_id: "p1",
        program_id: Some("prog1"),
        key_id: Some("k1"),
    }
}

fn sample() -> Vec<u8> {
    Envelope::new(
        header(Kind::Inputs),
        vec![("x".into(), vec![1, 2, 3]), ("s".into(), vec![9; 100])],
    )
    .encode()
}

#[test]
fn round_trip_and_items() {
    let env = open(&sample(), &expect(Kind::Inputs)).unwrap();
    let items = env.items();
    assert_eq!(items[0], ("x", &[1u8, 2, 3][..]));
    assert_eq!(items[1].1.len(), 100);
    assert_eq!(env.encode(), sample(), "encoding is deterministic");
}

#[test]
fn every_binding_is_enforced() {
    let bytes = sample();
    let code = |e: Expect| open(&bytes, &e).unwrap_err().code;
    assert_eq!(code(expect(Kind::Outputs)), Code::Incompatible);
    assert_eq!(
        code(Expect {
            backend_version: "1.4.0",
            ..expect(Kind::Inputs)
        }),
        Code::Incompatible
    );
    assert_eq!(
        code(Expect {
            scheme: "TFHE",
            ..expect(Kind::Inputs)
        }),
        Code::Incompatible,
        "a CKKS envelope is not accepted where TFHE is expected"
    );
    assert_eq!(
        code(Expect {
            backend: "seal",
            ..expect(Kind::Inputs)
        }),
        Code::Incompatible
    );
    assert_eq!(
        code(Expect {
            parameter_set_id: "p2",
            ..expect(Kind::Inputs)
        }),
        Code::WrongParameters
    );
    assert_eq!(
        code(Expect {
            program_id: Some("prog2"),
            ..expect(Kind::Inputs)
        }),
        Code::WrongProgram
    );
    assert_eq!(
        code(Expect {
            key_id: Some("k2"),
            ..expect(Kind::Inputs)
        }),
        Code::WrongKey
    );
}

#[test]
fn corruption_and_versions_are_rejected() {
    let mut b = sample();
    let mid = b.len() / 2;
    b[mid] ^= 1;
    assert_eq!(Envelope::decode(&b).unwrap_err().code, Code::Envelope);
    assert_eq!(
        Envelope::decode(&sample()[..20]).unwrap_err().code,
        Code::Envelope
    );
    assert_eq!(
        Envelope::decode(b"nonsense-bytes-that-are-long-enough-for-a-header")
            .unwrap_err()
            .code,
        Code::Envelope
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Any byte change is caught; nothing panics on arbitrary input.
    #[test]
    fn mutations_never_pass_or_panic(pos in any::<usize>(), byte in any::<u8>(), cut in any::<bool>()) {
        let mut b = sample();
        let i = pos % b.len();
        if cut { b.truncate(i); } else if b[i] != byte { b[i] = byte; } else { return Ok(()); }
        prop_assert!(Envelope::decode(&b).is_err());
    }

    #[test]
    fn arbitrary_bytes_never_panic(b in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = Envelope::decode(&b);
    }
}

/// A governed envelope carries its GovernanceId: it opens only where the
/// same binding is expected, never under another or none, and a standard
/// envelope never opens where a governed one is expected. Standard headers
/// do not serialize the field (their bytes are unchanged).
#[test]
fn the_governance_binding_is_enforced_both_ways() {
    let governed = |g: Option<&str>| {
        Envelope::new(
            Header {
                governance_id: g.map(str::to_owned),
                ..header(Kind::Inputs)
            },
            vec![("x".into(), vec![1])],
        )
        .encode()
    };
    let g1 = "1".repeat(64);
    let g2 = "2".repeat(64);
    let want = |g: Option<&'static str>| Expect {
        governance_id: g,
        ..expect(Kind::Inputs)
    };
    let g1s: &'static str = Box::leak(g1.clone().into_boxed_str());
    let g2s: &'static str = Box::leak(g2.clone().into_boxed_str());
    open(&governed(Some(&g1)), &want(Some(g1s))).unwrap();
    for (bytes, e) in [
        (governed(Some(&g1)), want(Some(g2s))),
        (governed(Some(&g1)), want(None)),
        (governed(None), want(Some(g1s))),
    ] {
        assert_eq!(
            open(&bytes, &e).unwrap_err().code,
            Code::GovernancePurposeMismatch
        );
    }
    open(&governed(None), &want(None)).unwrap();
    let standard = serde_json::to_string(&header(Kind::Inputs)).unwrap();
    assert!(!standard.contains("governance_id"));
}
