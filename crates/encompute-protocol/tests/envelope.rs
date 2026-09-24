use encompute_ir::Code;
use encompute_protocol::{open, Envelope, Expect, Header, Kind};
use proptest::prelude::*;

fn header(kind: Kind) -> Header {
    Header {
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
        kind,
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
