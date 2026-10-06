//! Fuzz smoke tests for envelope decoding: mutated envelopes (with the
//! checksum recomputed, so the header and items are reached) never panic,
//! and anything accepted re-encodes to itself. Resource limits: huge
//! header and item lengths are typed errors, found without allocating.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::time::Duration;

use encompute_ir::Code;
use encompute_protocol::{Envelope, Header, Item, Kind};
use fuzz_support::{run, within};
use sha2::{Digest, Sha256};

fn header(kind: Kind) -> Header {
    Header {
        governance_id: None,
        kind,
        scheme: "CKKS".into(),
        backend: "mock".into(),
        backend_version: "0".into(),
        parameter_set_id: "p".repeat(64),
        program_id: Some("q".repeat(64)),
        key_id: Some("k".repeat(64)),
        items: vec![],
    }
}

fn seal(body: &[u8]) -> Vec<u8> {
    let mut v = body.to_vec();
    v.extend_from_slice(&Sha256::digest(body));
    v
}

/// `ENCM | format | header_len | header | payload`, checksummed.
fn raw(format: u16, header_len: u32, header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut b = b"ENCM".to_vec();
    b.extend_from_slice(&format.to_le_bytes());
    b.extend_from_slice(&header_len.to_le_bytes());
    b.extend_from_slice(header);
    b.extend_from_slice(payload);
    seal(&b)
}

fn seeds() -> Vec<Vec<u8>> {
    let bodies = [
        Envelope::new(header(Kind::Inputs), vec![("x".into(), vec![1, 2, 3])]),
        Envelope::new(
            header(Kind::EvaluationKeys),
            vec![("a".into(), vec![9; 40]), ("b".into(), vec![])],
        ),
        Envelope::new(header(Kind::Outputs), vec![]),
    ];
    // Seeds without their checksum: the harness adds one.
    bodies
        .iter()
        .map(|e| {
            let v = e.encode();
            v[..v.len() - 32].to_vec()
        })
        .collect()
}

#[test]
fn mutated_envelopes_never_panic() {
    run(
        "envelope",
        &seeds(),
        20000,
        Duration::from_secs(1),
        |body| {
            for bytes in [body.to_vec(), seal(body)] {
                if let Ok(e) = Envelope::decode(&bytes) {
                    let total: usize = e.items().iter().map(|(_, b)| b.len()).sum();
                    assert_eq!(total, e.payload.len());
                    assert_eq!(Envelope::decode(&e.encode()).unwrap(), e);
                }
            }
        },
    );
}

#[test]
fn huge_declared_lengths_are_refused() {
    let h = serde_json::to_vec(&header(Kind::Inputs)).unwrap();
    let limit = Duration::from_millis(500);
    for len in [u32::MAX, u32::MAX - 9, 1 << 20 | 1, h.len() as u32 + 1] {
        let e = within(limit, || Envelope::decode(&raw(1, len, &h, b""))).unwrap_err();
        assert_eq!(e.code, Code::Envelope, "{len}: {e}");
    }
    // Item lengths that overflow, exceed or undershoot the payload.
    for lens in [
        vec![u64::MAX, 1],
        vec![u64::MAX],
        vec![1 << 63, 1 << 63],
        vec![4],
        vec![1],
    ] {
        let mut hd = header(Kind::Inputs);
        hd.items = lens
            .iter()
            .map(|&len| Item {
                name: "x".into(),
                len,
            })
            .collect();
        let hb = serde_json::to_vec(&hd).unwrap();
        let e = within(limit, || {
            Envelope::decode(&raw(1, hb.len() as u32, &hb, b"abc"))
        })
        .unwrap_err();
        assert_eq!(e.code, Code::Envelope, "{lens:?}: {e}");
    }
    let e = Envelope::decode(&raw(2, h.len() as u32, &h, b"")).unwrap_err();
    assert_eq!(e.code, Code::Incompatible);
}

#[test]
fn malformed_headers_are_typed_errors() {
    let limit = Duration::from_secs(1);
    let deep = fuzz_support::nested_json(100_000, "");
    for h in [
        b"".to_vec(),
        b"{".to_vec(),
        b"\xff\xfe\xfd".to_vec(),
        b"null".to_vec(),
        br#"{"kind":"inputs"}"#.to_vec(),
        br#"{"kind":"inputs","scheme":"\ud800"}"#.to_vec(),
        deep.into_bytes(),
        [
            b"{\"items\":[".as_slice(),
            &b"{\"name\":\"x\",\"len\":0},".repeat(20_000),
            b"]}",
        ]
        .concat(),
    ] {
        let e = within(limit, || Envelope::decode(&raw(1, h.len() as u32, &h, b""))).unwrap_err();
        assert_eq!(e.code, Code::Envelope, "{e}");
    }
    // Truncated anywhere: refused.
    let full = Envelope::new(header(Kind::Inputs), vec![("x".into(), vec![1; 64])]).encode();
    for cut in 0..full.len() {
        assert!(Envelope::decode(&full[..cut]).is_err());
    }
    // Wrong checksum, wrong magic.
    let mut bad = full.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(Envelope::decode(&bad).unwrap_err().code, Code::Envelope);
    let mut bad = full[..full.len() - 32].to_vec();
    bad[0] = b'X';
    assert_eq!(
        Envelope::decode(&seal(&bad)).unwrap_err().code,
        Code::Envelope
    );
}
