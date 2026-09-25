//! Multi-party secure aggregation (ADR-012): three hospitals contribute
//! private gradients; only the aggregate is released, and every invalid
//! round fails closed.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::{PartyId, Release};
use encompute_ir::{parse, Code};
use encompute_runtime::attestation::mock::{MockHardware, MockProvider};
use encompute_runtime::attestation::{
    AttestationChallenge, AttestationPolicy, AttestationRecord, Attester, TeeKind, Verifier,
    WorkloadSession,
};
use encompute_runtime::secagg::service::{join, CoordinatorService, ParticipantClient};
use encompute_runtime::secagg::{
    identity_of, verify_aggregation_receipt, AggregationSpec, RoundCoordinator, RoundParticipant,
};
use encompute_runtime::verification::EvaluatorIdentity;
use encompute_runtime::{sample_inputs, Mode, Model, Remote};

const T0: u64 = 1_900_000_000;

/// `n` hospitals (a, b, c, …), each owning one gradient of `len` values,
/// aggregate-only to the coordinator; `minimum` contributions required.
fn fedavg(n: usize, len: usize, minimum: usize, codec: &str) -> Model {
    let names: Vec<char> = ('a'..='z').take(n).collect();
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"disease-training\"\n\
         party \"coordinator\" \"Coordinator\"\n",
    );
    for x in &names {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
    }
    for x in &names {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"disease-training\"] release aggregate_only\n"
        ));
    }
    for (i, x) in names.iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<{len}>\n"
        ));
    }
    let mut acc = 0;
    for i in 1..n {
        let id = n + i - 1;
        s.push_str(&format!(
            "%{id} = add %{acc}, %{i} : secret vector<{len}>\n"
        ));
        acc = id;
    }
    s.push_str(&format!(
        "output \"global_gradient\" = %{acc} to \"coordinator\"\n"
    ));
    // Unanimity tolerates n - 1 colluders; otherwise none are declared.
    let colluding = if minimum == n { n - 1 } else { 0 };
    s.push_str(&format!(
        "aggregate \"global_gradient\" sum minimum {minimum} colluding {colluding} {codec}\n"
    ));
    Model::compile(parse(&s).unwrap()).unwrap()
}

const CODEC: &str = "clip [-1.0, 1.0] scale 65536 modulus 32";

fn party(i: usize) -> PartyId {
    PartyId::new(&format!("hospital-{}", (b'a' + i as u8) as char)).unwrap()
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[i as u8 + 1; 32])
}

fn spec_of(m: &Model) -> AggregationSpec {
    let plan = m.aggregation_plan(None).unwrap();
    let ids = (0..plan.participants.len())
        .map(|i| identity_of(&party(i), &key(i)))
        .collect();
    AggregationSpec::new(plan, ids).unwrap()
}

/// Deterministic pseudo-random gradients in [-1, 1].
fn gradient(i: usize, len: usize) -> Vec<f64> {
    (0..len)
        .map(|j| ((((i + 3) * 7919 + j * 104_729) % 20_001) as f64 / 10_000.0) - 1.0)
        .collect()
}

fn coordinator_key() -> SigningKey {
    SigningKey::from_bytes(&[200; 32])
}

/// Hospital A, B and C each run a participant against an HTTP coordinator.
#[test]
fn three_hospitals_over_http() {
    let len = 4096;
    let m = fedavg(3, len, 3, CODEC);
    let spec = spec_of(&m);
    let coord = RoundCoordinator::open(spec.clone(), 1, coordinator_key(), None, T0).unwrap();
    let svc = CoordinatorService::new(coord, Duration::from_secs(20)).unwrap();
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    svc.spawn(server);

    let hospitals: Vec<_> = (0..3)
        .map(|i| {
            let (spec, url) = (spec.clone(), url.clone());
            std::thread::spawn(move || {
                let client = ParticipantClient::new(&url, Duration::from_secs(30));
                let p = join(
                    &client,
                    &spec,
                    &party(i),
                    key(i),
                    &gradient(i, len),
                    None,
                    None,
                )?;
                client.participate(p)
            })
        })
        .collect();
    let (aggregate, receipt) = svc.run_to_completion().unwrap();
    for h in hospitals {
        let r = h.join().unwrap().unwrap();
        assert_eq!(r, receipt, "every hospital gets the same receipt");
    }

    // The aggregate matches the clear sum, exactly within the declared
    // quantization semantics.
    let codec = spec.plan.codec;
    for j in 0..len {
        let clear: f64 = (0..3).map(|i| gradient(i, len)[j]).sum();
        let encoded: u64 = (0..3).map(|i| codec.encode(gradient(i, len)[j])).sum();
        assert_eq!(aggregate.encoded_sum[j], encoded);
        assert_eq!(aggregate.values[j], codec.decode_sum(encoded, 3));
        assert!((aggregate.values[j] - clear).abs() <= 3.0 * codec.resolution() + 1e-12);
    }
    // The aggregate asset and its derived policy.
    assert_eq!(aggregate.contributors, [party(0), party(1), party(2)]);
    assert_eq!(
        aggregate.parents,
        ["gradient-a", "gradient-b", "gradient-c"]
    );
    assert_eq!(aggregate.policy.release, Release::AllowedParties);
    assert_eq!(
        aggregate.policy.audience,
        Some([PartyId::new("coordinator").unwrap()].into())
    );
    assert_eq!(aggregate.policy.owners.len(), 3);
    // The receipt verifies, binds the policy and round, and carries no
    // contribution values.
    verify_aggregation_receipt(
        &receipt,
        &spec,
        Some(&receipt.coordinator_key),
        Some(&aggregate),
    )
    .unwrap();
    let rm = &receipt.manifest;
    assert_eq!(rm.policy_id, m.ids().policy_id);
    assert_eq!(rm.contributors.len(), 3);
    assert!(rm.dropped.is_empty());
    let text = String::from_utf8(receipt.to_bytes().unwrap()).unwrap();
    assert!(
        text.len() < 20_000,
        "no vectors in the receipt ({} bytes)",
        text.len()
    );
    // A tampered receipt, or the wrong aggregate, fails.
    let mut t = receipt.clone();
    t.manifest.dropped.push(party(0));
    assert!(verify_aggregation_receipt(&t, &spec, None, None).is_err());
    let mut wrong = aggregate.clone();
    wrong.encoded_sum[0] += 1;
    assert!(verify_aggregation_receipt(&receipt, &spec, None, Some(&wrong)).is_err());
    // No endpoint serves an individual value.
    let agent = ureq::agent();
    for path in ["raw/hospital-a", "masked/hospital-a", "inputs", "aggregate"] {
        assert!(
            agent.get(&format!("{url}/v1/{path}")).call().is_err(),
            "{path}"
        );
    }
}

/// The in-memory driver: run a round with the given participants, where
/// `drop_at[i]` stops party i from that stage (0..=4).
fn run(
    coord: &mut RoundCoordinator,
    parts: &mut [RoundParticipant],
    drop_at: &[Option<u8>],
) -> encompute_ir::Result<(
    encompute_runtime::secagg::AggregateAsset,
    encompute_runtime::secagg::AggregationReceipt,
)> {
    let alive = |i: usize, st: u8| drop_at.get(i).copied().flatten().is_none_or(|s| s > st);
    for (i, p) in parts.iter_mut().enumerate() {
        if alive(i, 0) {
            coord.receive_advertise(p.advertise()?)?;
        }
    }
    let keys = coord.close_advertise()?;
    for (i, p) in parts.iter_mut().enumerate() {
        if alive(i, 1) {
            coord.receive_shares(p.share_keys(&keys)?)?;
        }
    }
    let inbox = coord.close_shares()?;
    for (i, p) in parts.iter_mut().enumerate() {
        if alive(i, 2) {
            let who = p.party().clone();
            coord.receive_masked(p.masked_input(&inbox[&who])?)?;
        }
    }
    let s = coord.close_masked()?;
    for (i, p) in parts.iter_mut().enumerate() {
        if alive(i, 3) {
            coord.receive_consistency(p.consistency(&s)?)?;
        }
    }
    let u = coord.close_consistency()?;
    for (i, p) in parts.iter_mut().enumerate() {
        if alive(i, 4) {
            coord.receive_reveal(p.unmask(&u)?)?;
        }
    }
    coord.finalize()
}

fn participants(
    spec: &AggregationSpec,
    coord: &RoundCoordinator,
    n: usize,
) -> Vec<RoundParticipant> {
    (0..n)
        .map(|i| {
            RoundParticipant::join(
                spec,
                &coord.spec,
                &coord.round,
                &party(i),
                key(i),
                &gradient(i, spec.plan.vector_len),
                None,
                None,
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn dropouts_within_the_threshold() {
    // Five hospitals, at least three contributions: two may drop.
    let m = fedavg(5, 64, 3, CODEC);
    let spec = spec_of(&m);
    assert_eq!(spec.threshold, 3);
    let mut c = RoundCoordinator::open(spec.clone(), 1, coordinator_key(), None, T0).unwrap();
    let mut parts = participants(&spec, &c, 5);
    let (agg, receipt) = run(&mut c, &mut parts, &[None, Some(2), None, Some(1), None]).unwrap();
    assert_eq!(agg.contributors, [party(0), party(2), party(4)]);
    assert_eq!(receipt.manifest.dropped, [party(1), party(3)]);
    assert_eq!(agg.parents, ["gradient-a", "gradient-c", "gradient-e"]);
    assert_eq!(
        agg.policy.owners.len(),
        3,
        "owners: the actual contributors"
    );
    let codec = spec.plan.codec;
    for j in 0..64 {
        let enc: u64 = [0, 2, 4]
            .iter()
            .map(|&i| codec.encode(gradient(i, 64)[j]))
            .sum();
        assert_eq!(agg.encoded_sum[j], enc);
    }
    verify_aggregation_receipt(&receipt, &spec, None, Some(&agg)).unwrap();
    // Three drops: below the threshold, nothing is released.
    let mut c = RoundCoordinator::open(spec.clone(), 2, coordinator_key(), None, T0).unwrap();
    let mut parts = participants(&spec, &c, 5);
    let e = run(&mut c, &mut parts, &[None, Some(2), Some(2), Some(1), None]).unwrap_err();
    assert_eq!(e.code, Code::AggregationThreshold);
}

#[test]
fn mean_divides_by_the_contributors() {
    let m = fedavg(4, 8, 3, CODEC);
    let text = m
        .program()
        .to_string()
        .replace("sum minimum", "mean minimum");
    let m = Model::compile(parse(&text).unwrap()).unwrap();
    let spec = spec_of(&m);
    let mut c = RoundCoordinator::open(spec.clone(), 1, coordinator_key(), None, T0).unwrap();
    let mut parts = participants(&spec, &c, 4);
    let (agg, _) = run(&mut c, &mut parts, &[None, None, Some(2), None]).unwrap();
    let codec = spec.plan.codec;
    for j in 0..8 {
        let enc: u64 = [0, 1, 3]
            .iter()
            .map(|&i| codec.encode(gradient(i, 8)[j]))
            .sum();
        assert_eq!(agg.values[j], codec.decode_sum(enc, 3) / 3.0);
    }
}

/// The attack list: each fails closed.
#[test]
fn attacks_fail_closed() {
    let m = fedavg(3, 16, 3, CODEC);
    let spec = spec_of(&m);
    let open =
        |seq| RoundCoordinator::open(spec.clone(), seq, coordinator_key(), None, T0).unwrap();

    // The coordinator (or anyone) asks an evaluator to run the program on
    // raw gradients: refused.
    let err = match Remote::new("http://127.0.0.1:1").run(
        &m.new_client(Mode::Mock).unwrap(),
        m.program(),
        None,
        &sample_inputs(m.program(), 1, 1),
        &EvaluatorIdentity::from_public_key(&[0; 32]).unwrap_or_else(|_| {
            encompute_runtime::verification::EvaluatorSigner::generate()
                .unwrap()
                .identity()
        }),
    ) {
        Err(e) => e,
        Ok(_) => panic!("an aggregation program ran on an evaluator"),
    };
    assert_eq!(err.code, Code::AggregationRequired);
    let ev = encompute_evaluator::server::Evaluator::new(
        encompute_runtime::Backends::MOCK,
        Default::default(),
    );
    assert_eq!(
        ev.add_program(&m.program().to_string()).unwrap_err().code,
        Code::AggregationRequired
    );

    // Only A participates.
    let mut c = open(1);
    let mut parts = participants(&spec, &c, 3);
    let e = run(&mut c, &mut parts, &[None, Some(0), Some(0)]).unwrap_err();
    assert_eq!(e.code, Code::AggregationThreshold);

    // A drops mid-round below the minimum (3 required, 3 eligible).
    let mut c = open(2);
    let mut parts = participants(&spec, &c, 3);
    let e = run(&mut c, &mut parts, &[None, None, Some(2)]).unwrap_err();
    assert_eq!(e.code, Code::AggregationThreshold);

    // B submits twice.
    let mut c = open(3);
    let mut parts = participants(&spec, &c, 3);
    let a = parts[1].advertise().unwrap();
    c.receive_advertise(a.clone()).unwrap();
    assert_eq!(
        c.receive_advertise(a).unwrap_err().code,
        Code::AggregationBinding
    );

    // A's contribution replayed in the next round: the party refuses an
    // older-or-equal round, and messages of round 3 are refused by round 4.
    let c4 = open(4);
    let mut old = RoundParticipant::join(
        &spec,
        &c.spec,
        &c.round,
        &party(0),
        key(0),
        &gradient(0, 16),
        None,
        None,
    )
    .unwrap();
    let mut c4m = c4;
    assert_eq!(
        c4m.receive_advertise(old.advertise().unwrap())
            .unwrap_err()
            .code,
        Code::AggregationBinding
    );
    assert_eq!(
        RoundParticipant::join(
            &spec,
            &c4m.spec,
            &c.round,
            &party(0),
            key(0),
            &gradient(0, 16),
            None,
            Some(3)
        )
        .err()
        .unwrap()
        .code,
        Code::AggregationBinding
    );

    // Unauthorized Hospital D.
    let d = PartyId::new("hospital-d").unwrap();
    let e = RoundParticipant::join(
        &spec,
        &c4m.spec,
        &c4m.round,
        &d,
        key(9),
        &gradient(3, 16),
        None,
        None,
    )
    .err()
    .unwrap();
    assert_eq!(e.code, Code::AggregationUnauthorized);
    // …and its self-made advertisement, signed with its own key.
    let mut rogue_spec = spec.clone();
    rogue_spec.parties[2].public_key = identity_of(&party(2), &key(9)).public_key;
    let e = RoundParticipant::join(
        &rogue_spec,
        &c4m.spec,
        &c4m.round,
        &party(2),
        key(9),
        &gradient(2, 16),
        None,
        None,
    )
    .err()
    .unwrap();
    assert_eq!(
        e.code,
        Code::AggregationBinding,
        "a party with another key sees another spec"
    );

    // Wrong PolicyID, wrong shape, wrong quantization, wrong program: the
    // party's approved spec differs from the round's.
    let variants = [
        (
            "PolicyID",
            fedavg(3, 16, 3, CODEC)
                .program()
                .to_string()
                .replace("disease-training", "advertising"),
        ),
        (
            "vector shape",
            fedavg(3, 32, 3, CODEC).program().to_string(),
        ),
        (
            "codec",
            fedavg(3, 16, 3, "clip [-2.0, 2.0] scale 65536 modulus 32")
                .program()
                .to_string(),
        ),
        ("minimum", fedavg(3, 16, 2, CODEC).program().to_string()),
    ];
    for (what, text) in variants {
        let other = Model::compile(parse(&text).unwrap()).unwrap();
        let approved = spec_of(&other);
        let e = RoundParticipant::join(
            &approved,
            &c4m.spec,
            &c4m.round,
            &party(0),
            key(0),
            &gradient(0, approved.plan.vector_len),
            None,
            None,
        )
        .err()
        .unwrap();
        assert_eq!(e.code, Code::AggregationBinding, "{what}");
        assert!(e.message.contains("differ"), "{what}: {e}");
    }
    // A round of another spec (another model round).
    let other = spec_of(&fedavg(3, 16, 2, CODEC));
    let foreign = RoundCoordinator::open(other.clone(), 1, coordinator_key(), None, T0).unwrap();
    let e = RoundParticipant::join(
        &spec,
        &spec,
        &foreign.round,
        &party(0),
        key(0),
        &gradient(0, 16),
        None,
        None,
    )
    .err()
    .unwrap();
    assert_eq!(e.code, Code::AggregationBinding);
    // Wrong vector shape from a well-formed party.
    let e = RoundParticipant::join(
        &spec,
        &c4m.spec,
        &c4m.round,
        &party(0),
        key(0),
        &gradient(0, 15),
        None,
        None,
    )
    .err()
    .unwrap();
    assert_eq!(e.code, Code::AggregationBinding);

    // Tampered masked contribution.
    let mut c = open(5);
    let mut parts = participants(&spec, &c, 3);
    for p in parts.iter_mut() {
        c.receive_advertise(p.advertise().unwrap()).unwrap();
    }
    let k = c.close_advertise().unwrap();
    for p in parts.iter_mut() {
        c.receive_shares(p.share_keys(&k).unwrap()).unwrap();
    }
    let inbox = c.close_shares().unwrap();
    let who = parts[0].party().clone();
    let mut masked = parts[0].masked_input(&inbox[&who]).unwrap();
    masked.masked[3] = masked.masked[3].wrapping_add(1) & 0xffff_ffff;
    assert_eq!(
        c.receive_masked(masked).unwrap_err().code,
        Code::AggregationProtocol
    );
}

/// A spec can require every contribution key to live in an attested
/// training workload.
#[test]
fn attested_participants() {
    let m = fedavg(3, 8, 3, CODEC);
    let hw = MockHardware::from_seed(&[5; 32]);
    let image = format!("sha256:{}", "9".repeat(64));
    let mut policy = AttestationPolicy::new(&"11".repeat(32), None);
    policy.allowed_tee = vec![TeeKind::Mock];
    policy.allowed_images = vec![image.clone()];
    policy.allow_development = true;
    let mut spec = spec_of(&m);
    spec.training_execution_spec_id = Some("11".repeat(32));
    spec.attestation = Some(policy);
    let verifier = || Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap());
    // Each party's aggregation key is the key its attested workload binds.
    let record = |i: usize, image: &str| {
        let session = WorkloadSession::new(
            &EvaluatorIdentity::from_public_key(&key(i).verifying_key().to_bytes()).unwrap(),
        );
        let ch = AttestationChallenge::new("coordinator", T0, 300).unwrap();
        let b = session.binding(&ch, &"11".repeat(32), None, &"22".repeat(32));
        AttestationRecord::new(hw.attester(image).issued_at(T0).attest(&ch, &b).unwrap())
    };
    let mut c =
        RoundCoordinator::open(spec.clone(), 1, coordinator_key(), Some(verifier()), T0).unwrap();
    let mut parts: Vec<RoundParticipant> = (0..3)
        .map(|i| {
            RoundParticipant::join(
                &spec,
                &c.spec,
                &c.round,
                &party(i),
                key(i),
                &gradient(i, 8),
                Some(record(i, &image)),
                None,
            )
            .unwrap()
        })
        .collect();
    let (agg, receipt) = run(&mut c, &mut parts, &[]).unwrap();
    assert_eq!(receipt.manifest.attestations.len(), 3);
    verify_aggregation_receipt(&receipt, &spec, None, Some(&agg)).unwrap();

    // Unattested, another image, or a record binding another key: refused.
    assert_eq!(
        RoundParticipant::join(
            &spec,
            &spec,
            &c.round,
            &party(0),
            key(0),
            &gradient(0, 8),
            None,
            None
        )
        .err()
        .unwrap()
        .code,
        Code::AggregationUnauthorized
    );
    let mut c =
        RoundCoordinator::open(spec.clone(), 2, coordinator_key(), Some(verifier()), T0).unwrap();
    let mut evil = RoundParticipant::join(
        &spec,
        &c.spec,
        &c.round,
        &party(0),
        key(0),
        &gradient(0, 8),
        Some(record(0, "sha256:evil")),
        None,
    )
    .unwrap();
    assert_eq!(
        c.receive_advertise(evil.advertise().unwrap())
            .unwrap_err()
            .code,
        Code::WorkloadPolicy
    );
    let mut swapped = RoundParticipant::join(
        &spec,
        &c.spec,
        &c.round,
        &party(1),
        key(1),
        &gradient(1, 8),
        Some(record(0, &image)),
        None,
    )
    .unwrap();
    assert_eq!(
        c.receive_advertise(swapped.advertise().unwrap())
            .unwrap_err()
            .code,
        Code::AggregationUnauthorized
    );
}

#[test]
fn explain_shows_policy_and_mechanism() {
    let m = fedavg(3, 4096, 3, CODEC);
    let text = m.privacy_explain().unwrap().unwrap();
    for want in [
        "Aggregation boundary  global_gradient",
        "POLICY        gradient contributions are aggregate_only",
        "MECHANISM     secure aggregation (secagg-bonawitz17 v1)",
        "hospital-a, hospital-b, hospital-c (3)",
        "clip [-1, 1], scale 65536, modulus 2^32",
        "✓ individual gradients never released",
        "STATUS        SATISFIED",
    ] {
        assert!(text.contains(want), "missing {want:?}\n{text}");
    }
    let plan = m.explain(None);
    for want in [
        "MULTI-PARTY EXECUTION",
        "individual updates visible  no",
        "vector length",
        "4096",
    ] {
        assert!(plan.contains(want), "missing {want:?}\n{plan}");
    }
}
