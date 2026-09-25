//! Provider-neutral verification: every way evidence can be wrong.

use encompute_attestation::gcp::{ConfidentialSpaceProvider, ISSUER, PROVIDER};
use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    seal_grant, AttestationChallenge, AttestationEvidence, AttestationPolicy, AttestationRecord,
    Attester, DebugPolicy, GrantHeader, Security, TcbStatus, TeeKind, Verifier, WorkloadBinding,
    WorkloadSession, EVIDENCE_VERSION, GRANT_VERSION,
};
use encompute_ir::Code;
use encompute_verification::EvaluatorSigner;
use jsonwebtoken::{EncodingKey, Header};
use serde_json::json;

const SPEC: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const POLICY: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const NOW: u64 = 1_900_000_000;

struct World {
    hw: MockHardware,
    verifier: Verifier,
    session: WorkloadSession,
    challenge: AttestationChallenge,
}

fn world() -> World {
    let hw = MockHardware::from_seed(&[7; 32]);
    let verifier = Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap());
    let signer = EvaluatorSigner::from_seed(&[9; 32]);
    World {
        hw,
        verifier,
        session: WorkloadSession::new(&signer.identity()),
        challenge: AttestationChallenge::new("hospital", NOW, 300).unwrap(),
    }
}

fn dev_policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

impl World {
    fn binding(&self) -> WorkloadBinding {
        self.session
            .binding(&self.challenge, SPEC, Some(POLICY), ARTIFACT)
    }

    fn evidence(&self) -> AttestationEvidence {
        self.hw
            .attester(IMAGE)
            .issued_at(NOW)
            .attest(&self.challenge, &self.binding())
            .unwrap()
    }

    fn code(&self, e: &AttestationEvidence, p: &AttestationPolicy, now: u64) -> Code {
        self.verifier
            .verify(e, p, &self.challenge, now)
            .unwrap_err()
            .code
    }
}

#[test]
fn mock_happy_path() {
    let w = world();
    let v = w
        .verifier
        .verify(&w.evidence(), &dev_policy(), &w.challenge, NOW + 5)
        .unwrap();
    assert_eq!(v.tee_kind, TeeKind::Mock);
    assert_eq!(v.security, Security::DevelopmentOnly);
    assert_eq!(v.binding, w.binding());
    assert_eq!(v.image_digest.as_deref(), Some(IMAGE));
    // Round trip on the wire.
    let e = AttestationEvidence::from_bytes(&w.evidence().to_bytes().unwrap()).unwrap();
    assert_eq!(e, w.evidence());
}

#[test]
fn production_policies_refuse_mock_evidence() {
    let w = world();
    let mut p = dev_policy();
    p.allow_development = false;
    assert_eq!(w.code(&w.evidence(), &p, NOW), Code::WorkloadPolicy);
    // A production policy cannot even list the mock TEE.
    assert!(p.validate().is_err());
}

#[test]
fn policy_mismatches() {
    let w = world();
    let e = w.evidence();
    let deny = |f: &dyn Fn(&mut AttestationPolicy)| {
        let mut p = dev_policy();
        f(&mut p);
        w.code(&e, &p, NOW)
    };
    // Wrong image.
    assert_eq!(
        deny(&|p| p.allowed_images = vec!["sha256:00".into()]),
        Code::WorkloadPolicy
    );
    // Wrong execution spec.
    assert_eq!(
        deny(&|p| p.execution_spec_id = POLICY.into()),
        Code::WorkloadPolicy
    );
    // Wrong confidentiality policy, or none expected.
    assert_eq!(
        deny(&|p| p.policy_id = Some(SPEC.into())),
        Code::WorkloadPolicy
    );
    assert_eq!(deny(&|p| p.policy_id = None), Code::WorkloadPolicy);
    // Wrong artifact.
    assert_eq!(
        deny(&|p| p.artifact_digest = Some(SPEC.into())),
        Code::WorkloadPolicy
    );
    // TEE not allowed.
    assert_eq!(
        deny(&|p| p.allowed_tee = vec![TeeKind::IntelTdx]),
        Code::WorkloadPolicy
    );
    // GPU required.
    assert_eq!(
        deny(&|p| p.require_gpu_attestation = true),
        Code::WorkloadPolicy
    );
}

#[test]
fn debug_and_tcb() {
    let w = world();
    let debug =
        w.hw.attester(IMAGE)
            .issued_at(NOW)
            .debug(true)
            .attest(&w.challenge, &w.binding())
            .unwrap();
    assert_eq!(w.code(&debug, &dev_policy(), NOW), Code::WorkloadPolicy);
    let mut p = dev_policy();
    p.debug = DebugPolicy::Allowed;
    assert!(w.verifier.verify(&debug, &p, &w.challenge, NOW).is_ok());
    let old =
        w.hw.attester(IMAGE)
            .issued_at(NOW)
            .tcb(TcbStatus::OutOfDate)
            .attest(&w.challenge, &w.binding())
            .unwrap();
    assert_eq!(w.code(&old, &dev_policy(), NOW), Code::WorkloadPolicy);
}

#[test]
fn freshness() {
    let w = world();
    let e = w.evidence();
    // Another challenge (a replay against a new challenge).
    let other = AttestationChallenge::new("hospital", NOW, 300).unwrap();
    assert_eq!(
        w.verifier
            .verify(&e, &dev_policy(), &other, NOW)
            .unwrap_err()
            .code,
        Code::Freshness
    );
    // The challenge has expired.
    assert_eq!(w.code(&e, &dev_policy(), NOW + 301), Code::Freshness);
    // Stale: older than the policy's maximum age.
    let mut p = dev_policy();
    p.max_evidence_age_secs = 10;
    assert_eq!(w.code(&e, &p, NOW + 11), Code::Freshness);
    // Issued before the challenge existed.
    let early =
        w.hw.attester(IMAGE)
            .issued_at(NOW - 3600)
            .attest(&w.challenge, &w.binding())
            .unwrap();
    assert_eq!(w.code(&early, &dev_policy(), NOW), Code::Freshness);
    // Expired evidence.
    let short =
        w.hw.attester(IMAGE)
            .issued_at(NOW)
            .lifetime(5)
            .attest(&w.challenge, &w.binding())
            .unwrap();
    assert_eq!(w.code(&short, &dev_policy(), NOW + 6), Code::Freshness);
}

#[test]
fn tampering_and_substitution() {
    let w = world();
    let e = w.evidence();
    // Tampered claims (the image) break the signature.
    let mut t = e.clone();
    t.evidence = t.evidence.replace("4444", "5555");
    assert_eq!(w.code(&t, &dev_policy(), NOW), Code::Attestation);
    // A host substituting its own session key, evaluator key, spec or policy
    // in the binding: the evidence no longer commits to it.
    let attacker = WorkloadSession::new(&EvaluatorSigner::from_seed(&[1; 32]).identity());
    let swaps: [&dyn Fn(&mut WorkloadBinding); 4] = [
        &|b| b.session_public_key = attacker.session_public_key_hex(),
        &|b| b.evaluator_public_key = "ab".repeat(32),
        &|b| b.execution_spec_id = POLICY.into(),
        &|b| b.policy_id = None,
    ];
    for swap in swaps {
        let mut t = e.clone();
        swap(&mut t.binding);
        assert_eq!(w.code(&t, &dev_policy(), NOW), Code::Attestation);
    }
    // Evidence signed by an unknown mock root.
    let rogue = MockHardware::from_seed(&[8; 32])
        .attester(IMAGE)
        .issued_at(NOW)
        .attest(&w.challenge, &w.binding())
        .unwrap();
    assert_eq!(w.code(&rogue, &dev_policy(), NOW), Code::Attestation);
    // Unknown provider.
    let mut t = e.clone();
    t.provider = "acme-tee".into();
    assert_eq!(w.code(&t, &dev_policy(), NOW), Code::Attestation);
    // Garbage.
    assert!(AttestationEvidence::from_bytes(b"{}").is_err());
}

#[test]
fn records_verify_as_history() {
    let w = world();
    let r = AttestationRecord::new(w.evidence());
    let back = AttestationRecord::from_bytes(&r.to_bytes().unwrap()).unwrap();
    assert_eq!(back.id().unwrap(), r.id().unwrap());
    assert_eq!(r.session_id().unwrap(), w.session.session_id());
    // Long after expiry the record still verifies (no freshness), but not
    // under another policy.
    assert!(r.verify(&w.verifier, &dev_policy()).is_ok());
    let mut p = dev_policy();
    p.execution_spec_id = POLICY.into();
    assert!(r.verify(&w.verifier, &p).is_err());
}

#[test]
fn grants_open_only_in_their_session() {
    let w = world();
    let b = w.binding();
    let header = GrantHeader {
        version: GRANT_VERSION,
        broker_id: "hospital".into(),
        asset_id: "patients".into(),
        key_version: 1,
        policy_id: Some(POLICY.into()),
        execution_spec_id: SPEC.into(),
        session_id: WorkloadSession::session_id_of(&b).unwrap(),
        binding_hash: b.nonce().unwrap(),
        attestation_digest: "00".repeat(32),
        expires_at: NOW + 300,
    };
    let key = [42u8; 32];
    let g = seal_grant(header, &b, &key).unwrap();
    assert!(!serde_json::to_string(&g)
        .unwrap()
        .contains(&"2a".repeat(32)));
    assert_eq!(w.session.open(&g).unwrap().as_slice(), &key);
    // Relabelled for another asset: authentication fails.
    let mut t = g.clone();
    t.header.asset_id = "weights".into();
    assert_eq!(w.session.open(&t).unwrap_err().code, Code::KeyRelease);
    // Another session (same evaluator, fresh key) cannot open it, even
    // with the header rewritten to name it.
    let other = WorkloadSession::new(&EvaluatorSigner::from_seed(&[9; 32]).identity());
    assert_eq!(other.open(&g).unwrap_err().code, Code::KeyRelease);
    let mut t = g.clone();
    t.header.session_id = other.session_id();
    assert_eq!(other.open(&t).unwrap_err().code, Code::KeyRelease);
}

// ---- Confidential Space -------------------------------------------------

const AUD: &str = "https://broker.hospital.example";

fn cs_provider() -> ConfidentialSpaceProvider {
    ConfidentialSpaceProvider::new(include_str!("fixtures/jwks.json"), AUD).unwrap()
}

fn cs_claims(nonce: &str) -> serde_json::Value {
    json!({
        "iss": ISSUER,
        "aud": AUD,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 3600,
        "eat_nonce": nonce,
        "hwmodel": "GCP_INTEL_TDX",
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["250800"],
        "dbgstat": "disabled-since-boot",
        "secboot": true,
        "oemid": 11129,
        "submods": {
            "container": {"image_digest": IMAGE, "image_reference": "us-docker.pkg.dev/p/r/w:1"},
            "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
            "gce": {"project_id": "p", "zone": "us-central1-a"}
        }
    })
}

fn token(claims: &serde_json::Value, pem: &[u8], kid: &str) -> String {
    let mut h = Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some(kid.into());
    jsonwebtoken::encode(&h, claims, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
}

const GOOGLE: &[u8] = include_bytes!("fixtures/google-test.pem");
const ATTACKER: &[u8] = include_bytes!("fixtures/attacker-test.pem");

fn cs_evidence(w: &World, edit: impl FnOnce(&mut serde_json::Value)) -> AttestationEvidence {
    let b = w.binding();
    let mut c = cs_claims(&b.nonce().unwrap());
    edit(&mut c);
    AttestationEvidence {
        version: EVIDENCE_VERSION,
        provider: PROVIDER.into(),
        binding: b,
        evidence: token(&c, GOOGLE, "test-key-1"),
    }
}

fn cs_policy() -> AttestationPolicy {
    let mut p = AttestationPolicy::new(SPEC, Some(POLICY));
    p.allowed_tee = vec![TeeKind::IntelTdx, TeeKind::AmdSevSnp];
    p.allowed_images = vec![IMAGE.into()];
    p
}

fn cs_code(w: &World, e: &AttestationEvidence) -> Code {
    Verifier::new()
        .with(cs_provider())
        .verify(e, &cs_policy(), &w.challenge, NOW + 1)
        .unwrap_err()
        .code
}

#[test]
fn confidential_space_happy_path() {
    let w = world();
    let v = Verifier::new()
        .with(cs_provider())
        .verify(
            &cs_evidence(&w, |_| {}),
            &cs_policy(),
            &w.challenge,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(v.tee_kind, TeeKind::IntelTdx);
    assert_eq!(v.security, Security::Production);
    assert_eq!(v.tcb_status, TcbStatus::Current);
    assert!(!v.debug_enabled);
    // An array of nonces (several brokers in one token) works too.
    let e = cs_evidence(&w, |c| {
        let n = c["eat_nonce"].clone();
        c["eat_nonce"] = json!(["other-nonce-0000", n]);
    });
    assert!(Verifier::new()
        .with(cs_provider())
        .verify(&e, &cs_policy(), &w.challenge, NOW + 1)
        .is_ok());
}

/// A named edit of token claims.
type ClaimEdit<'a> = (&'a str, &'a dyn Fn(&mut serde_json::Value));

#[test]
fn confidential_space_rejections() {
    let w = world();
    let attestation: [ClaimEdit; 6] = [
        ("wrong audience", &|c| {
            c["aud"] = json!("https://evil.example")
        }),
        ("wrong issuer", &|c| {
            c["iss"] = json!("https://evil.example")
        }),
        ("no nonce", &|c| c["eat_nonce"] = json!("x".repeat(64))),
        ("not confidential space", &|c| c["swname"] = json!("GCE")),
        ("no secure boot", &|c| c["secboot"] = json!(false)),
        ("no image", &|c| c["submods"]["container"] = json!({})),
    ];
    for (what, edit) in attestation {
        assert_eq!(
            cs_code(&w, &cs_evidence(&w, edit)),
            Code::Attestation,
            "{what}"
        );
    }
    let policy: [ClaimEdit; 4] = [
        ("debug image", &|c| c["dbgstat"] = json!("enabled")),
        ("SEV not allowed", &|c| c["hwmodel"] = json!("GCP_AMD_SEV")),
        ("shielded VM", &|c| c["hwmodel"] = json!("GCP_SHIELDED_VM")),
        ("experimental image", &|c| {
            c["submods"]["confidential_space"]["support_attributes"] = json!(["EXPERIMENTAL"])
        }),
    ];
    for (what, edit) in policy {
        assert_eq!(
            cs_code(&w, &cs_evidence(&w, edit)),
            Code::WorkloadPolicy,
            "{what}"
        );
    }
    assert_eq!(
        cs_code(&w, &cs_evidence(&w, |c| c["exp"] = json!(NOW))),
        Code::Freshness
    );
    // Signed by a key Google never published, under Google's key ID.
    let mut e = cs_evidence(&w, |_| {});
    e.evidence = token(
        &cs_claims(&w.binding().nonce().unwrap()),
        ATTACKER,
        "test-key-1",
    );
    assert_eq!(cs_code(&w, &e), Code::Attestation);
    // Unknown key ID.
    e.evidence = token(&cs_claims(&w.binding().nonce().unwrap()), GOOGLE, "other");
    assert_eq!(cs_code(&w, &e), Code::Attestation);
    // Tampered payload.
    let good = cs_evidence(&w, |_| {}).evidence;
    let parts: Vec<&str> = good.split('.').collect();
    let mut c = cs_claims(&w.binding().nonce().unwrap());
    c["dbgstat"] = json!("disabled-since-boot");
    c["submods"]["container"]["image_digest"] = json!("sha256:evil");
    use base64_like::encode;
    e.evidence = format!("{}.{}.{}", parts[0], encode(&c.to_string()), parts[2]);
    assert_eq!(cs_code(&w, &e), Code::Attestation);
    // Unsigned (alg none) and HMAC tokens.
    let body = encode(&cs_claims(&w.binding().nonce().unwrap()).to_string());
    e.evidence = format!("{}.{body}.", encode(r#"{"alg":"none","kid":"test-key-1"}"#));
    assert_eq!(cs_code(&w, &e), Code::Attestation);
    e.evidence = jsonwebtoken::encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &cs_claims(&w.binding().nonce().unwrap()),
        &EncodingKey::from_secret(b"k"),
    )
    .unwrap();
    assert_eq!(cs_code(&w, &e), Code::Attestation);
}

#[test]
fn confidential_space_gpu_claims() {
    let w = world();
    let e = cs_evidence(&w, |c| {
        c["submods"]["nvidia_gpu"] =
            json!({"cc_mode": "ON", "cc_feature": "SPT", "gpus": [{"hwmodel": "GCP_NVIDIA_H100"}]});
    });
    let mut p = cs_policy();
    p.require_gpu_attestation = true;
    let v = Verifier::new()
        .with(cs_provider())
        .verify(&e, &p, &w.challenge, NOW + 1)
        .unwrap();
    assert_eq!(v.gpu.unwrap().models, ["GCP_NVIDIA_H100"]);
    let off = cs_evidence(&w, |c| {
        c["submods"]["nvidia_gpu"] = json!({"cc_mode": "OFF", "gpus": []});
    });
    assert_eq!(
        Verifier::new()
            .with(cs_provider())
            .verify(&off, &p, &w.challenge, NOW + 1)
            .unwrap_err()
            .code,
        Code::WorkloadPolicy
    );
}

/// Unpadded base64url, for hand-built tokens.
mod base64_like {
    pub fn encode(s: &str) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let b = s.as_bytes();
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..=c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }
}
