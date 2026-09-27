//! Fuzz smoke tests for control-plane inputs that need no database: every
//! JSON request body, role and state names, signed-request headers, and
//! bearer tokens. Mutated inputs never panic; a mutated development token
//! never authenticates as someone else. Resource limits: oversized tokens,
//! deep JSON and out-of-range integers are typed errors.

#[path = "../../encompute-ir/tests/fuzz_support/mod.rs"]
mod fuzz_support;

use std::time::Duration;

use encompute_control::authn::{dev_token, Authenticator};
use encompute_control::config::Env;
use encompute_control::model::*;
use encompute_ir::Code;
use encompute_verification::ServiceHeaders;
use fuzz_support::{run, within};
use zeroize::Zeroizing;

fn body<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
    serde_json::from_slice(data).ok()
}

fn bodies() -> Vec<Vec<u8>> {
    [
        serde_json::json!({"id": "modelco", "display_name": "ModelCo",
            "admin": {"issuer": "https://idp", "subject": "alice", "email": "a@x"}}),
        serde_json::json!({"issuer": "https://idp", "subject": "bob", "roles": ["auditor"]}),
        serde_json::json!({"id": "evaluator-1", "kind": "evaluator", "public_key": "00", "roles": []}),
        serde_json::json!({"organization": "modelco", "kind": "dataset", "name": "d",
            "digest": "0", "size_bytes": 10, "policy": {"release": ["never", {"a": 1}]},
            "parents": [], "privacy_budget": {"unit": "patient", "epsilon": "1.0", "delta": "1e-6"},
            "key_ref": {"broker": "kb", "provider": "aws-kms", "key_ref": "k", "key_version": 1}}),
        serde_json::json!({"project": "prj_1", "plan": "pln_1", "purpose": "p",
            "source_assets": ["ast_1"], "requested_output": "d"}),
        serde_json::json!({"receipt": {"x": 1}, "request_commitment": "0",
            "output_commitment": "0", "key_id": "k"}),
        serde_json::json!({"id": "evaluator-1", "url": "http://e:8080", "receipt_key": "0",
            "backends": ["openfhe-exact"], "profiles": ["CKKS"], "openfhe_version": "1.5.1",
            "capacity": 2, "logical_cores": 8, "memory_bytes": 17179869184u64}),
        serde_json::json!({"project": "prj_1", "program": "encompute 0.1\nprogram p precision 0.1\n"}),
        serde_json::json!({"kind": "commit", "event_id": "e", "output_commitment": "0"}),
    ]
    .iter()
    .map(|v| serde_json::to_vec(v).unwrap())
    .collect()
}

fn parse_all(data: &[u8]) {
    let _ = body::<CreateOrganization>(data);
    let _ = body::<CreateUser>(data);
    let _ = body::<CreateServiceAccount>(data);
    let _ = body::<CreateProject>(data);
    let _ = body::<AddProjectMember>(data);
    if let Some(a) = body::<RegisterAsset>(data) {
        let _ = encompute_verification::canonical::canonical_json(&a.policy);
        if let Some(b) = &a.privacy_budget {
            let _ = b.validate();
        }
    }
    let _ = body::<ApproveAsset>(data);
    if let Some(p) = body::<CreatePlan>(data) {
        let _ = encompute_ir::parse(&p.program);
    }
    let _ = body::<SubmitJob>(data);
    if let Some(c) = body::<CompleteJob>(data) {
        let _ = encompute_verification::SignedExecutionReceipt::from_bytes(
            &serde_json::to_vec(&c.receipt).unwrap(),
        );
    }
    let _ = body::<RegisterEvaluator>(data);
    let _ = body::<EvaluatorStatus>(data);
    let _ = body::<encompute_privacy::PrivacyEvent>(data);
    let _ = body::<MessageEnvelope>(data);
    if let Some(v) = body::<serde_json::Value>(data) {
        let _ = encompute_verification::canonical::canonical_json(&v);
    }
    let text = String::from_utf8_lossy(data);
    let _ = Role::parse(&text);
    let _ = ServiceKind::parse(&text);
    let _ = JobState::parse(&text);
    if let Some(h) = body::<std::collections::BTreeMap<String, String>>(data) {
        let _ = ServiceHeaders::from_lookup(|k| h.get(k).cloned());
    }
}

fn auth() -> Authenticator {
    Authenticator::new(
        Env::Development,
        "control-plane",
        vec![],
        Some(Zeroizing::new("fuzz-secret".to_owned())),
    )
}

#[test]
fn mutated_request_bodies_never_panic() {
    run(
        "control-bodies",
        &bodies(),
        8000,
        Duration::from_secs(1),
        parse_all,
    );
}

#[test]
fn mutated_tokens_never_panic_or_authenticate_as_another() {
    let a = auth();
    let token = dev_token("fuzz-secret", "alice", 3600).unwrap();
    assert_eq!(a.verify_token(&token).unwrap().1, "alice");
    run(
        "control-tokens",
        &[token.clone().into_bytes()],
        6000,
        Duration::from_secs(1),
        |bytes| {
            let t = String::from_utf8_lossy(bytes);
            if let Ok((_, sub)) = a.verify_token(&t) {
                assert_eq!(sub, "alice", "{t}");
            }
        },
    );
}

#[test]
fn resource_limits_are_typed_errors() {
    let a = auth();
    let limit = Duration::from_secs(1);
    let deep = fuzz_support::nested_json(100_000, "");
    let deep_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&deep[..12_000])
    };
    for t in [
        "a".repeat(1 << 20),
        format!("x.{}.y", "A".repeat(15_000)),
        format!("x.{deep_b64}.y"),
        "..".into(),
        "\u{ff}.\u{ff}.\u{ff}".into(),
        String::new(),
    ] {
        let e = within(limit, || a.verify_token(&t)).unwrap_err();
        assert_eq!(e.code, Code::Unauthenticated, "{e}");
    }
    // Production refuses development tokens.
    let p = Authenticator::new(Env::Production, "control-plane", vec![], None);
    let t = dev_token("fuzz-secret", "alice", 3600).unwrap();
    assert_eq!(p.verify_token(&t).unwrap_err().code, Code::Unauthenticated);
    // Bodies: deep nesting and huge arrays are bounded.
    within(limit, || parse_all(deep.as_bytes()));
    let wide = format!(
        "{{\"issuer\":\"i\",\"subject\":\"s\",\"roles\":[{}]}}",
        vec!["\"auditor\""; 200_000].join(",")
    );
    within(Duration::from_secs(5), || parse_all(wide.as_bytes()));
    for bad in [
        r#"{"id":"e","url":"u","receipt_key":"k","backends":[],"profiles":[],"openfhe_version":"v","capacity":2147483648}"#,
        r#"{"id":"e","url":"u","receipt_key":"k","backends":[],"profiles":[],"openfhe_version":"v","capacity":-1e999}"#,
    ] {
        assert!(body::<RegisterEvaluator>(bad.as_bytes()).is_none());
    }
}
