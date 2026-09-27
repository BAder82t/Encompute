//! Control-plane API inputs that need no database: every request body
//! type, role and state names, signed-request headers carried as a JSON
//! object, and bearer tokens (development issuer and untrusted ones).
#![no_main]
use encompute_control::authn::{dev_token, Authenticator};
use encompute_control::config::Env;
use encompute_control::model::*;
use encompute_verification::ServiceHeaders;
use libfuzzer_sys::fuzz_target;

fn body<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
    serde_json::from_slice(data).ok()
}

fuzz_target!(|data: &[u8]| {
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
        if let Ok(b) = serde_json::to_vec(&c.receipt) {
            let _ = encompute_verification::SignedExecutionReceipt::from_bytes(&b);
        }
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
    let auth = Authenticator::new(
        Env::Development,
        "control-plane",
        vec![],
        Some(zeroize::Zeroizing::new("fuzz-secret".to_owned())),
    );
    let _ = auth.verify_token(&text);
    if data.len() < 64 {
        if let Ok(t) = dev_token("fuzz-secret", &text, 60) {
            let (_, sub) = auth.verify_token(&t).expect("own token verifies");
            assert_eq!(sub, text);
        }
    }
});
