//! Trust Graph records, as `encompute trust add` reads them: each record
//! type in turn, added to a graph that holds a program, then re-linked.
#![no_main]
use encompute_trust::{SignedAuthorization, SignedRevocation, TrustGraph};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut g = TrustGraph::new();
    let _ = g.add_program(encompute_fuzz::PROGRAM);
    if let Ok(r) = serde_json::from_slice::<encompute_secagg::AggregationReceipt>(data) {
        let _ = g.add_aggregation(r);
    }
    if let Ok(r) = encompute_verification::SignedExecutionReceipt::from_bytes(data) {
        let _ = g.add_execution_receipt(r);
    }
    if let Ok(r) = encompute_attestation::AttestationRecord::from_bytes(data) {
        let _ = g.add_attestation(r);
    }
    if let Ok(r) = serde_json::from_slice::<encompute_privacy::PrivacyReceipt>(data) {
        let _ = g.add_privacy_receipt(r);
    }
    if let Ok(s) = serde_json::from_slice::<encompute_secagg::AggregationSpec>(data) {
        let _ = g.add_aggregation_spec(s);
    }
    if let Ok(p) = encompute_planner::ConfidentialExecutionPlan::from_bytes(data) {
        let _ = g.add_plan(p);
    }
    if let Ok(s) = serde_json::from_slice::<encompute_training::TrainingSpec>(data) {
        let _ = g.add_training_spec(s);
    }
    if let Ok(r) = serde_json::from_slice::<encompute_training::SignedAdapterRecord>(data) {
        let _ = g.add_adapter(r);
    }
    if let Ok(r) = serde_json::from_slice::<encompute_training::SignedWorkerEvidence>(data) {
        let _ = g.add_worker_evidence(r);
    }
    if let Ok(a) = serde_json::from_slice::<SignedAuthorization>(data) {
        let _ = a.verify(&a.public_key);
        let _ = g.add_authorization(a);
    }
    if let Ok(r) = serde_json::from_slice::<SignedRevocation>(data) {
        let _ = r.verify(&r.public_key);
        let _ = g.add_revocation(r);
    }
    let _ = g.rebuild();
});
