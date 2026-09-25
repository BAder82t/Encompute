//! Confidentiality policies in artifacts and execution identity (ADR-010).

use encompute_evaluator::server::{Evaluator, Limits};
use encompute_ir::{parse, Code, Program};
use encompute_runtime::verification::PolicyId;
use encompute_runtime::{
    sample_inputs, verification_spec, BackendKind, Backends, Mode, Model, Remote,
};

fn training(purpose_list: &str, weight: &str) -> Program {
    parse(&format!(
        r#"encompute 0.1
program step precision 0.01 purpose "disease-training"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
party "coordinator" "Coordinator"
asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes [{purpose_list}] release never derive [gradient aggregate_only to ["coordinator"]]
asset "weights" model owners ["modelco"] readers ["modelco"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
%0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
%1 = input "w" [-1.0, 1.0] asset "weights" : secret vector<4>
%2 = mul %0, %1 : secret vector<4>
%3 = const [{weight}] : public scalar
%4 = mul %2, %3 : secret vector<4>
derive %4 gradient aggregate_only
output "gradient" = %4
"#
    ))
    .unwrap()
}

fn base() -> Program {
    training("\"disease-training\"", "0.5")
}

fn policy_id(p: &Program) -> String {
    PolicyId::of(p.confidentiality().unwrap()).hex()
}

#[test]
fn policy_ids_are_deterministic_and_bound_to_the_spec() {
    let (a, b) = (
        Model::compile(base()).unwrap(),
        Model::compile(base()).unwrap(),
    );
    assert_eq!(a.ids().policy_id, b.ids().policy_id);
    assert_eq!(
        a.ids().policy_id.as_deref(),
        Some(policy_id(&base()).as_str())
    );
    let spec = verification_spec(&a, BackendKind::OpenFhe);
    assert_eq!(spec.policy_id, a.ids().policy_id);
    // A policy change changes the policy ID and the spec ID.
    let wider = training("\"disease-training\", \"advertising\"", "0.5");
    assert_ne!(policy_id(&wider), policy_id(&base()));
    let other = Model::compile(wider).unwrap();
    assert_ne!(
        verification_spec(&other, BackendKind::OpenFhe).id(),
        spec.id()
    );
    // A program change that leaves the policy alone keeps the policy ID
    // (the program and spec IDs change).
    let tweaked = training("\"disease-training\"", "0.25");
    assert_eq!(policy_id(&tweaked), policy_id(&base()));
    let t = Model::compile(tweaked).unwrap();
    assert_ne!(t.ids().program_id, a.ids().program_id);
    assert_ne!(verification_spec(&t, BackendKind::OpenFhe).id(), spec.id());
    // Programs without declarations keep the spec they always had.
    let plain = parse(
        "encompute 0.1\nprogram p precision 0.01\n%0 = input \"x\" [-1.0, 1.0] : secret scalar\n\
         output \"y\" = %0\n",
    )
    .unwrap();
    let pm = Model::compile(plain).unwrap();
    assert_eq!(pm.ids().policy_id, None);
    assert!(!verification_spec(&pm, BackendKind::Mock)
        .canonical_bytes()
        .map(|b| String::from_utf8(b).unwrap())
        .unwrap()
        .contains("policy_id"));
}

#[test]
fn policy_artifact_round_trips_and_detects_tampering() {
    let dir = std::env::temp_dir().join(format!("encompute-policy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let m = Model::compile(base()).unwrap();
    m.save(&dir).unwrap();
    let policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("policy.json")).unwrap()).unwrap();
    assert_eq!(policy["policy_id"], m.ids().policy_id.clone().unwrap());
    assert_eq!(policy["declarations"]["purpose"], "disease-training");
    assert!(policy["assets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["label"] == "derived:%4"));
    let verification: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("verification.json")).unwrap()).unwrap();
    assert_eq!(verification["policy_id"], policy["policy_id"]);
    let loaded = Model::load(&dir).unwrap();
    assert_eq!(loaded.ids(), m.ids());
    assert!(loaded
        .privacy_explain()
        .unwrap()
        .unwrap()
        .contains("aggregate_only"));
    // Tampering with the policy file (even a weaker release) is detected.
    let path = dir.join("policy.json");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("aggregate_only", "public")).unwrap();
    assert_eq!(Model::load(&dir).err().unwrap().code, Code::Artifact);
    std::fs::remove_dir_all(&dir).unwrap();
    // Programs without declarations write `null`.
    let plain = parse(
        "encompute 0.1\nprogram p precision 0.01\n%0 = input \"x\" [-1.0, 1.0] : secret scalar\n\
         output \"y\" = %0\n",
    )
    .unwrap();
    assert_eq!(
        Model::compile(plain).unwrap().artifact_files()["policy.json"],
        "null\n"
    );
}

#[test]
fn illegal_flows_fail_compilation() {
    let text = base().to_string();
    let leak = parse(&text.replace(
        "output \"gradient\" = %4",
        "output \"gradient\" = %4 to \"coordinator\"",
    ))
    .unwrap();
    assert_eq!(
        Model::compile(leak).err().unwrap().code,
        Code::AggregationRequired
    );
    let public = parse(&text.replace(
        "output \"gradient\" = %4",
        "output \"gradient\" = %4 public",
    ))
    .unwrap();
    assert_eq!(
        Model::compile(public).err().unwrap().code,
        Code::PublicRelease
    );
}

/// Receipts bind the policy: a result produced under one policy does not
/// verify as execution under another.
#[test]
fn receipts_bind_the_policy() {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    std::thread::spawn(move || Evaluator::new(Backends::MOCK, Limits::default()).serve(server));
    let remote = Remote::new(&url);
    let trusted = remote.evaluator_identity().unwrap();
    let m = Model::compile(base()).unwrap();
    let client = m.new_client(Mode::Mock).unwrap();
    let run = remote
        .run(
            &client,
            m.program(),
            None,
            &sample_inputs(m.program(), 3, 1),
            &trusted,
        )
        .unwrap();
    assert_eq!(run.receipt.receipt.spec_id, client.spec().id().hex());
    assert_eq!(client.spec().policy_id, m.ids().policy_id);
    // The same receipt against the spec of a program under another policy.
    let other = Model::compile(training("\"disease-training\", \"advertising\"", "0.5")).unwrap();
    let other_client = other.new_client(Mode::Mock).unwrap();
    assert!(other_client
        .verify_receipt(&run.request, &run.response, &run.receipt, &trusted)
        .is_err());
}
