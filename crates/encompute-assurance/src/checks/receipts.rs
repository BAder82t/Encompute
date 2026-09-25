//! Execution receipts: every single-field mutation of a signed receipt,
//! including the policy fields, is refused; a receipt never verifies for
//! another execution.

use encompute_verification::{
    output_commitment, request_commitment, verify_receipt, EvaluatorSigner, ExecutionReceipt,
    ExecutionSpec, ExpectedExecution, SignedExecutionReceipt,
};

use crate::{ensure, mutate, CheckResult, Outcome, Scale};

fn spec(policy: bool) -> ExecutionSpec {
    ExecutionSpec {
        version: 1,
        program_id: "a".repeat(64),
        plan_id: "b".repeat(64),
        parameter_set_id: "c".repeat(64),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "TFHE".into(),
        backend: "tfhe-rs".into(),
        backend_version: "1.8.1".into(),
        policy_id: policy.then(|| "d".repeat(64)),
        privacy_policy_id: policy.then(|| "e".repeat(64)),
    }
}

const KEY: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const TRANSCRIPT: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";

fn verifies(
    r: &SignedExecutionReceipt,
    s: &ExecutionSpec,
    req: &[u8],
    out: &[u8],
    signer: &EvaluatorSigner,
) -> bool {
    let (rc, oc) = (request_commitment(req), output_commitment(out));
    let id = signer.identity();
    verify_receipt(
        r,
        &ExpectedExecution {
            spec: s,
            key_id: KEY,
            request_commitment: &rc,
            output_commitment: &oc,
            transcript_hash: Some(TRANSCRIPT),
            proof_expected: false,
            trusted_evaluator: &id,
        },
    )
    .is_ok()
}

/// INV-020/021: every field of a signed execution receipt is bound, and a
/// receipt does not verify for another request, output or spec (replay).
pub fn execution_receipt_mutation(_: Scale) -> CheckResult {
    let signer = EvaluatorSigner::generate().map_err(|e| e.to_string())?;
    let mut total = 0;
    for policy in [false, true] {
        let s = spec(policy);
        let (req, out) = (b"request-1".as_slice(), b"output-1".as_slice());
        let r = ExecutionReceipt::new(&s, Some(TRANSCRIPT), KEY, req, out, &signer.identity())
            .and_then(|r| r.sign(&signer))
            .map_err(|e| e.to_string())?;
        ensure!(
            verifies(&r, &s, req, out, &signer),
            "the honest receipt fails"
        );
        let json = serde_json::to_value(&r).map_err(|e| e.to_string())?;
        let (n, bad) = mutate::accepted(&json, &[], |m| {
            serde_json::from_value::<SignedExecutionReceipt>(m.clone())
                .ok()
                .is_some_and(|m| verifies(&m, &s, req, out, &signer))
        });
        ensure!(
            bad.is_empty(),
            "mutated receipts accepted (policy {policy}): {bad:?}"
        );
        total += n;
        // Replay against another execution.
        ensure!(
            !verifies(&r, &s, b"request-2", out, &signer),
            "replayed for another request"
        );
        ensure!(
            !verifies(&r, &s, req, b"output-2", &signer),
            "accepted for another output"
        );
        ensure!(
            !verifies(&r, &spec(!policy), req, out, &signer),
            "accepted under another policy"
        );
        let other = EvaluatorSigner::generate().map_err(|e| e.to_string())?;
        ensure!(
            !verifies(&r, &s, req, out, &other),
            "accepted from an untrusted evaluator"
        );
        total += 4;
    }
    Ok(Outcome::new(total))
}
