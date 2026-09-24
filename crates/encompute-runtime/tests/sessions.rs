//! Client ↔ evaluator binding: every envelope is rejected for the wrong key,
//! program, parameters, kind or corruption.

mod common;

use common::{logistic, mock_sessions};
use encompute_ir::Code;
use encompute_runtime::{sample_inputs, BackendKind, EvaluatorSession};

#[test]
fn round_trip_and_rejections() {
    let p = logistic(8, 1);
    let (client, ev) = mock_sessions(&p, None, 1);
    let inputs = sample_inputs(&p, 3, 0);
    let request = client.encrypt(&p, &inputs).unwrap();
    let (response, _) = ev.execute(&request).unwrap();
    assert!(client.decrypt(&response).is_ok());

    // Another client's keys are not registered on this evaluator.
    let (other, _) = mock_sessions(&p, None, 2);
    let foreign = other.encrypt(&p, &inputs).unwrap();
    assert_ne!(other.key_id(), client.key_id());
    assert_eq!(ev.execute(&foreign).unwrap_err().code, Code::WrongKey);
    // Nor can the other client read this client's results.
    assert_eq!(other.decrypt(&response).unwrap_err().code, Code::WrongKey);

    // Different program (different weights) and different parameters.
    let p2 = logistic(8, 2);
    let (_, ev2) = mock_sessions(&p2, None, 3);
    assert_eq!(ev2.execute(&request).unwrap_err().code, Code::WrongProgram);
    let p3 = logistic(64, 1);
    let (_, ev3) = mock_sessions(&p3, None, 4);
    assert_eq!(
        ev3.execute(&request).unwrap_err().code,
        Code::WrongParameters
    );

    // Wrong kind: a response is not a request, keys are not inputs.
    assert_eq!(ev.execute(&response).unwrap_err().code, Code::Incompatible);
    assert_eq!(
        client.decrypt(&request).unwrap_err().code,
        Code::Incompatible
    );

    // Corruption anywhere is caught by the envelope checksum.
    for i in [0, request.len() / 3, request.len() / 2, request.len() - 1] {
        let mut bad = request.clone();
        bad[i] ^= 0x40;
        assert_eq!(
            ev.execute(&bad).unwrap_err().code,
            Code::Envelope,
            "byte {i}"
        );
    }
    let mut bad = response.clone();
    bad.truncate(bad.len() - 5);
    assert_eq!(client.decrypt(&bad).unwrap_err().code, Code::Envelope);

    // Keys registered for another program's evaluator are refused if the
    // parameter set differs.
    let mut ev3 = EvaluatorSession::new(p3, BackendKind::Mock).unwrap();
    assert_eq!(
        ev3.register_keys(client.evaluation_keys().unwrap())
            .unwrap_err()
            .code,
        Code::WrongParameters
    );
}
