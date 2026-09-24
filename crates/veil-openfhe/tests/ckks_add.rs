//! Backend-level checks against OpenFHE: arithmetic, rotation semantics under
//! sparse packing, key separation, concurrency, and parameter agreement.

use veil_backend::CkksBackend;
use veil_ckks::select_params;
use veil_openfhe::{openfhe_choice, OpenFheBackend};

fn close(a: &[f64], b: &[f64], tol: f64) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        assert!((x - y).abs() < tol, "slot {i}: {x} vs {y}");
    }
}

#[test]
fn arithmetic_matches_plaintext() {
    let params = select_params(3, 4.0, 1e-3, 8).unwrap();
    let (be, sk) = OpenFheBackend::new(&params, &[1, 3]).unwrap();
    let n = be.slots();
    let a: Vec<f64> = (0..n).map(|i| i as f64 / n as f64 - 0.5).collect();
    let b: Vec<f64> = (0..n).map(|i| 0.25 * (i as f64).cos()).collect();
    let (ca, cb) = (be.encrypt(&a).unwrap(), be.encrypt(&b).unwrap());
    let dec = |c: &veil_openfhe::OpenFheCiphertext| be.decrypt(&sk, c).unwrap();

    close(
        &dec(&be.add(&ca, &cb).unwrap()),
        &a.iter().zip(&b).map(|(x, y)| x + y).collect::<Vec<_>>(),
        1e-6,
    );
    close(
        &dec(&be.sub(&ca, &cb).unwrap()),
        &a.iter().zip(&b).map(|(x, y)| x - y).collect::<Vec<_>>(),
        1e-6,
    );
    close(
        &dec(&be.neg(&ca).unwrap()),
        &a.iter().map(|x| -x).collect::<Vec<_>>(),
        1e-6,
    );
    let prod = be.mul(&ca, &cb).unwrap();
    close(
        &dec(&prod),
        &a.iter().zip(&b).map(|(x, y)| x * y).collect::<Vec<_>>(),
        1e-6,
    );
    // Plaintext ops on a product that FLEXIBLEAUTO has not yet rescaled.
    let pp = be.mul_plain(&prod, &b).unwrap();
    close(
        &dec(&pp),
        &a.iter().zip(&b).map(|(x, y)| x * y * y).collect::<Vec<_>>(),
        1e-6,
    );
    let ap = be.add_plain(&prod, &a).unwrap();
    close(
        &dec(&ap),
        &a.iter().zip(&b).map(|(x, y)| x * y + x).collect::<Vec<_>>(),
        1e-6,
    );
    close(
        &dec(&be.add_const(&ca, 2.5).unwrap()),
        &a.iter().map(|x| x + 2.5).collect::<Vec<_>>(),
        1e-6,
    );
    close(
        &dec(&be.mul_const(&ca, -3.0).unwrap()),
        &a.iter().map(|x| -3.0 * x).collect::<Vec<_>>(),
        1e-6,
    );
    // Mixed levels.
    let mixed = be.add(&pp, &ca).unwrap();
    close(
        &dec(&mixed),
        &a.iter()
            .zip(&b)
            .map(|(x, y)| x * y * y + x)
            .collect::<Vec<_>>(),
        1e-6,
    );
    assert!(be.ciphertext_bytes(&ca).unwrap() > be.ciphertext_bytes(&pp).unwrap());
}

#[test]
fn rotation_is_cyclic_over_the_batch() {
    // Sparse packing: 8 slots in a ring with 2048+ slots.
    let params = select_params(1, 1.0, 1e-3, 8).unwrap();
    assert!(params.ring_dim / 2 > params.slots);
    let (be, sk) = OpenFheBackend::new(&params, &[1, 3, 7]).unwrap();
    let v: Vec<f64> = (0..8).map(|i| i as f64).collect();
    let ct = be.encrypt(&v).unwrap();
    for k in [1u32, 3, 7] {
        let got = be.decrypt(&sk, &be.rotate(&ct, k).unwrap()).unwrap();
        let want: Vec<f64> = (0..8).map(|i| ((i + k as usize) % 8) as f64).collect();
        close(&got, &want, 1e-5);
    }
    assert!(be.rotate(&ct, 2).is_err(), "no key for 2");
}

#[test]
fn secret_key_is_bound_to_its_context() {
    let params = select_params(1, 1.0, 1e-3, 4).unwrap();
    let (a, _sk_a) = OpenFheBackend::new(&params, &[]).unwrap();
    let (_b, sk_b) = OpenFheBackend::new(&params, &[]).unwrap();
    let ct = a.encrypt(&[1.0, 2.0, 3.0, 4.0]).unwrap();
    // A different key decrypts to noise, not to the plaintext.
    let wrong = a.decrypt(&sk_b, &ct);
    if let Ok(v) = wrong {
        assert!(
            (v[0] - 1.0).abs() > 1.0,
            "decrypted with the wrong key: {v:?}"
        );
    }
    assert!(a.encrypt(&[0.0; 3]).is_err(), "wrong slot count");
}

#[test]
fn veil_parameter_choice_matches_openfhe() {
    for depth in [1, 2, 3, 5, 7, 9, 12, 16, 20] {
        for (max_abs, precision) in [(1.0, 1e-3), (30.0, 1e-4), (1.0, 1e-6)] {
            let p = select_params(depth, max_abs, precision, 8).unwrap();
            let (n, log_qp) = openfhe_choice(&p).unwrap();
            assert_eq!(n, p.ring_dim, "depth {depth}, {p:?}");
            assert!(
                log_qp <= p.log_qp,
                "OpenFHE log QP {log_qp} > Veil estimate {}",
                p.log_qp
            );
        }
    }
}

#[test]
fn contexts_can_be_created_and_used_concurrently() {
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                let params = select_params(2, 4.0, 1e-3, 4).unwrap();
                let (be, sk) = OpenFheBackend::new(&params, &[1]).unwrap();
                let x = [i as f64, 1.0, 2.0, 3.0];
                let ct = be.encrypt(&x).unwrap();
                let r = be.rotate(&be.add(&ct, &ct).unwrap(), 1).unwrap();
                let out = be.decrypt(&sk, &r).unwrap();
                assert!((out[3] - 2.0 * i as f64).abs() < 1e-5);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
