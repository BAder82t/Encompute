//! OpenFHE client ↔ evaluator: arithmetic through serialized ciphertexts,
//! rotation under sparse packing, key and parameter binding, key-pair
//! restore, and concurrency.

use encompute_backend::{CkksClient, CkksEvaluator};
use encompute_ckks::{select_params, CkksParams};
use encompute_ir::Code;
use encompute_openfhe::OpenFheEvaluator;
use encompute_openfhe_client::OpenFheClient;

fn pair(params: &CkksParams, rotations: &[u32]) -> (OpenFheClient, OpenFheEvaluator) {
    let client = OpenFheClient::generate(params, rotations).unwrap();
    let mut ev = OpenFheEvaluator::new(params).unwrap();
    ev.load_keys(&client.evaluation_keys().unwrap()).unwrap();
    (client, ev)
}

fn close(a: &[f64], b: &[f64], tol: f64) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        assert!((x - y).abs() < tol, "slot {i}: {x} vs {y}");
    }
}

#[test]
fn arithmetic_through_serialized_ciphertexts() {
    let params = select_params(3, 4.0, 1e-3, 8).unwrap();
    let (client, ev) = pair(&params, &[1, 3]);
    let n = client.slots();
    let a: Vec<f64> = (0..n).map(|i| i as f64 / n as f64 - 0.5).collect();
    let b: Vec<f64> = (0..n).map(|i| 0.25 * (i as f64).cos()).collect();
    let load = |v: &[f64]| ev.load_ciphertext(&client.encrypt(v).unwrap()).unwrap();
    let dec = |c: &encompute_openfhe::OpenFheCiphertext| {
        client.decrypt(&ev.store_ciphertext(c).unwrap()).unwrap()
    };
    let (ca, cb) = (load(&a), load(&b));
    let zip = |f: fn(f64, f64) -> f64| a.iter().zip(&b).map(|(x, y)| f(*x, *y)).collect::<Vec<_>>();

    close(&dec(&ev.add(&ca, &cb).unwrap()), &zip(|x, y| x + y), 1e-6);
    close(&dec(&ev.sub(&ca, &cb).unwrap()), &zip(|x, y| x - y), 1e-6);
    close(
        &dec(&ev.neg(&ca).unwrap()),
        &a.iter().map(|x| -x).collect::<Vec<_>>(),
        1e-6,
    );
    let prod = ev.mul(&ca, &cb).unwrap();
    close(&dec(&prod), &zip(|x, y| x * y), 1e-6);
    close(
        &dec(&ev.mul_plain(&prod, &b).unwrap()),
        &zip(|x, y| x * y * y),
        1e-6,
    );
    close(
        &dec(&ev.add_plain(&prod, &a).unwrap()),
        &zip(|x, y| x * y + x),
        1e-6,
    );
    close(
        &dec(&ev.add_const(&ca, 2.5).unwrap()),
        &a.iter().map(|x| x + 2.5).collect::<Vec<_>>(),
        1e-6,
    );
    close(
        &dec(&ev.mul_const(&ca, -3.0).unwrap()),
        &a.iter().map(|x| -3.0 * x).collect::<Vec<_>>(),
        1e-6,
    );
    let mixed = ev.add(&ev.mul_plain(&prod, &b).unwrap(), &ca).unwrap();
    close(&dec(&mixed), &zip(|x, y| x * y * y + x), 1e-6);
}

#[test]
fn rotation_is_cyclic_over_the_batch() {
    let params = select_params(1, 8.0, 1e-3, 8).unwrap();
    assert!(params.ring_dim / 2 > params.slots, "sparse packing");
    let (client, ev) = pair(&params, &[1, 3, 7]);
    let v: Vec<f64> = (0..8).map(|i| i as f64).collect();
    let ct = ev.load_ciphertext(&client.encrypt(&v).unwrap()).unwrap();
    for k in [1u32, 3, 7] {
        let r = ev.rotate(&ct, k).unwrap();
        let got = client.decrypt(&ev.store_ciphertext(&r).unwrap()).unwrap();
        let want: Vec<f64> = (0..8).map(|i| ((i + k as usize) % 8) as f64).collect();
        close(&got, &want, 1e-5);
    }
    assert!(ev.rotate(&ct, 2).is_err(), "no key for 2");
}

#[test]
fn keys_and_parameters_are_bound() {
    let params = select_params(1, 4.0, 1e-3, 4).unwrap();
    let (a, ev_a) = pair(&params, &[]);
    let b = OpenFheClient::generate(&params, &[]).unwrap();

    // Ciphertext under b's key, evaluator holding only a's keys.
    let ct_b = b.encrypt(&[1.0, 2.0, 3.0, 4.0]).unwrap();
    assert_eq!(
        ev_a.load_ciphertext(&ct_b).err().unwrap().code,
        Code::WrongKey
    );
    // a cannot decrypt b's ciphertext.
    assert_eq!(a.decrypt(&ct_b).unwrap_err().code, Code::WrongKey);

    // Different parameter set.
    let other = select_params(2, 4.0, 1e-3, 4).unwrap();
    let ev_other = {
        let mut e = OpenFheEvaluator::new(&other).unwrap();
        assert!(
            e.load_keys(&a.evaluation_keys().unwrap()).is_err(),
            "keys for other params"
        );
        e
    };
    let ct_a = a.encrypt(&[1.0, 2.0, 3.0, 4.0]).unwrap();
    assert!(ev_other.load_ciphertext(&ct_a).is_err());

    // Garbage and truncation are errors, not crashes.
    assert!(ev_a.load_ciphertext(&ct_a[..ct_a.len() / 2]).is_err());
    assert!(ev_a.load_ciphertext(b"not a ciphertext").is_err());
    let mut e = OpenFheEvaluator::new(&params).unwrap();
    assert!(e.load_keys(b"junk").is_err());
    assert!(a.encrypt(&[0.0; 3]).is_err(), "wrong slot count");
}

#[test]
fn client_restores_from_its_secret_key() {
    let params = select_params(1, 4.0, 1e-3, 4).unwrap();
    let (client, ev) = pair(&params, &[1]);
    let secret = client.secret_key().unwrap();
    let ct = ev
        .rotate(
            &ev.load_ciphertext(&client.encrypt(&[1.0, 2.0, 3.0, 4.0]).unwrap())
                .unwrap(),
            1,
        )
        .unwrap();
    let out = ev.store_ciphertext(&ct).unwrap();
    drop(client);

    let restored = OpenFheClient::restore(&params, &secret).unwrap();
    close(
        &restored.decrypt(&out).unwrap(),
        &[2.0, 3.0, 4.0, 1.0],
        1e-5,
    );
    // A restored client still encrypts for the same evaluator.
    let again = ev
        .load_ciphertext(&restored.encrypt(&[5.0; 4]).unwrap())
        .unwrap();
    close(
        &restored
            .decrypt(&ev.store_ciphertext(&again).unwrap())
            .unwrap(),
        &[5.0; 4],
        1e-5,
    );
    assert!(OpenFheClient::restore(&params, &secret[..secret.len() - 7]).is_err());
}

#[test]
fn contexts_can_be_created_used_and_dropped_concurrently() {
    // Creation, evaluation and destruction interleaved across threads; every
    // one must hold the shim's lock. Values reach 2 * 15 = 30, so parameters
    // are sized for 40.
    let handles: Vec<_> = (0..16)
        .map(|i| {
            std::thread::spawn(move || {
                for round in 0..4 {
                    let params = select_params(2, 40.0, 1e-3, 4).unwrap();
                    let (client, ev) = pair(&params, &[1]);
                    let ct = ev
                        .load_ciphertext(
                            &client.encrypt(&[i as f64, round as f64, 2.0, 3.0]).unwrap(),
                        )
                        .unwrap();
                    let doubled = ev.add(&ct, &ct).unwrap();
                    drop(ct);
                    let r = ev.rotate(&doubled, 1).unwrap();
                    let out = client.decrypt(&ev.store_ciphertext(&r).unwrap()).unwrap();
                    assert!(
                        (out[3] - 2.0 * i as f64).abs() < 1e-5,
                        "thread {i}: {out:?}"
                    );
                    // Drop order varies: evaluator first half the time.
                    if round % 2 == 0 {
                        drop(ev);
                        drop(client);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
