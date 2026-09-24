use veil_openfhe::CkksContext;

#[test]
fn encrypted_add_matches_plaintext() {
    let ctx = CkksContext::new(1, 50, 8).unwrap();
    assert!(
        ctx.ring_dimension() >= 8192,
        "128-bit security needs N >= 2^13 here"
    );

    let a = [1.5, -2.25, 3.0, 0.0, 1e3, -1e-3, 7.0, 42.0];
    let b = [0.5, 2.25, -1.0, 9.0, 1e3, 1e-3, -7.0, 0.125];
    let sum = ctx
        .add(&ctx.encrypt(&a).unwrap(), &ctx.encrypt(&b).unwrap())
        .unwrap();
    let out = ctx.decrypt(&sum, a.len()).unwrap();

    for i in 0..a.len() {
        let err = (out[i] - (a[i] + b[i])).abs();
        assert!(err < 1e-6, "slot {i}: got {}, error {err}", out[i]);
    }
}

#[test]
fn encrypt_rejects_more_values_than_batch_size() {
    let ctx = CkksContext::new(1, 50, 4).unwrap();
    assert!(ctx.encrypt(&[0.0; 5]).is_err());
}

#[test]
fn contexts_can_be_created_and_used_concurrently() {
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                let ctx = CkksContext::new(2, 45, 4).unwrap();
                let x = [i as f64, 1.0, 2.0, 3.0];
                let ct = ctx.encrypt(&x).unwrap();
                let out = ctx.decrypt(&ctx.add(&ct, &ct).unwrap(), 4).unwrap();
                assert!((out[0] - 2.0 * i as f64).abs() < 1e-5);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
