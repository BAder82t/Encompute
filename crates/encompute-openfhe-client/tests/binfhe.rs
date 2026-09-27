//! OpenFHE BinFHE through the client and evaluator shims: every gate's truth
//! table, NOT, constants, parameter and key checks.

use encompute_openfhe::binfhe::{BinContext, Gate};
use encompute_openfhe_client::BinClient;

#[test]
fn gates_match_their_truth_tables() {
    let t = std::time::Instant::now();
    let client = BinClient::generate("STD128").unwrap();
    let keygen = t.elapsed();
    let (refresh, switching) = client.bootstrapping_keys().unwrap();
    let mut ctx = BinContext::new("STD128").unwrap();
    ctx.load_keys(&refresh, &switching).unwrap();
    let enc = |b: bool| ctx.load(&client.encrypt_bit(b).unwrap()).unwrap();
    let dec = |c: &encompute_openfhe::binfhe::BinCiphertext| {
        client.decrypt_bit(&c.store().unwrap()).unwrap()
    };
    let t = std::time::Instant::now();
    let mut gates = 0;
    for (g, f) in [
        (Gate::And, (|a, b| a & b) as fn(bool, bool) -> bool),
        (Gate::Or, |a, b| a | b),
        (Gate::Xor, |a, b| a ^ b),
        (Gate::Nand, |a, b| !(a & b)),
        (Gate::Nor, |a, b| !(a | b)),
        (Gate::Xnor, |a, b| !(a ^ b)),
    ] {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    dec(&ctx.gate(g, &enc(a), &enc(b)).unwrap()),
                    f(a, b),
                    "{g:?} {a} {b}"
                );
                gates += 1;
            }
        }
    }
    let per_gate = t.elapsed() / gates;
    for a in [false, true] {
        assert_eq!(dec(&ctx.not(&enc(a)).unwrap()), !a);
        assert_eq!(dec(&ctx.constant(a).unwrap()), a);
        // A gate on a constant.
        assert_eq!(
            dec(&ctx
                .gate(Gate::And, &ctx.constant(true).unwrap(), &enc(a))
                .unwrap()),
            a
        );
    }
    eprintln!(
        "BinFHE STD128/GINX: keygen {keygen:?}, {per_gate:?} per gate (incl. encrypt/decrypt), \
         refresh key {} MB, switching key {} MB, ciphertext {} bytes",
        refresh.len() / 1_000_000,
        switching.len() / 1_000_000,
        client.encrypt_bit(true).unwrap().len()
    );
    // A restored client decrypts the same ciphertexts.
    let restored = BinClient::restore("STD128", &client.secret_key().unwrap()).unwrap();
    assert!(restored
        .decrypt_bit(&client.encrypt_bit(true).unwrap())
        .unwrap());
    // Another parameter set's ciphertext is refused.
    let other = BinClient::generate("STD128Q").unwrap();
    let e = ctx.load(&other.encrypt_bit(true).unwrap()).err().unwrap();
    assert_eq!(e.code, encompute_ir::Code::WrongParameters);
    assert!(ctx.load(b"garbage").is_err());
}

#[test]
#[ignore]
fn measure_paramsets() {
    for ps in ["STD128", "STD128_LMKCDEY"] {
        let client = BinClient::generate(ps).unwrap();
        let (refresh, switching) = client.bootstrapping_keys().unwrap();
        let mut ctx = BinContext::new(ps).unwrap();
        ctx.load_keys(&refresh, &switching).unwrap();
        let a = ctx.load(&client.encrypt_bit(true).unwrap()).unwrap();
        let b = ctx.load(&client.encrypt_bit(false).unwrap()).unwrap();
        let t = std::time::Instant::now();
        let mut c = ctx.gate(Gate::Xor, &a, &b).unwrap();
        for _ in 0..20 {
            c = ctx.gate(Gate::And, &c, &a).unwrap();
        }
        assert!(client.decrypt_bit(&c.store().unwrap()).unwrap());
        eprintln!(
            "{ps}: {:?}/gate, refresh {} MB, switching {} MB",
            t.elapsed() / 21,
            refresh.len() / 1_000_000,
            switching.len() / 1_000_000
        );
    }
}

/// A gate whose two operands are the same ciphertext (`x & x`, `x ^ x`,
/// which programs like `x * x` produce): OpenFHE refuses those; the shim
/// answers by the gate's identities.
/// The vetted profile's claims ("128-bit", "2^-135 per gate") are OpenFHE's
/// published STD128 set; this pins the context to that set's LWE
/// parameters (binfhecontext.cpp, OpenFHE 1.5.1: n = 556, q = 2048), so a
/// different OpenFHE build or parameter table cannot silently change them.
#[test]
fn std128_context_has_the_vetted_lwe_parameters() {
    let ctx = BinContext::new("STD128").unwrap();
    assert_eq!(ctx.lwe().unwrap(), (556, 2048));
}

#[test]
fn gates_on_one_ciphertext_twice() {
    let client = BinClient::generate("STD128").unwrap();
    let (refresh, switching) = client.bootstrapping_keys().unwrap();
    let mut ctx = BinContext::new("STD128").unwrap();
    ctx.load_keys(&refresh, &switching).unwrap();
    for x in [false, true] {
        let c = ctx.load(&client.encrypt_bit(x).unwrap()).unwrap();
        let dec = |r: encompute_openfhe::binfhe::BinCiphertext| {
            client.decrypt_bit(&r.store().unwrap()).unwrap()
        };
        assert_eq!(dec(ctx.gate(Gate::And, &c, &c).unwrap()), x);
        assert_eq!(dec(ctx.gate(Gate::Or, &c, &c).unwrap()), x);
        assert_eq!(dec(ctx.gate(Gate::Nand, &c, &c).unwrap()), !x);
        assert_eq!(dec(ctx.gate(Gate::Nor, &c, &c).unwrap()), !x);
        assert!(!dec(ctx.gate(Gate::Xor, &c, &c).unwrap()));
        assert!(dec(ctx.gate(Gate::Xnor, &c, &c).unwrap()));
    }
}

/// Concurrent gates: throughput by thread count, and every result equal to
/// the plaintext truth (run with --ignored --nocapture).
#[test]
#[ignore]
fn measure_concurrent_gates() {
    use std::sync::Arc;
    let client = BinClient::generate("STD128").unwrap();
    let (refresh, switching) = client.bootstrapping_keys().unwrap();
    let mut ctx = BinContext::new("STD128").unwrap();
    ctx.load_keys(&refresh, &switching).unwrap();
    let ctx = Arc::new(ctx);
    let bits: Vec<bool> = (0..64).map(|i| (i * 7 + 3) % 5 < 2).collect();
    let cts: Arc<Vec<_>> = Arc::new(
        bits.iter()
            .map(|b| ctx.load(&client.encrypt_bit(*b).unwrap()).unwrap())
            .collect(),
    );
    ctx.gate(Gate::And, &cts[0], &cts[1]).unwrap();
    let n = 64;
    for threads in [1usize, 2, 4, 8] {
        let t = std::time::Instant::now();
        let per = n / threads;
        let outs: Vec<(usize, Vec<encompute_openfhe::binfhe::BinCiphertext>)> =
            std::thread::scope(|s| {
                (0..threads)
                    .map(|w| {
                        let (ctx, cts) = (ctx.clone(), cts.clone());
                        s.spawn(move || {
                            encompute_openfhe::binfhe::worker_init();
                            let mut v = vec![];
                            for i in w * per..(w + 1) * per {
                                let g = [Gate::And, Gate::Or, Gate::Xor, Gate::Nand][i % 4];
                                v.push(
                                    ctx.gate_concurrent(g, &cts[i], &cts[(i + 1) % 64]).unwrap(),
                                );
                            }
                            (w, v)
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect()
            });
        let secs = t.elapsed().as_secs_f64();
        for (w, v) in outs {
            for (k, c) in v.iter().enumerate() {
                let i = w * per + k;
                let (a, b) = (bits[i], bits[(i + 1) % 64]);
                let want = match i % 4 {
                    0 => a & b,
                    1 => a | b,
                    2 => a ^ b,
                    _ => !(a & b),
                };
                assert_eq!(
                    client.decrypt_bit(&c.store().unwrap()).unwrap(),
                    want,
                    "gate {i}"
                );
            }
        }
        eprintln!(
            "{threads} threads: {n} gates in {secs:.2}s = {:.1} ms/gate",
            secs * 1000.0 / n as f64
        );
    }
}
