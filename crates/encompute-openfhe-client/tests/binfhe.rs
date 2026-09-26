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
