//! TFHE-rs spike: keygen, encrypt u32, compare, select, serialize, decrypt.
#![cfg(feature = "research-tfhe-rs")]

use std::time::Instant;

use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint32ConformanceParams,
    ServerKey,
};

#[test]
fn full_path_u32_compare_select() {
    let t = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let keygen = t.elapsed();

    // Evaluation key crosses to the evaluator as bytes.
    let mut sk_bytes = vec![];
    tfhe::safe_serialization::safe_serialize(&server_key, &mut sk_bytes, 1 << 32).unwrap();
    // The evaluator checks the key conforms to the expected parameters.
    let server_key: ServerKey = tfhe::safe_serialization::DeserializationConfig::new(1 << 32)
        .deserialize_from(sk_bytes.as_slice(), &config.into())
        .unwrap();
    let ct_params = FheUint32ConformanceParams::from(&server_key);
    set_server_key(server_key);

    let (debt, income) = (20_000u32, 100_000u32);
    let enc = |v: u32| {
        let ct = FheUint32::encrypt(v, &client_key);
        let mut b = vec![];
        tfhe::safe_serialization::safe_serialize(&ct, &mut b, 1 << 26).unwrap();
        b
    };
    let load = |b: &[u8]| -> FheUint32 {
        tfhe::safe_serialization::DeserializationConfig::new(1 << 26)
            .deserialize_from(b, &ct_params)
            .unwrap()
    };
    let (d, i) = (enc(debt), enc(income));
    let ct_bytes = d.len();

    let t = Instant::now();
    let (d, i) = (load(&d), load(&i));
    let lhs = &d * 100u32;
    let rhs = &i * 35u32;
    let ok: FheBool = lhs.lt(&rhs);
    let fee = ok.select(
        &FheUint32::encrypt_trivial(5u32),
        &FheUint32::encrypt_trivial(25u32),
    );
    let eval = t.elapsed();

    assert!(ok.decrypt(&client_key));
    let fee: u32 = fee.decrypt(&client_key);
    assert_eq!(fee, 5);
    eprintln!(
        "tfhe-rs 1.8.1: keygen {keygen:.2?}, server key {} MiB, u32 ciphertext {} KiB, 2 mul + lt + select {eval:.2?}",
        sk_bytes.len() >> 20,
        ct_bytes >> 10
    );
}
