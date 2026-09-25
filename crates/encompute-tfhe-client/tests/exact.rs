//! TFHE-rs executes exact plans with results equal to the clear reference.
//! `ENCOMPUTE_EXACT_CASES=1000` runs the flagship on 1000 random inputs.
#![cfg(feature = "tfhe-rs")]

use encompute_backend::{ExactClient, ExactEvaluator};
use encompute_exact::{compile, evaluate_exact};
use encompute_ir::{evaluate, Builder, CmpOp, Elem, Inputs, LogicOp, Program, Range};
use encompute_tfhe::tfhe_rs::TfheRsEvaluator;
use encompute_tfhe_client::TfheRsClient;

fn approve() -> Program {
    let mut b = Builder::new("approve", 1e-3).unwrap();
    let age = b
        .input_exact("age", Elem::U8, Some(Range::new(0.0, 120.0)))
        .unwrap();
    let income = b
        .input_exact("income", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let debt = b
        .input_exact("debt", Elem::U32, Some(Range::new(0.0, 1e6)))
        .unwrap();
    let risk = b
        .input_exact("risk", Elem::U16, Some(Range::new(0.0, 1000.0)))
        .unwrap();
    let c18 = b.constant_exact(Elem::U8, 18.0).unwrap();
    let c100 = b.constant_exact(Elem::U32, 100.0).unwrap();
    let c35 = b.constant_exact(Elem::U32, 35.0).unwrap();
    let c650 = b.constant_exact(Elem::U16, 650.0).unwrap();
    let adult = b.cmp(CmpOp::Ge, age, c18).unwrap();
    let d = b.mul(debt, c100).unwrap();
    let i = b.mul(income, c35).unwrap();
    let ok_debt = b.cmp(CmpOp::Lt, d, i).unwrap();
    let ok_risk = b.cmp(CmpOp::Lt, risk, c650).unwrap();
    let x = b.logic(LogicOp::And, adult, ok_debt).unwrap();
    let x = b.logic(LogicOp::And, x, ok_risk).unwrap();
    b.output("approved", x).unwrap();
    b.finish().unwrap()
}

/// Every exact op on one type, with outputs for each.
fn coverage(elem: Elem) -> Program {
    let signed = elem.is_signed();
    let (lo, hi) = if signed {
        (-100.0, 100.0)
    } else {
        (0.0, 200.0)
    };
    let mut b = Builder::new("cov", 1e-3).unwrap();
    let x = b.input_exact("x", elem, Some(Range::new(lo, hi))).unwrap();
    let y = b.input_exact("y", elem, Some(Range::new(lo, hi))).unwrap();
    let wide = if signed { Elem::I32 } else { Elem::U32 };
    let xw = b.cast(x, wide).unwrap();
    let yw = b.cast(y, wide).unwrap();
    let k3 = b.constant_exact(wide, 3.0).unwrap();
    let k7 = b.constant_exact(wide, 7.0).unwrap();
    let mut outs = vec![];
    outs.push(("add", b.add(xw, yw).unwrap()));
    // Unsigned differences are offset so they cannot go negative (ENC1303).
    let k500 = b.constant_exact(wide, 500.0).unwrap();
    let xo = if signed { xw } else { b.add(xw, k500).unwrap() };
    outs.push(("sub", b.sub(xo, yw).unwrap()));
    outs.push(("mul", b.mul(xw, yw).unwrap()));
    outs.push(("mulc", b.mul(xw, k3).unwrap()));
    outs.push(("csub", b.sub(k500, xw).unwrap()));
    outs.push(("div", b.div(xw, k7).unwrap()));
    outs.push(("rem", b.rem(xw, k7).unwrap()));
    outs.push(("min", b.min(xw, yw).unwrap()));
    outs.push(("max", b.max(xw, yw).unwrap()));
    outs.push(("and", b.logic(LogicOp::And, xw, yw).unwrap()));
    outs.push(("xor", b.logic(LogicOp::Xor, xw, yw).unwrap()));
    outs.push(("shl", b.shift(xw, true, 2).unwrap()));
    outs.push(("shr", b.shift(xw, false, 1).unwrap()));
    if signed {
        outs.push(("neg", b.neg(xw).unwrap()));
    } else {
        outs.push(("not", b.not(x).unwrap()));
    }
    let lt = b.cmp(CmpOp::Lt, x, y).unwrap();
    let eq = b.cmp(CmpOp::Eq, x, y).unwrap();
    let ge = b.cmp(CmpOp::Ge, xw, k7).unwrap();
    outs.push(("lt", lt));
    outs.push(("eq", eq));
    outs.push(("ge", ge));
    outs.push(("or", b.logic(LogicOp::Or, lt, eq).unwrap()));
    outs.push(("nlt", b.not(lt).unwrap()));
    outs.push(("sel", b.select(lt, xw, k7).unwrap()));
    let from_bool = b.cast(lt, Elem::U8).unwrap();
    outs.push(("b2i", from_bool));
    // Lookup: index |x| mod 16 into a table with negative entries.
    let k16 = b.constant_exact(wide, 16.0).unwrap();
    let r = b.rem(xw, k16).unwrap();
    let idx = if signed {
        let k15 = b.constant_exact(wide, 15.0).unwrap();
        b.add(r, k15).unwrap()
    } else {
        r
    };
    let table: Vec<f64> = (0..31)
        .map(|i| ((i * 13) % 29) as f64 - if signed { 10.0 } else { 0.0 })
        .collect();
    outs.push(("lut", b.lookup(idx, table).unwrap()));
    for (n, v) in outs {
        b.output(n, v).unwrap();
    }
    b.finish().unwrap()
}

fn run(client: &TfheRsClient, ev: &TfheRsEvaluator, p: &Program, inputs: &Inputs) -> Inputs {
    let c = compile(p).unwrap();
    let cts = c
        .plan
        .inputs
        .iter()
        .map(|i| {
            ev.load(
                i.elem,
                &client.encrypt(i.elem, inputs[&i.name][0] as i128).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let outs = evaluate_exact(ev, &c.plan, cts).unwrap();
    c.plan
        .outputs
        .iter()
        .zip(outs)
        .map(|(o, ct)| {
            let v = client
                .decrypt(o.elem, &ev.store(&ct).unwrap())
                .unwrap_or_else(|e| panic!("output {} ({}): {e}", o.name, o.elem));
            (o.name.clone(), vec![v as f64])
        })
        .collect()
}

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 33
}

#[test]
fn tfhe_rs_equals_clear_reference() {
    let client = TfheRsClient::generate().unwrap();
    let keys = client.evaluation_keys().unwrap();
    let ev = TfheRsEvaluator::new(&keys).unwrap();
    eprintln!("compressed server key: {} MiB", keys.len() >> 20);

    // Operator coverage at boundaries, unsigned and signed.
    for elem in [Elem::U8, Elem::I16] {
        let p = coverage(elem);
        let (lo, hi) = if elem.is_signed() {
            (-100, 100)
        } else {
            (0, 200)
        };
        for (x, y) in [
            (lo, hi),
            (hi, lo),
            (0, 0),
            (lo, lo),
            (37, (-3i64).max(lo)),
            (hi, 5),
        ] {
            let inputs: Inputs = [("x", x), ("y", y)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), vec![v as f64]))
                .collect();
            assert_eq!(
                run(&client, &ev, &p, &inputs),
                evaluate(&p, &inputs).unwrap(),
                "{elem} x={x} y={y}"
            );
        }
    }

    // Flagship on random and boundary inputs.
    let cases: usize = std::env::var("ENCOMPUTE_EXACT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let p = approve();
    let mut s = 42u64;
    let (mut yes, mut no) = (0, 0);
    for case in 0..cases {
        let v = |s: &mut u64, hi: u64| match case {
            0 => 0,
            1 => hi,
            _ => lcg(s) % (hi + 1),
        } as f64;
        let inputs: Inputs = [
            ("age", v(&mut s, 120)),
            ("income", v(&mut s, 1_000_000)),
            ("debt", v(&mut s, 400_000)),
            ("risk", v(&mut s, 1000)),
        ]
        .into_iter()
        .map(|(k, x)| (k.to_string(), vec![x]))
        .collect();
        let got = run(&client, &ev, &p, &inputs);
        let want = evaluate(&p, &inputs).unwrap();
        assert_eq!(got, want, "case {case}: {inputs:?}");
        if want["approved"][0] == 1.0 {
            yes += 1
        } else {
            no += 1
        }
    }
    eprintln!("flagship: {cases} cases exact ({yes} approved, {no} rejected)");
}

#[test]
fn malformed_keys_and_ciphertexts_fail_closed() {
    assert!(TfheRsEvaluator::new(b"not a server key").is_err());
    assert!(TfheRsClient::restore(b"not a client key").is_err());
    let client = TfheRsClient::generate().unwrap();
    let ev = TfheRsEvaluator::new(&client.evaluation_keys().unwrap()).unwrap();
    let ct = client.encrypt(Elem::U32, 7).unwrap();
    assert!(
        ev.load(Elem::U32, &ct[..ct.len() / 2]).is_err(),
        "truncated"
    );
    assert!(ev.load(Elem::U8, &ct).is_err(), "wrong type");
    assert!(ev.load(Elem::U32, b"garbage").is_err());
    let restored = TfheRsClient::restore(&client.secret_key().unwrap()).unwrap();
    assert_eq!(restored.decrypt(Elem::U32, &ct).unwrap(), 7);
    assert!(
        restored.evaluation_keys().is_err(),
        "restored client does not re-export keys"
    );
}
