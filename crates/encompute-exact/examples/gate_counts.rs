//! Bootstrapped gates per operation on a bit-level backend (OpenFHE exact),
//! by width: `cargo run --release -p encompute-exact --example gate_counts`.
//! Counts are data-independent; multiply by the measured time per gate
//! (docs/benchmarks.md) for an estimate.

use encompute_backend::ExactEvaluator;
use encompute_exact::bits::{plain_word, BitEvaluator, PlainGates, Word};
use encompute_ir::{CmpOp, Elem, LogicOp};

type Op = fn(&BitEvaluator<PlainGates>, &Word<bool>, &Word<bool>) -> Word<bool>;

fn main() {
    let ops: [(&str, Op); 12] = [
        ("add", |e, a, b| e.add(a, b).unwrap()),
        ("sub", |e, a, b| e.sub(a, b).unwrap()),
        ("mul", |e, a, b| e.mul(a, b).unwrap()),
        ("mul by constant 100", |e, a, _| {
            e.mul_scalar(a, 100).unwrap()
        }),
        ("div by constant 7", |e, a, _| e.div_scalar(a, 7).unwrap()),
        ("lt constant", |e, a, _| {
            e.cmp_scalar(CmpOp::Lt, a, 100).unwrap()
        }),
        ("eq", |e, a, b| e.cmp(CmpOp::Eq, a, b).unwrap()),
        ("lt", |e, a, b| e.cmp(CmpOp::Lt, a, b).unwrap()),
        ("min", |e, a, b| e.min(a, b).unwrap()),
        ("select", |e, a, b| {
            let c = e.cmp(CmpOp::Lt, a, b).unwrap();
            e.select(&c, a, b).unwrap()
        }),
        ("and (bitwise)", |e, a, b| {
            e.logic(LogicOp::And, a, b).unwrap()
        }),
        ("shift left 3", |e, a, _| e.shift(a, true, 3).unwrap()),
    ];
    let widths = [Elem::U8, Elem::U16, Elem::U32, Elem::I32, Elem::U64];
    print!("| operation |");
    for w in widths {
        print!(" {w} |");
    }
    println!("\n|---|{}", "---:|".repeat(widths.len()));
    for (name, op) in ops {
        print!("| {name} |");
        for w in widths {
            let ev = BitEvaluator::new(PlainGates);
            let (a, b) = (plain_word(w, 3), plain_word(w, 5));
            let before = ev.gate_count();
            op(&ev, &a, &b);
            let n = ev.gate_count() - before;
            // `select` also counts its comparison; report the select alone.
            let n = if name == "select" {
                let c = BitEvaluator::new(PlainGates);
                c.cmp(CmpOp::Lt, &a, &b).unwrap();
                n - c.gate_count()
            } else {
                n
            };
            print!(" {n} |");
        }
        println!();
    }
}
