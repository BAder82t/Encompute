//! Child process for crash injection and multi-process races:
//!
//! `assurance-helper release <dir> <round> <asset=epsilon>...` runs one DP
//! release (see `encompute_assurance::checks::privacy::spec`) and, only
//! after it returns, writes `<dir>/out-<round>.json`. Exit 0 on success, 3
//! on a refused release. With `ENCOMPUTE_FAILPOINT` set, the privacy crate
//! aborts at that point (built with its `failpoints` feature).

use encompute_assurance::checks::privacy::{key, spec, VECTOR_LEN};
use encompute_privacy::{release, Csprng};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 || args[0] != "release" {
        eprintln!("usage: assurance-helper release <dir> <round> <asset=epsilon>...");
        std::process::exit(2);
    }
    let dir = std::path::PathBuf::from(&args[1]);
    let round: u64 = args[2].parse().expect("round");
    let assets: Vec<(String, f64)> = args[3..]
        .iter()
        .map(|a| {
            let (n, e) = a.split_once('=').expect("asset=epsilon");
            (n.to_owned(), e.parse().expect("epsilon"))
        })
        .collect();
    let refs: Vec<(&str, f64)> = assets.iter().map(|(n, e)| (n.as_str(), *e)).collect();
    let mut rng = Csprng::from_os().expect("randomness");
    match release(
        &spec(round, &refs),
        &dir,
        &[1; VECTOR_LEN],
        &mut rng,
        &key(),
    ) {
        Ok(out) => {
            std::fs::write(
                dir.join(format!("out-{round}.json")),
                serde_json::to_vec(&out.noisy).expect("json"),
            )
            .expect("write output");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(3);
        }
    }
}
