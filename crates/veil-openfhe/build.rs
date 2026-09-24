//! Compiles the C++ shim against the OpenFHE install at `$OPENFHE_ROOT`
//! (default: `<workspace>/.deps/openfhe`, created by scripts/install-openfhe.sh).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = env::var_os("OPENFHE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../.deps/openfhe"));
    let include = root.join("include/openfhe");
    let lib = root.join("lib");
    if !include.join("pke/openfhe.h").exists() || !lib.join("libOPENFHEpke_static.a").exists() {
        panic!(
            "static OpenFHE v1.5.1 not found at {}. Run scripts/install-openfhe.sh or set OPENFHE_ROOT.",
            root.display()
        );
    }

    let mut build = cxx_build::bridge("src/lib.rs");
    build.file("cpp/shim.cc").include("cpp");
    // -isystem: warnings in OpenFHE's own headers are not ours to fix.
    for dir in ["", "core", "pke", "binfhe", "cereal"] {
        build.flag(format!("-isystem{}", include.join(dir).display()));
    }
    build
        .std("c++17")
        .define("MATHBACKEND", "4")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-function");

    if cfg!(target_os = "macos") {
        let omp = brew_prefix("libomp");
        build
            .flag("-Xpreprocessor")
            .flag("-fopenmp")
            .include(omp.join("include"));
        println!(
            "cargo:rustc-link-search=native={}",
            omp.join("lib").display()
        );
        println!("cargo:rustc-link-lib=dylib=omp");
    } else {
        build.flag("-fopenmp");
        println!("cargo:rustc-link-lib=dylib=gomp");
    }
    build.compile("veil_openfhe_shim");

    // Static: every dependent binary, test and the Python extension links
    // OpenFHE in, with no rpath or DYLD/LD_LIBRARY_PATH setup.
    println!("cargo:rustc-link-search=native={}", lib.display());
    // pke references binfhe (scheme switching); order: dependents first.
    println!("cargo:rustc-link-lib=static=OPENFHEpke_static");
    println!("cargo:rustc-link-lib=static=OPENFHEbinfhe_static");
    println!("cargo:rustc-link-lib=static=OPENFHEcore_static");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cpp/shim.h");
    println!("cargo:rerun-if-changed=cpp/shim.cc");
    println!("cargo:rerun-if-env-changed=OPENFHE_ROOT");
}

fn brew_prefix(formula: &str) -> PathBuf {
    let out = Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .expect("brew is required to locate libomp on macOS");
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}
