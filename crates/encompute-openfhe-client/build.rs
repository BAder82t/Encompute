//! Compiles the client shim against the same OpenFHE install and shared
//! header as encompute-openfhe (which also links the OpenFHE libraries).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let shared =
        PathBuf::from(env::var("DEP_OPENFHEPKE_INCLUDE").expect("set by encompute-openfhe"));
    let root = PathBuf::from(env::var("DEP_OPENFHEPKE_ROOT").expect("set by encompute-openfhe"));
    let include = root.join("include/openfhe");

    let mut build = cxx_build::bridge("src/lib.rs");
    build
        .file("cpp/client.cc")
        .file("cpp/binclient.cc")
        .include("cpp")
        .include(&shared);
    for dir in ["", "core", "pke", "binfhe", "cereal"] {
        build.flag(format!("-isystem{}", include.join(dir).display()));
    }
    build
        .std("c++17")
        .define("MATHBACKEND", "4")
        .flag_if_supported("-Wno-unused-parameter");
    if cfg!(target_os = "macos") {
        let out = Command::new("brew")
            .args(["--prefix", "libomp"])
            .output()
            .expect("brew is required to locate libomp on macOS");
        let omp = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
        build
            .flag("-Xpreprocessor")
            .flag("-fopenmp")
            .include(omp.join("include"));
    } else {
        build.flag("-fopenmp");
    }
    build.compile("encompute_openfhe_client_shim");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cpp/client.h");
    println!("cargo:rerun-if-changed=cpp/client.cc");
    println!("cargo:rerun-if-changed=cpp/binclient.cc");
}
