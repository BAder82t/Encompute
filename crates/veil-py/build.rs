fn main() {
    // Lets `cargo build`/`cargo test` link the extension module on macOS
    // (maturin passes these itself).
    pyo3_build_config::add_extension_module_link_args();
}
