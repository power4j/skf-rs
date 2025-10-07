use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let src_path = manifest_dir.join("c_src").join("src");
    let include_path = manifest_dir.join("c_src").join("include");

    let c_source_file = src_path.join("skf_stub.c");
    let c_def_file = src_path.join("skf_stub.def");

    let skf_header_file = include_path.join("skf.h");
    let sgd_header_file = include_path.join("sgd.h");

    let mut build = cc::Build::new();
    build.define("SKF_HAS_ECCDECRYPT", "1");

    build.file(&c_source_file);
    build.include(&include_path); // cc::Build 也能接受 PathBuf

    if cfg!(target_os = "windows") {
        let def_abs_path = c_def_file.to_string_lossy().to_string();

        let def_link_arg = format!("/DEF:{}", def_abs_path);

        println!("cargo:rustc-link-arg={}", def_link_arg);
        println!("cargo:rerun-if-changed={}", c_def_file.display());
    }

    build.compile("skf_abi_stub_c_static");

    println!("cargo:rerun-if-changed={}", c_source_file.display());
    println!("cargo:rerun-if-changed={}", skf_header_file.display());
    println!("cargo:rerun-if-changed={}", sgd_header_file.display());
}
