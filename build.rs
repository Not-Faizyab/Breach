use std::env;
use std::path::PathBuf;

fn main() {
    // Get the directory where the project is located
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_path = PathBuf::from(dir).join("lib");

    // Tell Cargo to tell rustc to tell the MSVC linker exactly where the folder is
    println!("cargo:rustc-link-search=native={}", lib_path.display());
}