use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = PathBuf::from(&out_dir).join("generated.rs");
    std::fs::write(&dest, "pub const VERSION: &str = \"1.0.0\";\n").unwrap();
    println!("cargo:rerun-if-changed=src/lib.rs");
}
