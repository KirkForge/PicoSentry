//! A clean Rust crate used as a baseline fixture.

/// Returns a greeting.
pub fn hello(name: &str) -> String {
    format!("hello, {}", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello("world"), "hello, world");
    }
}
