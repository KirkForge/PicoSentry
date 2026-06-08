//! fernet-msg — small Fernet-encrypted message library.
//! This file legitimately uses the `fernet` crate for symmetric encryption.
//! It must NOT be flagged as a cross-ecosystem supply-chain payload — it has
//! no marker constant, no payload filename, and no XOR key string.

use fernet::{Fernet, Key};

pub fn encrypt(key: &str, plaintext: &str) -> Result<String, fernet::DecryptError> {
    let k = Key::new(key.as_bytes());
    let f = Fernet::new(&k).expect("valid key");
    Ok::Ok(f.encrypt(plaintext.as_bytes()))
}

pub fn decrypt(key: &str, token: &str) -> Result<String, fernet::DecryptError> {
    let k = Key::new(key.as_bytes());
    let f = Fernet::new(&k).expect("valid key");
    f.decrypt(token)
}
