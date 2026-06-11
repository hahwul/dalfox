//! interactsh session crypto: RSA-2048 keypair, the base64(PEM) public key the
//! `/register` endpoint expects, RSA-OAEP(SHA-256) unwrap of the per-poll AES
//! key, and AES-256-CTR decryption of each interaction blob.
//!
//! `rsa` 0.9 is built against the `digest`/`sha2` 0.10 line, so the OAEP digest
//! comes from the aliased `sha2_oaep` crate (`sha2` 0.10). The rest of dalfox
//! keeps using `sha2` 0.11 for response fingerprinting; the two coexist.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2_oaep::Sha256;

type CryptoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// RSA key material for one OOB session.
pub struct SessionKeys {
    private: RsaPrivateKey,
    /// base64(PEM(SPKI)) of the public key — the exact form interactsh sends in
    /// `/register`. interactsh wraps the SPKI DER in a PEM block and ignores the
    /// block label on the server side, so the standard `PUBLIC KEY` label is fine.
    pub public_key_b64: String,
}

impl SessionKeys {
    /// Generate a fresh RSA-2048 keypair and pre-compute the base64 PEM public key.
    pub fn generate() -> CryptoResult<SessionKeys> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048)?;
        let public = RsaPublicKey::from(&private);
        let pem = public.to_public_key_pem(LineEnding::LF)?;
        let public_key_b64 = B64.encode(pem.as_bytes());
        Ok(SessionKeys {
            private,
            public_key_b64,
        })
    }

    /// Decrypt the RSA-OAEP(SHA-256) wrapped AES key from a poll response.
    pub fn decrypt_aes_key(&self, wrapped_b64: &str) -> CryptoResult<Vec<u8>> {
        let ct = B64.decode(wrapped_b64.trim())?;
        let key = self.private.decrypt(Oaep::new::<Sha256>(), &ct)?;
        Ok(key)
    }
}

/// Decrypt one interactsh `data` entry: base64 → `[16-byte IV][AES-256-CTR ct]`.
pub fn decrypt_interaction(aes_key: &[u8], data_b64: &str) -> CryptoResult<Vec<u8>> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

    let blob = B64.decode(data_b64.trim())?;
    if blob.len() < 16 {
        return Err("interaction ciphertext shorter than the 16-byte IV".into());
    }
    let (iv, ciphertext) = blob.split_at(16);
    let mut buf = ciphertext.to_vec();
    // `new_from_slices` validates key length (32) and IV length (16).
    let mut cipher =
        Aes256Ctr::new_from_slices(aes_key, iv).map_err(|_| "invalid AES-256-CTR key/IV length")?;
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;

    // Mirror the interactsh server side: encrypt a random AES key to the
    // client's public key with RSA-OAEP(SHA-256), then AES-256-CTR-encrypt a
    // payload as `base64(IV ‖ ciphertext)`. The client must recover both.
    fn server_encrypt(
        public_key_pem_b64: &str,
        aes_key: &[u8],
        plaintext: &[u8],
    ) -> (String, String) {
        use ctr::cipher::{KeyIvInit, StreamCipher};
        type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

        let pem_bytes = B64.decode(public_key_pem_b64).unwrap();
        let pem = String::from_utf8(pem_bytes).unwrap();
        let pubkey = RsaPublicKey::from_public_key_pem(&pem).unwrap();

        let mut rng = OsRng;
        let wrapped = pubkey
            .encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key)
            .unwrap();
        let aes_key_b64 = B64.encode(&wrapped);

        let iv = [7u8; 16];
        let mut buf = plaintext.to_vec();
        let mut cipher = Aes256Ctr::new_from_slices(aes_key, &iv).unwrap();
        cipher.apply_keystream(&mut buf);
        let mut blob = iv.to_vec();
        blob.extend_from_slice(&buf);
        (aes_key_b64, B64.encode(&blob))
    }

    #[test]
    fn oaep_and_ctr_round_trip() {
        let keys = SessionKeys::generate().expect("keygen");
        let aes_key = [0x42u8; 32];
        let plaintext = br#"{"protocol":"http","full-id":"abc"}"#;
        let (aes_key_b64, data_b64) = server_encrypt(&keys.public_key_b64, &aes_key, plaintext);

        let recovered_key = keys.decrypt_aes_key(&aes_key_b64).expect("unwrap aes key");
        assert_eq!(recovered_key, aes_key);

        let recovered = decrypt_interaction(&recovered_key, &data_b64).expect("decrypt data");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn short_ciphertext_is_rejected() {
        let err = decrypt_interaction(&[0u8; 32], &B64.encode([1u8, 2, 3]));
        assert!(err.is_err());
    }
}
