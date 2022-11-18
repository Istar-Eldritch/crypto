/*!
Cryptography module using AES 256

### Usage

```rs
use crate::crypto::Crypto;

let key = String::from("whatever");
let crypto = Crypto::new(&key);

let original = String::from("Hello encryption");
let encrypted = crypto.encrypt(&original).unwrap();

let decrypted: String = crypto.decrypt(&encrypted).unwrap();
```

### Internals

SHA256 is used to calculate the cryptography key derived from input password.

#### Encryption

- A random Initialization Vector (IV) is generated.
- `bincode` is used to serialize the payload to encrypt as a `Vec<u8>`.
- The encrypted payload is stored along with the IV in a [`CryptoBlob`].
- The blob is then base64 encoded for convenience.

#### Decryption

- The [`CryptoBlob`] containing the IV and encrypted payload is decoded from its base64 format.
- The payload is then decryped into its binary representation.
- `bincode` is used to recover the original object from the deserialization of the binary payload.
*/

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, Rng,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Crytptographic tools to use in the cloud API
#[derive(Clone)]
pub struct Crypto {
    key: [u8; 32],
}

/// Final result of encrypting a string
#[derive(Serialize, Deserialize)]
pub struct CryptoBlob {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Crypto {
    /// Creates a new instance of crypto
    ///
    /// Hashes the key using sha-256 (256 bits) so it can be used for AES 256
    pub fn new(key: &str) -> Self {
        let hash = Sha256::digest(key.as_bytes());
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = hash[i];
        }
        Crypto { key }
    }

    /// Encrypts the message passed in using AES-256-CBC PKCS#7
    ///
    /// The resulting `String` is the base64 encoded representation of the encrypted blob.
    pub fn encrypt<T>(&self, msg: &T) -> Result<String, Box<dyn std::error::Error>>
    where
        T: Serialize,
    {
        let rng = thread_rng();

        // Generate an initialization vector of 16 bytes
        // https://en.wikipedia.org/wiki/Initialization_vector
        let iv: Vec<u8> = Standard.sample_iter(rng).take(16).collect();
        let cipher = Aes256Cbc::new_var(&self.key, &iv)?;
        let bytes = bincode::serialize(&msg)?;
        let ciphertext = cipher.encrypt_vec(&bytes);
        let blob = CryptoBlob { iv, ciphertext };
        let result = base64::encode(bincode::serialize(&blob)?);
        Ok(result)
    }

    /// Decrypts the message passed in using AES-256-CBC PKCS#7
    ///
    /// The message should be provided as a base64 encoded string.
    pub fn decrypt<T>(&self, msg: &str) -> Result<T, Box<dyn std::error::Error>>
    where
        T: DeserializeOwned,
    {
        let bytes = base64::decode(msg)?;
        let blob: CryptoBlob = bincode::deserialize(&bytes)?;
        let cipher = Aes256Cbc::new_var(&self.key, &blob.iv)?;

        let bytes_decrypted = cipher.decrypt_vec(&blob.ciphertext)?;
        let deserialized: T = bincode::deserialize(&bytes_decrypted)?;
        Ok(deserialized)
    }
}

/// Base64 encoded encrypted password

#[derive(sqlx::Type, PartialEq, serde_derive::Serialize, serde_derive::Deserialize, Clone)]
#[sqlx(transparent)]
pub struct EncryptedPassword(String);

impl fmt::Debug for EncryptedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<encrypted password>")
    }
}

/// Returns a random word from EFF with the first letter capitalized
fn gen_word() -> String {
    let mut word: Vec<char> = eff_wordlist::large::random_word().chars().collect();
    word[0] = word[0].to_uppercase().next().unwrap();
    word.into_iter().collect()
}

impl EncryptedPassword {
    /// Create an encrypted password from a plaintext string
    pub fn from_plaintext(
        password: String,
        crypto: &Crypto,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let encrypted = crypto.encrypt(&password)?;

        Ok(Self(encrypted))
    }

    /// Decrypt a password
    pub fn decrypt(&self, crypto: &Crypto) -> Result<String, Box<dyn std::error::Error>> {
        crypto.decrypt(&self.0)
    }

    /// Uses the [EFF wordlist] to generate a plaintext secure and user friendly password
    ///
    /// Example result: `LonelySparrow032`
    ///
    /// [EFF wordlist]: https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
    pub fn generate_plaintext() -> String {
        let first = gen_word();
        let second = gen_word();
        let mut rng = rand::thread_rng();
        let number: u32 = rng.gen_range(1..1000);
        format!("{}{}{:03}", first, second, number)
    }

    /// Generate an encrypted password
    ///
    /// The plaintext password is generated using an [EFF wordlist] to make it secure but memorable.
    ///
    /// [EFF wordlist]: https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
    pub fn generate(crypto: &Crypto) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_plaintext(Self::generate_plaintext(), crypto)
    }

    /// Create a dummy, unencrypted password for use as a placeholder in tests
    ///
    /// The inner "password" created by this method is an empty string.
    #[doc(hidden)]
    pub fn dummy() -> Self {
        Self(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let key = String::from("whatever");
        let crypto = Crypto::new(&key);

        let original = String::from("Hello encryption");
        let encrypted = crypto.encrypt(&original).unwrap();

        assert_ne!(original, encrypted);

        let decrypted: String = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn encrypt_decrypt_struct() {
        let key = String::from("whatever");
        let crypto = Crypto::new(&key);
        let original = String::from("Hello encryption");
        let encrypted = EncryptedPassword::from_plaintext(original.clone(), &crypto).unwrap();
        let decrypted = encrypted.decrypt(&crypto).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn dummy_password() {
        assert_eq!(EncryptedPassword::dummy(), EncryptedPassword(String::new()));
    }
}
