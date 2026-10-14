//! `caching_sha2_password`, MySQL's login since 8.0 and its only one since
//! 9.0, which removed `mysql_native_password` (8.4 had it off unless the
//! server was started with it). Both ends: the client this crate logs in
//! with, and the far end its tests and the Playground serve.
//!
//! **The fast path.** The first answer is `SHA256(password) XOR
//! SHA256(SHA256(SHA256(password)) + nonce)`. A server that holds the
//! account's `SHA256(SHA256(password))` in its cache checks it and says so
//! with [`FAST_AUTH_SUCCESS`]; the OK follows.
//!
//! **The full path.** A server whose cache does not hold the account —
//! the first login after it started, after `FLUSH PRIVILEGES` — asks for
//! [`PERFORM_FULL_AUTHENTICATION`], and the password itself must reach it
//! unread on the way. Under TLS the client sends it as it is, NUL ended.
//! In the clear it asks for the server's RSA public key
//! ([`REQUEST_PUBLIC_KEY`]), and sends the NUL-ended password masked by XOR with
//! the nonce, encrypted to that key with OAEP padding over SHA-1, as MySQL
//! pads. A key asked for over the clear can be swapped on the way by
//! whoever can read the password otherwise; `tls = true` is the answer to
//! that, as MySQL's own `--get-server-public-key` documents.
//!
//! MySQL's to change, and so this crate's alone: the library holds the
//! protocol `MariaDB` and MySQL share, and nothing here reaches it.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use mariadb::{Authentication, Conversation, Result, Step, Verification, protocol_error};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// The plugin's name on the wire.
pub const CACHING_SHA2_PASSWORD: &str = "caching_sha2_password";
/// The client asks for the server's public key.
pub const REQUEST_PUBLIC_KEY: u8 = 0x02;
/// The server found the account in its cache and the answer right.
pub const FAST_AUTH_SUCCESS: u8 = 0x03;
/// The server wants the password itself.
pub const PERFORM_FULL_AUTHENTICATION: u8 = 0x04;
/// The size of the far end's key, as a MySQL server generates its own.
const KEY_BITS: usize = 2048;

/// The client's end.
#[derive(Clone, Copy, Debug, Default)]
pub struct CachingSha2Password;

/// `password` scrambled with `nonce`; empty for an empty password.
#[must_use]
pub fn scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let first = Sha256::digest(password.as_bytes());
    let second = Sha256::digest(first);
    let third = Sha256::new()
        .chain_update(second)
        .chain_update(nonce)
        .finalize();
    first.iter().zip(third.iter()).map(|(a, b)| a ^ b).collect()
}

/// `password` and its NUL.
fn ended(password: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(password.len() + 1);
    bytes.extend_from_slice(password.as_bytes());
    bytes.push(0);
    bytes
}

/// `bytes` masked by XOR with `nonce`, cycled: the NUL-ended password as it goes
/// inside the RSA envelope, and as it comes out again. An empty nonce
/// leaves them as they are.
fn masked(bytes: &[u8], nonce: &[u8]) -> Vec<u8> {
    if nonce.is_empty() {
        return bytes.to_vec();
    }
    bytes
        .iter()
        .zip(nonce.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// `password` for the server holding the public key `pem`: masked with
/// `nonce` and encrypted to the key with OAEP over SHA-1.
///
/// # Errors
/// Where `pem` is not an RSA public key, or the password is too long for
/// the key.
pub fn encrypt(pem: &[u8], password: &str, nonce: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem)
        .map_err(|_| protocol_error("the server's public key is not text"))?
        .trim_end_matches('\0');
    let key = RsaPublicKey::from_public_key_pem(text)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(text))
        .map_err(|e| protocol_error(format!("the server's public key: {e}")))?;
    let clear = masked(&ended(password), nonce);
    key.encrypt(&mut Random, Oaep::new::<sha1::Sha1>(), &clear)
        .map_err(|e| protocol_error(format!("encrypting the password: {e}")))
}

impl Authentication for CachingSha2Password {
    fn plugin(&self) -> &'static str {
        CACHING_SHA2_PASSWORD
    }

    fn first(&self, password: &str, nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(scramble(password, nonce))
    }

    fn more(&self, step: &Step<'_>) -> Result<Option<Vec<u8>>> {
        match step.data {
            [FAST_AUTH_SUCCESS] => Ok(None),
            [PERFORM_FULL_AUTHENTICATION] if step.guarded => Ok(Some(ended(step.password))),
            [PERFORM_FULL_AUTHENTICATION] => Ok(Some(vec![REQUEST_PUBLIC_KEY])),
            pem if pem.starts_with(b"-----BEGIN") => {
                encrypt(pem, step.password, step.nonce).map(Some)
            }
            other => Err(protocol_error(format!(
                "{CACHING_SHA2_PASSWORD} does not know the server's {} byte step",
                other.len()
            ))),
        }
    }
}

/// The far end's: an account cache, empty until the first full
/// authentication succeeds, and the key a client in the clear encrypts to.
/// Cloned transports share one, as a server's clients share its cache.
#[derive(Debug, Default)]
pub struct CachingSha2Cache {
    cached: AtomicBool,
}

impl CachingSha2Cache {
    /// The key this process's far ends hold, made the first time a client
    /// in the clear asks for it.
    fn key() -> &'static (RsaPrivateKey, String) {
        static KEY: OnceLock<(RsaPrivateKey, String)> = OnceLock::new();
        KEY.get_or_init(|| {
            let private = RsaPrivateKey::new(&mut Random, KEY_BITS).expect("an RSA key");
            let public = RsaPublicKey::from(&private)
                .to_public_key_pem(LineEnding::LF)
                .expect("a public key in PEM");
            (private, public)
        })
    }

    /// Whether the account has logged in fully since this far end started.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.cached.load(Ordering::Relaxed)
    }

    /// The password the client sent in full: as it is under TLS, out of
    /// the RSA envelope in the clear; `None` where it asked for no key.
    fn full(conversation: &mut Conversation<'_>, nonce: &[u8]) -> Result<Option<Vec<u8>>> {
        let sent = conversation.read()?;
        if conversation.guarded() {
            return Ok(Some(sent));
        }
        if sent != [REQUEST_PUBLIC_KEY] {
            return Ok(None);
        }
        let (private, public) = Self::key();
        conversation.more(public.as_bytes())?;
        let sealed = conversation.read()?;
        let Ok(opened) = private.decrypt(Oaep::new::<sha1::Sha1>(), &sealed) else {
            return Ok(None);
        };
        Ok(Some(masked(&opened, nonce)))
    }
}

impl Verification for CachingSha2Cache {
    fn plugin(&self) -> &'static str {
        CACHING_SHA2_PASSWORD
    }

    fn verify(
        &self,
        conversation: &mut Conversation<'_>,
        password: &str,
        nonce: &[u8],
        response: &[u8],
    ) -> Result<bool> {
        if response.is_empty() {
            return Ok(password.is_empty());
        }
        let right = scramble(password, nonce);
        if self.holds() && codec::constant_time::equal(&right, response) {
            conversation.more(&[FAST_AUTH_SUCCESS])?;
            return Ok(true);
        }
        conversation.more(&[PERFORM_FULL_AUTHENTICATION])?;
        let expected = ended(password);
        let proved = Self::full(conversation, nonce)?
            .is_some_and(|sent| codec::constant_time::equal(&sent, &expected));
        if proved {
            self.cached.store(true, Ordering::Relaxed);
        }
        Ok(proved)
    }
}

/// The operating system's random source, as RSA draws from it.
struct Random;

impl rsa::rand_core::RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(codec::random::array())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(codec::random::array())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        codec::random::fill(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> core::result::Result<(), rsa::rand_core::Error> {
        codec::random::fill(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for Random {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scramble_is_the_documented_one() {
        let nonce: Vec<u8> = (1..=20).collect();
        let scrambled = scramble("secret", &nonce);
        assert_eq!(scrambled.len(), 32);
        let first = Sha256::digest(b"secret");
        let mut salted = Sha256::digest(Sha256::digest(b"secret")).to_vec();
        salted.extend_from_slice(&nonce);
        let third = Sha256::digest(&salted);
        let expected: Vec<u8> = first.iter().zip(third.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(scrambled, expected);
        assert!(scramble("", &nonce).is_empty());
        assert_ne!(scramble("secret", &[0; 20]), scrambled, "another nonce");
    }

    #[test]
    fn the_password_goes_masked_inside_the_servers_key() {
        let (private, public) = CachingSha2Cache::key();
        let nonce = b"nonce-nonce-nonce-no";
        let sealed = encrypt(public.as_bytes(), "a password longer than its nonce", nonce)
            .expect("encrypted");
        let opened = private
            .decrypt(Oaep::new::<sha1::Sha1>(), &sealed)
            .expect("decrypted");
        assert_eq!(
            masked(&opened, nonce),
            b"a password longer than its nonce\0"
        );
        assert!(encrypt(b"-----BEGIN nothing", "x", nonce).is_err());
    }

    #[test]
    fn each_step_the_server_asks_for_is_answered() {
        let step = |data, guarded| Step {
            password: "secret",
            nonce: b"nonce-nonce-nonce-no",
            data,
            guarded,
        };
        let plugin = CachingSha2Password;
        assert_eq!(
            plugin.more(&step(&[FAST_AUTH_SUCCESS], false)).expect("ok"),
            None
        );
        assert_eq!(
            plugin
                .more(&step(&[PERFORM_FULL_AUTHENTICATION], true))
                .expect("tls"),
            Some(b"secret\0".to_vec())
        );
        assert_eq!(
            plugin
                .more(&step(&[PERFORM_FULL_AUTHENTICATION], false))
                .expect("key"),
            Some(vec![REQUEST_PUBLIC_KEY])
        );
        assert!(plugin.more(&step(&[9], false)).is_err());
    }
}
