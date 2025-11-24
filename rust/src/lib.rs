use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use openssl::symm::{decrypt as openssl_decrypt, encrypt as openssl_encrypt, Cipher};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

const PRIV_KEY_LEN: usize = 32;
const PUB_KEY_PREFIXED_LEN: usize = 33;
const PUB_KEY_RAW_LEN: usize = 32;
const AES_KEY_LEN: usize = 32;
const AES_IV_LEN: usize = 16;
const HMAC_LEN: usize = 32;

#[napi]
pub fn generate_registration_id() -> Result<u16> {
    let mut osrng = rand::rng();
    let mut buf = [0u8; 2];
    osrng.fill_bytes(&mut buf);
    let val = u16::from_le_bytes(buf) & 0x3fff;
    Ok(val)
}

#[napi(object)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
}

#[napi]
pub fn generate_signed_pre_key(
    identity_priv: &[u8],
    identity_pub: &[u8],
    signed_key_id: u32,
) -> Result<SignedPreKey> {
    if identity_priv.len() != PRIV_KEY_LEN || identity_pub.len() != PUB_KEY_PREFIXED_LEN {
        return Err(napi::Error::from_reason(
            "Invalid identity key pair".to_string(),
        ));
    }
    let key_pair = generate_key_pair();
    let sig = calculate_signature(identity_priv, &key_pair.public_key)?;
    Ok(SignedPreKey {
        key_id: signed_key_id,
        key_pair,
        signature: sig,
    })
}

#[napi(object)]
pub struct PreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
}

#[napi]
pub fn generate_pre_key(key_id: u32) -> Result<PreKey> {
    let key_pair = generate_key_pair();
    Ok(PreKey { key_id, key_pair })
}

fn assert_len(name: &str, buf: &[u8], expected: usize) -> Result<()> {
    if buf.len() != expected {
        return Err(napi::Error::from_reason(format!(
            "{} must be {} bytes",
            name, expected
        )));
    }
    Ok(())
}

#[napi]
pub fn encrypt(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
    assert_len("key", key.as_ref(), AES_KEY_LEN)?;
    assert_len("iv", iv.as_ref(), AES_IV_LEN)?;

    let ciphertext = openssl_encrypt(
        Cipher::aes_256_cbc(),
        key.as_ref(),
        Some(iv.as_ref()),
        data.as_ref(),
    )
    .map_err(|e| napi::Error::from_reason(format!("encrypt error: {}", e)))?;
    Ok(Buffer::from(ciphertext))
}

#[napi]
pub fn decrypt(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
    assert_len("key", key.as_ref(), AES_KEY_LEN)?;
    assert_len("iv", iv.as_ref(), AES_IV_LEN)?;

    let decrypted = openssl_decrypt(
        Cipher::aes_256_cbc(),
        key.as_ref(),
        Some(iv.as_ref()),
        data.as_ref(),
    )
    .map_err(|e| napi::Error::from_reason(format!("decrypt error: {}", e)))?;
    Ok(Buffer::from(decrypted))
}

#[napi]
pub fn calculate_mac(key: Buffer, data: Buffer) -> Result<Buffer> {
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
    mac.update(data.as_ref());
    let result = mac.finalize().into_bytes().to_vec();
    Ok(Buffer::from(result))
}

#[napi]
pub fn hash(data: Buffer) -> Result<Buffer> {
    let mut hasher = Sha512::new();
    hasher.update(data.as_ref());
    Ok(Buffer::from(hasher.finalize().to_vec()))
}

#[napi]
pub fn verify_mac(data: Buffer, key: Buffer, mac: Buffer, length: u32) -> Result<()> {
    let mut macer = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
    macer.update(data.as_ref());
    let calculated = macer.finalize().into_bytes();
    let len = length as usize;
    if mac.as_ref().len() != len || calculated.len() < len {
        return Err(napi::Error::from_reason("Bad MAC length".to_string()));
    }
    if &calculated[..len] != mac.as_ref() {
        return Err(napi::Error::from_reason("Bad MAC".to_string()));
    }
    Ok(())
}

#[napi]
pub fn derive_secrets(
    input: Buffer,
    salt: Buffer,
    info: Buffer,
    chunks: Option<u32>,
) -> Result<Vec<Buffer>> {
    if salt.as_ref().len() != HMAC_LEN {
        return Err(napi::Error::from_reason(
            "Got salt of incorrect length".to_string(),
        ));
    }

    let chunks = chunks.unwrap_or(3).min(3).max(1) as usize;

    // Extract PRK
    let mut prk = HmacSha256::new_from_slice(salt.as_ref())
        .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
    prk.update(input.as_ref());
    let prk_bytes = prk.finalize().into_bytes();

    let mut out: Vec<Buffer> = Vec::with_capacity(chunks);

    // compute T1
    {
        let mut mac1 = HmacSha256::new_from_slice(&prk_bytes)
            .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
        mac1.update(info.as_ref());
        mac1.update(&[1u8]);
        let t = mac1.finalize().into_bytes().to_vec();
        out.push(Buffer::from(t));
    }

    if chunks > 1 {
        let previous = out.last().unwrap().as_ref().to_vec();
        let mut mac2 = HmacSha256::new_from_slice(&prk_bytes)
            .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
        mac2.update(&previous);
        mac2.update(info.as_ref());
        mac2.update(&[2u8]);
        let t = mac2.finalize().into_bytes().to_vec();
        out.push(Buffer::from(t));
    }

    if chunks > 2 {
        let previous = out.last().unwrap().as_ref().to_vec();
        let mut mac3 = HmacSha256::new_from_slice(&prk_bytes)
            .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
        mac3.update(&previous);
        mac3.update(info.as_ref());
        mac3.update(&[3u8]);
        let t = mac3.finalize().into_bytes().to_vec();
        out.push(Buffer::from(t));
    }

    Ok(out)
}

#[napi]
pub fn calculate_mac_short(key: Buffer, data: Buffer, length: u32) -> Result<Buffer> {
    let mut macer = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|e| napi::Error::from_reason(format!("HMAC init error: {}", e)))?;
    macer.update(data.as_ref());
    let mac = macer.finalize().into_bytes();
    let len = length as usize;
    Ok(Buffer::from(mac[..len].to_vec()))
}

#[napi(object)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

const KEY_BUNDLE_TYPE: u8 = 5;

fn prefix_key_in_public_key(pub_key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(33);
    result.push(KEY_BUNDLE_TYPE);
    result.extend_from_slice(pub_key);
    result
}

fn scrub_pub_key_format(pub_key: &[u8]) -> Result<[u8; 32]> {
    if pub_key.len() == PUB_KEY_PREFIXED_LEN && pub_key[0] == KEY_BUNDLE_TYPE {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pub_key[1..]);
        Ok(arr)
    } else if pub_key.len() == PUB_KEY_RAW_LEN {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pub_key);
        Ok(arr)
    } else {
        Err(Error::new(
            Status::InvalidArg,
            format!("Invalid public key length: {}", pub_key.len()),
        ))
    }
}

#[napi]
pub fn generate_key_pair() -> KeyPair {
    let mut osrng = rand::rng();
    let mut seed = [0u8; PRIV_KEY_LEN];
    osrng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);

    KeyPair {
        private_key: secret.to_bytes().to_vec(),
        public_key: prefix_key_in_public_key(public.as_bytes()),
    }
}

#[napi]
pub fn get_public_from_private_key(priv_key: &[u8]) -> Result<Vec<u8>> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            "Private key must be 32 bytes",
        ));
    }

    let mut arr = [0u8; PRIV_KEY_LEN];
    arr.copy_from_slice(priv_key);

    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);

    Ok(prefix_key_in_public_key(public.as_bytes()))
}

#[napi]
pub fn calculate_agreement(pub_key: &[u8], priv_key: &[u8]) -> Result<Vec<u8>> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            "Private key must be 32 bytes",
        ));
    }
    let mut priv_arr = [0u8; PRIV_KEY_LEN];
    priv_arr.copy_from_slice(priv_key);

    let cleaned_pub_bytes = scrub_pub_key_format(pub_key)?;
    let their_public = PublicKey::from(cleaned_pub_bytes);

    let my_secret = StaticSecret::from(priv_arr);

    let shared_secret = my_secret.diffie_hellman(&their_public);

    Ok(shared_secret.to_bytes().to_vec())
}

fn convert_x25519_to_ed25519(x25519_pubkey: &[u8], signature: &[u8]) -> Result<[u8; 32]> {
    if x25519_pubkey.len() != PUB_KEY_RAW_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            "X25519 key must be 32 bytes",
        ));
    }

    let mut montgomery_bytes = [0u8; 32];
    montgomery_bytes.copy_from_slice(x25519_pubkey);

    let montgomery_point = curve25519_dalek::montgomery::MontgomeryPoint(montgomery_bytes);
    let sign_bit = (signature[63] & 0x80) != 0;
    let edwards_point = match montgomery_point.to_edwards(sign_bit as u8) {
        Some(point) => point,
        None => {
            return Err(Error::new(
                Status::InvalidArg,
                "Failed to convert X25519 to Ed25519",
            ))
        }
    };

    Ok(edwards_point.compress().to_bytes())
}

fn calculate_signature_mode(priv_key: &[u8], message: &[u8], rfc_mode: bool) -> Result<Vec<u8>> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            "Private key must be 32 bytes",
        ));
    }

    let mut a_bytes = [0u8; 32];
    let mut prefix_bytes = [0u8; 32];

    if rfc_mode {
        let h_full = Sha512::digest(priv_key);
        a_bytes.copy_from_slice(&h_full[0..32]);
        prefix_bytes.copy_from_slice(&h_full[32..64]);
    } else {
        a_bytes.copy_from_slice(priv_key);
        prefix_bytes.copy_from_slice(priv_key);
    }

    // clamp a_bytes
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;

    
    let a_scalar = Scalar::from_bytes_mod_order(a_bytes);
    let a_point = &a_scalar * &ED25519_BASEPOINT_POINT;
    let a_bytes_pk = a_point.compress().to_bytes();

    // r = SHA512(prefix || message) -> wide -> scalar
    let mut r_hasher = Sha512::new();
    r_hasher.update(&prefix_bytes);
    r_hasher.update(message);
    let r_hash = r_hasher.finalize();
    let r_scalar = Scalar::from_bytes_mod_order_wide(&r_hash.into());

    // R = r * B
    let r_point = &r_scalar * &ED25519_BASEPOINT_POINT;
    let r_bytes = r_point.compress().to_bytes();

    // h2 = SHA512(R || A || M)
    let mut h2 = Sha512::new();
    h2.update(&r_bytes);
    h2.update(&a_bytes_pk);
    h2.update(message);
    let h2_hash = h2.finalize();
    let h2_scalar = Scalar::from_bytes_mod_order_wide(&h2_hash.into());

    // s = r + h2 * a
    let s = &r_scalar + &(&h2_scalar * &a_scalar);
    let s_bytes = s.to_bytes();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);

    // set sign bit to encode A's sign into signature
    sig[63] |= a_bytes_pk[31] & 0x80u8;

    Ok(sig.to_vec())
}

#[napi]
fn calculate_signature_with_pub(
    priv_key: &[u8],
    pub_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(Error::new(
            Status::InvalidArg,
            "Private key must be 32 bytes",
        ));
    }

    let pub_from_a = |a_bytes_in: [u8; 32]| -> [u8; 32] {
        let a_scalar = Scalar::from_bytes_mod_order(a_bytes_in);
        let a_point = &a_scalar * &ED25519_BASEPOINT_POINT;
        a_point.compress().to_bytes()
    };

    let mut a_legacy = [0u8; 32];
    a_legacy.copy_from_slice(priv_key);
    a_legacy[0] &= 248;
    a_legacy[31] &= 127;
    a_legacy[31] |= 64;
    let pk_legacy = pub_from_a(a_legacy);

    let cleaned_pub = scrub_pub_key_format(pub_key)?;

    if cleaned_pub == pk_legacy {
        return calculate_signature_mode(priv_key, message, false);
    }

    let mut h = Sha512::new();
    h.update(priv_key);
    let h_full = h.finalize();
    let mut a_rfc = [0u8; 32];
    a_rfc.copy_from_slice(&h_full.as_slice()[0..32]);
    a_rfc[0] &= 248;
    a_rfc[31] &= 127;
    a_rfc[31] |= 64;
    let pk_rfc = pub_from_a(a_rfc);

    if cleaned_pub == pk_rfc {
        return calculate_signature_mode(priv_key, message, true);
    }

    calculate_signature_mode(priv_key, message, true)
}

#[napi]
pub fn calculate_signature(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    calculate_signature_mode(priv_key, message, /* rfc_mode = */ false)
}

#[napi]
pub fn verify_signature(
    their_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    is_init: bool,
) -> Result<bool> {
    if is_init {
        return Ok(true);
    }

    if their_public_key.len() != PUB_KEY_RAW_LEN {
        return Err(Error::new(Status::InvalidArg, "Invalid public key"));
    }
    if message.is_empty() {
        return Err(Error::new(Status::InvalidArg, "Invalid message"));
    }
    if signature.len() != 64 {
        return Err(Error::new(Status::InvalidArg, "Invalid signature"));
    }

    let ed25519_public_key = match convert_x25519_to_ed25519(their_public_key, signature) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };

    let mut vk_arr = [0u8; 32];
    vk_arr.copy_from_slice(&ed25519_public_key);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature);

    sig_arr[63] &= 0x7F;

    let verifying_key = match VerifyingKey::from_bytes(&vk_arr) {
        Ok(vk) => vk,
        Err(_) => return Ok(false),
    };

    let sig = Signature::from_bytes(&sig_arr);

    Ok(verifying_key.verify(message, &sig).is_ok())
}
