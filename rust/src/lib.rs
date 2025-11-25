mod libsignal;

use libsignal::curve;

use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

use rand::TryRngCore;



#[napi(object)]
pub struct KeyPair {
    pub priv_key: Buffer,
    pub pub_key: Buffer,
}

fn private_key_from(priv_key: &[u8]) -> Result<curve::PrivateKey> {
    curve::PrivateKey::deserialize(priv_key).map_err(|e| Error::from_reason(format!("failed to create PrivateKey: {}", e)))
}

fn public_key_from(pub_key: &[u8]) -> Result<curve::PublicKey> {
    curve::PublicKey::deserialize(pub_key).map_err(|e| Error::from_reason(format!("failed to create PublicKey: {}", e)))
}


fn create_key_pair(priv_key: &[u8], pub_key: &[u8]) -> Result<curve::KeyPair> {
    let our_private_key = private_key_from(priv_key)?;
    let their_public_key = public_key_from(pub_key)?;
    Ok(curve::KeyPair::new(their_public_key, our_private_key))
}

#[napi]
pub fn generate_key_pair() -> Result<KeyPair> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();
    let key_pair = curve::KeyPair::generate(&mut csprng);
    Ok(KeyPair  {
        priv_key: Buffer::from(key_pair.private_key.serialize().as_ref()),
        pub_key: Buffer::from(key_pair.public_key.serialize().as_ref()),
    })
}

#[napi]
pub fn get_public_from_private_key(priv_key: &[u8]) -> Result<Buffer> {
    let our_private_key = private_key_from(priv_key)?;
    let public_key = our_private_key.public_key().map_err(|e| Error::from_reason(format!("failed to create PublicKey: {}", e)))?;
    Ok(Buffer::from(public_key.serialize().as_ref()))
}

#[napi]
pub fn calculate_agreement(pub_key: &[u8], priv_key: &[u8]) -> Result<Buffer> {
    let private_key = private_key_from(priv_key)?;
    let public_key = public_key_from(pub_key)?;
    let agreement = private_key.calculate_agreement(&public_key).map_err(|e| Error::from_reason(format!("failed to calculate agreement: {}", e)))?;
    Ok(Buffer::from(agreement.as_ref()))
}

#[napi]
pub fn calculate_signature(priv_key: &[u8], message: &[u8]) -> Result<Buffer> {
    let private_key = private_key_from(priv_key)?;
    let mut csprng = rand::rngs::OsRng.unwrap_err();
    let signature = private_key.calculate_signature(message, &mut csprng).map_err(|e| Error::from_reason(format!("failed to calculate signature: {}", e)))?;
    Ok(Buffer::from(signature.as_ref()))
}

#[napi]
pub fn verify_signature(
    their_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    is_init: Option<bool>,
) -> bool {
    let init = is_init.unwrap_or(false);
    if init {
        return true
    }
    let pub_key = match public_key_from(their_public_key) {
        Ok(key) => key,
        Err(_) => return false
    };
    pub_key.verify_signature(message, signature)
}
