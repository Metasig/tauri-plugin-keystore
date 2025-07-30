use hex::ToHex;
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use tauri::{command, App, AppHandle, Runtime};

use crate::models::*;
use crate::KeystoreExt;

#[command]
pub(crate) async fn store_unencrypted<R: Runtime>(
    app: AppHandle<R>,
    payload: StoreRequest
) -> crate::Result<()> {
    app.keystore().store_unencrypted(payload)
}

#[command]
pub(crate) async fn store<R: Runtime>(
    app: AppHandle<R>,
    payload: StoreRequest,
) -> crate::Result<()> {
    app.keystore().store(payload)
}

#[command]
pub(crate) async fn retrieve_unencrypted<R: Runtime>(
    app: AppHandle<R>,
    payload: RetrieveRequest,
) -> crate::Result<RetrieveResponse> {
    app.keystore().retrieve_unencrypted(payload)
}

#[command]
pub(crate) async fn retrieve<R: Runtime>(
    app: AppHandle<R>,
    payload: RetrieveRequest,
) -> crate::Result<RetrieveResponse> {
    app.keystore().retrieve(payload)
}

#[command]
pub(crate) async fn contains_key<R: Runtime>(
    app: AppHandle<R>,
    payload: RetrieveRequest,
) -> crate::Result<bool> {
    app.keystore().contains_key(payload)
}

#[command]
pub(crate) async fn contains_unencrypted_key<R: Runtime>(
    app: AppHandle<R>,
    payload: RetrieveRequest,
) -> crate::Result<bool> {
    app.keystore().contains_unencrypted_key(payload)
}

#[command]
pub(crate) async fn remove<R: Runtime>(
    app: AppHandle<R>,
    payload: RemoveRequest,
) -> crate::Result<()> {
    app.keystore().remove(payload)
}

#[command]
pub(crate) async fn shared_secret_pub_key<R: Runtime>(
    app: AppHandle<R>,
) -> crate::Result<PubKeyResponse> {
    app.keystore().shared_secret_pub_key()
}

#[command]
pub(crate) async fn shared_secret<R: Runtime> (
    app: AppHandle<R>,
    payload: SharedSecretRequest
) -> crate::Result<ChaChaSharedSecret> {

    // Create the salt
    let salt_hasher = Sha512::new();
    let mut salt = salt_hasher
        .chain_update(payload.salt.as_bytes());
    if let Some(extra) = &payload.extra_info {
        salt = salt.chain_update(extra.as_bytes());
    }
    let salt_value = salt.finalize();

    let shared_secret_result = app.keystore().shared_secret(payload)?;

    // Process each shared secret
    let mut chacha_20_keys = Vec::new();
    for shared_secret in &shared_secret_result.shared_secrets {
        let ikm: Vec<u8> = hex::decode(shared_secret).map_err(|e| {
            crate::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
        })?;

        let hk = Hkdf::<Sha512>::new(Some(&salt_value), &ikm);
        let mut okm = [0u8;32];
        hk.expand(&[], &mut okm).map_err(|_| {
            crate::Error::Generic("invalid length".to_string())
        })?;

        chacha_20_keys.push(okm.encode_hex());
    }

    Ok(ChaChaSharedSecret {
        chacha_20_keys,
    })
}

#[command]
pub(crate) async fn hmac_sha256<R: Runtime>(
    app: AppHandle<R>,
    payload: HmacSha256Request
) -> crate::Result<HmacSha256Response> {
    app.keystore().hmac_sha256(payload)
}