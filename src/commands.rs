use hex::ToHex;
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::KeystoreExt;

#[command]
pub(crate) async fn store<R: Runtime>(
    app: AppHandle<R>,
    payload: StoreRequest,
) -> crate::Result<()> {
    app.keystore().store(payload)
}

#[command]
pub(crate) async fn retrieve<R: Runtime>(
    app: AppHandle<R>,
    payload: RetrieveRequest,
) -> crate::Result<RetrieveResponse> {
    app.keystore().retrieve(payload)
}

#[command]
pub(crate) async fn remove<R: Runtime>(
    app: AppHandle<R>,
    payload: RemoveRequest,
) -> crate::Result<()> {
    app.keystore().remove(payload)
}

#[command]
pub(crate) async fn shared_secret<R: Runtime> (
    app: AppHandle<R>,
    payload: SharedSecretRequest
) -> crate::Result<ChaChaSharedSecret> {

    let extra_info = payload.extra_info.clone();

    let shared_secret_result = app.keystore().shared_secret(payload)?;

    let salt_hasher = Sha512::new();

    let ikm: Vec<u8> = hex::decode(&shared_secret_result.shared_secret).map_err(|e| {
        crate::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    })?;

    let mut salt = salt_hasher
        .chain_update(b"tauri-plugin-keystore");
    if let Some(extra) = extra_info {
        salt = salt.chain_update(extra.as_bytes());
    }

    let hk = Hkdf::<Sha512>::new(Some(&salt.finalize()), &ikm);
    let mut okm = [0u8;32];
    hk.expand(&[], &mut okm).map_err(|e| {
        crate::Error::Generic("invalid length".to_string())
    })?;

    Ok(ChaChaSharedSecret {
        chacha_20_key: okm.encode_hex(),
    })
}