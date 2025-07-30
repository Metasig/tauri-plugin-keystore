use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_keystore);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<Keystore<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("app.tauri.keystore", "KeystorePlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_keystore)?;
    Ok(Keystore(handle))
}

/// Access to the keystore APIs.
pub struct Keystore<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Keystore<R> {

    pub fn store_unencrypted(&self, payload: StoreRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("store_unencrypted", payload)
            .map_err(Into::into)
    }

    pub fn store(&self, payload: StoreRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("store", payload)
            .map_err(Into::into)
    }

    pub fn retrieve_unencrypted(&self, payload: RetrieveRequest) -> crate::Result<RetrieveResponse> {
        self.0
            .run_mobile_plugin("retrieve_unencrypted", payload)
            .map_err(Into::into)
    }

    pub fn retrieve(&self, payload: RetrieveRequest) -> crate::Result<RetrieveResponse> {
        self.0
            .run_mobile_plugin("retrieve", payload)
            .map_err(Into::into)
    }

    pub fn contains_key(&self, payload: RetrieveRequest) -> crate::Result<bool> {
        self.0
            .run_mobile_plugin("contains_key", payload)
            .map_err(Into::into)
    }
    
    pub fn contains_unencrypted_key(&self, payload: RetrieveRequest) -> crate::Result<bool> {
        self.0
            .run_mobile_plugin("contains_unencrypted_key", payload)
            .map_err(Into::into)
    }

    pub fn remove(&self, payload: RemoveRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("remove", payload)
            .map_err(Into::into)
    }

    pub fn shared_secret(&self, payload: SharedSecretRequest) -> crate::Result<SharedSecretResponse> {
        self.0
            .run_mobile_plugin("shared_secret", payload)
            .map_err(Into::into)
    }

    pub fn shared_secret_pub_key(&self) -> crate::Result<PubKeyResponse> {
        self.0
            .run_mobile_plugin("shared_secret_pub_key", ())
            .map_err(Into::into)
    }
    
    pub fn hmac_sha256(&self, payload: HmacSha256Request) -> crate::Result<HmacSha256Response> {
        self.0
            .run_mobile_plugin("hmac_sha256", payload)
            .map_err(Into::into)
    }

}
