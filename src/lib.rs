#![cfg(mobile)]

use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};
use tauri::plugin::PluginApi;
pub use models::*;

mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

use mobile::Keystore;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the keystore APIs.
pub trait KeystoreExt<R: Runtime> {
    fn keystore(&self) -> &Keystore<R>;
}

impl<R: Runtime, T: Manager<R>> KeystoreExt<R> for T {
    fn keystore(&self) -> &Keystore<R> {
        self.state::<Keystore<R>>().inner()
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub unencrypted_store_name: Option<String>
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R, Config> {
    Builder::new("keystore")
        .invoke_handler(tauri::generate_handler![
            commands::store_unencrypted,
            commands::retrieve_unencrypted,
            commands::contains_key,
            commands::contains_unencrypted_key,
            commands::remove,
            commands::retrieve,
            commands::store,
            commands::shared_secret,
            commands::shared_secret_pub_key,
            commands::hmac_sha256
        ])
        .setup(|app, api: PluginApi<R, Config>| {
            let keystore = mobile::init(app, api)?;
            app.manage(keystore);
            Ok(())
        })
        .build()
}
