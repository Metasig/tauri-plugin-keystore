const COMMANDS: &[&str] = &[
    "remove",
    "retrieve",
    "store",
    "contains_unencrypted_key",
    "contains_key",
    "shared_secret",
    "shared_secret_pub_key",
    "store_unencrypted",
    "retrieve_unencrypted",
    "hmac_sha256"
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
