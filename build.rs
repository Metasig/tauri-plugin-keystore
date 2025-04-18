const COMMANDS: &[&str] = &["remove", "retrieve", "store", "shared_secret", "shared_secret_pub_key"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
