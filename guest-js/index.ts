import {invoke} from "@tauri-apps/api/core";
import {p256} from "@noble/curves/p256";

export async function store(value: string): Promise<void> {
    return await invoke<void>("plugin:keystore|store", {
        payload: {
            value,
        },
    });
}

export async function retrieve(
    service: string,
    user: string
): Promise<string | null> {
    return await invoke<{ value?: string }>("plugin:keystore|retrieve", {
        payload: {
            service,
            user,
        },
    }).then((r) => (r.value ? r.value : null));
}

export async function remove(service: string, user: string) {
    return await invoke<void>("plugin:keystore|remove", {
        payload: {
            service,
            user,
        },
    });
}

export async function sharedSecretPubKey() {
    return await invoke<string>("plugin:keystore|shared_secret_pub_key")
        .then((pubkey) => p256.ProjectivePoint.fromHex(pubkey));
}

export async function sharedSecret(pubHex: string, salt: string, extraInfo?: string): Promise<string | null> {
    return await invoke<string | null>("plugin:keystore|shared_secret", {
        payload: {
            withP256PubKey: pubHex,
            extraInfo,
            salt
        },
    });
}