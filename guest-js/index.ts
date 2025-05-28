import {invoke} from "@tauri-apps/api/core";
import {p256} from "@noble/curves/p256";

export async function storePlaintext(key: string, value: string): Promise<void> {
    return await invoke<void>("plugin:keystore|store_unencrypted", {
        payload: {
            key,
            value,
        },
    });
}

export async function store(key: string, value: string): Promise<void> {
    return await invoke<void>("plugin:keystore|store", {
        payload: {
            key,
            value,
        },
    });
}

export async function retrievePlaintext(key: string): Promise<string | null> {
    return await invoke<{ value?: string }>("plugin:keystore|retrieve_unencrypted", {
        payload: {
            key
        }
    }).then((r) => (r.value ? r.value : null));
}

export async function containsPlaintextKey(key: string): Promise<boolean> {
    return await invoke<boolean>("plugin:keystore|contains_unencrypted_key", {
        payload: {
            key
        }
    });
}

export async function containsKey(key: string): Promise<boolean> {
    return await invoke<boolean>("plugin:keystore|contains_key", {
        payload: {
            key
        }
    }).then()
}

export async function retrieve(key: string): Promise<string | null> {
    return await invoke<{  value?: string }>("plugin:keystore|retrieve", {
        payload: {
            key
        },
    }).then((r) => r.value ? r.value : null);
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

export async function sharedSecret(pubKeysHex: string[], salt: string, extraInfo?: string): Promise<{
    chacha20Keys: string[]
} | null> {
    return await invoke<{ chacha20Keys: string[] }>("plugin:keystore|shared_secret", {
        payload: {
            withP256PubKeys: pubKeysHex,
            extraInfo,
            salt
        },
    });
}