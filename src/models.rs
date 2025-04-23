use serde::{Deserialize, Serialize};

/// Request to store a value in the keystore
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreRequest {
    /// The value to store in the keystore
    pub value: String,
}

/// Request to retrieve a value from the keystore
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveRequest {
    /// The service identifier
    pub service: String,
    /// The user identifier
    pub user: String,
}

/// Response containing the retrieved value from the keystore
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveResponse {
    /// The retrieved value, if it exists
    pub value: Option<String>,
}

/// Request to remove a value from the keystore
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveRequest {
    /// The service identifier
    pub service: String,
    /// The user identifier
    pub user: String,
}

/// Response containing the public key
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubKeyResponse {
    /// The public key in Hex format
    pub pub_key: String
}


/// Request to generate shared secrets with P-256 public keys
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedSecretRequest {
    /// Vector of P-256 public keys to generate shared secrets with
    pub with_p256_pub_keys: Vec<String>,
    
    /// The salt value used in the HKDF key derivation process
    pub salt: String,
    /// Optional additional information for the shared secret generation
    pub extra_info: Option<String>
}

/// Response containing the generated shared secrets
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedSecretResponse {
    /// List of generated shared secrets
    pub shared_secrets: Vec<String>
}

/// Contains ChaCha20 keys derived from shared secrets
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChaChaSharedSecret {
    /// List of ChaCha20 keys in hex format
    pub chacha_20_keys: Vec<String>
}
