import CryptoKit
import Foundation
import LocalAuthentication
import Security

public struct KeystoreResult<T: Encodable>: Encodable {
    public let ok: Bool
    public let data: T?
    public let error: String?
    public init(ok: Bool, data: T? = nil, error: String? = nil) {
        self.ok = ok
        self.data = data
        self.error = error
    }
}

@available(iOS 15, *)
public final class KeystoreCore {
    public static let shared = KeystoreCore() // Singleton
    private let accessQueue: DispatchQueue = DispatchQueue(label: "app.metasig.keystore.access", attributes: .concurrent)
    private let plainPrefs = UserDefaults(suiteName: "unencrypted_store")!
    private let keychainServiceGroupName = "app.metasig.keystore.encrypted"
    let hmacKeyAlias = "app.metasig.hmac.key.v2"
    
    private init() {}
    
    /**
     *
     */
    public func contains_unencrypted_key(_ key: String) -> KeystoreResult<Bool> {
        let exists = plainPrefs.object(forKey: key) != nil
        return KeystoreResult(ok: true, data: exists)
    }
    
    /**
     *
     */
    public func store_unencrypted(_ key: String, value: String) -> KeystoreResult<Bool> {
        plainPrefs.setValue(value, forKey: key)
        return KeystoreResult(ok: true, data: true)
    }
    
    /**
     *
     */
    public func retrieve_unencrypted(_ key: String) -> KeystoreResult<String?> {
        let v = plainPrefs.string(forKey: key)
        return KeystoreResult(ok: true, data: v)
    }
    
    /**
     *
     */
    public func contains_key(_ key: String) -> KeystoreResult<Bool> {
        return accessQueue.sync {
            NSLog("🔍 DEBUG: Checking Keychain for key: \(key)")
            
            let hasKey = keychainExists(forKey: key)
            
            NSLog("🔒 Key '\(key)' check: \(hasKey)")
            
            return KeystoreResult(ok: true, data: hasKey)
        }
    }
    
    public func store(_ key: String, plaintext: String) -> KeystoreResult<Bool> {
        return accessQueue.sync(flags: .barrier) {
            NSLog("🔍 Key '\(key)' store begin")
            do {
                NSLog("🔍 DEBUG:  Key '\(key)' store saveToKeychain")
                try saveToKeychain(value: plaintext, forKey: key)
                
                return KeystoreResult(ok: true, data: true)
            } catch {
                NSLog("❌ ERROR: Key '\(key)' store with error \(String(describing: error))")
                return KeystoreResult(ok: false, data: nil, error: String(describing: error))
            }
        }
    }
    
    public func retrieve(_ key: String) -> KeystoreResult<String?> {
        return accessQueue.sync {
            NSLog("🔍 Key '\(key)' retrieve begin")
            do {
                NSLog("🔍 DEBUG:  Key '\(key)' retrieveFromKeychain")
                let plaintext = try retrieveFromKeychain(forKey: key)
                return KeystoreResult(ok: true, data: plaintext)
            } catch {
                return KeystoreResult(ok: false, data: nil, error: String(describing: error))
            }
        }
    }
    public func remove(_ key: String) -> KeystoreResult<Bool> {
        return accessQueue.sync(flags: .barrier) {
            deleteFromKeychain(forKey: key)
            plainPrefs.removeObject(forKey: key)
            return KeystoreResult(ok: true, data: true)
        }
    }
    
    public func hmac_sha256(_ message: String) -> KeystoreResult<String> {
        return accessQueue.sync {
            do {
                // Ensure HMAC key exists
                try ensureHmacKey()
                
                // Retrieve the key (this will trigger biometric authentication)
                guard let keyBase64 = try retrieveFromKeychain(forKey: hmacKeyAlias),
                      let keyData = Data(base64Encoded: keyBase64) else {
                    throw NSError(domain: "KeystoreCore", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to retrieve HMAC key"])
                }
                
                let key = SymmetricKey(data: keyData)
                
                // Compute the HMAC
                let messageData = Data(message.utf8)
                let tag = HMAC<SHA256>.authenticationCode(for: messageData, using: key)
                
                // Convert to hexadecimal string
                let hexString = tag.map { String(format: "%02x", $0) }.joined()
                
                return KeystoreResult(ok: true, data: hexString)
            } catch {
                NSLog("❌ ERROR: HMAC computation failed: \(error)")
                return KeystoreResult(ok: false, data: nil, error: "Failed to compute HMAC-SHA256: \(error.localizedDescription)")
            }
        }
    }
    
    public func shared_secret_pub_key() -> KeystoreResult<String> {
        return KeystoreResult(ok: false, data: nil, error: "Not implement")
    }
    
    public func shared_secret(_ pubKeys: [String]) -> KeystoreResult<[String]> {
        return KeystoreResult(ok: false, data: nil, error: "Not implement")
    }
    
    // MARK: - Keychain Helper Methods
    
    private func ensureHmacKey() throws {
        
        // Check if the key already exists
        if let _ = try? retrieveFromKeychain(forKey: hmacKeyAlias) {
            // Key already exists, nothing to do
            return
        }
        
        // Create a new key if it doesn't exist
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        let keyBase64 = keyData.base64EncodedString()
        
        // Store the key in the keychain with biometric protection
        // Your existing saveToKeychain method already handles the biometric requirement
        try saveToKeychain(value: keyBase64, forKey: hmacKeyAlias)
        
        NSLog("✅ Created new HMAC key")
    }
    
    /**
     *
     */
    private func keychainExists(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceGroupName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /**
     *
     */
    private func saveToKeychain(value: String, forKey key: String) throws {
        guard let data = value.data(using: .utf8) else {
            NSLog("💥 Failed to encode string")
            throw NSError(domain: "KeystoreCore", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode string"])
        }
        
        NSLog("🔒 Key '\(key)' store: value: [REDACTED]")
        
        // Use relaxed access control for HMAC key, strict for others
        let isHmacKey = (key == hmacKeyAlias)
        let access = try makeAccessControl(requirePrivateKeyUsage: false, relaxedForHmac: isHmacKey)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceGroupName,
            kSecAttrAccount as String: key,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecValueData as String: data
        ]
        
        // Delete existing item if present
        SecItemDelete(query as CFDictionary)
        
        NSLog("🔍 DEBUG:  Account '\(key)' SecItemAdd")
        let status = SecItemAdd(query as CFDictionary, nil)
        NSLog("🔍 DEBUG:  Account '\(key)' with status: \(status)")
        guard status == errSecSuccess else {
            NSLog("❌ ERROR: Account '\(key)' with status: \(status)")
            if let error = SecCopyErrorMessageString(status, nil) as String? {
                NSLog("❌ Error message: \(error)")
            }
            throw NSError(domain: "KeystoreCore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to store to Keychain"])
        }
    }
    
    private func retrieveFromKeychain(forKey key: String) throws -> String? {
        // For HMAC key, don't require authentication context (allows access when device is unlocked)
        // For other keys, require explicit biometric/passcode authentication
        let isHmacKey = (key == hmacKeyAlias)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceGroupName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Only add authentication context for non-HMAC keys
        if !isHmacKey {
            let context = LAContext()
            context.localizedReason = "Access your passkey"
            context.localizedFallbackTitle = "Use Passcode"
            query[kSecUseAuthenticationContext as String] = context
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecItemNotFound {
            return nil
        }
        
        guard status == errSecSuccess else {
            NSLog("❌ ERROR: Failed to retrieve key '\(key)' with status: \(status)")
            if let error = SecCopyErrorMessageString(status, nil) as String? {
                NSLog("❌ Error message: \(error)")
            }
            throw NSError(domain: "KeystoreCore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to retrieve from Keychain. Status: \(status)"])
        }
        
        guard let data = result as? Data else {
            NSLog("❌ ERROR: Retrieved item for key '\(key)' but couldn't cast to Data")
            throw NSError(domain: "KeystoreCore", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to cast result to Data"])
        }
        
        guard let string = String(data: data, encoding: .utf8) else {
            NSLog("❌ ERROR: Retrieved Data for key '\(key)' but couldn't decode as UTF-8 string")
            NSLog("❌ DEBUG: Data length: \(data.count) bytes, first few bytes: \(data.prefix(min(10, data.count)).map { String(format: "%02x", $0) }.joined())")
            throw NSError(domain: "KeystoreCore", code: -3, userInfo: [NSLocalizedDescriptionKey: "Failed to decode data as UTF-8 string"])
        }
        
        NSLog("✅ SUCCESS: Retrieved and decoded item for key '\(key)'")
        
        return string
    }
    
    /**
     *
     */
    private func deleteFromKeychain(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceGroupName,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
    
    
    private func makeAccessControl(requirePrivateKeyUsage: Bool, relaxedForHmac: Bool = false) throws -> SecAccessControl {
        if relaxedForHmac {
            // For HMAC key: only require device to be unlocked, no biometric/passcode prompt
            var error: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [], // No additional flags - just "when unlocked"
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }
            return ac
        } else {
            // For other keys: strict authentication required
            var flags: SecAccessControlCreateFlags = [.or]
            flags.insert(.biometryAny)
            flags.insert(.devicePasscode)
            
            if requirePrivateKeyUsage {
                flags.insert(.privateKeyUsage)
            }
            
            var error: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                flags,
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }
            return ac
        }
    }
}
