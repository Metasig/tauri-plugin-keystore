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
    private let symEncAccount = "sym.enc"
    private let symHmacAccount = "sym.hmac"
    private let ecdhTag = "se.ecdh.private".data(using: .utf8)!
    private let keychainService = "app.metasig.keystore.encrypted"

    private init() {}

    public func contains_key(_ key: String) -> KeystoreResult<Bool> {
        return accessQueue.sync {
            NSLog("🔍 DEBUG: Checking Keychain for key: \(key)")

            let hasIv = keychainExists(forKey: "iv-\(key)")
            let hasCt = keychainExists(forKey: "ciphertext-\(key)")

            NSLog("🔒 Key '\(key)' check: IV exists: \(hasIv), CT exists: \(hasCt)")

            return KeystoreResult(ok: true, data: hasIv && hasCt)
        }
    }

    public func contains_unencrypted_key(_ key: String) -> KeystoreResult<Bool> {
        let exists = plainPrefs.object(forKey: key) != nil
        return KeystoreResult(ok: true, data: exists)
    }

    public func store_unencrypted(_ key: String, value: String) -> KeystoreResult<Bool> {
        plainPrefs.setValue(value, forKey: key)
        return KeystoreResult(ok: true, data: true)
    }

    public func retrieve_unencrypted(_ key: String) -> KeystoreResult<String?> {
        let v = plainPrefs.string(forKey: key)
        return KeystoreResult(ok: true, data: v)
    }

    public func store(_ key: String, plaintext: String) -> KeystoreResult<Bool> {
        return accessQueue.sync(flags: .barrier) {
            do {
                let ctx = LAContext()
                ctx.localizedReason = "Unlock to access encryption key"
                let encKey = try loadOrCreateSymmetricKey(account: symEncAccount, context: ctx)
                let nonce = AES.GCM.Nonce()
                let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: encKey, nonce: nonce)
                let ivB64 = Data(nonce.withUnsafeBytes { Data($0) }).base64EncodedString()
                let ct = sealed.ciphertext + sealed.tag
                let ctB64 = ct.base64EncodedString()

                try saveToKeychain(value: ivB64, forKey: "iv-\(key)")
                try saveToKeychain(value: ctB64, forKey: "ciphertext-\(key)")

                return KeystoreResult(ok: true, data: true)
            } catch {
                return KeystoreResult(ok: false, data: nil, error: String(describing: error))
            }
        }
    }

    public func retrieve(_ key: String) -> KeystoreResult<String?> {
        return accessQueue.sync {
            do {
                guard let ivB64 = try retrieveFromKeychain(forKey: "iv-\(key)"),
                      let ctB64 = try retrieveFromKeychain(forKey: "ciphertext-\(key)"),
                      let iv = Data(base64Encoded: ivB64),
                      let ct = Data(base64Encoded: ctB64)
                else {
                    return KeystoreResult(ok: true, data: nil)
                }
                let ctx = LAContext()
                ctx.localizedReason = "Unlock to access encryption key"
                let encKey = try loadOrCreateSymmetricKey(account: symEncAccount, context: ctx)
                guard iv.count == 12 else {
                    return KeystoreResult(ok: false, data: nil, error: "bad_iv_length")
                }
                let nonce = try AES.GCM.Nonce(data: iv)
                let ctOnly = ct.prefix(ct.count - 16)
                let tag = ct.suffix(16)
                let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctOnly, tag: tag)
                let plaintext = try AES.GCM.open(sealed, using: encKey)
                return KeystoreResult(ok: true, data: String(data: plaintext, encoding: .utf8) ?? "")
            } catch {
                return KeystoreResult(ok: false, data: nil, error: String(describing: error))
            }
        }
    }

    public func remove(_ key: String) -> KeystoreResult<Bool> {
        return accessQueue.sync(flags: .barrier) {
            deleteFromKeychain(forKey: "iv-\(key)")
            deleteFromKeychain(forKey: "ciphertext-\(key)")
            plainPrefs.removeObject(forKey: key)
            return KeystoreResult(ok: true, data: true)
        }
    }

    public func hmac_sha256(_ message: String) -> KeystoreResult<String> {
        do {
            let ctx = LAContext()
            ctx.localizedReason = "Unlock to access HMAC key"
            let key = try loadOrCreateSymmetricKey(account: symHmacAccount, context: ctx)
            let tag = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key)
            return KeystoreResult(ok: true, data: dataToHex(Data(tag)))
        } catch {
            return KeystoreResult(ok: false, data: nil, error: String(describing: error))
        }
    }

    public func shared_secret_pub_key() -> KeystoreResult<String> {
        do {
            let ctx = LAContext()
            ctx.localizedReason = "Unlock to access ECDH key"
            let priv = try loadOrCreateECPrivateKey(context: ctx)
            let pub = try KeychainHelper.publicKey(for: priv)
            let pubData = try KeychainHelper.publicKeyX963Data(for: pub)
            return KeystoreResult(ok: true, data: dataToHex(pubData))
        } catch {
            return KeystoreResult(ok: false, data: nil, error: String(describing: error))
        }
    }

    public func shared_secret(_ pubKeys: [String]) -> KeystoreResult<[String]> {
        do {
            let ctx = LAContext()
            ctx.localizedReason = "Unlock to perform key agreement"
            let priv = try loadOrCreateECPrivateKey(context: ctx)
            var results: [String] = []
            for hex in pubKeys {
                guard let peerX963 = hexToData(hex) else {
                    return KeystoreResult(ok: false, data: nil, error: "bad_pubkey_hex")
                }
                let attrs: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                    kSecAttrKeySizeInBits as String: 256,
                ]
                var err: Unmanaged<CFError>?
                guard
                    let peerKey = SecKeyCreateWithData(
                        peerX963 as CFData, attrs as CFDictionary, &err)
                else {
                    throw err!.takeRetainedValue() as Error
                }
                var error: Unmanaged<CFError>?
                guard
                    let secret = SecKeyCopyKeyExchangeResult(
                        priv, SecKeyAlgorithm.ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary,
                        &error) as Data?
                else {
                    throw error!.takeRetainedValue() as Error
                }
                results.append(dataToHex(secret))
            }
            return KeystoreResult(ok: true, data: results)
        } catch {
            return KeystoreResult(ok: false, data: nil, error: String(describing: error))
        }
    }

    // MARK: - Keychain Helper Methods

    private func keychainExists(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    private func saveToKeychain(value: String, forKey key: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw NSError(domain: "KeystoreCore", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode string"])
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete existing item if present
        SecItemDelete(query as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw NSError(domain: "KeystoreCore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to save to Keychain. Status: \(status)"])
        }
    }

    private func retrieveFromKeychain(forKey key: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw NSError(domain: "KeystoreCore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to retrieve from Keychain. Status: \(status)"])
        }

        guard let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "KeystoreCore", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to decode data"])
        }

        return string
    }

    private func deleteFromKeychain(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key
        ]

        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Internals

    private func loadOrCreateSymmetricKey(account: String, context: LAContext?) throws
        -> SymmetricKey
    {
        if let data = try? KeychainHelper.retrieveGenericPassword(
            account: account, context: context)
        {
            return SymmetricKey(data: data)
        }
        let key = SymmetricKey(size: .bits256)
        let data = key.withUnsafeBytes { Data($0) }
        let access = try makeAccessControl(requirePrivateKeyUsage: false)
        try KeychainHelper.saveGenericPassword(account: account, data: data, access: access)
        return key
    }

    private func loadOrCreateECPrivateKey(context: LAContext?) throws -> SecKey {
        let access = try makeAccessControl(requirePrivateKeyUsage: true)
        return try KeychainHelper.createOrLoadSecureEnclavePrivateKey(tag: ecdhTag, access: access)
    }

    private func makeAccessControl(requirePrivateKeyUsage: Bool) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.biometryCurrentSet, .userPresence]
        if requirePrivateKeyUsage {
            flags.insert(.privateKeyUsage)
        }
        var error: Unmanaged<CFError>?
        guard
            let ac = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else {
            throw error!.takeRetainedValue() as Error
        }
        return ac
    }

    // MARK: - Utility Methods (assumed to exist)

    private func dataToHex(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private func hexToData(_ hex: String) -> Data? {
        var data = Data()
        var hex = hex
        if hex.count % 2 != 0 {
            return nil
        }
        while !hex.isEmpty {
            let index = hex.index(hex.startIndex, offsetBy: 2)
            let byteString = String(hex[..<index])
            hex = String(hex[index...])
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
        }
        return data
    }
}