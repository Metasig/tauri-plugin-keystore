
import Foundation
import Security
import LocalAuthentication

enum KeychainError: Error {
    case unhandledOSStatus(OSStatus)
    case typeMismatch
    case itemNotFound
}

final class KeychainHelper {
    static let service = "app.tauri.keystore"
    static let account = ""

    static func saveGenericPassword(account: String, data: Data, access: SecAccessControl) throws {
        _ = try? deleteGenericPassword(account: account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrAccessControl as String: access,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecValueData as String: data
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unhandledOSStatus(status) }
    }

    static func retrieveGenericPassword(account: String, context: LAContext?) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        if let ctx = context {
            query[kSecUseAuthenticationContext as String] = ctx
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw KeychainError.itemNotFound }
        guard status == errSecSuccess else { throw KeychainError.unhandledOSStatus(status) }
        guard let data = item as? Data else { throw KeychainError.typeMismatch }
        return data
    }

    static func deleteGenericPassword(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledOSStatus(status)
        }
    }

    static func createOrLoadSecureEnclavePrivateKey(tag: Data, access: SecAccessControl) throws -> SecKey {
        if let existing = try? loadPrivateKey(tag: tag, context: nil) {
            return existing
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }

    static func loadPrivateKey(tag: Data, context: LAContext?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let ctx = context {
            query[kSecUseAuthenticationContext as String] = ctx
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw KeychainError.itemNotFound }
        guard status == errSecSuccess else { throw KeychainError.unhandledOSStatus(status) }
        return item as! SecKey
    }

    static func publicKey(for privateKey: SecKey) throws -> SecKey {
        guard let pub = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainError.unhandledOSStatus(errSecInvalidKeyRef)
        }
        return pub
    }

    static func publicKeyX963Data(for publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return data
    }
}
