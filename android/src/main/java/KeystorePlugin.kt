package app.tauri.keystore

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.webkit.WebView
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import app.tauri.Logger
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.komputing.khex.encode
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

private const val KEY_ALIAS = "key_alias"
private const val KEY_AGREEMENT_ALIAS = "key_agreement_alias"
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val SHARED_PREFERENCES_NAME = "secure_storage"

class KeystoreConfig {
    var unencryptedStoreName: String? = null
}

@InvokeArg
class StoreRequest {
    lateinit var key: String
    lateinit var value: String
}

@InvokeArg
class RetrieveRequest {
    lateinit var key: String
}

data class RetrieveResponse(
    val value: String?
)

@InvokeArg
class RemoveRequest {
    lateinit var key: String
}

@InvokeArg
class SharedSecretRequest {
    lateinit var withP256PubKeys: List<String>
}

data class SharedSecretResponse(
    val sharedSecrets: List<String>
)

@TauriPlugin
class KeystorePlugin(private val activity: Activity) : Plugin(activity) {

    lateinit var unencryptedStoreName: String


    override fun load(webView: WebView) {
        super.load(webView)
        getConfig(KeystoreConfig::class.java).let { config ->
            unencryptedStoreName = config.unencryptedStoreName ?: "unencrypted_store"
        }
    }

    @Command
    fun store_unencrypted(invoke: Invoke) {
        val args = invoke.parseArgs(StoreRequest::class.java)
        activity.getSharedPreferences(unencryptedStoreName, Context.MODE_PRIVATE).edit {
            putString(args.key, args.value)
        }
        invoke.resolve()
    }

    @Command
    fun retrieve_unencrypted(invoke: Invoke) {
        val args = invoke.parseArgs(RetrieveRequest::class.java)
        val value = activity.getSharedPreferences(unencryptedStoreName, Context.MODE_PRIVATE).getString(args.key, null)
        invoke.resolveObject(RetrieveResponse(value))
    }

    @Command
    fun store(invoke: Invoke) {
        val storeRequest = invoke.parseArgs(StoreRequest::class.java)

        // Generate Key (biometrics-protected)
        generateBiometricProtectedKey()

        // Get cipher for encryption
        val cipher = getEncryptionCipher()

        // Wrap the Cipher in a CryptoObject.
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        // Create biometric prompt
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt =
            BiometricPrompt(activity as androidx.fragment.app.FragmentActivity, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            // Get the cipher from the authentication result.
                            val authCipher = result.cryptoObject?.cipher
                                ?: throw IllegalStateException("Cipher not available after auth")

                            // Encrypt the value.
                            val ciphertext =
                                authCipher.doFinal(storeRequest.value.toByteArray())
                            val iv = authCipher.iv  // Capture the initialization vector.
                            // Store the ciphertext and IV.
                            storeCiphertext(storeRequest.key, iv, ciphertext)
                            Logger.info("Secret stored securely")
                        } catch (e: Exception) {
                            e.printStackTrace()
                            Logger.error("Encryption failed: ${e.message}")
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        invoke.reject("Authentication error: $errorCode")
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        invoke.reject("Authentication failed")
                    }
                })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to Store Secret")
            .setSubtitle("Biometric authentication is required")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo, cryptoObject)

        invoke.resolve()
    }

    // Generate key, if it doesn't exist.
    private fun generateBiometricProtectedKey() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                // Require authentication on every use:
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
                .build()
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    fun getPublicKeyFromHex(hexPublicKey: String): PublicKey {
        // Handle uncompressed format (starting with 04)
        if (hexPublicKey.startsWith("04")) {
            val hexString = hexPublicKey.substring(2) // Remove "04" prefix
            val coordinateLength = hexString.length / 2

            // Extract x and y coordinates (each should be 64 chars for secp256r1)
            val xHex = hexString.substring(0, coordinateLength)
            val yHex = hexString.substring(coordinateLength)

            val x = BigInteger(xHex, 16)
            val y = BigInteger(yHex, 16)

            // Create EC point
            val ecPoint = ECPoint(x, y)

            // Get secp256r1 parameters
            val params = AlgorithmParameters.getInstance("EC")
            params.init(ECGenParameterSpec("secp256r1"))
            val ecParameterSpec = params.getParameterSpec(ECParameterSpec::class.java)

            // Create public key spec and generate the public key
            val pubKeySpec = ECPublicKeySpec(ecPoint, ecParameterSpec)
            val keyFactory = KeyFactory.getInstance("EC")
            return keyFactory.generatePublic(pubKeySpec)
        }
        // Handle compressed format (starting with 02 or 03)
        else if (hexPublicKey.startsWith("02") || hexPublicKey.startsWith("03")) {
            // This requires point decompression which is more complex
            // Consider using Bouncy Castle for this
            throw IllegalArgumentException("Compressed keys not supported in this simple implementation")
        }
        else {
            throw IllegalArgumentException("Invalid public key format")
        }
    }

    private fun ensureP256Key() {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keystore.containsAlias(KEY_AGREEMENT_ALIAS)) {
            val keyGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_AGREEMENT_ALIAS,
                // do all of the above (sign internal for verifying key integrity)
                KeyProperties.PURPOSE_AGREE_KEY or
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()

            keyGenerator.initialize(keyGenParameterSpec)
            keyGenerator.generateKeyPair()
        }
    }

    @Command
    fun shared_secret_pub_key(invoke: Invoke) {
        // ensure we have generated the key
        ensureP256Key()

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val certificate = keyStore.getCertificate(KEY_AGREEMENT_ALIAS)
            val publicKey = certificate.publicKey

            // Convert public key to uncompressed format (04 + x + y)
            val ecPublicKey = publicKey as java.security.interfaces.ECPublicKey
            val x = ecPublicKey.w.affineX
            val y = ecPublicKey.w.affineY

            // Convert to hex string with 04 prefix (uncompressed format)
            val xHex = x.toString(16).padStart(64, '0')
            val yHex = y.toString(16).padStart(64, '0')
            val pubKeyHex = "04$xHex$yHex"

            // Return the public key
            val response = JSObject()
            response.put("pubKey", pubKeyHex)
            invoke.resolve(response)
        } catch (e: Exception) {
            e.printStackTrace()
            invoke.reject("Failed to get public key: ${e.message}")
        }
    }

    @Command
    fun shared_secret(invoke: Invoke) {
        val params = invoke.parseArgs(SharedSecretRequest::class.java)

        // ensure we have generated the key
        ensureP256Key()
        val signature = getSignature()
        Logger.debug("initiated cryptoObject")

        // Create biometric prompt
        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt =
            BiometricPrompt(activity as androidx.fragment.app.FragmentActivity, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            // Get the Signature from the authentication result.
                            val authSig = signature

                            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                            val certificate = keyStore.getCertificate(KEY_AGREEMENT_ALIAS)

                            // generate a random message
                            val message = SecureRandom.getSeed(32)
                            // update and output the signature previously initialized for signing
                            authSig.update(message)
                            val outputSig = authSig.sign()
                            Logger.debug("signed message")

                            // init in verify mode and check the signature matches the key agreement certificate
                            authSig.initVerify(certificate)
                            Logger.debug("initVerify success")
                            authSig.update(message)
                            authSig.verify(outputSig)


                            // generate the shared secrets from agreement
                            val agreement = getAgreement()
                            val sharedSecrets = mutableListOf<String>()

                            // Process each public key
                            for (pubKey in params.withP256PubKeys) {
                                agreement.init(keyStore.getKey(KEY_AGREEMENT_ALIAS, null))
                                agreement.doPhase(getPublicKeyFromHex(pubKey), true)
                                val secret = agreement.generateSecret()
                                sharedSecrets.add(encode(secret, prefix = ""))
                            }

                            invoke.resolveObject(SharedSecretResponse(sharedSecrets))
                        } catch (e: Exception) {
                            invoke.reject("Shared secret failed: ${e.message}")
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        invoke.reject("Authentication error: $errorCode")
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        invoke.reject("Authentication failed")
                    }
                })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to Compute Shared Secret")
            .setSubtitle("Biometric authentication is required")
            .setNegativeButtonText("Cancel")
            .build()

        try {
            biometricPrompt.authenticate(promptInfo)
        } catch (e: Error) {
            Logger.error("couldn't start biometric?: ${e.message}")
        }
    }

    private fun getAgreement(): KeyAgreement {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        val privateKey = keyStore.getKey(KEY_AGREEMENT_ALIAS, null)
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)

        return keyAgreement
    }

    private fun getSignature(): Signature {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        val secretKey = keyStore.getKey(KEY_AGREEMENT_ALIAS, null)

        val sig = Signature.getInstance("SHA256withECDSA")
        Logger.debug("initializing signing...")
        sig.initSign(secretKey as PrivateKey)
        Logger.debug("initialized signing!")
        return sig
    }

    // Prepares and returns a Cipher instance for encryption using the key from the Keystore.
    private fun getEncryptionCipher(): Cipher {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        val secretKey = keyStore.getKey(KEY_ALIAS, null)
        val cipher = Cipher.getInstance( "AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    // Stores the IV and ciphertext in SharedPreferences.
    private fun storeCiphertext(key: String, iv: ByteArray, ciphertext: ByteArray) {
        val prefs: SharedPreferences =
            activity.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        val ivEncoded = Base64.encodeToString(iv, Base64.DEFAULT)
        val ctEncoded = Base64.encodeToString(ciphertext, Base64.DEFAULT)
        editor.putString("iv-$key", ivEncoded)
        editor.putString("ciphertext-$key", ctEncoded)
        editor.apply()
    }

    @Command
    fun retrieve(invoke: Invoke) {
        val args = invoke.parseArgs(RetrieveRequest::class.java)

        val cipherData = readCipherData()
        if (cipherData == null) {
            invoke.resolve(JSObject("{value: null}"))
            return
        }

        val (iv, ciphertext) = cipherData

        val cipher = try {
            getDecryptionCipher(iv)
        } catch (e: Exception) {
            invoke.reject("Error initializing cipher: ${e.message}", "001")
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(activity as androidx.fragment.app.FragmentActivity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    try {
                        // Use the cipher from the authentication result (which is now unlocked).
                        val authCipher = result.cryptoObject?.cipher
                            ?: throw IllegalStateException("Cipher not available after authentication")
                        val decryptedBytes = authCipher.doFinal(ciphertext)
                        val cleartext = String(decryptedBytes)

                        val ret = JSObject()
                        ret.put("value", cleartext)
                        invoke.resolve(ret)
                    } catch (e: Exception) {
                        invoke.reject("Decryption failed: $e")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    invoke.reject("Authentication error: $errorCode")
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    invoke.reject("Authentication failed")
                }
            })

        // Build the prompt info.
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to decrypt your secret")
            .setNegativeButtonText("Cancel")
            .build()

        // Launch the biometric prompt.
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    // Reads the IV and ciphertext from SharedPreferences.
    private fun readCipherData(): Pair<ByteArray, ByteArray>? {
        val prefs: SharedPreferences =
            activity.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val ivEncoded: String? = prefs.getString("iv", null)
        val ctEncoded: String? = prefs.getString("ciphertext", null)
        if (ivEncoded == null || ctEncoded == null) {
            return null
        }
        val iv = Base64.decode(ivEncoded, Base64.DEFAULT)
        val ciphertext = Base64.decode(ctEncoded, Base64.DEFAULT)
        return Pair(iv, ciphertext)
    }

    private fun getDecryptionCipher(iv: ByteArray): Cipher {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return cipher
    }

    @Command
    fun remove(invoke: Invoke) {
        val request = invoke.parseArgs(RemoveRequest::class.java)
        try {

            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Could not delete entry from KeyStore: ${e.localizedMessage}")
        }
    }
}
