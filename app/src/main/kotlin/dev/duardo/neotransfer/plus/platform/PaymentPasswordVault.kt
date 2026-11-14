package dev.duardo.neotransfer.plus.platform

import android.content.Context
import android.security.KeyStoreException
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The ENZONA payment password, AES-GCM under a Keystore key that needs a strong biometric on every use and dies
 * when a new fingerprint is enrolled. Ciphers are authorized with `BiometricPrompt.CryptoObject` before [seal] or
 * [open]. A typed password is sealed when its payment is approved and [store]d only once ENZONA confirmed that
 * payment. Outside Android backup (the app disables it) and never exported.
 *
 * Some devices (realme Note 60: Unisoc T612, Silead sensor) bind fingerprint keys to an authenticator id that their
 * own fingerprint tokens never carry, so the key is rejected right after a valid fingerprint
 * (`KEY_USER_NOT_AUTHENTICATED`). On the first such rejection the vault moves for good to a key that any strong
 * fingerprint or the screen lock opens for [TIMED_SECONDS]: the token's user id matches it. The prompt still offers
 * only the fingerprint and authorizes a cipher of a separate per-use gate key; [seal] / [open] use the timed key right
 * after. A new fingerprint no longer kills that key.
 */
class PaymentPasswordVault(context: Context) {
    private val preferences = context.getSharedPreferences("payment_password", Context.MODE_PRIVATE)
    private val device = context.getSharedPreferences("payment_password_device", Context.MODE_PRIVATE)
    private val keyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    private val timed get() = device.getBoolean(TIMED, false)
    private val mutableSaved = MutableStateFlow(preferences.contains(CIPHERTEXT) && preferences.contains(IV))
    val saved: StateFlow<Boolean> = mutableSaved.asStateFlow()
    // A password saved before payments confirmed it (no [CHECKED]) was never accepted by ENZONA: it is in doubt too.
    private val mutableUnverified = MutableStateFlow(preferences.getBoolean(UNVERIFIED, false) || (mutableSaved.value && !preferences.contains(CHECKED)))
    /** ENZONA answered the last payment made with a password without confirming it: the next one asks for it again. */
    val unverified: StateFlow<Boolean> = mutableUnverified.asStateFlow()

    /** The password encrypted under this phone's key and not stored yet. Not secret without the key, kept only in memory. */
    class Sealed internal constructor(internal val ciphertext: String, internal val iv: String) {
        override fun toString() = "Sealed(redacted)"
    }

    fun clear() {
        check(preferences.edit().clear().commit()) { "No se pudo borrar el PIN" }
        for (alias in listOf(KEY_ALIAS, TIMED_ALIAS, GATE_ALIAS)) if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        mutableSaved.value = false
        mutableUnverified.value = false
    }

    fun markUnverified() {
        if (preferences.edit().putBoolean(UNVERIFIED, true).commit()) mutableUnverified.value = true
    }

    /** ENZONA confirmed a payment made with the saved password. */
    fun markVerified() {
        if (mutableUnverified.value && preferences.edit().remove(UNVERIFIED).putBoolean(CHECKED, true).commit()) mutableUnverified.value = false
    }

    fun encryptCipher(): Cipher = if (timed) gateCipher() else try {
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, createdKey(KEY_ALIAS, 0)) }
    } catch (_: KeyPermanentlyInvalidatedException) {
        clear()
        encryptCipher()
    }

    /** Stores [password] at once (Ajustes) and zeroes the bytes it used; the caller still owns (and zeroes) [password]. */
    fun save(authorized: Cipher, password: CharArray) = store(seal(authorized, password))

    /** Encrypts [password] without storing it and zeroes the bytes it used; the caller still owns (and zeroes) [password]. */
    fun seal(authorized: Cipher, password: CharArray): Sealed {
        val bytes = utf8(password)
        try {
            val cipher = if (timed) Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, createdKey(TIMED_ALIAS, TIMED_SECONDS)) } else authorized
            val encrypted = try {
                cipher.doFinal(bytes)
            } catch (e: Exception) {
                if (timed || !rejectedAfterFingerprint(e)) throw e
                // This Keystore cannot use a per-use key: the fingerprint just passed, so the timed key opens now.
                check(device.edit().putBoolean(TIMED, true).commit()) { "No se pudo guardar el PIN" }
                if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
                return seal(authorized, password)
            }
            return Sealed(Base64.encodeToString(encrypted, Base64.NO_WRAP), Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
        } finally { bytes.fill(0) }
    }

    /** Makes [sealed] the saved password, no longer in doubt. */
    fun store(sealed: Sealed) {
        check(preferences.edit().putString(CIPHERTEXT, sealed.ciphertext).putString(IV, sealed.iv).remove(UNVERIFIED).putBoolean(CHECKED, true).commit()) {
            "No se pudo guardar el PIN"
        }
        mutableSaved.value = true
        mutableUnverified.value = false
    }

    /** Null when the key died (a new fingerprint; in timed mode, the screen lock removed): the password must be typed again. */
    fun decryptCipher(): Cipher? {
        val iv = preferences.getString(IV, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        return try {
            if (timed) {
                // Only to learn whether the timed key died: without a recent fingerprint it cannot open.
                try {
                    timedDecryptCipher(iv)
                } catch (_: UserNotAuthenticatedException) {
                }
                gateCipher()
            } else {
                Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(KEY_ALIAS), GCMParameterSpec(128, iv)) }
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            clear()
            null
        }
    }

    /** The password for one payment. The caller hands it to the payment, which zeroes it. */
    fun open(authorized: Cipher): CharArray {
        val cipher = if (timed) timedDecryptCipher(Base64.decode(requireNotNull(preferences.getString(IV, null)), Base64.NO_WRAP)) else authorized
        val bytes = cipher.doFinal(Base64.decode(requireNotNull(preferences.getString(CIPHERTEXT, null)), Base64.NO_WRAP))
        try {
            val chars = Charsets.UTF_8.decode(ByteBuffer.wrap(bytes))
            return CharArray(chars.remaining()).also { chars.get(it); chars.array().fill('\u0000') }
        } finally { bytes.fill(0) }
    }

    private fun utf8(password: CharArray): ByteArray {
        val buffer = Charsets.UTF_8.encode(CharBuffer.wrap(password))
        return ByteArray(buffer.remaining()).also { buffer.get(it); buffer.array().fill(0) }
    }

    /** The timed key's cipher for the saved password, right after the fingerprint. */
    private fun timedDecryptCipher(iv: ByteArray): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(TIMED_ALIAS), GCMParameterSpec(128, iv)) }

    /** What the prompt authorizes in timed mode; it never encrypts anything. */
    private fun gateCipher(): Cipher = try {
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, createdKey(GATE_ALIAS, 0)) }
    } catch (_: KeyPermanentlyInvalidatedException) {
        keyStore.deleteEntry(GATE_ALIAS)
        gateCipher()
    }

    /**
     * The key at [alias], made if missing: for every use with the fingerprint (`seconds = 0`), or for [seconds] after
     * the fingerprint or the screen lock.
     */
    private fun createdKey(alias: String, seconds: Int): SecretKey {
        if (!keyStore.containsAlias(alias)) KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(seconds,
                    if (seconds == 0) KeyProperties.AUTH_BIOMETRIC_STRONG
                    else KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setInvalidatedByBiometricEnrollment(seconds == 0)
                .build())
            generateKey()
        }
        return key(alias)
    }

    private fun key(alias: String): SecretKey = keyStore.getKey(alias, null) as SecretKey

    /** The Keystore turned down the per-use key that the fingerprint had just authorized. */
    private fun rejectedAfterFingerprint(error: Throwable): Boolean = generateSequence(error) { it.cause }.any {
        it is UserNotAuthenticatedException ||
            (it is KeyStoreException && it.numericErrorCode == KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED)
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_ALIAS = "dev.duardo.neotransfer.plus.payment-password"
        const val TIMED_ALIAS = "dev.duardo.neotransfer.plus.payment-password.timed"
        const val GATE_ALIAS = "dev.duardo.neotransfer.plus.payment-password.gate"
        const val TIMED_SECONDS = 10
        const val CIPHERTEXT = "ciphertext"
        const val IV = "iv"
        const val UNVERIFIED = "unverified"
        const val CHECKED = "checked"
        const val TIMED = "timed"
    }
}
