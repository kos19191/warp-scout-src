package dev.warpscout.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dev.warpscout.core.keys.AccountStore
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Приватный ключ аккаунта хранится зашифрованным ключом из AndroidKeyStore (никогда не в
 * открытом виде и не в резервных копиях — см. dataExtractionRules).
 */
class KeyVault(context: Context) {

    private val prefs = context.getSharedPreferences("warpscout_vault", Context.MODE_PRIVATE)

    private fun secretKey(): SecretKey? = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey) ?: run {
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            gen.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            gen.generateKey()
        }
    }.getOrNull()

    fun put(alias: String, value: String): Boolean {
        val key = secretKey() ?: return false
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val ct = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            val blob = Base64.encodeToString(cipher.iv + ct, Base64.NO_WRAP)
            prefs.edit().putString(alias, blob).apply()
            true
        }.getOrDefault(false)
    }

    fun get(alias: String): String? {
        val blob = prefs.getString(alias, null) ?: return null
        val key = secretKey() ?: return null
        return runCatching {
            val raw = Base64.decode(blob, Base64.NO_WRAP)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE, key,
                GCMParameterSpec(128, raw.copyOfRange(0, 12))
            )
            String(cipher.doFinal(raw, 12, raw.size - 12), Charsets.UTF_8)
        }.getOrNull() ?: run {
            // ключ в keyStore мог быть сброшен (прошивка/сброс отпечатка) — чистим мусор
            prefs.edit().remove(alias).apply()
            null
        }
    }

    fun clear() = prefs.edit().clear().apply()

    /** [AccountStore] из ядра поверх хранилища: кеш аккаунта генератора лежит в вольте. */
    fun accountStore(): AccountStore = object : AccountStore {
        override fun load(): String? = get(ALIAS_ACCOUNT)
        override fun save(raw: String) {
            if (!put(ALIAS_ACCOUNT, raw)) prefs.edit().putString(ALIAS_ACCOUNT_PLAIN, raw).apply()
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "warpscout.aes.gcm"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val ALIAS_ACCOUNT = "account"
        const val ALIAS_ACCOUNT_PLAIN = "account.plain"
    }
}
