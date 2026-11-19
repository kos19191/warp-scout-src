package dev.warpscout.core.keys

import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.json.parseFlatObject
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.net.HttpClient
import java.io.File

/**
 * Источник ключей WireGuard-аккаунта WARP.
 *
 * Публичный генератор (warp-generation.github.io) ходит в свой API и получает свежую пару ключей +
 * адреса. Мы используем те же зеркала, в том же порядке, с тем же заголовком X-Client — иначе ничем
 * отличаться от «скачать конфиг руками» приложение не будет. Если все зеркала лежат, берём
 * закешированный аккаунт (ключ живой, пока его не отзовут) или ключ, введённый вручную.
 */
data class KeySourceConfig(
    val mirrors: List<String> = MIRRORS,
    val timeoutMs: Int = 3500,
    val requireIpv6: Boolean = false
) {
    companion object {
        /** Те же эндпоинты, что в script.js генератора. */
        val MIRRORS = listOf(
            "https://warp-workers.warp-api.cfd",
            "https://warp-sub.warp-api.cfd",
            "https://warp-vercel-chi.warp-api.cfd",
            "https://warp-vercel-murex.warp-api.cfd",
            "https://warp-netlify.warp-api.cfd"
        )
        val MASQUE_MIRRORS = listOf(
            "https://masque-workers.warp-api.cfd",
            "https://masque-vercel.warp-api.cfd"
        )
        const val HEADER = "X-Client"
        const val HEADER_VALUE = "WARP"
    }
}

/** Хранилище последнего удачного аккаунта (на Android — приватный каталог приложения). */
interface AccountStore {
    fun load(): String?
    fun save(raw: String)

    companion object {
        fun file(path: String) = object : AccountStore {
            override fun load(): String? = runCatching { File(path).takeIf { it.exists() }?.readText() }.getOrNull()
            override fun save(raw: String) {
                runCatching { File(path).apply { parentFile?.mkdirs() }.writeText(raw) }
            }
        }
        val IN_MEMORY = object : AccountStore {
            private var data: String? = null
            override fun load(): String? = data
            override fun save(raw: String) { data = raw }
        }
    }
}

class KeySource(
    private val http: HttpClient = HttpClient(timeoutMs = 3500),
    private val store: AccountStore = AccountStore.IN_MEMORY,
    private val config: KeySourceConfig = KeySourceConfig(),
    private val manual: WarpAccount? = null
) {

    class AllMirrorsFailed(msg: String) : RuntimeException(msg)

    /** Свежий аккаунт с первого ответившего зеркала. */
    fun fetchFresh(): WarpAccount {
        val errors = StringBuilder()
        for (mirror in config.mirrors) {
            try {
                val resp = http.get(mirror, mapOf(KeySourceConfig.HEADER to KeySourceConfig.HEADER_VALUE))
                if (resp.status !in 200..299) {
                    errors.append("$mirror → HTTP ${resp.status}; ")
                    continue
                }
                val acc = parseAccount(resp.body, mirror)
                if (acc == null) {
                    errors.append("$mirror → непредсказуемый ответ; ")
                } else {
                    store.save(resp.body)
                    return acc
                }
            } catch (e: Exception) {
                errors.append("$mirror → ${e.javaClass.simpleName}; ")
            }
        }
        throw AllMirrorsFailed("ни одно зеркало не ответило: $errors")
    }

    /**
     * Основной путь: свежий ключ → кеш → ручной. Всегда возвращает *валидный* аккаунт,
     * если хоть что-то из трёх живёт.
     */
    fun account(): WarpAccount {
        return try {
            fetchFresh()
        } catch (e: Exception) {
            cached() ?: manual ?: throw AllMirrorsFailed("нет ни свежего ключа (${e.message?.take(80)}), ни кеша, ни ручного")
        }
    }

    fun cached(): WarpAccount? = store.load()?.let { parseAccount(it, "cache") }

    companion object {
        /** Разбор ответа генератора: {privKey, peer_pub, client_ipv4, client_ipv6}. */
        fun parseAccount(json: String, source: String): WarpAccount? {
            val flat = parseFlatObject(json)
            val priv = flat["privKey"] ?: return null
            val peer = flat["peer_pub"] ?: return null
            if (priv.isBlank() || peer.isBlank()) return null
            // Для WARP/AWG это Curve25519-ключи (32 байта). Для MASQUE приходят EC-ключи (длиннее) —
            // их тоже принимаем, но профиль тогда обязан быть MASQUE.
            return WarpAccount(
                privateB64 = priv.trim(),
                peerPublicB64 = peer.trim(),
                ipv4 = flat["client_ipv4"]?.trim() ?: "172.16.0.2",
                ipv6 = flat["client_ipv6"]?.trim(),
                source = source
            )
        }

        fun looksLikeCurve25519(b64: String): Boolean = runCatching { Crypto.unBase64(b64).size == 32 }.getOrDefault(false)
    }
}
