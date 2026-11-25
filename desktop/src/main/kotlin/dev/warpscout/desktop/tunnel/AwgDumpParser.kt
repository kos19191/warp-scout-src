package dev.warpscout.desktop.tunnel

/**
 * Снимок состояния peer'а из вывода `awg.exe show <tunnel> dump` (или `wg.exe show <tunnel> dump`).
 *
 * Формат строк `show <iface> dump` (разделитель TAB):
 *   Строка 1 (интерфейс): private-key \t public-key \t listen-port \t fwmark ...
 *   Строки 2+ (peer):     public-key \t preshared-key \t endpoint \t allowed-ips \t
 *                         latest-handshake-epoch-sec \t transfer-rx-bytes \t transfer-tx-bytes \t
 *                         persistent-keepalive
 */
data class TunnelPeerStats(
    val peerPublicKey: String,
    val endpoint: String,
    val latestHandshakeEpochSec: Long,
    val rxBytes: Long,
    val txBytes: Long,
    val keepaliveSec: Int
) {
    val hasHandshake: Boolean get() = latestHandshakeEpochSec > 0L

    fun handshakeAgeSec(nowEpochSec: Long = System.currentTimeMillis() / 1000L): Long =
        if (latestHandshakeEpochSec <= 0L) Long.MAX_VALUE
        else (nowEpochSec - latestHandshakeEpochSec).coerceAtLeast(0L)
}

object AwgDumpParser {

    fun parseFirstPeer(dumpOutput: String): TunnelPeerStats? {
        val lines = dumpOutput.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toList()
        if (lines.size < 2) return null

        // Первая строка — интерфейс; ищем первую корректную строку peer'а (8 полей через TAB).
        for (line in lines.drop(1)) {
            val cols = line.split('\t')
            if (cols.size < 7) continue
            val pub = cols[0].trim()
            if (pub.isBlank()) continue
            val endpoint = cols[2].trim().let { if (it == "(none)") "" else it }
            val handshake = cols[4].trim().toLongOrNull() ?: 0L
            val rx = cols[5].trim().toLongOrNull() ?: 0L
            val tx = cols[6].trim().toLongOrNull() ?: 0L
            val ka = cols.getOrNull(7)?.trim()?.let { if (it == "off") 0 else it.toIntOrNull() ?: 0 } ?: 0
            return TunnelPeerStats(
                peerPublicKey = pub,
                endpoint = endpoint,
                latestHandshakeEpochSec = handshake,
                rxBytes = rx,
                txBytes = tx,
                keepaliveSec = ka
            )
        }
        return null
    }
}
