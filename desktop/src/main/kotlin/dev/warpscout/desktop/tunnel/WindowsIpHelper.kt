package dev.warpscout.desktop.tunnel

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Прямые JNA-привязки к системной библиотеке Windows `iphlpapi.dll` (IP Helper API).
 *
 * Зачем вместо PowerShell `New-NetRoute`:
 *  • `New-NetRoute` делает WMI/CIM-вызов на каждый префикс (~15–25 мс на маршрут → 21 000 маршрутов
 *    обхода РФ ставились бы несколько минут);
 *  • `CreateIpForwardEntry2` (ровно тот же Win32 API, что использует официальный WireGuard for Windows)
 *    добавляет тысячи маршрутов напрямую в ядро `tcpip.sys` за доли/единицы секунд;
 *  • все маршруты привязываются к `InterfaceLuid` нашего адаптера Wintun — при закрытии адаптера или
 *    аварийном завершении процесса Windows мгновенно и автоматически удаляет их все без остатка.
 */
interface IpHlpApi : Library {
    fun InitializeIpForwardEntry(row: Pointer)
    fun CreateIpForwardEntry2(row: Pointer): Int
}

data class RouteInstallSummary(
    val total: Int,
    val added: Int,
    val existed: Int,
    val failed: Int,
    val elapsedMs: Long
) {
    val ok: Boolean get() = total == 0 || (added + existed) > 0
}

object WindowsIpHelper {

    /**
     * Размер и смещения полей структуры `MIB_IPFORWARD_ROW2` (Windows SDK `netioapi.h` + `ws2ipdef.h`):
     *  • 0..7   : InterfaceLuid (NET_LUID / ULONG64)
     *  • 8..11  : InterfaceIndex (ULONG)
     *  • 12..39 : DestinationPrefix.Prefix (SOCKADDR_INET, 28 байт)
     *             IPv4: family@12 (u16=2), sin_addr@16 (4 байта)
     *             IPv6: family@12 (u16=23), sin6_addr@20 (16 байт)
     *  • 40     : DestinationPrefix.PrefixLength (UINT8)
     *  • 44..71 : NextHop (SOCKADDR_INET, 28 байт; family@44, нули = on-link на L3 Wintun)
     *  • 72     : SitePrefixLength (UCHAR)
     *  • 76..79 : ValidLifetime (ULONG)
     *  • 80..83 : PreferredLifetime (ULONG)
     *  • 84..87 : Metric (ULONG)
     *  • 88..91 : Protocol (NL_ROUTE_PROTOCOL)
     *  • 92..95 : Loopback / AutoconfigureAddress / Publish / Immortal (4 × BOOLEAN)
     *  • 96..99 : Age (ULONG)
     *  • 100..103: Origin (NL_ROUTE_ORIGIN)
     */
    internal const val ROW_SIZE = 104
    internal const val OFF_INTERFACE_LUID = 0L
    internal const val OFF_DEST_FAMILY = 12L
    internal const val OFF_DEST_V4 = 16L
    internal const val OFF_DEST_V6 = 20L
    internal const val OFF_DEST_PREFIX_LEN = 40L
    internal const val OFF_NEXTHOP_FAMILY = 44L
    internal const val OFF_VALID_LIFETIME = 76L
    internal const val OFF_PREFERRED_LIFETIME = 80L
    internal const val OFF_METRIC = 84L

    private const val AF_INET: Short = 2
    private const val AF_INET6: Short = 23
    private const val NO_ERROR = 0
    private const val ERROR_OBJECT_ALREADY_EXISTS = 5010

    @Volatile
    private var cachedApi: IpHlpApi? = null

    @Synchronized
    internal fun loadApi(): IpHlpApi {
        cachedApi?.let { return it }
        val api = Native.load("iphlpapi", IpHlpApi::class.java)
        cachedApi = api
        return api
    }

    /**
     * Быстро устанавливает список on-link маршрутов (`0.0.0.0` / `::`) на адаптер Wintun по его `LUID`.
     */
    fun addOnLinkRoutes(
        adapterLuid: Long,
        cidrs: List<String>,
        metric: Int = 5
    ): RouteInstallSummary {
        val t0 = System.currentTimeMillis()
        if (cidrs.isEmpty()) return RouteInstallSummary(0, 0, 0, 0, 0)
        val api = loadApi()
        val buf = Memory(ROW_SIZE.toLong())

        var added = 0
        var existed = 0
        var failed = 0

        for (raw in cidrs) {
            val slash = raw.indexOf('/')
            if (slash <= 0) {
                failed++
                continue
            }
            val host = raw.substring(0, slash).trim()
            val prefixLen = raw.substring(slash + 1).trim().toIntOrNull()
            if (prefixLen == null) {
                failed++
                continue
            }

            if (':' !in host) {
                val ipLong = CidrMath.parseIpv4(host)
                if (ipLong == null || prefixLen !in 0..32) {
                    failed++
                    continue
                }
                val mask = if (prefixLen == 0) 0L else (0xFFFF_FFFFL shl (32 - prefixLen)) and 0xFFFF_FFFFL
                val net = ipLong and mask
                val bytes = byteArrayOf(
                    ((net ushr 24) and 0xFF).toByte(),
                    ((net ushr 16) and 0xFF).toByte(),
                    ((net ushr 8) and 0xFF).toByte(),
                    (net and 0xFF).toByte()
                )
                buf.clear()
                api.InitializeIpForwardEntry(buf)
                buf.setLong(OFF_INTERFACE_LUID, adapterLuid)
                buf.setShort(OFF_DEST_FAMILY, AF_INET)
                buf.write(OFF_DEST_V4, bytes, 0, 4)
                buf.setByte(OFF_DEST_PREFIX_LEN, prefixLen.toByte())
                buf.setShort(OFF_NEXTHOP_FAMILY, AF_INET)
                buf.setInt(OFF_METRIC, metric)
            } else {
                if (prefixLen !in 0..128) {
                    failed++
                    continue
                }
                val addr = runCatching { InetAddress.getByName(host) as? Inet6Address }.getOrNull()
                if (addr == null) {
                    failed++
                    continue
                }
                val bytes = maskBytes(addr.address, prefixLen)
                buf.clear()
                api.InitializeIpForwardEntry(buf)
                buf.setLong(OFF_INTERFACE_LUID, adapterLuid)
                buf.setShort(OFF_DEST_FAMILY, AF_INET6)
                buf.write(OFF_DEST_V6, bytes, 0, 16)
                buf.setByte(OFF_DEST_PREFIX_LEN, prefixLen.toByte())
                buf.setShort(OFF_NEXTHOP_FAMILY, AF_INET6)
                buf.setInt(OFF_METRIC, metric)
            }

            when (api.CreateIpForwardEntry2(buf)) {
                NO_ERROR -> added++
                ERROR_OBJECT_ALREADY_EXISTS -> existed++
                else -> failed++
            }
        }

        val elapsed = System.currentTimeMillis() - t0
        return RouteInstallSummary(cidrs.size, added, existed, failed, elapsed)
    }

    private fun maskBytes(raw: ByteArray, prefixLen: Int): ByteArray {
        val out = raw.copyOf()
        val fullBytes = prefixLen / 8
        val remBits = prefixLen % 8
        if (fullBytes < out.size) {
            if (remBits > 0) {
                val mask = (0xFF shl (8 - remBits)) and 0xFF
                out[fullBytes] = (out[fullBytes].toInt() and mask).toByte()
                for (i in (fullBytes + 1) until out.size) out[i] = 0
            } else {
                for (i in fullBytes until out.size) out[i] = 0
            }
        }
        return out
    }
}
