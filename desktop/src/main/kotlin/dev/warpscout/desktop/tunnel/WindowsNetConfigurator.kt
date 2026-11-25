package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.SplitRoutes

data class PhysicalGateway(
    val nextHop: String,
    val interfaceIndex: Int
)

/**
 * Настройка сетевого интерфейса Wintun, DNS и таблицы маршрутизации Windows.
 *
 * Ключевые гарантии безопасности сети:
 *  1. Перед добавлением маршрутов в туннель определяем физический шлюз и добавляем `/32`
 *     bypass-маршруты до IP точек WARP (и Второго выхода) через физическую сетевую карту —
 *     петля маршрутизации невозможна.
 *  2. Полный туннель (`0.0.0.0/0`, `::/0`) реализуется через парные префиксы
 *     `0.0.0.0/1 + 128.0.0.0/1` и `::/1 + 8000::/1`: мы НИКОГДА не удаляем физический
 *     маршрут по умолчанию пользователя. При закрытии адаптера Wintun Windows сама мгновенно
 *     удаляет все маршруты туннеля и возвращает обычный интернет.
 *  3. Все маршруты применяются одним пакетным вызовом PowerShell — быстро даже на сотнях CIDR.
 */
class WindowsNetConfigurator(
    private val runner: CommandRunner = ProcessCommandRunner(),
    private val onLog: (String) -> Unit = {}
) {

    fun detectPhysicalGateway(): PhysicalGateway? {
        val ps = """
            ${'$'}r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { ${'$'}_.NextHop -and ${'$'}_.NextHop -ne '0.0.0.0' } |
                Sort-Object -Property { ${'$'}_.RouteMetric + ${'$'}_.InterfaceMetric } |
                Select-Object -First 1
            if (${'$'}r) { Write-Output "${'$'}(${'$'}r.NextHop)|${'$'}(${'$'}r.InterfaceIndex)" }
        """.trimIndent()
        val res = runPs(ps, timeoutMs = 8000L)
        if (!res.ok) return null
        return parseGatewayOutput(res.stdout)
    }

    /** Добавляет `/32` маршруты к endpoint'ам через физическую карту (чтобы UDP не уходил в туннель). */
    fun addBypassHostRoutes(ipv4Hosts: List<String>, gateway: PhysicalGateway?): List<String> {
        val gw = gateway ?: return emptyList()
        val valid = ipv4Hosts.filter { CidrMath.parseIpv4(it) != null }.distinct()
        if (valid.isEmpty()) return emptyList()
        val added = ArrayList<String>()
        for (ip in valid) {
            // Сначала тихо удаляем возможный старый маршрут, затем добавляем свежий.
            runner.run(listOf("route.exe", "DELETE", ip), timeoutMs = 4000L)
            val res = runner.run(
                listOf("route.exe", "ADD", ip, "MASK", "255.255.255.255", gw.nextHop, "METRIC", "5", "IF", gw.interfaceIndex.toString()),
                timeoutMs = 5000L
            )
            if (res.ok) {
                added.add(ip)
            } else {
                onLog("bypass-маршрут $ip: ${res.combined.take(120)}")
            }
        }
        return added
    }

    fun removeBypassHostRoutes(ipv4Hosts: List<String>) {
        for (ip in ipv4Hosts.distinct()) {
            runner.run(listOf("route.exe", "DELETE", ip), timeoutMs = 4000L)
        }
    }

    /** Назначает IPv4/IPv6, MTU, низкую метрику и DNS на созданный Wintun-адаптер. */
    fun configureAdapter(
        adapterName: String,
        ipv4: String,
        ipv6: String?,
        mtu: Int,
        dnsServers: List<String>
    ): CommandResult {
        val safeName = psEscape(adapterName)
        val cleanV4 = ipv4.substringBefore('/').trim()
        val cleanV6 = ipv6?.substringBefore('/')?.trim()?.takeIf { it.isNotBlank() }
        val dnsFiltered = dnsServers.map { it.trim() }.filter { it.isNotEmpty() }
        val dnsArrayPs = dnsFiltered.joinToString(", ") { "'${psEscape(it)}'" }

        val script = buildString {
            appendLine("\$ErrorActionPreference = 'Stop'")
            appendLine("\$adapter = \$null")
            appendLine("for (\$i = 0; \$i -lt 25; \$i++) {")
            appendLine("  \$adapter = Get-NetAdapter -Name '$safeName' -ErrorAction SilentlyContinue")
            appendLine("  if (\$adapter) { break }")
            appendLine("  Start-Sleep -Milliseconds 150")
            appendLine("}")
            appendLine("if (-not \$adapter) { throw 'Адаптер $safeName не появился в Windows' }")
            appendLine("\$idx = \$adapter.ifIndex")
            appendLine("Get-NetIPAddress -InterfaceIndex \$idx -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:\$false -ErrorAction SilentlyContinue")
            appendLine("New-NetIPAddress -InterfaceIndex \$idx -IPAddress '${psEscape(cleanV4)}' -PrefixLength 32 -AddressFamily IPv4 -ErrorAction Stop | Out-Null")
            appendLine("Set-NetIPInterface -InterfaceIndex \$idx -AddressFamily IPv4 -InterfaceMetric 5 -NlMtuBytes $mtu -ErrorAction SilentlyContinue")
            if (cleanV6 != null) {
                appendLine("New-NetIPAddress -InterfaceIndex \$idx -IPAddress '${psEscape(cleanV6)}' -PrefixLength 128 -AddressFamily IPv6 -ErrorAction SilentlyContinue | Out-Null")
                appendLine("Set-NetIPInterface -InterfaceIndex \$idx -AddressFamily IPv6 -InterfaceMetric 5 -NlMtuBytes $mtu -ErrorAction SilentlyContinue")
            }
            if (dnsFiltered.isNotEmpty()) {
                appendLine("Set-DnsClientServerAddress -InterfaceIndex \$idx -ServerAddresses @($dnsArrayPs) -ErrorAction SilentlyContinue")
            }
            appendLine("Write-Output \"ifIndex=\$idx\"")
        }
        return runPs(script, timeoutMs = 15_000L)
    }

    /** Проверяет, есть ли у физического подключения пользователя глобальный IPv6-маршрут по умолчанию. */
    fun hasPhysicalIpv6DefaultRoute(): Boolean {
        val ps = """
            ${'$'}r = Get-NetRoute -DestinationPrefix '::/0' -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object { ${'$'}_.NextHop -and ${'$'}_.NextHop -ne '::' } |
                Select-Object -First 1
            if (${'$'}r) { Write-Output 'yes' }
        """.trimIndent()
        val res = runPs(ps, timeoutMs = 5000L)
        return res.ok && res.stdout.trim().equals("yes", ignoreCase = true)
    }

    /**
     * Устанавливает маршруты туннеля на адаптер Wintun.
     *
     * `0.0.0.0/0` автоматически разворачивается в `0.0.0.0/1` + `128.0.0.0/1`.
     * Если передан [adapterLuid] на Windows — маршруты ставятся напрямую через `iphlpapi.dll`
     * (`CreateIpForwardEntry2`), что в ~100× быстрее PowerShell `New-NetRoute` и критично
     * для пресета обхода РФ (~21 000 зарубежных подсетей).
     */
    fun applyRoutes(
        adapterName: String,
        allowedIpsCsv: String,
        extraCidrs: List<String> = emptyList(),
        enableIpv6: Boolean = true,
        adapterLuid: Long? = null
    ): CommandResult {
        val allPrefixes = expandSafeRoutes(allowedIpsCsv, extraCidrs, enableIpv6)
        if (allPrefixes.isEmpty()) return CommandResult(0, "нет маршрутов", "")

        val v4List = allPrefixes.filter { ':' !in it }
        var v6List = allPrefixes.filter { ':' in it }

        // Для большого split-списка IPv6 (пресет обхода РФ) не захламляем таблицу маршрутов на IPv4-only провайдерах.
        if (v6List.size > 100 && !hasPhysicalIpv6DefaultRoute()) {
            onLog("Физический IPv6 у провайдера отсутствует — пропускаю ${v6List.size} IPv6-маршрутов")
            v6List = emptyList()
        }
        val prefixes = v4List + v6List

        // Быстрый путь: прямой Win32 IP Helper API (`CreateIpForwardEntry2`) по LUID адаптера Wintun.
        if (adapterLuid != null && WindowsAutostart.isWindows()) {
            val nativeRes = runCatching {
                WindowsIpHelper.addOnLinkRoutes(adapterLuid, prefixes, metric = 5)
            }.getOrNull()
            if (nativeRes != null && nativeRes.ok) {
                flushDns()
                val msg = "routes_native=${nativeRes.added + nativeRes.existed}/${nativeRes.total} за ${nativeRes.elapsedMs} мс" +
                    if (nativeRes.failed > 0) " (ошибок: ${nativeRes.failed})" else ""
                onLog("Маршруты применены: $msg")
                return CommandResult(0, msg, "")
            }
            onLog("Не удалось применить маршруты через iphlpapi.dll — пробую PowerShell…")
        }

        val safeName = psEscape(adapterName)
        val script = buildString {
            appendLine("\$adapter = Get-NetAdapter -Name '$safeName' -ErrorAction Stop")
            appendLine("\$idx = \$adapter.ifIndex")
            if (v4List.isNotEmpty()) {
                val arr = v4List.joinToString(", ") { "'${psEscape(it)}'" }
                appendLine("foreach (\$p in @($arr)) {")
                appendLine("  New-NetRoute -DestinationPrefix \$p -InterfaceIndex \$idx -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null")
                appendLine("}")
            }
            if (v6List.isNotEmpty()) {
                val arr = v6List.joinToString(", ") { "'${psEscape(it)}'" }
                appendLine("foreach (\$p in @($arr)) {")
                appendLine("  New-NetRoute -DestinationPrefix \$p -InterfaceIndex \$idx -NextHop '::' -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null")
                appendLine("}")
            }
            appendLine("Clear-DnsClientCache -ErrorAction SilentlyContinue")
            appendLine("Write-Output 'routes_ok=${v4List.size + v6List.size}'")
        }
        return runPs(script, timeoutMs = 20_000L)
    }

    fun flushDns() {
        runner.run(listOf("ipconfig.exe", "/flushdns"), timeoutMs = 5000L)
    }

    private fun runPs(script: String, timeoutMs: Long): CommandResult =
        runner.run(
            listOf("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script),
            timeoutMs = timeoutMs
        )

    private fun psEscape(s: String): String = s.replace("'", "''")

    companion object {
        fun parseGatewayOutput(output: String): PhysicalGateway? {
            val line = output.lineSequence().map { it.trim() }.firstOrNull { '|' in it } ?: return null
            val parts = line.split('|')
            if (parts.size != 2) return null
            val hop = parts[0].trim()
            val idx = parts[1].trim().toIntOrNull() ?: return null
            if (CidrMath.parseIpv4(hop) == null || idx <= 0) return null
            return PhysicalGateway(hop, idx)
        }

        /**
         * Разворачивает `0.0.0.0/0` → `0.0.0.0/1, 128.0.0.0/1` и `::/0` → `::/1, 8000::/1`,
         * чтобы не затирать физический шлюз по умолчанию, и объединяет с `extraCidrs` (Второй выход).
         */
        fun expandSafeRoutes(
            allowedIpsCsv: String,
            extraCidrs: List<String> = emptyList(),
            enableIpv6: Boolean = true
        ): List<String> {
            val raw = SplitRoutes.prefixesOf(allowedIpsCsv) + extraCidrs.map { it.trim() }.filter { '/' in it }
            val out = LinkedHashSet<String>()
            for (cidr in raw) {
                val c = cidr.trim()
                when {
                    c == "0.0.0.0/0" -> {
                        out.add("0.0.0.0/1")
                        out.add("128.0.0.0/1")
                    }
                    c == "::/0" -> {
                        if (enableIpv6) {
                            out.add("::/1")
                            out.add("8000::/1")
                        }
                    }
                    ':' in c -> if (enableIpv6) out.add(c)
                    else -> out.add(c)
                }
            }
            return out.toList()
        }
    }
}
