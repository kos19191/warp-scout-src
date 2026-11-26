package dev.warpscout.core.tune

import dev.warpscout.core.model.Candidate
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats

/**
 * Разнообразие точек подбора (с 1.10.49-beta2, перенесено из версии для компьютера).
 *
 * У российских провайдеров разные семейства адресов Cloudflare (первый байт адреса: 8.*, 162.*,
 * 188.*) часто уходят в разные площадки: 8.* — в Москву (DME), 162.* и 188.* — во Франкфурт,
 * Стокгольм, Хельсинки. Самые быстрые по пингу точки — как раз московские, поэтому «лучшие по
 * баллу» раз за разом оказывались из одного семейства с одним и тем же выходом через Москву
 * (журнал 24.11: все три сохранённые точки — 8.*, все через DME, 6 из 8 сайтов). Отсюда правило:
 * сначала по лучшей точке от каждого семейства, потом разные подсети /24, потом остальные по рангу.
 */
object PointMix {

    /** Семейство адреса: первый байт IPv4 («8», «162», «188»); не IPv4 — сам адрес. */
    fun familyOf(host: String): String {
        val parts = host.split('.')
        return if (parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } }) parts[0] else host.lowercase()
    }

    /** Подсеть /24: «8.34.70.3» → «8.34.70»; не IPv4 — сам адрес. */
    fun subnetOf(host: String): String {
        val parts = host.split('.')
        return if (parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } }) parts.take(3).joinToString(".") else host.lowercase()
    }

    fun familyOf(e: Endpoint): String = familyOf(e.host)
    fun subnetOf(e: Endpoint): String = subnetOf(e.host)

    /**
     * Кого проверять подробно (с профилями шума). [first] — точки, которые проверяются в любом случае
     * (прежняя очередь сети); дальше по лучшей точке от каждого ещё не взятого семейства, затем
     * лучшие из ещё не взятых подсетей /24, остаток — по рангу [ranked] (лучшие первыми).
     */
    fun pickRefine(first: List<EndpointStats>, ranked: List<EndpointStats>, limit: Int): List<EndpointStats> {
        if (limit <= 0) return emptyList()
        val out = ArrayList<EndpointStats>()
        val endpoints = HashSet<String>()
        val subnets = HashSet<String>()
        val families = HashSet<String>()
        fun add(s: EndpointStats): Boolean {
            if (out.size >= limit || !endpoints.add(s.endpoint.render())) return false
            subnets += subnetOf(s.endpoint)
            families += familyOf(s.endpoint)
            out += s
            return true
        }
        first.forEach { add(it) }
        for (s in ranked) if (familyOf(s.endpoint) !in families) add(s)
        for (s in ranked) if (subnetOf(s.endpoint) !in subnets) add(s)
        for (s in ranked) add(s)
        return out
    }

    /**
     * Кого проверять изнутри туннеля, в каком порядке. [ordered] — кандидаты «точка + шум», лучшие
     * первыми. Только годные ([Candidate.usable]): сначала лучший от каждого семейства адресов, потом
     * из новых подсетей /24, потом новые точки, потом остальные годные. Негодные — лишь чтобы набрать
     * [floor] (столько проверялось до 1.10.49-beta2: годных может не быть вовсе).
     */
    fun forVerification(ordered: List<Candidate>, max: Int, floor: Int = 3): List<Candidate> {
        if (max <= 0 || ordered.isEmpty()) return emptyList()
        val out = ArrayList<Candidate>()
        val keys = HashSet<String>()
        val endpoints = HashSet<String>()
        val subnets = HashSet<String>()
        val families = HashSet<String>()
        fun add(c: Candidate, newSubnet: Boolean, newEndpoint: Boolean, cap: Int = max): Boolean {
            if (out.size >= cap) return false
            val e = c.config.endpoint
            if (newSubnet && subnetOf(e) in subnets) return false
            if (newEndpoint && e.render() in endpoints) return false
            if (!keys.add(e.render() + "|" + c.junk.name)) return false
            endpoints += e.render()
            subnets += subnetOf(e)
            families += familyOf(e)
            out += c
            return true
        }
        val usable = ordered.filter { it.usable }
        for (c in usable) if (familyOf(c.config.endpoint) !in families) add(c, newSubnet = true, newEndpoint = true)
        for (c in usable) add(c, newSubnet = true, newEndpoint = true)
        for (c in usable) add(c, newSubnet = false, newEndpoint = true)
        for (c in usable) add(c, newSubnet = false, newEndpoint = false)
        val cap = minOf(max, floor)
        for (c in ordered) add(c, newSubnet = false, newEndpoint = true, cap = cap)
        for (c in ordered) add(c, newSubnet = false, newEndpoint = false, cap = cap)
        return out
    }

    /**
     * Хватит ли проверять изнутри: после [STOP_AFTER] проверенных — если хотя бы две точки открыли
     * не меньше 80% сайтов («сильные»). Посредственные 6 из 8 (так выходит через DME) проверку не
     * останавливают: дальше могут быть точки с выходом за рубежом.
     */
    fun enough(verifiedOk: List<Int>, total: Int): Boolean {
        if (verifiedOk.size < STOP_AFTER || total <= 0) return false
        return verifiedOk.count { it * 10 >= total * 8 } >= 2
    }

    /** Сколько проверить изнутри до правила [enough]. */
    const val STOP_AFTER = 3

    /** Сколько проверить изнутри при полном подборе; быстрый старт — не больше [STOP_AFTER]. */
    const val VERIFY_MAX = 4
}
