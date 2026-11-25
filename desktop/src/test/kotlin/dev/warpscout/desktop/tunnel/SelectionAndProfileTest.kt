package dev.warpscout.desktop.tunnel

import dev.warpscout.core.config.WgConf
import dev.warpscout.core.junk.JunkLibrary
import dev.warpscout.core.model.Candidate
import dev.warpscout.core.model.Endpoint
import dev.warpscout.core.model.EndpointStats
import dev.warpscout.core.model.JunkProfile
import dev.warpscout.core.model.Verdict
import dev.warpscout.core.model.WarpAccount
import dev.warpscout.core.model.WarpConfig
import dev.warpscout.core.net.EndpointPool
import dev.warpscout.core.net.EndpointSpec
import dev.warpscout.core.tune.AutoTuner
import dev.warpscout.core.tune.Scoring
import dev.warpscout.core.tune.Shortlist
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SelectionAndProfileTest {

    private fun cand(
        host: String,
        port: Int,
        junk: JunkProfile,
        replies: Int = 3,
        ok: Int = -1,
        total: Int = 0
    ): Candidate {
        val cfg = WarpConfig(
            name = "test",
            account = WarpAccount("a=", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "172.16.0.2"),
            endpoint = Endpoint(host, port),
            junk = junk,
            allowedIps = "0.0.0.0/0",
            comments = listOf("профиль шума: ${junk.name}")
        )
        val stats = EndpointStats(cfg.endpoint, emptyList(), Verdict.HANDSHAKE_OK, replies, 3)
        return Candidate(
            config = cfg,
            stats = stats,
            parts = Scoring.evaluate(stats, replies > 0, ok.coerceAtLeast(0), total),
            resourcesOk = ok,
            resourcesTotal = total
        )
    }

    @Test
    fun `Shortlist excludes proven-broken 0-of-10 candidates in favor of untested alive candidates`() {
        val brokenNone1 = cand("162.159.192.10", 8886, JunkLibrary.none(), ok = 0, total = 10)
        val brokenNone2 = cand("162.159.195.6", 500, JunkLibrary.none(), ok = 0, total = 10)
        val workingUntestedSip = cand("162.159.192.10", 880, JunkLibrary.sip(), ok = -1, total = 0)
        val workingUntestedQuic = cand("162.159.193.4", 2408, JunkLibrary.quic("deepseek.com"), ok = -1, total = 0)

        val picked = Shortlist.pick(listOf(brokenNone1, brokenNone2, workingUntestedSip, workingUntestedQuic))
        assertEquals(2, picked.size)
        assertTrue(picked.none { it.resourcesTotal > 0 && it.resourcesOk == 0 }, "0/10 broken configs must not be shortlisted")
        assertEquals("sip-invite", picked[0].junk.name)
    }

    @Test
    fun `AutoTuner selectForVerification diversifies junk kinds and endpoints instead of repeating none`() {
        val ordered = listOf(
            cand("162.159.192.10", 8886, JunkLibrary.none()),
            cand("162.159.195.6", 500, JunkLibrary.none()),
            cand("162.159.195.6", 500, JunkLibrary.tlsFixed()),
            cand("162.159.192.10", 880, JunkLibrary.sip()),
            cand("162.159.193.7", 4500, JunkLibrary.quic("akbars.ru"))
        )

        val selected = AutoTuner.selectForVerification(ordered, maxCount = 5)
        val firstThreeKinds = selected.take(3).map { it.junk.kind }.toSet()
        assertTrue(firstThreeKinds.size == 3, "First 3 verification slots must cover 3 distinct junk kinds: $firstThreeKinds")
        assertTrue(selected.take(3).any { it.junk.name == "sip-invite" }, "sip-invite must be verified in top-3")
        assertEquals(3, selected.take(3).map { it.config.endpoint.render() }.distinct().size, "Top-3 must use distinct endpoints")
    }

    @Test
    fun `WgConf round-trip preserves real junk profile name instead of imported`() {
        val sipCfg = WarpConfig(
            name = "WARP-Auto",
            account = WarpAccount(
                privateB64 = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=",
                peerPublicB64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                ipv4 = "172.16.0.2"
            ),
            endpoint = Endpoint("162.159.192.10", 880),
            junk = JunkLibrary.sip(),
            allowedIps = "0.0.0.0/0",
            comments = listOf("сгенерировано WARP Scout", "профиль шума: sip-invite")
        )
        val rendered = WgConf.render(sipCfg)
        val parsed = WgConf.toWarpConfig("Active", rendered)!!
        assertEquals("sip-invite", parsed.junk.name)

        // Второй цикл render → parse (как в connectActive) тоже сохраняет имя профиля!
        val renderedAgain = WgConf.render(parsed)
        val parsedAgain = WgConf.toWarpConfig("Active2", renderedAgain)!!
        assertEquals("sip-invite", parsedAgain.junk.name)

        // Чистый WireGuard без комментария автоматически распознаётся как none (Jc = 0, без I1/I2).
        val noneCfg = sipCfg.copy(junk = JunkLibrary.none(), comments = emptyList())
        val parsedNone = WgConf.toWarpConfig("None", WgConf.render(noneCfg))!!
        assertEquals("none", parsedNone.junk.name)
    }

    @Test
    fun `selectForVerification and Shortlist diversify across Cloudflare slash-24 subnets`() {
        val ordered = listOf(
            cand("162.159.195.5", 500, JunkLibrary.sip()),
            cand("162.159.195.6", 891, JunkLibrary.tlsFixed()),
            cand("162.159.195.7", 2408, JunkLibrary.quic("akbars.ru")),
            cand("162.159.192.10", 880, JunkLibrary.sip()),
            cand("188.114.97.4", 4500, JunkLibrary.tlsFixed())
        )
        val toVerify = AutoTuner.selectForVerification(ordered, maxCount = 5)
        val top3Subnets = toVerify.take(3).map { AutoTuner.subnet24Of(it.config.endpoint.host) }.toSet()
        assertEquals(3, top3Subnets.size, "Top-3 verification slots must cover 3 distinct /24 PoP subnets: $top3Subnets")

        val picked = Shortlist.pick(ordered, limit = 3)
        val pickedSubnets = picked.map { AutoTuner.subnet24Of(it.config.endpoint.host) }.toSet()
        assertEquals(3, pickedSubnets.size, "Shortlist Top-3 must prefer distinct /24 PoP subnets: $pickedSubnets")

        assertTrue(ExitInfo(colo = "DME", warpOn = true).isRussianColo)
        assertTrue(!ExitInfo(colo = "ARN", warpOn = true).isRussianColo)
    }

    @Test
    fun `EndpointPool stratified mode covers all Cloudflare subnets even at maxEndpoints 120`() {
        val pool = EndpointPool.build(EndpointSpec(maxEndpoints = 120))
        assertEquals(120, pool.size)
        val subnets = pool.map { AutoTuner.subnet24Of(it.host) }.toSet()
        assertTrue(subnets.size >= 12, "Stratified pool of 120 endpoints must cover >=12 subnets, got ${subnets.size}: $subnets")
        assertTrue("162.159.192" in subnets)
        assertTrue("162.159.195" in subnets)
        assertTrue("188.114.96" in subnets)
        assertTrue("188.114.97" in subnets)

        // pickRefineCandidates также охватывает разные /24-подсети даже при одинаковом вердикте UDP_SILENT.
        val silentRanked = pool.map { ep ->
            EndpointStats(ep, emptyList(), Verdict.UDP_SILENT, replies = 0, attempts = 3)
        }
        val refine = AutoTuner.pickRefineCandidates(silentRanked, limit = 10)
        val refineSubnets = refine.map { AutoTuner.subnet24Of(it.endpoint.host) }.toSet()
        assertEquals(10, refineSubnets.size, "Phase-2 refine candidates must span 10 distinct /24 subnets: $refineSubnets")
    }
}
