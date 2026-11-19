package dev.warpscout.core.config

/**
 * Под что компилировать конфиг.
 *
 * Один и тот же [dev.warpscout.core.model.WarpConfig] умеет превращаться в три разных файла:
 * от этого зависит, куда пользователь его вставит — и, что важнее, будет ли он вообще рабочим.
 *
 *  • [WIREGUARD] — чистый WireGuard: без `Jc/Jmin/Jmax/H1..H4/S1..S4/I1/I2`. Сток-WireGuard,
 *    роутер, раздел «WireGuard» в AmneziaVPN, WireGuard-клиент на ПК. Мусорные поля там просто
 *    не понимают, а часть клиентов на неизвестных ключах падает;
 *  • [AMNEZIAWG] — тот же конфиг + параметры обфускации: нужен против DPI, ставится в AmneziaWG
 *    (или в Amnezia в раздел AmneziaWG);
 *  • [CLASH] — YAML для Clash Meta / Stash / FlClash с блоком `amnezia-wg-option`.
 */
enum class ConfigTarget(
    val title: String,
    val note: String,
    val supportsJunk: Boolean,
    val yaml: Boolean
) {
    WIREGUARD(
        title = "WireGuard",
        note = "Чистый WG без AWG-полей: сток-клиент, роутер, раздел WireGuard в Amnezia",
        supportsJunk = false,
        yaml = false
    ),
    AMNEZIAWG(
        title = "AmneziaWG",
        note = "WG + Jc/Jmin/Jmax/H1..H4/S1..S4/I1/I2 — против DPI, раздел AmneziaWG в Amnezia",
        supportsJunk = true,
        yaml = false
    ),
    CLASH(
        title = "Clash Meta",
        note = "YAML для Clash Meta / Stash / FlClash (amnezia-wg-option внутри)",
        supportsJunk = true,
        yaml = true
    );

    companion object {
        /** По умолчанию — чистый WireGuard: работает везде, где DPI не мешает. */
        val DEFAULT: ConfigTarget = WIREGUARD

        fun byName(value: String?): ConfigTarget =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) || it.title.equals(value, ignoreCase = true) }
                ?: DEFAULT

        fun ofOrdinal(index: Int): ConfigTarget = entries.getOrElse(index) { DEFAULT }
    }
}
