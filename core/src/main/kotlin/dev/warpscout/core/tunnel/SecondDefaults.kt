package dev.warpscout.core.tunnel

import dev.warpscout.core.lists.AppServices
import dev.warpscout.core.state.ServiceSettings

/**
 * «Второй выход» по умолчанию (с 1.10.44, в бете — с 1.10.44-beta4): у TikTok, ChatGPT, Claude, Gemini и Grok выход
 * сразу «Второй выход» — приложение целиком через свой сервер, а не «Само».
 *
 * Зачем. Человек попросил 24.11: «Добавь по умолчанию тикток и всякие там клауд, гемини, грок,
 * чатгпт через второй туннель по умолчанию. В бету пока что». Этим сервисам нужен зарубежный адрес:
 * ChatGPT, Claude, Gemini и Grok российским адресам отказывают («страна не поддерживается»), TikTok по
 * адресу решает, какую ленту показывать. В бете у человека через второй выход шёл только TikTok —
 * его он выбрал руками, а Claude, Gemini, Grok и ChatGPT не были даже отмечены и шли мимо туннеля.
 * Проверено в бетах, 25.11 человек попросил перенести всё в обычную версию — с 1.10.44 так и там.
 *
 * Правила ([plan]):
 *  • только официальные приложения — по пакету ([AppServices.Service.packages] и их варианты
 *    «пакет.что-то»); подсказки по имени («…chatgpt…», «…tiktok…») не в счёт: так называются и
 *    сторонние «AI-чаты», и «скачать из TikTok»;
 *  • только установленные: правило для приложения, которого нет на телефоне, ничего не даёт, а журнал
 *    засоряет («нет на телефоне: …»). Поставят позже — правило появится при следующем открытии экрана;
 *  • выбор человека сильнее: у приложения уже есть правило («Всегда WARP» или «Второй выход») — не
 *    трогаем; в «все, кроме» оно исключено из туннеля или в «только выбранные» с него сняли галочку
 *    руками — тоже не трогаем;
 *  • один раз на приложение ([Plan.seen]): правило поставили (или решили не ставить) — больше этого
 *    приложения не касаемся. Выбрал человек потом «Само» — так и останется;
 *  • в «только выбранные» приложение со своим выходом идёт через туннель — его отмечаем, как это
 *    делает кнопка выхода в строке приложения.
 *
 * Когда применять, решает экран: только когда выход приложений вообще есть (второй выход включён и
 * его конфиг читается, Android 10+). Без второго выхода правило не действует, а отмеченные
 * приложения шли бы через WARP — с тем же российским адресом, только медленнее. Настроят второй
 * выход — правила появятся тогда.
 */
object SecondDefaults {

    /** Сервисы из [AppServices.SERVICES], которым по умолчанию — второй выход. */
    val SERVICES: List<String> = listOf("TikTok", "ChatGPT", "Claude", "Gemini", "Grok")

    /** Официальное приложение такого сервиса: известный пакет или его вариант («пакет.что-то»). */
    fun wants(pkg: String): Boolean {
        val p = pkg.trim().lowercase()
        if (p.isEmpty()) return false
        return AppServices.SERVICES.any { s ->
            s.title in SERVICES && (p in s.packages || s.packages.any { p.startsWith("$it.") })
        }
    }

    /** Что получилось: новые правила и отметки, кого больше не трогать, кому поставили и кого оставили. */
    data class Plan(
        /** Правила выхода после применения: прежние и новые. */
        val exits: Map<String, Int>,
        /** Отмеченные приложения после применения (в «только выбранные» — с новыми). */
        val selected: Set<String>,
        /** Пакеты, которых больше не касаемся: прежние и рассмотренные сейчас. */
        val seen: Set<String>,
        /** Кому сейчас поставили «Второй выход» — по алфавиту пакетов. */
        val added: List<String>,
        /** Кого рассмотрели и оставили как есть (выбор человека) — для журнала. */
        val kept: List<String>,
        /** Кого из [added] отметили в «только выбранные» (раньше шли мимо туннеля). */
        val ticked: List<String>,
    ) {
        /** Что-то поменялось в правилах или отметках (а не только в [seen]). */
        val changed: Boolean get() = added.isNotEmpty()
    }

    /**
     * @param installed установленные приложения (пакеты)
     * @param exits     правила выхода сейчас: пакет → [AppExit.WARP] / [AppExit.SECOND]
     * @param appsMode  [ServiceSettings.APPS_ALL] / [ServiceSettings.APPS_ONLY] / [ServiceSettings.APPS_EXCEPT]
     * @param selected  отмеченные приложения: в «только выбранные» — кто идёт через туннель, в «все,
     *                  кроме» — кто исключён
     * @param unticked  с кого человек снял галочку руками
     * @param seen      кого уже рассмотрели раньше
     */
    fun plan(
        installed: Collection<String>,
        exits: Map<String, Int>,
        appsMode: Int,
        selected: Set<String>,
        unticked: Set<String>,
        seen: Set<String>,
    ): Plan {
        val outExits = LinkedHashMap(exits)
        val outSelected = LinkedHashSet(selected)
        val outSeen = LinkedHashSet(seen)
        val added = ArrayList<String>()
        val kept = ArrayList<String>()
        val ticked = ArrayList<String>()
        installed.map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted().forEach { pkg ->
            if (!wants(pkg) || pkg in seen) return@forEach
            outSeen += pkg
            val chosen = pkg in exits ||
                (appsMode == ServiceSettings.APPS_ONLY && pkg in unticked) ||
                (appsMode == ServiceSettings.APPS_EXCEPT && pkg in selected)
            if (chosen) {
                kept += pkg
                return@forEach
            }
            outExits[pkg] = AppExit.SECOND
            added += pkg
            if (appsMode == ServiceSettings.APPS_ONLY && outSelected.add(pkg)) ticked += pkg
        }
        return Plan(outExits, outSelected, outSeen, added, kept, ticked)
    }
}
