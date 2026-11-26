package dev.warpscout.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.text.InputType
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dev.warpscout.core.crypto.Crypto
import dev.warpscout.core.lists.ProtonFree
import dev.warpscout.core.proton.HttpReply
import dev.warpscout.core.proton.ProtonApi
import dev.warpscout.core.proton.ProtonChoice
import dev.warpscout.core.proton.ProtonDevice
import dev.warpscout.core.proton.ProtonException
import dev.warpscout.core.proton.ProtonHttp
import dev.warpscout.core.proton.ProtonKeys
import dev.warpscout.core.proton.ProtonService
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * «Подключить второй выход (Proton)» (с 1.10.44-beta5, просьба 25.11): ключ WireGuard Proton VPN
 * Free без похода на сайт Proton. Три способа:
 *
 *  1. Вход в свой аккаунт Proton — основной: пароль проверяется по SRP (на сервер не уходит),
 *     второй фактор и проверка «я не робот» — в окнах приложения. Ключ постоянный, на год, после
 *     входа сессия закрывается; пароль и токены не храним.
 *  2. Без аккаунта, напрямую у Proton — как «без регистрации» в приложении Proton для Android.
 *  3. Без аккаунта, сторонний сервис proton-generation (warp-api.cfd) — запасной.
 *
 * Во всех трёх ключ создаётся на телефоне, наружу уходит только открытая часть. Дальше человек
 * выбирает страну и сервер (по загрузке), а готовый конфиг встаёт во второй выход — как вставленный
 * вручную: автопоиск сервера работает так же.
 */
class ProtonConnect(
    private val activity: Activity,
    private val prefs: Prefs,
    private val onDone: (Result) -> Unit,
) {

    enum class Via(val id: String) { ACCOUNT("account"), ANONYMOUS("anonymous"), SERVICE("service") }

    class Result(
        val conf: String,
        val server: ProtonFree.Server,
        /** Выбранная страна: "" — любая, ближние первыми. */
        val country: String,
        /** Свежий список бесплатных серверов (пусто — не получили, остаётся прежний). */
        val servers: List<ProtonFree.Server>,
        val via: Via,
        val account: String,
        /** До какого числа действует ключ (мс), 0 — неизвестно. */
        val expiresAt: Long,
        val wgPublic: String,
    )

    private class Grant(
        val keys: ProtonKeys.Pair,
        val expiresAt: Long,
        val servers: List<ProtonApi.FreeServer>,
        val via: Via,
        val account: String,
    )

    private val density = activity.resources.displayMetrics.density
    private fun dp(v: Int): Int = (v * density).toInt()
    private fun s(id: Int, vararg args: Any): String = activity.getString(id, *args)

    private var busy: AlertDialog? = null
    private var busyText: TextView? = null

    @Volatile
    private var cancelled = false

    fun start() {
        TunnelDebug.stage("Proton: «Подключить второй выход» — выбор способа")
        chooseWay()
    }

    // ------------------------------------------------------------------ способ

    private fun chooseWay() {
        var dialog: AlertDialog? = null
        val box = column()
        box.addView(caption(s(R.string.proton_connect_intro), bottom = 8))
        box.addView(option(R.string.proton_way_account, R.string.proton_way_account_note) {
            dialog?.dismiss()
            askLogin("", null)
        })
        box.addView(option(R.string.proton_way_anonymous, R.string.proton_way_anonymous_note) {
            dialog?.dismiss()
            anonymousFlow()
        })
        box.addView(option(R.string.proton_way_service, R.string.proton_way_service_note) {
            dialog?.dismiss()
            serviceFlow()
        })
        box.addView(caption(s(R.string.proton_connect_tunnel_hint), top = 8))
        dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.proton_connect_title)
            .setView(scroll(box))
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ------------------------------------------------------------------ 1. вход в аккаунт

    private fun askLogin(user: String, error: String?) {
        val box = column()
        if (error != null) box.addView(errorText(error))
        val userLayout = TextInputLayout(activity).apply { hint = s(R.string.proton_login_user) }
        val userEdit = TextInputEditText(userLayout.context).apply {
            setText(user)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            isSingleLine = true
        }
        userLayout.addView(userEdit)
        val passLayout = TextInputLayout(activity).apply {
            hint = s(R.string.proton_login_password)
            endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
        }
        val passEdit = TextInputEditText(passLayout.context).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
        }
        passLayout.addView(passEdit)
        box.addView(userLayout, matchWrap(top = 4))
        box.addView(passLayout, matchWrap(top = 8))
        box.addView(caption(s(R.string.proton_login_note), top = 8))
        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.proton_login_title)
            .setView(scroll(box))
            .setPositiveButton(R.string.proton_login_go, null)
            .setNeutralButton(R.string.proton_login_signup, null)
            .setNegativeButton(android.R.string.cancel, null)
            .show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val u = userEdit.text?.toString()?.trim().orEmpty()
            val p = passEdit.text?.toString().orEmpty()
            userLayout.error = if (u.isEmpty()) s(R.string.proton_login_empty) else null
            passLayout.error = if (p.isEmpty()) s(R.string.proton_login_empty) else null
            if (u.isEmpty() || p.isEmpty()) return@setOnClickListener
            passEdit.setText("")
            dialog.dismiss()
            loginFlow(u, p.toByteArray(Charsets.UTF_8))
        }
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { openUrl(SIGNUP_URL) }
    }

    private fun loginFlow(user: String, password: ByteArray) {
        cancelled = false
        val api = newApi()
        TunnelDebug.stage("Proton: вход в аккаунт")
        fun attempt() {
            showBusy(s(R.string.proton_busy_login))
            background(onFail = { t ->
                password.fill(0)
                val e = t as? ProtonException
                if (e?.reason == ProtonException.Reason.WRONG_PASSWORD) {
                    hideBusy()
                    TunnelDebug.stage("Proton: неверный логин или пароль")
                    askLogin(user, s(R.string.proton_err_password))
                } else {
                    fail(t)
                }
            }) {
                val session = try {
                    api.login(user, password)
                } catch (e: ProtonException) {
                    if (e.reason == ProtonException.Reason.HUMAN_VERIFICATION && e.hvToken.isNotBlank() && !cancelled) {
                        hideBusy()
                        ui { verifyHuman(e, onCancel = { password.fill(0) }) { token -> api.humanVerification = token; attempt() } }
                        return@background
                    }
                    throw e
                }
                password.fill(0)
                // Проверка «я не робот» нужна была только этому шагу — дальше без её заголовков.
                api.humanVerification = null
                rememberVersion(api)
                if (cancelled) return@background
                if (session.needsTwoFactor) {
                    hideBusy()
                    ui { askCode(api, session, user, 1, null) }
                    return@background
                }
                if (!session.hasVpn) throw ProtonException(s(R.string.proton_err_no_vpn))
                finishWithSession(api, session, Via.ACCOUNT, user)
            }
        }
        attempt()
    }

    private fun askCode(api: ProtonApi, session: ProtonApi.Session, user: String, attempt: Int, error: String?) {
        if (!session.totp) {
            TunnelDebug.stage("Proton: второй фактор — только ключ безопасности (FIDO2), такой вход не поддерживается")
            Thread { api.logout(session) }.apply { isDaemon = true }.start()
            showError(s(R.string.proton_2fa_fido), retryAccount = user)
            return
        }
        TunnelDebug.stage("Proton: второй фактор — жду код")
        val box = column()
        if (error != null) box.addView(errorText(error))
        val layout = TextInputLayout(activity).apply { hint = s(R.string.proton_2fa_hint) }
        val edit = TextInputEditText(layout.context).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        layout.addView(edit)
        box.addView(layout, matchWrap(top = 4))
        val dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.proton_2fa_title)
            .setView(scroll(box))
            .setPositiveButton(R.string.proton_login_go, null)
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                TunnelDebug.stage("Proton: код второго фактора не ввели")
                Thread { api.logout(session) }.apply { isDaemon = true }.start()
            }
            .setCancelable(false)
            .show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val code = edit.text?.toString()?.filter { it.isDigit() }.orEmpty()
            if (code.length < 6) {
                layout.error = s(R.string.proton_2fa_short)
                return@setOnClickListener
            }
            dialog.dismiss()
            cancelled = false
            showBusy(s(R.string.proton_busy_code))
            background(onFail = { t -> fail(t) }) {
                val upgraded = try {
                    api.submitTwoFactor(session, code)
                } catch (e: ProtonException) {
                    if (e.reason == ProtonException.Reason.TWO_FACTOR_WRONG && attempt < 3) {
                        hideBusy()
                        ui { askCode(api, session, user, attempt + 1, s(R.string.proton_2fa_wrong)) }
                        return@background
                    }
                    throw e
                }
                if (!upgraded.hasVpn) throw ProtonException(s(R.string.proton_err_no_vpn))
                finishWithSession(api, upgraded, Via.ACCOUNT, user)
            }
        }
    }

    // ------------------------------------------------------------------ 2. без аккаунта у Proton

    private fun anonymousFlow() {
        cancelled = false
        val api = newApi()
        TunnelDebug.stage("Proton: без аккаунта, напрямую у Proton")
        fun attempt() {
            showBusy(s(R.string.proton_busy_anonymous))
            background(onFail = { t -> fail(t) }) {
                val session = try {
                    api.withoutAccount()
                } catch (e: ProtonException) {
                    if (e.reason == ProtonException.Reason.HUMAN_VERIFICATION && e.hvToken.isNotBlank() && !cancelled) {
                        hideBusy()
                        ui { verifyHuman(e, onCancel = {}) { token -> api.humanVerification = token; attempt() } }
                        return@background
                    }
                    throw e
                }
                api.humanVerification = null
                rememberVersion(api)
                if (cancelled) return@background
                finishWithSession(api, session, Via.ANONYMOUS, "")
            }
        }
        attempt()
    }

    // ------------------------------------------------------------------ 3. сторонний сервис

    private fun serviceFlow() {
        cancelled = false
        TunnelDebug.stage("Proton: без аккаунта, сторонний сервис proton-generation")
        showBusy(s(R.string.proton_busy_service))
        background(onFail = { t -> fail(t, service = true) }) {
            val svc = ProtonService(AndroidHttp(), userAgent = "WilyScout/${BuildConfig.VERSION_NAME}", log = { TunnelDebug.stage(it) })
            val session = svc.session()
            if (cancelled) return@background
            showBusy(s(R.string.proton_busy_servers))
            val servers = svc.servers(session)
            TunnelDebug.stage("Proton (сервис): бесплатных серверов ${servers.size}")
            if (cancelled) return@background
            showBusy(s(R.string.proton_busy_key))
            val keys = ProtonKeys.generate()
            val expires = svc.register(session, keys) ?: 0L
            TunnelDebug.stage("Proton (сервис): ключ зарегистрирован" + if (expires > 0) " до ${date(expires)}" else ", срок не сообщён")
            hideBusy()
            if (cancelled) return@background
            ui { pickServer(Grant(keys, expires, servers, Via.SERVICE, "")) }
        }
    }

    // ------------------------------------------------------------------ общее: ключ и серверы

    /** Сессия с доступом к VPN → ключ на год → серверы. Идёт в фоне. */
    private fun finishWithSession(api: ProtonApi, session: ProtonApi.Session, via: Via, account: String) {
        showBusy(s(R.string.proton_busy_key))
        val keys = ProtonKeys.generate()
        val cert = api.registerKey(session, keys, "WilyScout · ${Build.MODEL.orEmpty()}")
        TunnelDebug.stage("Proton: ключ выдан до ${date(cert.expiresAt)}")
        showBusy(s(R.string.proton_busy_servers))
        val servers = try {
            api.freeServers(session)
        } catch (e: ProtonException) {
            TunnelDebug.stage("Proton: список серверов не получен (${e.message}) — беру список приложения")
            emptyList()
        }
        if (servers.isNotEmpty()) {
            TunnelDebug.stage("Proton: бесплатных серверов ${servers.size}, стран ${ProtonChoice.countries(servers).size}")
        }
        // Ключ постоянный и от сессии не зависит: сессию аккаунта закрываем. Сессию без аккаунта не
        // трогаем — неизвестно, не уйдёт ли вместе с ней безымянный аккаунт, а с ним и ключ.
        if (via == Via.ACCOUNT) api.logout(session)
        hideBusy()
        if (cancelled) return
        ui { pickServer(Grant(keys, cert.expiresAt, servers, via, account)) }
    }

    // ------------------------------------------------------------------ выбор сервера

    private fun pickServer(g: Grant) {
        val list = g.servers.ifEmpty { SecondProton.servers(activity).map { ProtonApi.FreeServer(it, -1) } }
        val countries = ProtonChoice.countries(list)
        val labels = ArrayList<String>()
        labels += s(R.string.proton_pick_any)
        countries.forEach { c ->
            val name = SecondProton.countryName(activity, c.code)
            labels += if (c.minLoad >= 0) s(R.string.proton_pick_country_load, name, c.count, c.minLoad) else s(R.string.proton_pick_country, name, c.count)
        }
        val title = if (g.expiresAt > 0) s(R.string.proton_pick_title_until, date(g.expiresAt)) else s(R.string.proton_pick_title)
        MaterialAlertDialogBuilder(activity)
            .setTitle(title)
            .setItems(labels.toTypedArray()) { _, which ->
                if (which == 0) finish(g, list, "", null) else pickInCountry(g, list, countries[which - 1].code)
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                TunnelDebug.stage("Proton: ключ получен, сервер не выбран — второй выход не менял")
            }
            .setCancelable(false)
            .show()
    }

    private fun pickInCountry(g: Grant, list: List<ProtonApi.FreeServer>, code: String) {
        val servers = ProtonChoice.inCountry(list, code)
        val name = SecondProton.countryName(activity, code)
        val labels = ArrayList<String>()
        labels += s(R.string.proton_pick_any_in, name)
        servers.forEach { f ->
            val city = f.server.city.ifBlank { name }
            labels += if (f.load >= 0) s(R.string.proton_pick_server_load, f.server.name.ifBlank { f.server.ip }, city, f.load)
            else s(R.string.proton_pick_server, f.server.name.ifBlank { f.server.ip }, city)
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(name)
            .setItems(labels.toTypedArray()) { _, which ->
                if (which == 0) finish(g, list, code, null) else finish(g, list, code, servers[which - 1])
            }
            .setNeutralButton(R.string.proton_pick_back) { _, _ -> pickServer(g) }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                TunnelDebug.stage("Proton: ключ получен, сервер не выбран — второй выход не менял")
            }
            .setCancelable(false)
            .show()
    }

    private fun finish(g: Grant, list: List<ProtonApi.FreeServer>, country: String, chosen: ProtonApi.FreeServer?) {
        val server = (chosen ?: ProtonChoice.best(list, country))?.server
        if (server == null) {
            showError(s(R.string.proton_err_no_servers), retryAccount = null)
            return
        }
        val until = if (g.expiresAt > 0) date(g.expiresAt) else s(R.string.proton_until_unknown)
        val note = when (g.via) {
            Via.ACCOUNT -> s(R.string.proton_note_account, g.account, until)
            Via.ANONYMOUS -> s(R.string.proton_note_anonymous, until)
            Via.SERVICE -> s(R.string.proton_note_service, until)
        }
        val conf = ProtonFree.confFor(Crypto.base64(g.keys.wgPrivate), server, note)
        TunnelDebug.stage(
            "Proton: сервер ${server.name.ifBlank { server.ip }} (${server.code}" +
                (if (chosen == null) ", выбран по загрузке" else "") + ") — конфиг готов"
        )
        onDone(
            Result(
                conf = conf,
                server = server,
                country = country,
                servers = g.servers.map { it.server },
                via = g.via,
                account = g.account,
                expiresAt = g.expiresAt,
                wgPublic = Crypto.base64(g.keys.wgPublic),
            )
        )
    }

    // ------------------------------------------------------------------ «я не робот»

    /** Мост для страницы проверки Proton: она зовёт AndroidInterface.dispatch(JSON), как в приложении Proton. */
    private inner class HvBridge(private val onResult: (Pair<String, String>) -> Unit) {
        @JavascriptInterface
        fun dispatch(message: String) {
            val result = ProtonApi.hvResult(message) ?: return
            activity.runOnUiThread { onResult(result) }
        }
    }

    private fun verifyHuman(e: ProtonException, onCancel: () -> Unit, onToken: (Pair<String, String>) -> Unit) {
        TunnelDebug.stage("Proton: просит проверку «я не робот» (${e.hvMethods.joinToString().ifEmpty { "captcha" }})")
        // Нет WebView (системный компонент выключен или сломан) — говорим, а не молча стоим.
        try {
            showVerification(e, onCancel, onToken)
        } catch (t: Throwable) {
            TunnelDebug.problem("Proton: окно проверки не открылось — ${SafeMode.describe(t)}")
            onCancel()
            fail(ProtonException(s(R.string.proton_err_webview, SafeMode.describe(t))))
        }
    }

    @SuppressLint("SetJavaScriptEnabled", "JavascriptInterface", "AddJavascriptInterface")
    private fun showVerification(e: ProtonException, onCancel: () -> Unit, onToken: (Pair<String, String>) -> Unit) {
        val web = WebView(activity)
        var dialog: AlertDialog? = null
        var done = false
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(HvBridge { result ->
            if (!done) {
                done = true
                TunnelDebug.stage("Proton: проверка пройдена (${result.second})")
                runCatching { dialog?.dismiss() }
                onToken(result)
            }
        }, "AndroidInterface")
        web.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView, url: String?) {
                // Капча сообщает об успехе и postMessage'ем (как страница /core/v4/captcha) — ловим и его.
                view.evaluateJavascript(HOOK_JS, null)
            }
        }
        val holder = FrameLayout(activity)
        holder.addView(web, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(520)))
        web.loadUrl(ProtonApi.hvUrl(e.hvToken, e.hvMethods, dark(), Locale.getDefault().language.ifBlank { "ru" }))
        dialog = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.proton_hv_title)
            .setView(holder)
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                if (!done) {
                    done = true
                    cancelled = true
                    TunnelDebug.stage("Proton: проверку «я не робот» отменили")
                    onCancel()
                }
            }
            .setCancelable(false)
            .setOnDismissListener { web.postDelayed({ runCatching { web.destroy() } }, 500L) }
            .show()
        // В окне диалога WebView без этого не получает клавиатуру (поле кода из письма).
        dialog.window?.clearFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM)
        web.requestFocus()
    }

    // ------------------------------------------------------------------ ошибки

    private fun fail(t: Throwable, service: Boolean = false) {
        hideBusy()
        if (cancelled) return
        val e = t as? ProtonException
        val detail = e?.message ?: SafeMode.describe(t)
        TunnelDebug.problem("Proton: $detail")
        val text = when (e?.reason) {
            ProtonException.Reason.NETWORK -> s(if (service) R.string.proton_err_service_network else R.string.proton_err_network, detail)
            ProtonException.Reason.APP_VERSION -> s(R.string.proton_err_version, detail)
            ProtonException.Reason.HUMAN_VERIFICATION -> s(R.string.proton_err_hv)
            else -> s(R.string.proton_err_other, detail)
        }
        showError(text, retryAccount = null)
    }

    private fun showError(text: String, retryAccount: String?) {
        ui {
            MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.proton_err_title)
                .setMessage(text)
                .setPositiveButton(R.string.proton_err_other_way) { _, _ -> chooseWay() }
                .apply { if (retryAccount != null) setNeutralButton(R.string.proton_err_retry) { _, _ -> askLogin(retryAccount, null) } }
                .setNegativeButton(R.string.proton_guide_close, null)
                .show()
        }
    }

    // ------------------------------------------------------------------ фон и окна

    private fun background(onFail: (Throwable) -> Unit, work: () -> Unit) {
        Thread {
            try {
                work()
            } catch (t: Throwable) {
                ui { onFail(t) }
            }
        }.apply {
            isDaemon = true
            name = "warpscout-proton-connect"
        }.start()
    }

    private fun ui(block: () -> Unit) {
        activity.runOnUiThread {
            if (activity.isFinishing || activity.isDestroyed) return@runOnUiThread
            runCatching(block).onFailure { t -> TunnelDebug.problem("Proton: окно — ${SafeMode.describe(t)}") }
        }
    }

    private fun showBusy(text: String) = ui {
        if (busy == null) {
            val row = LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(dp(24), dp(20), dp(24), dp(8))
            }
            row.addView(ProgressBar(activity).apply { isIndeterminate = true }, LinearLayout.LayoutParams(dp(36), dp(36)))
            val tv = TextView(activity).apply {
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
                setPadding(dp(16), 0, 0, 0)
            }
            row.addView(tv, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            busyText = tv
            busy = MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.proton_connect_title)
                .setView(row)
                .setCancelable(false)
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    cancelled = true
                    busy = null
                    busyText = null
                    TunnelDebug.stage("Proton: отменено")
                }
                .show()
        }
        busyText?.text = text
    }

    private fun hideBusy() = ui {
        runCatching { busy?.dismiss() }
        busy = null
        busyText = null
    }

    private fun column() = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(24), dp(8), dp(24), dp(4))
    }

    private fun scroll(content: View) = ScrollView(activity).apply { addView(content) }

    private fun matchWrap(top: Int = 0) = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        .apply { topMargin = dp(top) }

    private fun caption(text: String, top: Int = 0, bottom: Int = 0) = TextView(activity).apply {
        this.text = text
        setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
        setTextColor(Design.color(activity, R.color.colorOnSurfaceVariant))
        setPadding(0, dp(top), 0, dp(bottom))
    }

    private fun errorText(text: String) = TextView(activity).apply {
        this.text = text
        setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
        setTextColor(ContextCompat.getColor(activity, R.color.state_error))
        setPadding(0, 0, 0, dp(6))
    }

    private fun option(title: Int, note: Int, onClick: () -> Unit): View = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(4), dp(10), dp(4), dp(10))
        isClickable = true
        isFocusable = true
        val tv = TypedValue()
        if (activity.theme.resolveAttribute(android.R.attr.selectableItemBackground, tv, true)) setBackgroundResource(tv.resourceId)
        addView(TextView(activity).apply {
            setText(title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(Design.color(activity, R.color.colorPrimary))
        })
        addView(TextView(activity).apply {
            setText(note)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(Design.color(activity, R.color.colorOnSurfaceVariant))
        })
        setOnClickListener { onClick() }
    }

    private fun openUrl(url: String) {
        runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    private fun dark(): Boolean =
        activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES

    private fun date(ms: Long): String = SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()).format(Date(ms))

    // ------------------------------------------------------------------ API

    private fun newApi(): ProtonApi {
        val stored = prefs.protonAppVersion
        val version = if (stored.isNotBlank() && ProtonApi.compareVersions(stored, ProtonApi.APP_VERSION) > 0) stored else ProtonApi.APP_VERSION
        return ProtonApi(
            http = AndroidHttp(),
            device = device(),
            appVersion = version,
            log = { TunnelDebug.stage(it) },
            newerVersion = { newestVersion() },
        )
    }

    private fun rememberVersion(api: ProtonApi) {
        if (api.appVersion != prefs.protonAppVersion && ProtonApi.compareVersions(api.appVersion, ProtonApi.APP_VERSION) > 0) {
            prefs.protonAppVersion = api.appVersion
        }
    }

    /** Новая версия приложения Proton для Android — по тегам на GitHub (GitHub из России открыт). */
    private fun newestVersion(): String? = runCatching {
        val reply = AndroidHttp().send(
            "GET", ProtonApi.TAGS_URL,
            mapOf("Accept" to "application/vnd.github+json", "User-Agent" to "WilyScout/${BuildConfig.VERSION_NAME}"),
            null,
        )
        if (reply.status in 200..299) ProtonApi.newestVersion(reply.body) else null
    }.getOrNull()

    /** Поля «кадра» устройства — те же, что собирает приложение Proton (честные значения телефона). */
    private fun device(): ProtonDevice {
        val cfg = activity.resources.configuration
        val locale = if (cfg.locales.isEmpty) Locale.getDefault() else cfg.locales[0]
        val tz = TimeZone.getDefault()
        val storage = runCatching {
            val st = StatFs(Environment.getDataDirectory().path)
            Math.round(st.blockCountLong * st.blockSizeLong / 1e9 * 100) / 100.0
        }.getOrDefault(64.0)
        val keyboards = runCatching {
            (activity.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).enabledInputMethodList.map { it.packageName }.distinct()
        }.getOrDefault(emptyList())
        return ProtonDevice(
            model = Build.MODEL.orEmpty(),
            brand = Build.BRAND.orEmpty(),
            device = Build.DEVICE.orEmpty(),
            androidRelease = Build.VERSION.RELEASE.orEmpty(),
            language = locale.language,
            region = locale.country,
            timezone = tz.id,
            timezoneOffset = -(tz.getOffset(System.currentTimeMillis()) / 60_000),
            fontScale = cfg.fontScale.toString(),
            storageGb = storage,
            darkMode = dark(),
            keyboards = keyboards,
        )
    }

    /**
     * HTTP через обычный стек Android. WarpScout сам всегда в туннеле, поэтому при поднятом WARP
     * запросы идут через него — из России адреса Proton иначе закрыты. С московской площадки WARP их режут
     * и через туннель — тогда ProtonApi идёт обходным путём Proton (с 1.10.46): DoH ([getBytes]) и
     * посредники с закреплёнными ключами ([sendPinned]), см. ProtonAlt.
     */
    private class AndroidHttp : ProtonHttp {
        override fun send(method: String, url: String, headers: Map<String, String>, body: String?): HttpReply =
            exchange(URL(url).openConnection() as HttpURLConnection, method, headers, body)

        override fun sendPinned(method: String, url: String, headers: Map<String, String>, body: String?, pins: List<String>): HttpReply {
            val conn = URL(url).openConnection() as? HttpsURLConnection ?: throw IOException("посредник Proton — только https")
            conn.sslSocketFactory = pinnedFactory(pins)
            // Сертификат посредника выписан не на его адрес: верим ключу сертификата (пины), а не имени — как Proton.
            conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
            return exchange(conn, method, headers, body)
        }

        override fun getBytes(url: String, headers: Map<String, String>): ByteArray? {
            val conn = URL(url).openConnection() as HttpURLConnection
            try {
                conn.connectTimeout = 6_000
                conn.readTimeout = 8_000
                conn.instanceFollowRedirects = false
                conn.useCaches = false
                headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
                if (conn.responseCode != 200) return null
                return conn.inputStream.use { readBytes(it, 64 shl 10) }
            } finally {
                runCatching { conn.disconnect() }
            }
        }

        /** Ключ сертификата посредника (SHA-256 SPKI, base64) — только из закреплённых; цепочку CA не смотрим. */
        private fun pinnedFactory(pins: List<String>): SSLSocketFactory {
            val trust = object : X509TrustManager {
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    val leaf = chain.firstOrNull() ?: throw CertificateException("посредник Proton: пустая цепочка сертификатов")
                    val pin = java.util.Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded))
                    if (pin !in pins) throw CertificateException("посредник Proton: ключ сертификата $pin не из закреплённых")
                }

                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                    throw CertificateException("клиентские сертификаты не нужны")
                }

                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
            return SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust), null) }.socketFactory
        }

        private fun exchange(conn: HttpURLConnection, method: String, headers: Map<String, String>, body: String?): HttpReply {
            try {
                conn.requestMethod = method
                conn.connectTimeout = 12_000
                conn.readTimeout = 30_000
                conn.instanceFollowRedirects = false
                conn.useCaches = false
                headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
                if (body != null) {
                    val bytes = body.toByteArray(Charsets.UTF_8)
                    conn.doOutput = true
                    conn.setFixedLengthStreamingMode(bytes.size)
                    conn.outputStream.use { it.write(bytes) }
                }
                val code = conn.responseCode
                val stream = if (code >= 400) conn.errorStream else conn.inputStream
                val text = stream?.use { String(readBytes(it, 16 shl 20), Charsets.UTF_8) }.orEmpty()
                return HttpReply(code, text)
            } finally {
                runCatching { conn.disconnect() }
            }
        }

        private fun readBytes(input: InputStream, limit: Int): ByteArray {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > limit) {
                    throw IOException(if (limit >= 1 shl 20) "ответ больше ${limit shr 20} МБ" else "ответ больше ${limit shr 10} КБ")
                }
            }
            return out.toByteArray()
        }
    }

    companion object {
        const val SIGNUP_URL = "https://account.protonvpn.com/signup?plan=free"

        /** Слушатель postMessage для страницы проверки: отдаёт сообщения в тот же мост. */
        private const val HOOK_JS = "(function(){if(window.__wsHvHook)return;window.__wsHvHook=true;" +
            "window.addEventListener('message',function(e){try{var d=e.data;" +
            "AndroidInterface.dispatch(typeof d==='string'?d:JSON.stringify(d));}catch(x){}});})();"
    }
}
