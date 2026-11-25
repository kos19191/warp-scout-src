package dev.warpscout.desktop.engine

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

object Formatters {
    private val timeFmt = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
    private val dateTimeFmt = DateTimeFormatter.ofPattern("dd.MM HH:mm").withZone(ZoneId.systemDefault())

    fun timeOf(epochMs: Long): String = timeFmt.format(Instant.ofEpochMilli(epochMs))
    fun dateTimeOf(epochMs: Long): String = dateTimeFmt.format(Instant.ofEpochMilli(epochMs))

    fun bytes(b: Long): String {
        val v = b.coerceAtLeast(0L)
        return when {
            v < 1024L -> "$v Б"
            v < 1024L * 1024L -> String.format("%.1f КБ", v / 1024.0)
            v < 1024L * 1024L * 1024L -> String.format("%.1f МБ", v / (1024.0 * 1024.0))
            else -> String.format("%.2f ГБ", v / (1024.0 * 1024.0 * 1024.0))
        }
    }

    fun speed(bytesPerSec: Long): String = "${bytes(bytesPerSec)}/с"

    fun duration(seconds: Long): String {
        val s = seconds.coerceAtLeast(0L)
        val h = s / 3600
        val m = (s % 3600) / 60
        val sec = s % 60
        return when {
            h > 0 -> String.format("%d ч %02d мин", h, m)
            m > 0 -> String.format("%d мин %02d с", m, sec)
            else -> "$sec с"
        }
    }

    fun ago(epochMs: Long, nowMs: Long = System.currentTimeMillis()): String {
        if (epochMs <= 0L) return "никогда"
        val diffSec = ((nowMs - epochMs) / 1000L).coerceAtLeast(0L)
        return when {
            diffSec < 60L -> "только что"
            diffSec < 3600L -> "${diffSec / 60L} мин назад"
            diffSec < 86_400L -> "${diffSec / 3600L} ч назад"
            else -> "${diffSec / 86_400L} дн назад"
        }
    }
}
