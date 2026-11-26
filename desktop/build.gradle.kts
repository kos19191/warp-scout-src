import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import java.time.Instant
import java.time.format.DateTimeFormatter

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

val appVersion = "1.10.33"
val githubRepo = "kos19191/warp-scout-src"

val generatedBuildInfoDir = layout.buildDirectory.dir("generated/resources/buildinfo")

val generateBuildInfo by tasks.registering {
    val outDir = generatedBuildInfoDir
    val versionStr = appVersion
    val repoStr = githubRepo
    val commitSha = providers.environmentVariable("GITHUB_SHA")
        .orElse(providers.provider {
            runCatching {
                ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                    .directory(rootProject.projectDir)
                    .start()
                    .inputStream.bufferedReader().readText().trim()
            }.getOrDefault("")
        })
        .map { it.take(12).ifBlank { "local" } }
    inputs.property("version", versionStr)
    inputs.property("repo", repoStr)
    outputs.dir(outDir)
    doLast {
        val dir = outDir.get().asFile
        dir.mkdirs()
        val nowIso = DateTimeFormatter.ISO_INSTANT.format(Instant.now())
        dir.resolve("warpscout-build.properties").writeText(
            """
            version=$versionStr
            buildTimeUtc=$nowIso
            commitSha=${commitSha.get()}
            githubRepo=$repoStr
            """.trimIndent() + "\n",
            Charsets.UTF_8
        )
    }
}

sourceSets {
    main {
        resources.srcDir(generatedBuildInfoDir)
    }
}

tasks.named("processResources") {
    dependsOn(generateBuildInfo)
}

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("net.java.dev.jna:jna:5.15.0")
    implementation("net.java.dev.jna:jna-platform:5.15.0")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}

compose.desktop {
    application {
        mainClass = "dev.warpscout.desktop.MainKt"

        jvmArgs(
            "-Dfile.encoding=UTF-8",
            "-Dsun.java2d.dpiaware=true"
        )

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe)
            packageName = "WilyScout"
            packageVersion = appVersion
            description = "WilyScout Desktop - Cloudflare WARP and AmneziaWG auto-tuner, DPI bypass and Telegram proxy helper"
            vendor = "WilyScout"
            copyright = "MIT License"

            // jdk.crypto.ec и java.net.http нужны в собранном JRE для HTTPS/DoH/Cloudflare.
            modules(
                "java.desktop",
                "java.instrument",
                "java.logging",
                "java.management",
                "java.naming",
                "java.net.http",
                "java.prefs",
                "jdk.crypto.ec",
                "jdk.unsupported"
            )

            windows {
                menuGroup = "WilyScout"
                shortcut = true
                dirChooser = true
                perUserInstall = false
                upgradeUuid = "7a6b3e1d-8c42-4d91-9b0f-45b9b9188a3c"
                iconFile.set(project.file("src/main/resources/icons/warpscout.ico"))
            }
        }
    }
}
