import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

val appVersion = "1.10.24"

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

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
            packageName = "WarpScout"
            packageVersion = appVersion
            description = "WarpScout — автоматический подбор WARP/AmneziaWG и туннель в один клик"
            vendor = "WarpScout"
            copyright = "MIT License"

            // jdk.crypto.ec и java.net.http нужны в собранном JRE для HTTPS/DoH/Cloudflare.
            modules(
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
                menuGroup = "WarpScout"
                shortcut = true
                dirChooser = true
                perUserInstall = false
                upgradeUuid = "7a6b3e1d-8c42-4d91-9b0f-45b9b9188a3c"
                iconFile.set(project.file("src/main/resources/icons/warpscout.ico"))
            }
        }
    }
}
