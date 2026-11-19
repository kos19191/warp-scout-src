plugins {
    id("org.jetbrains.kotlin.jvm")
    `java-library`
}

// Ядро — чистый Kotlin/JVM: его же использует и Android-модуль, и CLI, и самопроверка.
dependencies {
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

kotlin {
    jvmToolchain(17)
}

java {
    withSourcesJar()
}
