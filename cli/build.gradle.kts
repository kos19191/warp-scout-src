plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

dependencies {
    implementation(project(":core"))
}

kotlin { jvmToolchain(17) }

application {
    mainClass.set("dev.warpscout.cli.MainKt")
}

// ./gradlew :cli:run --args="tune --out out"
tasks.register<JavaExec>("selftest") {
    group = "verification"
    description = "Офлайн-самопроверка всех примитивов ядра"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("dev.warpscout.cli.MainKt")
    args("selftest")
}
