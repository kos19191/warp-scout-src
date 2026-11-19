// WarpScout — корневой build-файл.
// Версии плагинов заданы здесь, модули их только применяют.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.jvm") version "2.0.21" apply false
}

// Быстрая команда для проверки ядра без Android:  ./gradlew selftest
tasks.register("selftest") {
    group = "verification"
    description = "Самопроверка ядра (офлайн-векторы) через CLI-модуль"
    dependsOn(":cli:selftest")
}
