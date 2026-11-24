plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.warpscout.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.warpscout.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 73
        versionName = "1.10.44-beta2"
        // Номер сборки (короткий хеш коммита из CI): по этой метке в журнале видно, какая именно
        // сборка стоит на телефоне. Локально — «local».
        // С 1.10.41 каждая сборка для телефона получает НОВЫЙ номер версии. Пересборку с тем же
        // номером (тег переносится) телефон узнаёт только через GitHub API (см. Updater.check), а у
        // API без входа лимит — 60 запросов в час на адрес; через общие адреса Cloudflare/оператора
        // он обычно исчерпан, и запасная проверка по сайту видит «та же версия — обновлений нет».
        // Так доправки 1.10.40 до телефона и не дошли.
        buildConfigField(
            "String",
            "BUILD_REV",
            "\"" + (System.getenv("GITHUB_SHA")?.take(7) ?: "local") + "\""
        )
        // Бета (с 1.10.44-beta1): версия вида «1.10.44-beta1». Ставится отдельным приложением рядом с
        // обычным («WarpScout β», applicationId с «.beta» на конце), обновляется только бетами из
        // пре-релизов и обычную версию на телефоне не трогает.
        buildConfigField("boolean", "BETA", versionName.orEmpty().contains("-beta").toString())
    }

    val beta = defaultConfig.versionName.orEmpty().contains("-beta")

    flavorDimensions += "mode"
    productFlavors {
        // С 1.10.27 «только конфиги» больше нет: обе сборки — полное приложение со своим
        // туннелем. Разница одна — каким экраном оно открывается, пока человек сам не выбрал
        // (тумблер внизу экрана, выбор запоминается). Идентификаторы и подписи прежние, поэтому
        // обе обновляются поверх старых версий без потери настроек.
        create("scout") {
            dimension = "mode"
            buildConfigField("boolean", "TUNNEL_SUPPORTED", "true")
            // scout открывается расширенным экраном — всеми вкладками, как раньше.
            buildConfigField("boolean", "DEFAULT_SIMPLE", "false")
            resValue("string", "app_name", if (beta) "WarpScout β (scout)" else "WarpScout")
        }
        create("tunnel") {
            dimension = "mode"
            buildConfigField("boolean", "TUNNEL_SUPPORTED", "true")
            // tunnel открывается упрощённым: кнопка подключения, резервная точка, проверка связи.
            buildConfigField("boolean", "DEFAULT_SIMPLE", "true")
            resValue("string", "app_name", if (beta) "WarpScout β" else "WarpScout (tunnel)")
            // чтобы обе сборки можно было держать на телефоне одновременно и сравнивать
            applicationIdSuffix = ".tunnel"
        }
    }

    signingConfigs {
        /**
         * Постоянный ключ подписи, лежащий в репозитории (`app/debug.keystore`).
         *
         * Android узнаёт приложение по подписи: если новый APK подписан другим ключом, обновление
         * не ставится — «Приложение не установлено», и человек вынужден удалять старое (теряя
         * настройки). Раньше ключ пытались фиксировать кешем GitHub Actions; кеш истекает после
         * недели без обращений, на следующей сборке создавался новый ключ — и обновление ломалось
         * ровно у того, кто обновляется раз в неделю. Теперь ключ в репозитории: подпись не
         * зависит ни от кеша, ни от раннера.
         *
         * Это тестовый ключ (не для магазина), пароль открыт так же, как он лежит в репозитории.
         */
        create("pinned") {
            val ks = file("debug.keystore")
            if (ks.exists()) {
                storeFile = ks
                storeType = "PKCS12"
                storePassword = System.getenv("WARPSCOUT_STOREPASS") ?: "warpscout"
                keyAlias = System.getenv("WARPSCOUT_KEYALIAS") ?: "warpscout"
                keyPassword = System.getenv("WARPSCOUT_KEYPASS") ?: "warpscout"
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            // Бета — отдельное приложение: «dev.warpscout.app.tunnel.beta» рядом с «dev.warpscout.app.tunnel».
            if (beta) applicationIdSuffix = ".beta"
            // Один и тот же ключ на всех сборках — иначе обновление «поверх» не ставится.
            if (file("debug.keystore").exists()) {
                signingConfig = signingConfigs.getByName("pinned")
            }
        }
        release {
            isMinifyEnabled = true
            if (beta) applicationIdSuffix = ".beta"
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Подпись релиза: либо переменные окружения, либо debug-ключ (см. README).
            val ks = file("release.keystore")
            if (ks.exists()) {
                signingConfig = signingConfigs.getByName("debug").also {
                    it.storeFile = ks
                    it.storePassword = System.getenv("WARPSCOUT_STOREPASS") ?: "android"
                    it.keyAlias = System.getenv("WARPSCOUT_KEYALIAS") ?: "androiddebugkey"
                    it.keyPassword = System.getenv("WARPSCOUT_KEYPASS") ?: "android"
                }
            }
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        // Lint не должен ронять CI на предупреждениях: он у нас информационный.
        abortOnError = false
        warningsAsErrors = false
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        resources.excludes += "/META-INF/DEPENDENCIES"
        resources.excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }

    sourceSets {
        getByName("main") { java.srcDirs("src/main/kotlin") }
        // Туннель (сервис, плитка, автоподъём) — общий для обеих сборок: код и манифест берутся
        // из src/tunnel. Отдельной заглушки «туннеля нет» у scout больше нет.
        getByName("scout") {
            java.srcDirs("src/tunnel/kotlin")
            manifest.srcFile("src/tunnel/AndroidManifest.xml")
        }
        getByName("tunnel") { java.srcDirs("src/tunnel/kotlin") }
    }
}

dependencies {
    implementation(project(":core"))
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.0")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
}
