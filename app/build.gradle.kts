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
        versionCode = 14
        versionName = "1.8.0"
    }

    flavorDimensions += "mode"
    productFlavors {
        // Только сканер + генератор конфигов + передача в Amnezia.
        create("scout") {
            dimension = "mode"
            buildConfigField("boolean", "TUNNEL_SUPPORTED", "false")
            resValue("string", "app_name", "WarpScout")
        }
        // То же + собственный туннель (VpnService), проверка ресурсов из-под туннеля.
        create("tunnel") {
            dimension = "mode"
            buildConfigField("boolean", "TUNNEL_SUPPORTED", "true")
            resValue("string", "app_name", "WarpScout (tunnel)")
            // чтобы обе сборки можно было держать на телефоне одновременно и сравнивать
            applicationIdSuffix = ".tunnel"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
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
        getByName("scout") { java.srcDirs("src/scout/kotlin") }
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
