plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.warpscout.netdiag"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.warpscout.netdiag"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        create("pinned") {
            val ks = rootProject.file("app/debug.keystore")
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
            if (rootProject.file("app/debug.keystore").exists()) {
                signingConfig = signingConfigs.getByName("pinned")
            }
        }
        release {
            isMinifyEnabled = false
            if (rootProject.file("app/debug.keystore").exists()) {
                signingConfig = signingConfigs.getByName("pinned")
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    testImplementation("junit:junit:4.13.2")
}
