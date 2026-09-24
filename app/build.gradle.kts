import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()

if (keystorePropertiesFile.exists()) {
    FileInputStream(keystorePropertiesFile).use {
        keystoreProperties.load(it)
    }
}

android {
    namespace = "org.vextaproject.wallet"
    compileSdk = 36
    ndkVersion = "27.3.13750724"

    defaultConfig {
        applicationId = "org.vextaproject.wallet"
        minSdk = 26
        targetSdk = 36
        versionCode = 41
        versionName = "0.7.2"
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = file(
                    keystoreProperties.getProperty("storeFile")
                )
                storePassword =
                    keystoreProperties.getProperty("storePassword")
                keyAlias =
                    keystoreProperties.getProperty("keyAlias")
                keyPassword =
                    keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    externalNativeBuild {
        cmake {
            version = "3.22.1"
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }

        getByName("release") {
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }

            isMinifyEnabled = false
            isShrinkResources = false
        }
    }
}

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("org.bitcoinj:bitcoinj-core:0.16.3")
    implementation("com.google.zxing:core:3.5.3")
    implementation(
        "com.google.android.gms:play-services-code-scanner:16.1.0"
    )
}
