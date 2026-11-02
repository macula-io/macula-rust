plugins {
    id("com.android.library")
}

android {
    namespace = "io.macula.rust.keystore"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    // libmacula_rust_ffi.so per ABI, and the generated bindings under
    // src/main/kotlin/io/macula/sdk/: both written by
    // scripts/android_keystore_proof.sh, neither committed.
    sourceSets {
        getByName("main") {
            jniLibs.directories.add("src/main/jniLibs")
        }
    }

    lint {
        // The generated bindings guard their one API 33 call behind a
        // runtime class check that lint cannot see through.
        disable += "NewApi"
    }
}

dependencies {
    // Runtime requirements of the generated bindings.
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("junit:junit:4.13.2")
}
