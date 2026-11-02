// An Android app can keep its node key in the Android Keystore through
// macula-rust-ffi (macula-io/macula-rust#63). This project runs that on an
// emulator: scripts/android_keystore_proof.sh builds the library and the
// bindings into it, then runs the instrumented test.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "macula-rust-ffi-android-keystore"
include(":keystore")
