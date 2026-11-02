package io.crates.keyring

import android.content.Context

/**
 * The JNI hook android-native-keyring-store exports, called once before any
 * keystore use. Its package, class and method names are fixed by the JNI
 * symbol. It loads macula_rust_ffi, the library that runs the SDK: the hook
 * has to set that library's ndk-context, not a copy in another library.
 */
class Keyring {
    companion object {
        init {
            System.loadLibrary("macula_rust_ffi")
        }

        external fun initializeNdkContext(context: Context)
    }
}
