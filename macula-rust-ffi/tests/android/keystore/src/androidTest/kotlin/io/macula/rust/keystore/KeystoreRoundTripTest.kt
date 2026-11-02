package io.macula.rust.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.crates.keyring.Keyring
import io.macula.sdk.FfiException
import io.macula.sdk.FfiNodeKey
import io.macula.sdk.FfiProfile
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A node key kept in the Android Keystore through macula-rust-ffi comes back
 * as the same node (macula-io/macula-rust#63). Runs on an emulator.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreRoundTripTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val service = "io.macula.rust.keystore.test"

    @Before
    fun initializeTheStore() {
        Keyring.initializeNdkContext(context)
    }

    @Test
    fun aSavedKeyLoadsBackAsTheSameNode() {
        val key = FfiNodeKey.generate(FfiProfile.PQ_PURE)
        key.saveToKeystore(service, "round_trip")

        val back = FfiNodeKey.loadFromKeystore(service, "round_trip", FfiProfile.PQ_PURE)

        assertArrayEquals(key.nodeId(), back.nodeId())
    }

    @Test
    fun aKeyNeverSavedIsNotFound() {
        val refusal = runCatching {
            FfiNodeKey.loadFromKeystore(service, "never_saved", FfiProfile.PQ_PURE)
        }.exceptionOrNull()

        assertTrue("got $refusal", refusal is FfiException.KeystoreNotFound)
    }

    /** No plaintext fallback: the only file a save writes is the store's
     *  own encrypted preferences file. */
    @Test
    fun aSaveWritesOnlyTheStoreFile() {
        val dataDir = File(context.applicationInfo.dataDir)
        val before = filesUnder(dataDir)

        FfiNodeKey.generate(FfiProfile.PQ_PURE).saveToKeystore(service, "only_the_store")

        val written = filesUnder(dataDir) - before
        assertTrue(
            "unexpected files: $written",
            written.all { it == "shared_prefs/keyring-macula-rust.xml" },
        )
    }

    private fun filesUnder(dir: File): Set<String> =
        dir.walkTopDown()
            .filter { it.isFile }
            .map { it.relativeTo(dir).path }
            .toSet()
}
