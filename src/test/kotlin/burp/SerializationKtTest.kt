package burp

import org.testng.Assert.*
import org.testng.annotations.Test
import kotlin.text.Charsets.UTF_8

val testInput = "ABCDEFGHIJKLMNO".toByteArray(UTF_8)

class SerializationKtTest {

    @Test
    fun testPad4() {
        for (len in 0.rangeTo(testInput.size)) {
            val subset = testInput.copyOfRange(0, len)
            val padded = pad4(subset)
            assertEquals(padded.size % 4, 0)
            assertEquals(subset, unpad4(padded))
        }
    }

    @Test
    fun testCompress() {
        assertEquals(testInput, decompress(compress(testInput)))
    }
}