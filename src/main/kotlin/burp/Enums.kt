package burp

import org.snakeyaml.engine.v1.api.Dump
import org.snakeyaml.engine.v1.api.DumpSettingsBuilder
import java.util.regex.Pattern

enum class RegExpFlag {
    CASE_INSENSITIVE, MULTILINE, DOTALL, UNICODE_CASE, CANON_EQ,
    UNIX_LINES, LITERAL, UNICODE_CHARACTER_CLASS, COMMENTS;

    val value = Pattern::class.java.getField(name).getInt(null)

    override fun toString(): String {
        return name.toLowerCase().replace('_', ' ')
    }
}

enum class RequestResponse {
    REQUEST {
        override fun getMessage(rr: IHttpRequestResponse): ByteArray? = rr.request

        override fun setMessage(rr: IHttpRequestResponse, value: ByteArray) {
            rr.request = value
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int =
                helpers.analyzeRequest(data).bodyOffset

        override fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String> =
                helpers.analyzeRequest(data).headers
    },

    RESPONSE {
        override fun getMessage(rr: IHttpRequestResponse): ByteArray? = rr.response

        override fun setMessage(rr: IHttpRequestResponse, value: ByteArray) {
            rr.response = value
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int =
                helpers.analyzeResponse(data).bodyOffset

        override fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String> =
                helpers.analyzeResponse(data).headers
    };

    abstract fun getMessage(rr: IHttpRequestResponse): ByteArray?
    abstract fun setMessage(rr: IHttpRequestResponse, value: ByteArray)
    abstract fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int
    abstract fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String>

    companion object {
        fun fromBoolean(isRequest: Boolean) = if (isRequest) REQUEST else RESPONSE
    }
}

enum class BurpTool {
    SUITE, TARGET, PROXY, SPIDER, SCANNER, INTRUDER, REPEATER, SEQUENCER, DECODER, COMPARER, EXTENDER;

    val value = IBurpExtenderCallbacks::class.java.getField("TOOL_$name").getInt(null)

    override fun toString(): String {
        return name.toLowerCase().capitalize()
    }
}

enum class MatchNegation(val negation: Boolean, private val description: String) {
    NORMAL(false, "Match when all the rules below apply"),
    NEGATED(true, "Match when none of the rules below apply");

    override fun toString(): String = description
}

enum class ConfigRequestResponse(val rr: Piper.RequestResponse) {
    REQUEST (Piper.RequestResponse.REQUEST),
    RESPONSE(Piper.RequestResponse.RESPONSE);

    override fun toString(): String = "HTTP ${rr.toString().toLowerCase()}s"
}

enum class ConfigFormat {
    YAML {
        override fun parse(blob: ByteArray): Piper.Config = configFromYaml(String(blob, Charsets.UTF_8))
        override fun serialize(config: Piper.Config): ByteArray =
                Dump(DumpSettingsBuilder().build()).dumpToString(config.toSettings()).toByteArray(/* default is UTF-8 */)

        override val fileExtension: String
            get() = "yaml"
    },

    PROTOBUF {
        override fun parse(blob: ByteArray): Piper.Config = Piper.Config.parseFrom(blob)
        override fun serialize(config: Piper.Config): ByteArray = config.toByteArray()
        override val fileExtension: String
            get() = "pb"
    };

    abstract fun serialize(config: Piper.Config): ByteArray
    abstract fun parse(blob: ByteArray): Piper.Config
    abstract val fileExtension: String
}