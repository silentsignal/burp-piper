package burp

import com.amihaiemil.eoyaml.*
import com.google.protobuf.ByteString
import java.io.ByteArrayOutputStream
import java.lang.RuntimeException
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream

fun configFromYaml(value: String): Piper.Config {
    val ym = Yaml.createYamlInput(value).readYamlMapping()!!
    return Piper.Config.newBuilder()
            .addAllMessageViewer(ym.yamlSequence("messageViewers")?.map(MessageViewerFromYaml) ?: emptyList())
            // TODO macro
            // TODO menuItem
            .build()
}

object MessageViewerFromYaml : (YamlMapping) -> Piper.MessageViewer {
    override fun invoke(source: YamlMapping): Piper.MessageViewer {
        val b = Piper.MessageViewer.newBuilder()!!
        source.copyBooleanFlag("usesColors", b::setUsesColors)
        return b.setCommon(minimalToolFromYaml(source)).build()
    }
}

object MessageMatchFromYaml : (YamlMapping) -> Piper.MessageMatch {
    override fun invoke(source: YamlMapping): Piper.MessageMatch {
        val b = Piper.MessageMatch.newBuilder()!!
        with(source) {
            copyBytes("prefix", b::setPrefix)
            copyBytes("postfix", b::setPostfix)
            copyBooleanFlag("negation", b::setNegation)
            copyStructured("regex", b::setRegex, RegExpFromYaml)
            // TODO header
            copyStructured("cmd", b::setCmd, CommandInvocationFromYaml)
            // TODO andAlso
            // TODO orElse
        }
        return b.build()
    }
}

object CommandInvocationFromYaml : (YamlMapping) -> Piper.CommandInvocation {
    override fun invoke(source: YamlMapping): Piper.CommandInvocation {
        val b = Piper.CommandInvocation.newBuilder()!!
                .addAllPrefix(source.stringSequence("prefix"))
                .addAllPostfix(source.stringSequence("postfix", required = false))
                .setInputMethod(enumFromString(source.stringOrDie("inputMethod"),
                        Piper.CommandInvocation.InputMethod::class.java))
                .addAllRequiredInPath(source.stringSequence("requiredInPath", required = false))
                .addAllExitCode(source.stringSequence("requiredInPath", required = false).map(String::toInt))
        with(source) {
            copyBooleanFlag("passHeaders", b::setPassHeaders)
            copyStructured("stdout", b::setStdout, MessageMatchFromYaml)
        }
        return b.build()
    }
}

object RegExpFromYaml : (YamlMapping) -> Piper.RegularExpression {
    override fun invoke(source: YamlMapping): Piper.RegularExpression {
        val b = Piper.RegularExpression.newBuilder()!!
                .setPattern(source.stringOrDie("pattern"))
        val ss = source.stringSequence("flags", required = false)
                .map { enumFromString(it, RegExpFlag::class.java) }
        if (ss.isNotEmpty()) b.setFlagSet(ss.toSet())
        return b.build()
    }
}

fun YamlMapping.copyBytes(key: String, setter: (ByteString) -> Any) {
    val s = this.string(key) ?: return
    setter(ByteString.copyFrom(s.split(':').map {
        it.trim().toInt(16).toByte()
    }.toByteArray()))
}

fun minimalToolFromYaml(source: YamlMapping): Piper.MinimalTool =
        Piper.MinimalTool.newBuilder()!!
                .setName(source.stringOrDie("name"))
                .setCmd(CommandInvocationFromYaml.invoke(source))
                .build() // TODO filter

fun <E> YamlMapping.copyStructured(key: String, setter: (E) -> Any, transform: (YamlMapping) -> E) {
    setter(transform(this.yamlMapping(key) ?: return))
}

fun <E : Enum<E>> enumFromString(value: String, cls: Class<E>): E {
    try {
        val search = value.replace(' ', '_')
        return cls.enumConstants.first { it.name.equals(search, ignoreCase = true) }
    } catch (_: NoSuchElementException) {
        throw RuntimeException("Invalid value for inputMethod: $value")
    }
}

fun YamlMapping.stringOrDie(key: String): String = this.string(key) ?: throw RuntimeException("Missing value for $key")

fun YamlMapping.stringSequence(key: String, required: Boolean = true): Iterable<String> {
    val seq = this.yamlSequence(key) ?: if (required) throw RuntimeException("Missing list for $key") else return emptyList()
    return seq.indices.map { seq.string(it)!! }
}

fun YamlMapping.copyBooleanFlag(key: String, setter: (Boolean) -> Any) {
    if ("true".equals(this.string(key), ignoreCase = true)) setter(true)
}

fun <E> YamlSequence.map(transform: (YamlMapping) -> E): Iterable<E> =
        this.indices.map { transform(this.yamlMapping(it)!!) }

val YamlSequence.indices: IntRange
    get() = 0 until this.size()

fun pad4(value: ByteArray): ByteArray {
    val pad = (4 - value.size % 4).toByte()
    return value + pad.downTo(1).map { pad }.toByteArray()
}

fun unpad4(value: ByteArray): ByteArray =
    value.dropLast(value.last().toInt()).toByteArray()

fun compress(value: ByteArray): ByteArray {
    val bos = ByteArrayOutputStream()
    DeflaterOutputStream(bos).use { it.write(value) }
    return bos.toByteArray()
}

fun decompress(value: ByteArray): ByteArray =
    InflaterInputStream(value.inputStream()).use { it.readBytes() }

fun YamlMappingBuilder.add(key: String, value: ByteString): YamlMappingBuilder =
        if (value.isEmpty) this else this.add(key, value.toByteArray().joinToString(separator=":",
                transform={ it.toInt().and(0xFF).toString(16).padStart(2, '0') }))

fun YamlMappingBuilder.addIf(enabled: Boolean, key: String, producer: () -> YamlNode): YamlMappingBuilder =
        if (enabled) this.add(key, producer()) else this

fun YamlMappingBuilder.add(key: String, value: Boolean): YamlMappingBuilder =
        if (value) this.add(key, "true") else this

fun YamlMappingBuilder.add(key: String, value: Int): YamlMappingBuilder =
        if (value == 0) this else this.add(key, value.toString())

fun <E> YamlMappingBuilder.add(key: String, value: List<E>, transform: (E) -> YamlNode): YamlMappingBuilder =
        if (value.isEmpty()) this else this.add(key, value.fold(
                Yaml.createYamlSequenceBuilder()) { acc, e -> acc.add(transform(e)) }.build())

fun YamlMappingBuilder.add(key: String, value: List<String>): YamlMappingBuilder =
        if (value.isEmpty()) this else this.add(key, value.fold(
                Yaml.createYamlSequenceBuilder()) { acc, e -> acc.add(e) }.build())

fun Piper.RegularExpression.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("pattern", this.pattern)
        .add("flags", this.flagSet.asSequence().map(RegExpFlag::toString).sorted().toList())
        .build()

fun Piper.Config.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("messageViewers", this.messageViewerList, Piper.MessageViewer::toYaml)
        .add("menuItems", this.menuItemList, Piper.UserActionTool::toYaml)
        .add("macros", this.macroList, Piper.MinimalTool::toYaml)
        .build()

fun Piper.UserActionTool.toYaml(): YamlNode = this.common.toYamlBuilder()
        .add("hasGUI", this.hasGUI)
        .add("maxInputs", this.maxInputs)
        .add("minInputs", this.minInputs)
        .build()

fun Piper.MessageViewer.toYaml(): YamlNode = this.common.toYamlBuilder()
        .add("usesColors", this.usesColors)
        .build()

fun Piper.MinimalTool.toYaml(): YamlNode = this.toYamlBuilder().build()
fun Piper.MinimalTool.toYamlBuilder(): YamlMappingBuilder = this.cmd.toYamlBuilder()
        .add("name", this.name)
        .addIf(this.hasFilter(), "filter", this.filter::toYaml)

fun Piper.CommandInvocation.toYaml(): YamlNode = this.toYamlBuilder().build()
fun Piper.CommandInvocation.toYamlBuilder(): YamlMappingBuilder = Yaml.createYamlMappingBuilder()
        .add("prefix", this.prefixList)
        .add("postfix", this.postfixList)
        .add("inputMethod", this.inputMethod.name.toLowerCase())
        .add("passHeaders", this.passHeaders)
        .add("requiredInPath", this.requiredInPathList)
        .add("exitCode", this.exitCodeList.map(Int::toString))
        .addIf(this.hasStdout(), "stdout", this.stdout::toYaml)
        .addIf(this.hasStderr(), "stderr", this.stderr::toYaml)

fun Piper.HeaderMatch.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("header", this.header)
        .add("regex", this.regex.toYaml())
        .build()

fun Piper.MessageMatch.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("prefix", this.prefix)
        .add("postfix", this.postfix)
        .addIf(this.hasRegex(), "regex", this.regex::toYaml)
        .addIf(this.hasHeader(), "header", this.header::toYaml)
        .addIf(this.hasCmd(), "cmd", this.cmd::toYaml)
        .add("negation", this.negation)
        .add("andAlso", this.andAlsoList, Piper.MessageMatch::toYaml)
        .add("orElse", this.orElseList, Piper.MessageMatch::toYaml)
        .build()