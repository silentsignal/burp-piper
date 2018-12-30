package burp

import com.amihaiemil.eoyaml.Yaml
import com.amihaiemil.eoyaml.YamlMappingBuilder
import com.amihaiemil.eoyaml.YamlNode
import com.google.protobuf.ByteString
import java.io.ByteArrayOutputStream
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream

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