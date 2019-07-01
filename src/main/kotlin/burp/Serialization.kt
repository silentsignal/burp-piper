package burp

import com.google.protobuf.ByteString
import org.snakeyaml.engine.v1.api.Load
import org.snakeyaml.engine.v1.api.LoadSettingsBuilder
import java.io.ByteArrayOutputStream
import java.lang.RuntimeException
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream

fun configFromYaml(value: String): Piper.Config {
    val ls = Load(LoadSettingsBuilder().build())
    val b = Piper.Config.newBuilder()!!
    with(ls.loadFromString(value) as Map<String, List<*>>) {
        copyListOfStructured("messageViewers", b::addMessageViewer, ::messageViewerFromMap)
        copyListOfStructured("macros", b::addMacro, ::minimalToolFromMap)
        copyListOfStructured("menuItems", b::addMenuItem, UserActionToolFromMap)
        copyListOfStructured("httpListeners", b::addHttpListener, ::httpListenerFromMap)
        copyListOfStructured("commentators", b::addCommentator, ::commentatorFromMap)
    }
    return b.build()
}

fun commentatorFromMap(source: Map<String, Any>): Piper.Commentator {
    val b = Piper.Commentator.newBuilder()!!
            .setSource(enumFromString(source.stringOrDie("source"),
                    Piper.RequestResponse::class.java))
    source.copyBooleanFlag("overwrite", b::setOverwrite)
    return b.setCommon(minimalToolFromMap(source)).build()
}

fun messageViewerFromMap(source: Map<String, Any>): Piper.MessageViewer {
    val b = Piper.MessageViewer.newBuilder()!!
    source.copyBooleanFlag("usesColors", b::setUsesColors)
    return b.setCommon(minimalToolFromMap(source)).build()
}

fun minimalToolFromMap(source: Map<String, Any>): Piper.MinimalTool {
    val b = Piper.MinimalTool.newBuilder()!!
            .setName(source.stringOrDie("name"))
            .setCmd(commandInvocationFromMap(source))
    source.copyStructured("filter", b::setFilter, ::messageMatchFromMap)
    return b.build()
}

fun httpListenerFromMap(source: Map<String, Any>): Piper.HttpListener {
    val b = Piper.HttpListener.newBuilder()!!
            .setScope(enumFromString(source.stringOrDie("scope"),
                    Piper.RequestResponse::class.java))
    val ss = source.stringSequence("tool", required = false)
            .map { enumFromString(it, BurpTool::class.java) }
    if (ss.isNotEmpty()) b.setToolSet(ss.toSet())
    return b.setCommon(minimalToolFromMap(source)).build()
}

fun commandInvocationFromMap(source: Map<String, Any>): Piper.CommandInvocation {
    val b = Piper.CommandInvocation.newBuilder()!!
            .addAllPrefix(source.stringSequence("prefix"))
            .addAllPostfix(source.stringSequence("postfix", required = false))
            .setInputMethod(enumFromString(source.stringOrDie("inputMethod"),
                    Piper.CommandInvocation.InputMethod::class.java))
            .addAllRequiredInPath(source.stringSequence("requiredInPath", required = false))
            .addAllExitCode(source.intSequence("exitCode"))
    with(source) {
        copyBooleanFlag("passHeaders", b::setPassHeaders)
        copyStructured("stdout", b::setStdout, ::messageMatchFromMap)
        copyStructured("stderr", b::setStderr, ::messageMatchFromMap)
    }
    return b.build()
}

fun messageMatchFromMap(source: Map<String, Any>): Piper.MessageMatch {
    val b = Piper.MessageMatch.newBuilder()!!
    with(source) {
        copyBytes("prefix", b::setPrefix)
        copyBytes("postfix", b::setPostfix)
        copyBooleanFlag("negation", b::setNegation)
        copyStructured("regex", b::setRegex, RegExpFromMap)
        copyStructured("header", b::setHeader, HeaderMatchFromMap)
        copyStructured("cmd", b::setCmd, ::commandInvocationFromMap)
        copyListOfStructured("andAlso", b::addAndAlso, ::messageMatchFromMap)
        copyListOfStructured("orElse", b::addOrElse, ::messageMatchFromMap)
    }
    return b.build()
}

object HeaderMatchFromMap : (Map<String, Any>) -> Piper.HeaderMatch {
    override fun invoke(source: Map<String, Any>): Piper.HeaderMatch {
        val b = Piper.HeaderMatch.newBuilder()!!
                .setHeader(source.stringOrDie("header"))
        source.copyStructured("regex", b::setRegex, RegExpFromMap)
        return b.build()
    }
}

object RegExpFromMap : (Map<String, Any>) -> Piper.RegularExpression {
    override fun invoke(source: Map<String, Any>): Piper.RegularExpression {
        val b = Piper.RegularExpression.newBuilder()!!
                .setPattern(source.stringOrDie("pattern"))
        val ss = source.stringSequence("flags", required = false)
                .map { enumFromString(it, RegExpFlag::class.java) }
        if (ss.isNotEmpty()) b.setFlagSet(ss.toSet())
        return b.build()
    }
}

object UserActionToolFromMap : (Map<String, Any>) -> Piper.UserActionTool {
    override fun invoke(source: Map<String, Any>): Piper.UserActionTool {
        val b = Piper.UserActionTool.newBuilder()!!
                .setCommon(minimalToolFromMap(source))
        source.copyBooleanFlag("hasGUI", b::setHasGUI)
        source.copyInt("minInputs", b::setMinInputs)
        source.copyInt("maxInputs", b::setMaxInputs)
        return b.build()
    }
}

fun Map<String, Any>.copyInt(key: String, setter: (Int) -> Any) {
    when (val value = this[key] ?: return) {
        is Int -> if (value != 0) setter(value)
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun <E> Map<String, Any>.copyStructured(key: String, setter: (E) -> Any, transform: (Map<String, Any>) -> E) {
    when (val value = this[key] ?: return) {
        is Map<*, *> -> setter(transform(value as Map<String, Any>))
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun <E> Map<String, Any>.copyListOfStructured(key: String, setter: (E) -> Any, transform: (Map<String, Any>) -> E) {
    when (val value = this[key] ?: return) {
        is List<*> -> value.forEach { setter(transform(it as Map<String, Any>)) }
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun Map<String, Any>.copyBytes(key: String, setter: (ByteString) -> Any) {
    when (val value = this[key] ?: return) {
        is String -> setter(ByteString.copyFromUtf8(value))
        is ByteArray -> setter(ByteString.copyFrom(value))
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun <E : Enum<E>> enumFromString(value: String, cls: Class<E>): E {
    try {
        val search = value.replace(' ', '_')
        return cls.enumConstants.first { it.name.equals(search, ignoreCase = true) }
    } catch (_: NoSuchElementException) {
        throw RuntimeException("Invalid value for enumerated type: $value")
    }
}

fun Map<String, Any>.stringOrDie(key: String): String {
    when (val value = this[key]) {
        null -> throw RuntimeException("Missing value for $key")
        is String -> return value
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun Map<String, Any>.stringSequence(key: String, required: Boolean = true): Iterable<String> {
    return when (val value = this[key]) {
        null -> if (required) throw RuntimeException("Missing list for $key") else return emptyList()
        is List<*> -> value.map {
            when (it) {
                null -> throw RuntimeException("Invalid item for $key")
                is String -> return@map it
                else -> throw RuntimeException("Invalid value for $key: $it")
            }
        } as List<String>
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun Map<String, Any>.intSequence(key: String): Iterable<Int> {
    return when (val value = this[key]) {
        null -> emptyList()
        is List<*> -> value.map {
            when (it) {
                null -> throw RuntimeException("Invalid item for $key")
                is Int -> return@map it
                else -> throw RuntimeException("Invalid value for $key: $it")
            }
        } as List<Int>
        else -> throw RuntimeException("Invalid value for $key: $value")
    }
}

fun Map<String, Any>.copyBooleanFlag(key: String, setter: (Boolean) -> Any) {
    val value = this[key]
    if (value != null && value is Boolean && value) setter(true)
}

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

fun Piper.Config.toSettings(): Map<String, Any> {
    val m = mutableMapOf<String, Any>()
    m.add("messageViewers", this.messageViewerList, Piper.MessageViewer::toMap)
    m.add("menuItems", this.menuItemList, Piper.UserActionTool::toMap)
    m.add("macros", this.macroList, Piper.MinimalTool::toMap)
    m.add("httpListeners", this.httpListenerList, Piper.HttpListener::toMap)
    m.add("commentators", this.commentatorList, Piper.Commentator::toMap)
    return m
}

fun <E> MutableMap<String, Any>.add(key: String, value: List<E>, transform: (E) -> Any) {
    if (value.isNotEmpty()) this[key] = value.map(transform)
}

fun MutableMap<String, Any>.add(key: String, value: ByteString?) {
    if (value == null || value.isEmpty) return
    this[key] = if (value.isValidUtf8) value.toStringUtf8() else value.toByteArray()
}

fun Piper.MessageViewer.toMap(): Map<String, Any> =
        if (this.usesColors) this.common.toMap() + ("usesColors" to true) else this.common.toMap()

fun Piper.UserActionTool.toMap(): Map<String, Any> {
    val m = this.common.toMap()
    if (this.hasGUI) m["hasGUI"] = true
    if (this.minInputs != 0) m["minInputs"] = this.minInputs
    if (this.maxInputs != 0) m["maxInputs"] = this.maxInputs
    return m
}

fun Piper.HttpListener.toMap(): Map<String, Any> {
    val m = this.common.toMap()
    if (this.tool != 0) m["tool"] = this.toolSet.toSortedStringList()
    m["scope"] = this.scope.name.toLowerCase()
    return m
}

fun Piper.Commentator.toMap(): Map<String, Any> {
    val m = this.common.toMap()
    if (this.overwrite) m["overwrite"] = true
    m["source"] = this.source.name.toLowerCase()
    return m
}

fun Piper.MinimalTool.toMap(): MutableMap<String, Any> {
    val m = this.cmd.toMap()
    m["name"] = this.name!!
    if (this.hasFilter()) m["filter"] = this.filter.toMap()
    return m
}

fun Piper.MessageMatch.toMap(): Map<String, Any> {
    val m = mutableMapOf<String, Any>()
    m.add("prefix", this.prefix)
    m.add("postfix", this.postfix)
    if (this.hasRegex()) m["regex"] = this.regex.toMap()
    if (this.hasHeader()) m["header"] = this.header.toMap()
    if (this.hasCmd()) m["cmd"] = this.cmd.toMap()
    if (this.negation) m["negation"] = true
    if (this.orElseCount > 0) m["orElse"] = this.orElseList.map(Piper.MessageMatch::toMap)
    if (this.andAlsoCount > 0) m["andAlso"] = this.andAlsoList.map(Piper.MessageMatch::toMap)
    return m
}

fun Piper.CommandInvocation.toMap(): MutableMap<String, Any> {
    val m = mutableMapOf<String, Any>()
    m["prefix"] = this.prefixList
    if (this.postfixCount > 0) m["postfix"] = this.postfixList
    m["inputMethod"] = this.inputMethod.name.toLowerCase()
    if (this.passHeaders) m["passHeaders"] = true
    if (this.requiredInPathCount > 0) m["requiredInPath"] = this.requiredInPathList
    if (this.exitCodeCount > 0) m["exitCode"] = this.exitCodeList
    if (this.hasStdout()) m["stdout"] = this.stdout.toMap()
    if (this.hasStderr()) m["stderr"] = this.stderr.toMap()
    return m
}

fun Piper.RegularExpression.toMap(): Map<String, Any> {
    val m = mutableMapOf<String, Any>("pattern" to this.pattern!!)
    if (this.flags != 0) m["flags"] = this.flagSet.toSortedStringList()
    return m
}

fun <E> Set<E>.toSortedStringList() = this.asSequence().map { it.toString() }.sorted().toList()

fun Piper.HeaderMatch.toMap() = mapOf(("header" to this.header), ("regex" to this.regex.toMap()))