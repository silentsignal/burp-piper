package burp

import com.google.protobuf.ByteString
import java.io.File
import java.io.InputStream
import java.util.*
import java.util.regex.Pattern
import javax.swing.DefaultListModel

////////////////////////////////////// GUI //////////////////////////////////////

fun Piper.MessageMatch.toHumanReadable(negation: Boolean, hideParentheses: Boolean = false): String {
    val match = this
    val negated = negation xor match.negation
    val items = sequence {
        if (match.prefix != null && !match.prefix.isEmpty) {
            val prefix = if (negated) "doesn't start" else "starts"
            yield("$prefix with ${match.prefix.toHumanReadable()}")
        }
        if (match.postfix != null && !match.postfix.isEmpty) {
            val prefix = if (negated) "doesn't end" else "ends"
            yield("$prefix with ${match.postfix.toHumanReadable()}")
        }
        if (match.hasRegex()) yield(match.regex.toHumanReadable(negated))

        if (match.hasHeader()) yield(match.header.toHumanReadable(negated))

        if (match.hasCmd()) yield(match.cmd.toHumanReadable(negated))

        if (match.andAlsoCount > 0) {
            yield(match.andAlsoList.joinToString(separator = (if (negated) " or " else " and "),
                    transform = { it.toHumanReadable(negation) } ))
        }

        if (match.orElseCount > 0) {
            yield(match.orElseList.joinToString(separator = (if (negated) " and " else " or "),
                    transform = { it.toHumanReadable(negation) } ))
        }
    }.toList()
    val result = items.joinToString(separator = (if (negated) " or " else " and "))
    return if (items.size == 1 || hideParentheses) result else "($result)"
}

fun Piper.HeaderMatch.toHumanReadable(negation: Boolean): String =
    "header \"$header\" " + regex.toHumanReadable(negation)

fun Piper.CommandInvocation.toHumanReadable(negation: Boolean): String = sequence {
    if (this@toHumanReadable.exitCodeCount > 0) {
        val nt = if (negation) "n't" else ""
        val ecl = this@toHumanReadable.exitCodeList
        val values =
                if (ecl.size == 1) ecl[0].toString()
                else ecl.dropLast(1).joinToString(separator = ", ") + " or ${ecl.last()}"
        yield("exit code is$nt $values")
    }
    if (this@toHumanReadable.hasStdout()) {
        yield("stdout " + this@toHumanReadable.stdout.toHumanReadable(negation))
    }
    if (this@toHumanReadable.hasStderr()) {
        yield("stderr " + this@toHumanReadable.stderr.toHumanReadable(negation))
    }
}.joinToString(separator = (if (negation) " or " else " and "),
        prefix = "when invoking `${this@toHumanReadable.commandLine}`, ")

val Piper.CommandInvocation.commandLine: String
    get() = sequence {
        yieldAll(this@commandLine.prefixList.map(::shellQuote))
        if (this@commandLine.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) yield("<INPUT>")
        yieldAll(this@commandLine.postfixList.map(::shellQuote))
    }.joinToString(separator = " ")

fun shellQuote(s: String): String = if (!s.contains(Regex("[\"\\s\\\\]"))) s
        else '"' + s.replace(Regex("[\"\\\\]"), "\\$0") + '"'

fun Piper.RegularExpression.toHumanReadable(negation: Boolean): String =
        (if (negation) "doesn't match" else "matches") +
                " regex \"${this.pattern}\"" +
                (if (this.flags == 0) "" else " (${this.flagSet.joinToString(separator = ", ")})")

fun ByteString.toHumanReadable(): String = if (this.isValidUtf8) '"' + this.toStringUtf8() + '"'
    else "bytes " + this.toHexPairs()

fun ByteString.toHexPairs(): String = this.toByteArray().toHexPairs()

fun ByteArray.toHexPairs(): String = this.joinToString(separator = ":",
        transform = { it.toInt().and(0xFF).toString(16).padStart(2, '0') })

////////////////////////////////////// MATCHING //////////////////////////////////////

fun Piper.MinimalTool.canProcess(messages: List<MessageInfo>, helpers: IExtensionHelpers): Boolean =
        !this.hasFilter() || messages.all { this.filter.matches(it, helpers) }

fun Piper.MinimalTool.buildEnabled(value: Boolean = true): Piper.MinimalTool = toBuilder().setEnabled(value).build()

fun Piper.MessageMatch.matches(message: MessageInfo, helpers: IExtensionHelpers): Boolean = (
        (this.prefix == null  || this.prefix.size() == 0  || message.content.startsWith(this.prefix)) &&
                (this.postfix == null || this.postfix.size() == 0 || message.content.endsWith(this.postfix)) &&
                (!this.hasRegex() || this.regex.matches(message.text)) &&
                (!this.hasCmd()   || this.cmd.matches(message.content, helpers)) &&

                (message.headers == null || !this.hasHeader() || this.header.matches(message.headers)) &&

                (this.andAlsoCount == 0 || this.andAlsoList.all { it.matches(message, helpers) }) &&
                (this.orElseCount  == 0 || this.orElseList.any  { it.matches(message, helpers) })
        ) xor this.negation

fun ByteArray.startsWith(value: ByteString): Boolean {
    val mps = value.size()
    return this.size >= mps && this.copyOfRange(0, mps) contentEquals value.toByteArray()
}

fun ByteArray.endsWith(value: ByteString): Boolean {
    val mps = value.size()
    val mbs = this.size
    return mbs >= mps && this.copyOfRange(mbs - mps, mbs) contentEquals value.toByteArray()
}

fun Piper.CommandInvocation.execute(vararg inputs: ByteArray): Pair<Process, List<File>> {
    val tempFiles = if (this.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) {
        inputs.map {
            File.createTempFile("piper-", ".bin").apply { writeBytes(it) }
        }
    } else emptyList()
    val args = this.prefixList + tempFiles.map(File::getAbsolutePath) + this.postfixList
    val p = Runtime.getRuntime().exec(args.toTypedArray())
    if (this.inputMethod == Piper.CommandInvocation.InputMethod.STDIN) {
        p.outputStream.use {
            inputs.forEach(p.outputStream::write)
        }
    }
    return p to tempFiles
}

fun Piper.CommandInvocation.matches(subject: ByteArray, helpers: IExtensionHelpers): Boolean {
    val (process, tempFiles) = this.execute(subject)
    if ((this.hasStderr() && !this.stderr.matches(process.errorStream, helpers)) ||
            (this.hasStdout() && !this.stdout.matches(process.inputStream, helpers))) return false
    val exitCode = process.waitFor()
    tempFiles.forEach { it.delete() }
    return (this.exitCodeCount == 0) || this.exitCodeList.contains(exitCode)
}

fun Piper.MessageMatch.matches(stream: InputStream, helpers: IExtensionHelpers): Boolean =
        this.matches(stream.readBytes(), helpers)

fun Piper.MessageMatch.matches(data: ByteArray, helpers: IExtensionHelpers): Boolean =
        this.matches(MessageInfo(data, helpers.bytesToString(data), null), helpers)

fun Piper.HeaderMatch.matches(headers: List<String>): Boolean = headers.any {
    it.startsWith("${this.header}: ", true) &&
            this.regex.matches(it.substring(this.header.length + 2))
}

fun Piper.RegularExpression.matches(subject: String): Boolean =
        this.compile().matcher(subject).find()

fun Piper.RegularExpression.compile(): Pattern = Pattern.compile(this.pattern, this.flags)

val Piper.RegularExpression.flagSet: Set<RegExpFlag>
    get() = calcEnumSet(RegExpFlag::class.java, RegExpFlag::value, flags, EnumSet.noneOf(RegExpFlag::class.java))

fun Piper.RegularExpression.Builder.setFlagSet(flags: Set<RegExpFlag>): Piper.RegularExpression.Builder =
        this.setFlags(flags.fold(0) { acc: Int, regExpFlag: RegExpFlag -> acc or regExpFlag.value })

val Piper.HttpListener.toolSet: Set<BurpTool>
    get() = calcEnumSet(BurpTool::class.java, BurpTool::value, tool, EnumSet.allOf(BurpTool::class.java))

fun Piper.HttpListener.Builder.setToolSet(tools: Set<BurpTool>): Piper.HttpListener.Builder =
        this.setTool(tools.fold(0) { acc: Int, tool: BurpTool -> acc or tool.value })

fun <E> Pair<Process, List<File>>.processOutput(processor: (Process) -> E): E {
    val output = processor(this.first)
    this.first.waitFor()
    this.second.forEach { it.delete() }
    return output
}

fun <E : Enum<E>> calcEnumSet(enumClass: Class<E>, getter: (E) -> Int, value: Int, zero: Set<E>): Set<E> =
        if (value == 0) zero else EnumSet.copyOf(enumClass.enumConstants.filter { (getter(it) and value) != 0 })

fun <S, T> DefaultListModel<S>.map(transform: (S) -> T): Iterable<T> = toIterable().map(transform)
fun <E> DefaultListModel<E>.toIterable(): Iterable<E> = (0 until size).map(this::elementAt)