package burp

import com.google.protobuf.ByteString
import java.awt.Window
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.lang.RuntimeException
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

        if (match.inScope) yield("request is" + (if (negated) "n't" else "") + " in scope")

        if (match.andAlsoCount > 0) {
            yield(match.andAlsoList.joinToString(separator = (if (negated) " or " else " and "),
                    transform = { it.toHumanReadable(negated) } ))
        }

        if (match.orElseCount > 0) {
            yield(match.orElseList.joinToString(separator = (if (negated) " and " else " or "),
                    transform = { it.toHumanReadable(negated) } ))
        }
    }.toList()
    val result = items.joinToString(separator = (if (negated) " or " else " and ")).truncateTo(64)
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
        if (this@commandLine.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) yield(CMDLINE_INPUT_FILENAME_PLACEHOLDER)
        yieldAll(this@commandLine.postfixList.map(::shellQuote))
    }.joinToString(separator = " ").truncateTo(64)

fun shellQuote(s: String): String = if (!s.contains(Regex("[\"\\s\\\\]"))) s
        else '"' + s.replace(Regex("[\"\\\\]")) { "\\" + it.groups[0]!!.value }  + '"'

fun String.truncateTo(charLimit: Int): String = if (length < charLimit) this else this.substring(0, charLimit) + "..."

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

fun Piper.MinimalTool.isInToolScope(isRequest: Boolean): Boolean =
    when (scope) {
        Piper.MinimalTool.Scope.REQUEST_ONLY -> isRequest
        Piper.MinimalTool.Scope.RESPONSE_ONLY -> !isRequest
        else -> true
    }

fun Piper.MinimalTool.canProcess(md: List<MessageInfo>, mims: MessageInfoMatchStrategy, helpers: IExtensionHelpers,
                                 callbacks: IBurpExtenderCallbacks): Boolean =
        !this.hasFilter() || mims.predicate(md) { this.filter.matches(it, helpers, callbacks) }

fun Piper.MinimalTool.buildEnabled(value: Boolean? = null): Piper.MinimalTool {
    val enabled = value ?: try {
        this.cmd.checkDependencies()
        true
    } catch (_: DependencyException) {
        false
    }
    return toBuilder().setEnabled(enabled).build()
}

fun Piper.UserActionTool.buildEnabled(value: Boolean? = null): Piper.UserActionTool = toBuilder().setCommon(common.buildEnabled(value)).build()
fun Piper.HttpListener  .buildEnabled(value: Boolean? = null): Piper.HttpListener   = toBuilder().setCommon(common.buildEnabled(value)).build()
fun Piper.MessageViewer .buildEnabled(value: Boolean? = null): Piper.MessageViewer  = toBuilder().setCommon(common.buildEnabled(value)).build()
fun Piper.Commentator   .buildEnabled(value: Boolean? = null): Piper.Commentator    = toBuilder().setCommon(common.buildEnabled(value)).build()
fun Piper.Highlighter   .buildEnabled(value: Boolean? = null): Piper.Highlighter    = toBuilder().setCommon(common.buildEnabled(value)).build()

fun Piper.MessageMatch.matches(message: MessageInfo, helpers: IExtensionHelpers, callbacks: IBurpExtenderCallbacks): Boolean = (
        (this.prefix == null  || this.prefix.size() == 0  || message.content.startsWith(this.prefix)) &&
                (this.postfix == null || this.postfix.size() == 0 || message.content.endsWith(this.postfix)) &&
                (!this.hasRegex() || this.regex.matches(message.text)) &&
                (!this.hasCmd()   || this.cmd.matches(message.content, helpers, callbacks)) &&

                (message.headers == null || !this.hasHeader() || this.header.matches(message.headers)) &&
                (message.url == null || !this.inScope || callbacks.isInScope(message.url)) &&

                (this.andAlsoCount == 0 || this.andAlsoList.all { it.matches(message, helpers, callbacks) }) &&
                (this.orElseCount  == 0 || this.orElseList.any  { it.matches(message, helpers, callbacks) })
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

private const val DEFAULT_FILE_EXTENSION = ".bin"

fun Piper.CommandInvocation.execute(vararg inputs: ByteArray): Pair<Process, List<File>> = execute(*inputs.map { it to null }.toTypedArray())

fun Piper.CommandInvocation.execute(vararg inputs: Pair<ByteArray, String?>): Pair<Process, List<File>> {
    val tempFiles = if (this.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) {
        inputs.map { (contents, extension) ->
            File.createTempFile("piper-", extension ?: DEFAULT_FILE_EXTENSION).apply { writeBytes(contents) }
        }
    } else emptyList()
    val args = this.prefixList + tempFiles.map(File::getAbsolutePath) + this.postfixList
    val p = Runtime.getRuntime().exec(args.toTypedArray())
    if (this.inputMethod == Piper.CommandInvocation.InputMethod.STDIN) {
        try {
            p.outputStream.use {
                inputs.map(Pair<ByteArray, String?>::first).forEach(p.outputStream::write)
            }
        } catch (_: IOException) {
            // ignore, see https://github.com/silentsignal/burp-piper/issues/6
        }
    }
    return p to tempFiles
}

val Piper.CommandInvocationOrBuilder.hasFilter: Boolean
    get() = hasStderr() || hasStdout() || exitCodeCount > 0

fun Piper.CommandInvocation.matches(subject: ByteArray, helpers: IExtensionHelpers, callbacks: IBurpExtenderCallbacks): Boolean {
    val (process, tempFiles) = this.execute(subject)
    if ((this.hasStderr() && !this.stderr.matches(process.errorStream, helpers, callbacks)) ||
            (this.hasStdout() && !this.stdout.matches(process.inputStream, helpers, callbacks))) return false
    val exitCode = process.waitFor()
    tempFiles.forEach { it.delete() }
    return (this.exitCodeCount == 0) || exitCode in this.exitCodeList
}

fun Piper.MessageMatch.matches(stream: InputStream, helpers: IExtensionHelpers, callbacks: IBurpExtenderCallbacks): Boolean =
        this.matches(stream.readBytes(), helpers, callbacks)

fun Piper.MessageMatch.matches(data: ByteArray, helpers: IExtensionHelpers, callbacks: IBurpExtenderCallbacks): Boolean =
        this.matches(MessageInfo(data, helpers.bytesToString(data), headers = null, url = null), helpers, callbacks)

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

class DependencyException(dependency: String) : RuntimeException("Dependent executable `$dependency` cannot be found in \$PATH")

fun Piper.CommandInvocation.checkDependencies() {
    val s = sequence {
        if (prefixCount != 0) yield(getPrefix(0)!!)
        yieldAll(requiredInPathList)
    }
    throw DependencyException(s.firstOrNull { !findExecutable(it) } ?: return)
}

private fun findExecutable(name: String): Boolean {
    val endings = if ("Windows" in System.getProperty("os.name")) listOf("", ".cmd", ".exe", ".com", ".bat") else listOf("")
    return sequence {
        yield(null) // current directory
        yieldAll(System.getenv().filterKeys { it.equals("PATH", ignoreCase = true) }.values.map { it.split(File.pathSeparator) }.flatten())
    }.any { parent -> endings.any { ending -> canExecute(File(parent, name + ending)) } }
}

private fun canExecute(f: File): Boolean = f.exists() && !f.isDirectory && f.canExecute()

fun Window.repack() {
    val oldWidth = width
    pack()
    val loc = location
    setLocation(loc.x + ((oldWidth - width) / 2), loc.y)
}

fun Piper.Config.updateEnabled(value: Boolean): Piper.Config {
    return Piper.Config.newBuilder()
            .addAllMacro                   (macroList                   .map { it.buildEnabled(value) })
            .addAllMenuItem                (menuItemList                .map { it.buildEnabled(value) })
            .addAllMessageViewer           (messageViewerList           .map { it.buildEnabled(value) })
            .addAllHttpListener            (httpListenerList            .map { it.buildEnabled(value) })
            .addAllCommentator             (commentatorList             .map { it.buildEnabled(value) })
            .addAllIntruderPayloadProcessor(intruderPayloadProcessorList.map { it.buildEnabled(value) })
            .addAllIntruderPayloadGenerator(intruderPayloadGeneratorList.map { it.buildEnabled(value) })
            .addAllHighlighter             (highlighterList             .map { it.buildEnabled(value) })
            .build()
}