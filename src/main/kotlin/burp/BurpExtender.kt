/*
 * This file is part of Piper for Burp Suite (https://github.com/silentsignal/burp-piper)
 * Copyright (c) 2018 Andras Veres-Szentkiralyi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package burp

import com.google.protobuf.ByteString
import com.redpois0n.terminal.JTerminal
import org.snakeyaml.engine.v1.api.Dump
import org.snakeyaml.engine.v1.api.DumpSettingsBuilder
import java.io.File
import java.io.InputStream
import java.util.*
import java.util.regex.Pattern
import javax.swing.*
import kotlin.concurrent.thread
import org.zeromq.codec.Z85
import java.awt.Component

const val NAME = "Piper"
const val EXTENSION_SETTINGS_KEY = "settings"


data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?)

data class MessageViewerWrapper(val cfgItem: Piper.MessageViewer) {
    override fun toString(): String = cfgItem.common.name
}

data class UserActionToolWrapper(val cfgItem: Piper.UserActionTool) {
    override fun toString(): String = cfgItem.common.name
}

data class MessageMatchWrapper(val cfgItem: Piper.MessageMatch) {
    override fun toString(): String = cfgItem.toHumanReadable(false, true)
}

private fun Piper.MessageMatch.toHumanReadable(negation: Boolean, hideParentheses: Boolean = false): String {
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

        if (match.hasHeader()) yield("header \"${match.header.header}\" " +
                match.header.regex.toHumanReadable(negated))

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

private fun Piper.CommandInvocation.toHumanReadable(negation: Boolean): String = sequence {
        if (this@toHumanReadable.exitCodeCount > 0) {
            val nt = if (negation) "n't" else ""
            val ecl = this@toHumanReadable.exitCodeList
            val values =
                    if (ecl.size == 1) ecl[0].toString()
                    else ecl.takeLast(1).joinToString(separator = ", ") + " or ${ecl.last()}"
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

private val Piper.CommandInvocation.commandLine: String
    get() = sequence {
        yieldAll(this@commandLine.prefixList.map(::shellQuote))
        if (this@commandLine.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) yield("<INPUT>")
        yieldAll(this@commandLine.postfixList.map(::shellQuote))
    }.joinToString(separator = " ")

private fun shellQuote(s: String): String = if (!s.contains(Regex("[\"\\s\\\\]"))) s
        else '"' + s.replace(Regex("[\"\\\\]"), "\\$0") + '"'

private fun Piper.RegularExpression.toHumanReadable(negation: Boolean): String =
        (if (negation) "doesn't match" else "matches") +
        " regex \"${this.pattern}\"" +
        (if (this.flags == 0) "" else " (${this.flagSet.joinToString(separator = ", ")})")

private fun ByteString.toHumanReadable(): String = if (this.isValidUtf8) '"' + this.toStringUtf8() + '"'
    else "bytes " + this.toByteArray().joinToString(separator = ":",
        transform = { it.toInt().and(0xFF).toString(16).padStart(2, '0') })

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
        fun fromBoolean(isRequest: Boolean) =
                if (isRequest) RequestResponse.REQUEST else RequestResponse.RESPONSE
    }
}

class BurpExtender : IBurpExtender, ITab {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private val tabs = JTabbedPane()

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        val cfg = loadConfig()

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory {
            val messages = it.selectedMessages
            if (messages.isNullOrEmpty()) return@registerContextMenuFactory emptyList()
            val topLevel = generateContextMenu(messages)
            if (topLevel.subElements.isEmpty()) return@registerContextMenuFactory emptyList()
            return@registerContextMenuFactory Collections.singletonList(topLevel)
        }

        cfg.messageViewerList.forEach {
            if (it.common.enabled) {
                callbacks.registerMessageEditorTabFactory { _, _ ->
                    if (it.usesColors) TerminalEditor(it, helpers)
                    else TextEditor(it, helpers, callbacks)
                }
            }
        }

        cfg.macroList.filter(Piper.MinimalTool::getEnabled).forEach {
            callbacks.registerSessionHandlingAction(object : ISessionHandlingAction {
                override fun performAction(currentRequest: IHttpRequestResponse?, macroItems: Array<out IHttpRequestResponse>?) {
                    it.pipeMessage(RequestResponse.REQUEST, currentRequest ?: return)
                }

                override fun getActionName() : String = it.name
            })
        }

        populateTabs(cfg)
        callbacks.addSuiteTab(this)
    }

    private fun Piper.MinimalTool.pipeMessage(rr: RequestResponse, messageInfo: IHttpRequestResponse) {
        val bytes = rr.getMessage(messageInfo)!!
        val headers = rr.getHeaders(bytes, helpers)
        val bo = if (this.cmd.passHeaders) 0 else rr.getBodyOffset(bytes, helpers)
        val body = if (this.cmd.passHeaders) bytes else {
            if (bo < bytes.size - 1) {
                bytes.copyOfRange(bo, bytes.size)
            } else return
        }
        if (this.hasFilter() && !this.filter.matches(MessageInfo(body, helpers.bytesToString(body), headers), helpers)) return
        val replacement = this.cmd.execute(body).processOutput { process ->
            process.inputStream.readBytes()
        }
        if (this.cmd.passHeaders) {
            rr.setMessage(messageInfo, replacement)
        } else {
            rr.setMessage(messageInfo, bytes.copyOfRange(0, bo) + replacement)
        }
    }

    private fun populateTabs(cfg: Piper.Config) {
        // TODO tabs.addTab("Load/Save configuration")
        // TODO tabs.addTab("Message viewers")
        // TODO tabs.addTab("Context menu items")
        // TODO tabs.addTab("Macros")
        // TODO tabs.addTab("Commentators")
    }

    // ITab members
    override fun getTabCaption(): String = NAME
    override fun getUiComponent(): Component = tabs

    private data class MessageSource(val direction: RequestResponse, val includeHeaders: Boolean)

    private fun generateContextMenu(messages: Array<IHttpRequestResponse>): JMenuItem {
        val topLevel = JMenu(NAME)
        val cfg = loadConfig()
        val msize = messages.size
        val plural = if (msize == 1) "" else "s"

        val messageDetails = HashMap<MessageSource, List<MessageInfo>>()
        for (rr in RequestResponse.values()) {
            val miWithHeaders = ArrayList<MessageInfo>(messages.size)
            val miWithoutHeaders = ArrayList<MessageInfo>(messages.size)
            messages.forEach {
                val bytes = rr.getMessage(it) ?: return@forEach
                val headers = rr.getHeaders(bytes, helpers)
                miWithHeaders.add(MessageInfo(bytes, helpers.bytesToString(bytes), headers))
                val bo = rr.getBodyOffset(bytes, helpers)
                if (bo < bytes.size - 1) {
                    val body = bytes.copyOfRange(bo, bytes.size)
                    miWithoutHeaders.add(MessageInfo(body, helpers.bytesToString(body), headers))
                }
            }
            messageDetails[MessageSource(rr, true)] = miWithHeaders
            if (miWithoutHeaders.isNotEmpty()) {
                messageDetails[MessageSource(rr, false)] = miWithoutHeaders
            }
        }

        for (cfgItem in cfg.menuItemList) {
            if ((cfgItem.maxInputs != 0 && cfgItem.maxInputs < msize)
                    || cfgItem.minInputs > msize || !cfgItem.common.enabled) continue
            for ((msrc, md) in messageDetails) {
                if (cfgItem.common.cmd.passHeaders == msrc.includeHeaders && cfgItem.common.canProcess(md, helpers)) {
                    val noun = msrc.direction.name.toLowerCase()
                    val outItem = JMenuItem("${cfgItem.common.name} ($noun$plural)")
                    outItem.addActionListener { performMenuAction(cfgItem, md) }
                    topLevel.add(outItem)
                }
                if (!cfgItem.common.cmd.passHeaders && !cfgItem.common.hasFilter()) {
                    cfg.messageViewerList.forEach { mv ->
                        if (mv.common.cmd.passHeaders == msrc.includeHeaders && mv.common.canProcess(md, helpers)) {
                            val noun = msrc.direction.name.toLowerCase()
                            val outItem = JMenuItem("${mv.common.name} | ${cfgItem.common.name} ($noun$plural)")
                            outItem.addActionListener { performMenuAction(cfgItem, md, mv) }
                            topLevel.add(outItem)
                        }
                    }
                }
            }
        }
        return topLevel
    }

    private fun loadConfig(): Piper.Config {
        val serialized = callbacks.loadExtensionSetting(EXTENSION_SETTINGS_KEY)
        return if (serialized == null)
        {
            val cfgMod = loadDefaultConfig()
            saveConfig(cfgMod)
            cfgMod
        } else {
            Piper.Config.parseFrom(decompress(unpad4(Z85.Z85Decoder(serialized))))
        }
    }

    private fun saveConfig(cfg: Piper.Config) {
        val serialized = Z85.Z85Encoder(pad4(compress(cfg.toByteArray())))
        callbacks.saveExtensionSetting(EXTENSION_SETTINGS_KEY, serialized)
    }

    private fun performMenuAction(cfgItem: Piper.UserActionTool, messages: List<MessageInfo>,
                                  messageViewer: Piper.MessageViewer? = null) {
        thread {
            val input = if (messageViewer == null) {
                messages.map(MessageInfo::content)
            } else {
                messages.map { msg ->
                    messageViewer.common.cmd.execute(msg.content).processOutput { process ->
                        process.inputStream.use { it.readBytes() }
                    }
                }
            }.toTypedArray()
            cfgItem.common.cmd.execute(*input).processOutput { process ->
                if (!cfgItem.hasGUI) handleGUI(process, cfgItem.common)
            }
        }.start()
    }

    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            val cfg = loadDefaultConfig()
            println("----menuItem-----")
            cfg.menuItemList.forEach {
                println(UserActionToolWrapper(it))
                if (it.common.hasFilter()) println(MessageMatchWrapper(it.common.filter))
            }
            println("----messageViewer-----")
            cfg.messageViewerList.forEach {
                println(MessageViewerWrapper(it))
                if (it.common.hasFilter()) println(MessageMatchWrapper(it.common.filter))
            }
            val ba = cfg.toByteArray()
            val z = Z85.Z85Encoder(pad4(compress(ba)))
            println(z)
            println(decompress(unpad4(Z85.Z85Decoder(z))) contentEquals ba)
            val yaml = Dump(DumpSettingsBuilder().build())
                    .dumpToString(cfg.toSettings())
            println(yaml)
            val parsed = configFromYaml(yaml)
            println(parsed)
        }
    }
}

private fun loadDefaultConfig(): Piper.Config {
    // TODO use more efficient Protocol Buffers encoded version
    val cfg = configFromYaml(BurpExtender::class.java.classLoader
            .getResourceAsStream("defaults.yaml").reader().readText())
    return Piper.Config.newBuilder()
            .addAllMacro(cfg.macroList.map { it.toBuilder().setEnabled(true).build() })
            .addAllMenuItem(cfg.menuItemList.map {
                it.toBuilder().setCommon(it.common.toBuilder().setEnabled(true)).build()
            })
            .addAllMessageViewer(cfg.messageViewerList.map {
                it.toBuilder().setCommon(it.common.toBuilder().setEnabled(true)).build()
            })
            .build()
}

private fun handleGUI(process: Process, tool: Piper.MinimalTool) {
    val terminal = JTerminal()
    val scrollPane = JScrollPane()
    scrollPane.setViewportView(terminal)
    val frame = JFrame()
    with(frame) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        addKeyListener(terminal.keyListener)
        add(scrollPane)
        setSize(675, 300)
        title = "$NAME - ${tool.name}"
        isVisible = true
    }

    for (stream in arrayOf(process.inputStream, process.errorStream)) {
        thread {
            val reader = stream.bufferedReader()
            while (true) {
                val line = reader.readLine() ?: break
                terminal.append("$line\n")
            }
        }.start()
    }
}

fun Piper.MinimalTool.canProcess(messages: List<MessageInfo>, helpers: IExtensionHelpers): Boolean =
        !this.hasFilter() || messages.all { this.filter.matches(it, helpers) }

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
            val f = File.createTempFile("piper-", ".bin")
            f.writeBytes(it)
            f
        }
    } else emptyList()
    val args = this.prefixList + tempFiles.map { it.absolutePath } + this.postfixList
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
    get() = if (this.flags == 0) EnumSet.noneOf(RegExpFlag::class.java)
            else EnumSet.copyOf(RegExpFlag.values().filter { this.flags.and(it.value) != 0 })

fun Piper.RegularExpression.Builder.setFlagSet(flags: Set<RegExpFlag>): Piper.RegularExpression.Builder =
        this.setFlags(flags.fold(0) { acc: Int, regExpFlag: RegExpFlag -> acc or regExpFlag.value })

fun <E> Pair<Process, List<File>>.processOutput(processor: (Process) -> E): E {
    val output = processor(this.first)
    this.first.waitFor()
    this.second.forEach { it.delete() }
    return output
}
