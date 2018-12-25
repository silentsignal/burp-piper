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

import com.amihaiemil.eoyaml.Yaml
import com.amihaiemil.eoyaml.YamlMapping
import com.amihaiemil.eoyaml.YamlMappingBuilder
import com.amihaiemil.eoyaml.YamlNode
import com.google.protobuf.ByteString
import com.redpois0n.terminal.JTerminal
import sun.misc.BASE64Encoder
import java.awt.Component
import java.io.File
import java.io.InputStream
import java.util.*
import java.util.regex.Pattern
import javax.swing.*
import kotlin.concurrent.thread

const val NAME = "Piper"

data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?)

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
        override fun getMessage(rr: IHttpRequestResponse): ByteArray? {
            return rr.request
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int {
            return helpers.analyzeRequest(data).bodyOffset
        }

        override fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String> {
            return helpers.analyzeRequest(data).headers
        }
    },

    RESPONSE {
        override fun getMessage(rr: IHttpRequestResponse): ByteArray? {
            return rr.response
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int {
            return helpers.analyzeResponse(data).bodyOffset
        }

        override fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String> {
            return helpers.analyzeResponse(data).headers
        }
    };

    abstract fun getMessage(rr: IHttpRequestResponse): ByteArray?
    abstract fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int
    abstract fun getHeaders(data: ByteArray, helpers: IExtensionHelpers): List<String>
}

val IS_REQUEST_MAP = mapOf(
        true to RequestResponse.REQUEST,
        false to RequestResponse.RESPONSE
)

class TerminalEditor(private val tool: Piper.MessageViewer, private val helpers: IExtensionHelpers, private val callbacks: IBurpExtenderCallbacks) : IMessageEditorTab {
    private var msg: ByteArray? = null
    private val terminal = JTerminal()
    private val scrollPane = JScrollPane()

    init {
        scrollPane.setViewportView(terminal)
    }

    override fun isEnabled(content: ByteArray?, isRequest: Boolean): Boolean {
        if (content == null) return false
        if (!tool.common.hasFilter()) return true
        val payload = transformContent(content, isRequest)
        return payload.isNotEmpty() && tool.common.filter.matches(payload, helpers)
    }

    private fun transformContent(content: ByteArray, isRequest: Boolean): ByteArray {
        if (tool.common.cmd.passHeaders) return content
        val rr = IS_REQUEST_MAP[isRequest]!!
        val bo = rr.getBodyOffset(content, helpers)
        return content.copyOfRange(bo, content.size)
    }

    override fun getMessage(): ByteArray? {
        return msg
    }

    override fun isModified(): Boolean {
        return false
    }

    override fun getTabCaption(): String {
        return tool.common.name
    }

    override fun getSelectedData(): ByteArray {
        return helpers.stringToBytes(terminal.selectedText)
    }

    override fun getUiComponent(): Component {
        return terminal
    }

    override fun setMessage(content: ByteArray?, isRequest: Boolean) {
        msg = content
        if (content == null) return
        terminal.text = ""
        thread {
            tool.common.cmd.execute(listOf(transformContent(content, isRequest))).processOutput { process ->
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
        }.start()
    }
}

class TextEditor(private val tool: Piper.MessageViewer, private val helpers: IExtensionHelpers, private val callbacks: IBurpExtenderCallbacks) : IMessageEditorTab {
    private var msg: ByteArray? = null
    private val editor = callbacks.createTextEditor()

    init {
        editor.setEditable(false)
    }

    override fun isEnabled(content: ByteArray?, isRequest: Boolean): Boolean {
        if (content == null) return false
        if (!tool.common.hasFilter()) return true
        val payload = transformContent(content, isRequest)
        return payload.content.isNotEmpty() && tool.common.filter.matches(payload, helpers)
    }

    private fun transformContent(content: ByteArray, isRequest: Boolean): MessageInfo {
        val rr = IS_REQUEST_MAP[isRequest]!!
        var payload = if (tool.common.cmd.passHeaders) content
            else content.copyOfRange(rr.getBodyOffset(content, helpers), content.size)
        return MessageInfo(payload, helpers.bytesToString(payload), rr.getHeaders(content, helpers))
    }

    override fun getMessage(): ByteArray? {
        return msg
    }

    override fun isModified(): Boolean {
        return false
    }

    override fun getTabCaption(): String {
        return tool.common.name
    }

    override fun getSelectedData(): ByteArray {
        return editor.selectedText
    }

    override fun getUiComponent(): Component {
        return editor.component
    }

    override fun setMessage(content: ByteArray?, isRequest: Boolean) {
        msg = content
        if (content == null) return
        thread {
            tool.common.cmd.execute(listOf(transformContent(content, isRequest).content)).processOutput { process ->
                process.inputStream.use {
                    val bytes = it.readBytes()
                    SwingUtilities.invokeLater { editor.text = bytes }
                }
            }
        }.start()
    }
}

class BurpExtender : IBurpExtender {

    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        val cfg = loadConfig()

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory {
            val messages = it.selectedMessages
            if (messages == null || messages.isEmpty()) return@registerContextMenuFactory Collections.emptyList()
            val topLevel = generateContextMenu(messages)
            if (topLevel.subElements.isEmpty()) return@registerContextMenuFactory Collections.emptyList()
            return@registerContextMenuFactory Collections.singletonList(topLevel)
        }

        cfg.messageViewerList.forEach {
            if (it.common.enabled) {
                callbacks.registerMessageEditorTabFactory { _, _ ->
                    if (it.usesColors) TerminalEditor(it, helpers, callbacks)
                    else TextEditor(it, helpers, callbacks)
                }
            }
        }
    }

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
            if (cfgItem.maxInputs < msize || cfgItem.minInputs > msize || !cfgItem.common.enabled) continue
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

    private fun loadConfig(): Piper.Config = Piper.Config.newBuilder().addMenuItem( // TODO load from settings
            Piper.UserActionTool.newBuilder()
                    .setCommon(
                            Piper.MinimalTool.newBuilder()
                                    .setName("hexcurse")
                                    .setCmd(
                                            Piper.CommandInvocation.newBuilder()
                                                    .addAllPrefix(mutableListOf("urxvt", "-e", "hexcurse"))
                                                    .setInputMethod(Piper.CommandInvocation.InputMethod.FILENAME)
                                                    .setPassHeaders(false)
                                    )
                                    .setEnabled(true)
                    )
                    .setHasGUI(true)
                    .setMaxInputs(1)
    ).addMenuItem(
            Piper.UserActionTool.newBuilder()
                    .setCommon(
                            Piper.MinimalTool.newBuilder()
                                    .setName("vbindiff without headers")
                                    .setCmd(
                                            Piper.CommandInvocation.newBuilder()
                                            .addAllPrefix(mutableListOf("urxvt", "-e", "vbindiff"))
                                            .setInputMethod(Piper.CommandInvocation.InputMethod.FILENAME)
                                            .setPassHeaders(false)
                                    )
                                    .setEnabled(true)
                    )
                    .setHasGUI(true)
                    .setMaxInputs(2)
    ).addMenuItem(
            Piper.UserActionTool.newBuilder()
                    .setCommon(
                            Piper.MinimalTool.newBuilder()
                                    .setName("vbindiff with headers")
                                    .setCmd(
                                            Piper.CommandInvocation.newBuilder()
                                                    .addAllPrefix(mutableListOf("urxvt", "-e", "vbindiff"))
                                                    .setInputMethod(Piper.CommandInvocation.InputMethod.FILENAME)
                                                    .setPassHeaders(true)
                                    )
                                    .setEnabled(true)
                    )
                    .setHasGUI(true)
                    .setMaxInputs(2)
    ).addMenuItem(
            Piper.UserActionTool.newBuilder()
                    .setCommon(
                            Piper.MinimalTool.newBuilder()
                                    .setName("git diff")
                                    .setCmd(
                                            Piper.CommandInvocation.newBuilder()
                                                    .addAllPrefix(mutableListOf("git", "diff", "--color=always"))
                                                    .setInputMethod(Piper.CommandInvocation.InputMethod.FILENAME)
                                                    .setPassHeaders(false)
                                    )
                                    .setEnabled(true)
                    )
                    .setHasGUI(false)
                    .setMinInputs(2)
                    .setMaxInputs(2)
    ).addMessageViewer(
            Piper.MessageViewer.newBuilder().setCommon(
                    Piper.MinimalTool.newBuilder()
                            .setName("rev")
                            .setCmd(
                                    Piper.CommandInvocation.newBuilder()
                                            .addAllPrefix(mutableListOf("rev"))
                                            .setInputMethod(Piper.CommandInvocation.InputMethod.STDIN)
                                            .setPassHeaders(true)
                            )
                            .setEnabled(true)
            )
    ).addMessageViewer(
            Piper.MessageViewer.newBuilder().setCommon(
                    Piper.MinimalTool.newBuilder()
                            .setName("Pygmentize")
                            .setCmd(
                                    Piper.CommandInvocation.newBuilder()
                                            .addAllPrefix(mutableListOf("pygmentize", "-g"))
                                            .setInputMethod(Piper.CommandInvocation.InputMethod.STDIN)
                                            .setPassHeaders(false)
                            )
                            .setEnabled(true)
                    )
                    .setUsesColors(true)
    ).addMessageViewer(
            Piper.MessageViewer.newBuilder().setCommon(
                    Piper.MinimalTool.newBuilder()
                            .setName("OpenSSL ASN.1 decoder")
                            .setCmd(
                                    Piper.CommandInvocation.newBuilder()
                                            .addAllPrefix(mutableListOf("openssl", "asn1parse", "-inform", "DER", "-i"))
                                            .setInputMethod(Piper.CommandInvocation.InputMethod.STDIN)
                                            .setPassHeaders(false)
                            )
                            .setFilter(
                                    Piper.MessageMatch.newBuilder()
                                            .addOrElse(Piper.MessageMatch.newBuilder().setPrefix(ByteString.copyFrom(byteArrayOf(0x30, 0x82.toByte()))))
                                            .addOrElse(Piper.MessageMatch.newBuilder().setPrefix(ByteString.copyFrom(byteArrayOf(0x30, 0x80.toByte()))))
                            )
                            .setEnabled(true)
            )
    ).addMessageViewer(
            Piper.MessageViewer.newBuilder().setCommon(
                    Piper.MinimalTool.newBuilder()
                            .setName("Python JSON formatter")
                            .setCmd(
                                    Piper.CommandInvocation.newBuilder()
                                            .addAllPrefix(mutableListOf("python", "-m", "json.tool"))
                                            .setInputMethod(Piper.CommandInvocation.InputMethod.STDIN)
                                            .setPassHeaders(false)
                            )
                            .setFilter(
                                    Piper.MessageMatch.newBuilder()
                                            .addOrElse(Piper.MessageMatch.newBuilder().setPrefix(ByteString.copyFromUtf8("{")).setPostfix(ByteString.copyFromUtf8("}")))
                                            .addOrElse(Piper.MessageMatch.newBuilder().setPrefix(ByteString.copyFromUtf8("[")).setPostfix(ByteString.copyFromUtf8("]")))
                            )
                            .setEnabled(true)
            )
    ).build()

    private fun performMenuAction(cfgItem: Piper.UserActionTool, messages: List<MessageInfo>, messageViewer: Piper.MessageViewer? = null) {
        thread {
            val input = if (messageViewer == null) {
                messages.map(MessageInfo::content)
            } else {
                messages.map { msg ->
                    messageViewer.common.cmd.execute(listOf(msg.content)).processOutput { process ->
                        process.inputStream.use { it.readBytes() }
                    }
                }
            }
            cfgItem.common.cmd.execute(input).processOutput { process ->
                if (!cfgItem.hasGUI) handleGUI(process, cfgItem.common)
            }
        }.start()
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
            isVisible = true
            title = "$NAME - ${tool.name}"
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

    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            val cfg = BurpExtender().loadConfig()
            println(Base64.getEncoder().encodeToString(cfg.toByteArray()))
            println(cfg.toYaml().toString())
        }
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
    return this.size >= mps && this.copyOfRange(0, mps) == value.toByteArray()
}

fun ByteArray.endsWith(value: ByteString): Boolean {
    val mps = value.size()
    val mbs = this.size
    return mbs >= mps && this.copyOfRange(mbs - mps, mbs) == value.toByteArray()
}

fun Piper.CommandInvocation.execute(inputs: List<ByteArray>): Pair<Process, List<File>> {
    val tempFiles = if (this.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME) {
        inputs.map {
            val f = File.createTempFile("piper-", ".bin")
            f.writeBytes(it)
            f
        }
    } else Collections.emptyList()
    val args = this.prefixList + tempFiles.map { it.absolutePath } + this.postfixList
    val p = Runtime.getRuntime().exec(args.toTypedArray())
    if (this.inputMethod == Piper.CommandInvocation.InputMethod.STDIN) {
        p.outputStream.use {
            inputs.forEach { p.outputStream.write(it) }
        }
    }
    return p to tempFiles
}

fun Piper.CommandInvocation.matches(subject: ByteArray, helpers: IExtensionHelpers): Boolean {
    val inputs = listOf(subject)
    val (process, tempFiles) = this.execute(inputs)
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
            this.regex.matches(it.substring(this.header.length + 2, it.length))
}

fun Piper.RegularExpression.matches(subject: String): Boolean =
        this.compile().matcher(subject).find()

fun Piper.RegularExpression.compile(): Pattern = Pattern.compile(this.pattern, this.flags)

val Piper.RegularExpression.flagSet: Set<RegExpFlag>
    get() = if (this.flags == 0) EnumSet.noneOf(RegExpFlag::class.java)
            else EnumSet.copyOf(RegExpFlag.values().filter { this.flags.and(it.value) != 0 })

fun Piper.RegularExpression.Builder.setFlagSet(flags: Set<RegExpFlag>) =
        this.setFlags(flags.fold(0) { acc: Int, regExpFlag: RegExpFlag -> acc or regExpFlag.value })

fun Piper.RegularExpression.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("pattern", this.pattern)
        .add("flags", this.flagSet.asSequence().map(RegExpFlag::toString).sorted().toList())
        .build()

fun Piper.Config.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("messageViewers", this.messageViewerList, Piper.MessageViewer::toYaml)
        .build()

fun Piper.MessageViewer.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("common", this.common.toYaml())
        .add("usesColors", this.usesColors)
        .build()

fun Piper.MinimalTool.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("name", this.name)
        .add("cmd", this.cmd.toYaml())
        .addIf(this.hasFilter(), "filter", this.filter::toYaml)
        .build()

fun Piper.CommandInvocation.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("prefix", this.prefixList)
        .add("postfix", this.postfixList)
        .add("inputMethod", this.inputMethod.name.toLowerCase())
        .add("passHeaders", this.passHeaders)
        .build()

fun Piper.MessageMatch.toYaml(): YamlNode = Yaml.createYamlMappingBuilder()
        .add("prefix", this.prefix)
        .add("postfix", this.postfix)
        // TODO header, cmd
        .addIf(this.hasRegex(), "regex", this.regex::toYaml)
        .add("negation", this.negation)
        .add("andAlso", this.andAlsoList, Piper.MessageMatch::toYaml)
        .add("orElse", this.orElseList, Piper.MessageMatch::toYaml)
        .build()

fun YamlMappingBuilder.add(key: String, value: ByteString) =
        if (value.isEmpty) this else this.add(key, value.toByteArray().joinToString(separator=":",
                transform={ it.toInt().and(0xFF).toString(16).padStart(2, '0') }))

fun YamlMappingBuilder.addIf(enabled: Boolean, key: String, producer: () -> YamlNode) =
        if (enabled) this.add(key, producer()) else this

fun YamlMappingBuilder.add(key: String, value: Boolean) =
        if (value) this.add(key, "true") else this

fun <E> YamlMappingBuilder.add(key: String, value: List<E>, transform: (E) -> YamlNode): YamlMappingBuilder =
        if (value.isEmpty()) this else this.add(key, value.fold(
                Yaml.createYamlSequenceBuilder()) { acc, e -> acc.add(transform(e)) }.build())

fun YamlMappingBuilder.add(key: String, value: List<String>): YamlMappingBuilder =
        if (value.isEmpty()) this else this.add(key, value.fold(
                Yaml.createYamlSequenceBuilder()) { acc, e -> acc.add(e) }.build())

fun <E> Pair<Process, List<File>>.processOutput(processor: (Process) -> E): E {
    val output = processor(this.first)
    this.first.waitFor()
    this.second.forEach { it.delete() }
    return output
}