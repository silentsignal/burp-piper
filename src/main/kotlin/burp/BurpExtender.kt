package burp

import com.google.protobuf.ByteString
import sun.misc.BASE64Encoder
import java.awt.Component
import java.io.File
import java.io.InputStream
import java.util.*
import java.util.regex.Pattern
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

const val NAME = "Piper"

data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?)

enum class RequestResponse {
    REQUEST {
        override fun getMessage(rr: IHttpRequestResponse): ByteArray {
            return rr.request
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int {
            return helpers.analyzeRequest(data).bodyOffset
        }

        override fun getHeaders(rr: IHttpRequestResponse, helpers: IExtensionHelpers): List<String> {
            return helpers.analyzeRequest(rr).headers
        }
    },

    RESPONSE {
        override fun getMessage(rr: IHttpRequestResponse): ByteArray {
            return rr.response
        }

        override fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int {
            return helpers.analyzeResponse(data).bodyOffset
        }

        override fun getHeaders(rr: IHttpRequestResponse, helpers: IExtensionHelpers): List<String> {
            return helpers.analyzeResponse(rr.response).headers
        }
    };

    abstract fun getMessage(rr: IHttpRequestResponse): ByteArray
    abstract fun getBodyOffset(data: ByteArray, helpers: IExtensionHelpers): Int
    abstract fun getHeaders(rr: IHttpRequestResponse, helpers: IExtensionHelpers): List<String>
}

class PiperEditor(private val tool: Piper.MinimalTool, private val helpers: IExtensionHelpers, private val callbacks: IBurpExtenderCallbacks) : IMessageEditorTab {
    private var msg: ByteArray? = null
    private val editor = callbacks.createTextEditor()

    init {
        editor.setEditable(false)
    }

    override fun isEnabled(content: ByteArray?, isRequest: Boolean): Boolean {
        return content != null && content.isNotEmpty() && (!tool.hasFilter() || tool.filter.matches(content, helpers))
    }

    override fun getMessage(): ByteArray? {
        return msg
    }

    override fun isModified(): Boolean {
        return false
    }

    override fun getTabCaption(): String {
        return tool.name
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
            val (process, tempFiles) = tool.cmd.execute(listOf(content))
            process.inputStream.use {
                val bytes = it.readBytes()
                SwingUtilities.invokeLater { editor.text = bytes }
            }
            process.waitFor()
            tempFiles.forEach { it.delete() }
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
            if (it.enabled) {
                callbacks.registerMessageEditorTabFactory { controller, editable ->
                    PiperEditor(it, helpers, callbacks)
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
                val bytes = rr.getMessage(it)
                val headers = rr.getHeaders(it, helpers)
                miWithHeaders.add(MessageInfo(bytes, helpers.bytesToString(bytes), headers))
                val bo = rr.getBodyOffset(bytes, helpers)
                if (bo < bytes.size - 1) {
                    val body = bytes.sliceArray(IntRange(bo, bytes.size - 1))
                    miWithoutHeaders.add(MessageInfo(body, helpers.bytesToString(body), headers))
                }
            }
            messageDetails[MessageSource(rr, true)] = miWithHeaders
            if (miWithoutHeaders.isNotEmpty()) {
                messageDetails[MessageSource(rr, false)] = miWithoutHeaders
            }
        }

        for (cfgItem in cfg.menuItemList) {
            if (cfgItem.maxInputs < msize || !cfgItem.common.enabled) continue
            for ((msrc, md) in messageDetails) {
                if (cfgItem.common.passHeaders == msrc.includeHeaders && cfgItem.canProcess(md, helpers)) {
                    val noun = msrc.direction.toString().toLowerCase()
                    val outItem = JMenuItem("${cfgItem.common.name} ($noun$plural)")
                    outItem.addActionListener { performMenuAction(cfgItem, md) }
                    topLevel.add(outItem)
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
                                    )
                                    .setEnabled(true)
                                    .setPassHeaders(false)
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
                                    )
                                    .setEnabled(true)
                                    .setPassHeaders(false)
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
                                    )
                                    .setEnabled(true)
                                    .setPassHeaders(true)
                    )
                    .setHasGUI(true)
                    .setMaxInputs(2)
    ).addMessageViewer(
            Piper.MinimalTool.newBuilder()
                    .setName("rev")
                    .setCmd(
                            Piper.CommandInvocation.newBuilder()
                                    .addAllPrefix(mutableListOf("rev"))
                                    .setInputMethod(Piper.CommandInvocation.InputMethod.STDIN)
                    )
                    .setEnabled(true)
                    .setPassHeaders(true)
    ).build()

    private fun performMenuAction(cfgItem: Piper.UserActionTool, messages: List<MessageInfo>) {
        thread {
            val (process, tempFiles) = cfgItem.common.cmd.execute(messages.map(MessageInfo::content))
            if (!cfgItem.hasGUI) {
                // TODO show it in textual interface, sync with UI thread
            }
            process.waitFor()
            tempFiles.forEach { it.delete() }
        }.start()
    }

    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            val obj = Piper.RegularExpression.newBuilder().setPattern("teszt").setFlags(Pattern.CASE_INSENSITIVE).build()
            println(BASE64Encoder().encode(obj.toByteArray()))
        }
    }
}

fun Piper.UserActionTool.canProcess(messages: List<MessageInfo>, helpers: IExtensionHelpers): Boolean =
        !this.common.hasFilter() || messages.all { this.common.filter.matches(it, helpers) }

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
    return this.size >= mps && this.sliceArray(IntRange(0, mps - 1)).contentEquals(value.toByteArray())
}

fun ByteArray.endsWith(value: ByteString): Boolean {
    val mps = value.size()
    val mbs = this.size
    return this.size >= mps && !this.sliceArray(IntRange(mbs - mps, mbs - 1)).contentEquals(value.toByteArray())
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

fun Piper.CommandMatch.matches(subject: ByteArray, helpers: IExtensionHelpers): Boolean {
    val inputs = listOf(subject)
    val (process, tempFiles) = this.cmd.execute(inputs)
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
            this.regex.matches(it.slice(IntRange(this.header.length + 2, it.length - 1)))
}

fun Piper.RegularExpression.matches(subject: String): Boolean =
        Pattern.compile(this.pattern, this.flags).matcher(subject).matches()