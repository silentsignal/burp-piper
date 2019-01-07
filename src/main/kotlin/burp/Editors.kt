package burp

import com.redpois0n.terminal.JTerminal
import java.awt.Component
import javax.swing.JScrollPane
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

private val IS_REQUEST_MAP = mapOf(
        true to RequestResponse.REQUEST,
        false to RequestResponse.RESPONSE
)

class TerminalEditor(private val tool: Piper.MessageViewer, private val helpers: IExtensionHelpers,
                     private val callbacks: IBurpExtenderCallbacks) : IMessageEditorTab {
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

    override fun getMessage(): ByteArray? = msg
    override fun isModified(): Boolean = false
    override fun getTabCaption(): String = tool.common.name
    override fun getSelectedData(): ByteArray = helpers.stringToBytes(terminal.selectedText)
    override fun getUiComponent(): Component = terminal

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

class TextEditor(private val tool: Piper.MessageViewer, private val helpers: IExtensionHelpers,
                 private val callbacks: IBurpExtenderCallbacks) : IMessageEditorTab {
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

    override fun getMessage(): ByteArray? = msg
    override fun isModified(): Boolean = false
    override fun getTabCaption(): String = tool.common.name
    override fun getSelectedData(): ByteArray = editor.selectedText
    override fun getUiComponent(): Component = editor.component

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