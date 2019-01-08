package burp

import com.redpois0n.terminal.JTerminal
import java.awt.Component
import javax.swing.JScrollPane
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

abstract class Editor(private val tool: Piper.MessageViewer,
                      protected val helpers: IExtensionHelpers) : IMessageEditorTab {
    private var msg: ByteArray? = null

    override fun getMessage(): ByteArray? = msg
    override fun isModified(): Boolean = false
    override fun getTabCaption(): String = tool.common.name

    override fun isEnabled(content: ByteArray?, isRequest: Boolean): Boolean {
        if (content == null) return false
        if (!tool.common.hasFilter()) return true

        val rr = booleanToRequestResponse(isRequest)
        var payload = getPayload(content, rr)

        if (payload.isEmpty()) return false

        val mi = MessageInfo(payload, helpers.bytesToString(payload), rr.getHeaders(content, helpers))
        return tool.common.filter.matches(mi, helpers)
    }

    override fun setMessage(content: ByteArray?, isRequest: Boolean) {
        msg = content
        if (content == null) return
        thread(start = true) {
            val input = getPayload(content, booleanToRequestResponse(isRequest))
            tool.common.cmd.execute(input).processOutput { outputProcessor(it) }
        }
    }

    private fun booleanToRequestResponse(isRequest: Boolean) =
            if (isRequest) RequestResponse.REQUEST else RequestResponse.RESPONSE

    private fun getPayload(content: ByteArray, rr: RequestResponse) =
            if (tool.common.cmd.passHeaders) content
            else content.copyOfRange(rr.getBodyOffset(content, helpers), content.size)

    abstract fun outputProcessor(process: Process)

    abstract override fun getSelectedData(): ByteArray
    abstract override fun getUiComponent(): Component
}

class TerminalEditor(tool: Piper.MessageViewer, helpers: IExtensionHelpers) : Editor(tool, helpers) {
    private val terminal = JTerminal()
    private val scrollPane = JScrollPane()

    init {
        scrollPane.setViewportView(terminal)
    }

    override fun getSelectedData(): ByteArray = helpers.stringToBytes(terminal.selectedText)
    override fun getUiComponent(): Component = terminal

    override fun outputProcessor(process: Process) {
        terminal.text = ""
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
}

class TextEditor(tool: Piper.MessageViewer, helpers: IExtensionHelpers,
                 callbacks: IBurpExtenderCallbacks) : Editor(tool, helpers) {
    private val editor = callbacks.createTextEditor()

    init {
        editor.setEditable(false)
    }

    override fun getSelectedData(): ByteArray = editor.selectedText
    override fun getUiComponent(): Component = editor.component

    override fun outputProcessor(process: Process) {
        process.inputStream.use {
            val bytes = it.readBytes()
            SwingUtilities.invokeLater { editor.text = bytes }
        }
    }
}