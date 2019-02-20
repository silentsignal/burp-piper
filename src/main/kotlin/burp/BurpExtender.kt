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

        cfg.httpListenerList.forEach {
            if (it.common.enabled) {
                callbacks.registerHttpListener { toolFlag, messageIsRequest, messageInfo ->
                    if ((messageIsRequest xor (it.scope == Piper.HttpListener.RequestResponse.REQUEST))
                            || (it.tool != 0 && (it.tool and toolFlag == 0))) return@registerHttpListener
                    it.common.pipeMessage(RequestResponse.fromBoolean(messageIsRequest), messageInfo)
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
            rr.setMessage(messageInfo, helpers.buildHttpMessage(headers, replacement))
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
            .addAllHttpListener(cfg.httpListenerList.map {
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