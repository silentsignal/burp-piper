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

import com.redpois0n.terminal.JTerminal
import org.zeromq.codec.Z85
import java.awt.*
import java.util.*
import javax.swing.*
import javax.swing.event.ListDataEvent
import javax.swing.event.ListDataListener
import javax.swing.filechooser.FileNameExtensionFilter
import kotlin.concurrent.thread


const val NAME = "Piper"
const val EXTENSION_SETTINGS_KEY = "settings"

data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?)

class BurpExtender : IBurpExtender, ITab, ListDataListener {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var configModel: ConfigModel
    private val tabs = JTabbedPane()

    override fun contentsChanged(p0: ListDataEvent?) = saveConfig()
    override fun intervalAdded(p0: ListDataEvent?)   = saveConfig()
    override fun intervalRemoved(p0: ListDataEvent?) = saveConfig()

    private open inner class ConfigChangeListener : ListDataListener {
        override fun contentsChanged(p0: ListDataEvent?) = handler()
        override fun intervalAdded(p0: ListDataEvent?)   = handler()
        override fun intervalRemoved(p0: ListDataEvent?) = handler()

        open fun handler() {
            saveConfig()
        }
    }

    private inner class ReloaderConfigChangeListener<E>(private val enumerator: () -> Iterable<E>,
                                                        private val eraser: (E) -> Unit,
                                                        private val reloader: () -> Unit) : ConfigChangeListener() {
        override fun handler() {
            super.handler()
            enumerator().forEach(eraser)
            reloader()
        }
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        val cfg = loadConfig()
        configModel = ConfigModel(cfg)

        val ccl = ConfigChangeListener()
        configModel.menuItemsModel.addListDataListener(ccl)  // Menu items are loaded on-demand, thus saving the config is enough
        configModel.commentatorsModel.addListDataListener(ccl)  // Commentators are menu items as well, see above
        configModel.messageViewersModel.addListDataListener(ReloaderConfigChangeListener(
                callbacks::getMessageEditorTabFactories, callbacks::removeMessageEditorTabFactory, ::registerMessageViewers))
        configModel.macrosModel.addListDataListener(ReloaderConfigChangeListener(
                callbacks::getSessionHandlingActions,    callbacks::removeSessionHandlingAction,   ::registerMacros))
        configModel.httpListenersModel.addListDataListener(ReloaderConfigChangeListener(
                callbacks::getHttpListeners,             callbacks::removeHttpListener,            ::registerHttpListeners))

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory {
            val messages = it.selectedMessages
            if (messages.isNullOrEmpty()) return@registerContextMenuFactory emptyList()
            val topLevel = generateContextMenu(messages)
            if (topLevel.subElements.isEmpty()) return@registerContextMenuFactory emptyList()
            return@registerContextMenuFactory Collections.singletonList(topLevel)
        }

        registerMessageViewers()
        registerHttpListeners()
        registerMacros()

        populateTabs(configModel, null)
        callbacks.addSuiteTab(this)
    }

    private fun registerHttpListeners() {
        configModel.enabledHttpListeners.forEach {
            callbacks.registerHttpListener { toolFlag, messageIsRequest, messageInfo ->
                if ((messageIsRequest xor (it.scope == Piper.RequestResponse.REQUEST))
                        || (it.tool != 0 && (it.tool and toolFlag == 0))) return@registerHttpListener
                it.common.pipeMessage(RequestResponse.fromBoolean(messageIsRequest), messageInfo)
            }
        }
    }

    private fun registerMacros() {
        configModel.enabledMacros.forEach {
            callbacks.registerSessionHandlingAction(object : ISessionHandlingAction {
                override fun performAction(currentRequest: IHttpRequestResponse?, macroItems: Array<out IHttpRequestResponse>?) {
                    it.pipeMessage(RequestResponse.REQUEST, currentRequest ?: return)
                }

                override fun getActionName(): String = it.name
            })
        }
    }

    private fun registerMessageViewers() {
        configModel.enabledMessageViewers.forEach {
            callbacks.registerMessageEditorTabFactory { _, _ ->
                if (it.usesColors) TerminalEditor(it, helpers)
                else TextEditor(it, helpers, callbacks)
            }
        }
    }

    private fun Piper.MinimalTool.pipeMessage(rr: RequestResponse, messageInfo: IHttpRequestResponse) {
        val bytes = rr.getMessage(messageInfo)!!
        val headers = rr.getHeaders(bytes, helpers)
        val bo = if (this.cmd.passHeaders) 0 else rr.getBodyOffset(bytes, helpers)
        val body = if (this.cmd.passHeaders) bytes else {
            if (bo < bytes.size - 1) {
                bytes.copyOfRange(bo, bytes.size)
            } else return // if the request has no body, passHeaders=false tools have no use for it
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

    private fun populateTabs(cfg: ConfigModel, parent: Component?) {
        tabs.addTab("Message viewers", MinimalToolListEditor(cfg.messageViewersModel, parent,
                ::MessageViewerDialog, Piper.MessageViewer::getDefaultInstance))
        tabs.addTab("Context menu items", MinimalToolListEditor(cfg.menuItemsModel, parent,
                ::MenuItemDialog, Piper.UserActionTool::getDefaultInstance))
        tabs.addTab("Macros", MinimalToolListEditor(cfg.macrosModel, parent,
                ::MacroDialog, Piper.MinimalTool::getDefaultInstance))
        tabs.addTab("HTTP listeners", MinimalToolListEditor(cfg.httpListenersModel, parent,
                ::HttpListenerDialog, Piper.HttpListener::getDefaultInstance))
        tabs.addTab("Commentators", MinimalToolListEditor(cfg.commentatorsModel, parent,
                ::CommentatorDialog, Piper.Commentator::getDefaultInstance))
        tabs.addTab("Load/Save configuration", createLoadSaveUI(cfg, parent))
    }

    // ITab members
    override fun getTabCaption(): String = NAME
    override fun getUiComponent(): Component = tabs

    private data class MessageSource(val direction: RequestResponse, val includeHeaders: Boolean)

    private fun generateContextMenu(messages: Array<IHttpRequestResponse>): JMenuItem {
        val topLevel = JMenu(NAME)
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
                    // if the request has no body, passHeaders=false actions have no use for it
                    val body = bytes.copyOfRange(bo, bytes.size)
                    miWithoutHeaders.add(MessageInfo(body, helpers.bytesToString(body), headers))
                }
            }
            messageDetails[MessageSource(rr, true)] = miWithHeaders
            if (miWithoutHeaders.isNotEmpty()) {
                messageDetails[MessageSource(rr, false)] = miWithoutHeaders
            }
        }

        for (cfgItem in configModel.enabledMenuItems) {
            // TODO check dependencies
            if ((cfgItem.maxInputs != 0 && cfgItem.maxInputs < msize) || cfgItem.minInputs > msize) continue
            for ((msrc, md) in messageDetails) {
                if (cfgItem.common.cmd.passHeaders == msrc.includeHeaders && cfgItem.common.canProcess(md, helpers)) {
                    val noun = msrc.direction.name.toLowerCase()
                    val outItem = JMenuItem("${cfgItem.common.name} ($noun$plural)")
                    outItem.addActionListener { performMenuAction(cfgItem, md) }
                    topLevel.add(outItem)
                }
                if (!cfgItem.common.cmd.passHeaders && !cfgItem.common.hasFilter()) {
                    configModel.enabledMessageViewers.forEach { mv ->
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

        var separatorAdded = false
        for (cfgItem in configModel.enabledCommentators) {
            for ((msrc, md) in messageDetails) {
                if (cfgItem.common.cmd.passHeaders == msrc.includeHeaders && cfgItem.common.canProcess(md, helpers)) {
                    val noun = msrc.direction.name.toLowerCase()
                    val outItem = JMenuItem("${cfgItem.common.name} ($noun$plural)")
                    outItem.addActionListener { performCommentator(cfgItem, md zip messages) }
                    if (!separatorAdded) {
                        separatorAdded = true
                        topLevel.addSeparator()
                    }
                    topLevel.add(outItem)
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

    private fun saveConfig(cfg: Piper.Config = configModel.serialize()) {
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

    private fun performCommentator(cfgItem: Piper.Commentator, messages: List<Pair<MessageInfo, IHttpRequestResponse>>) {
        messages.forEach { (mi, hrr) ->
            if (hrr.comment.isNullOrEmpty() || cfgItem.overwrite) {
                val stdout = cfgItem.common.cmd.execute(mi.content).processOutput { process ->
                    process.inputStream.readBytes()
                }
                hrr.comment = String(stdout, Charsets.UTF_8)
            }
        }
    }

    companion object {
        @JvmStatic
        fun main (args: Array<String>) {
            val be = BurpExtender()
            val cfg = loadDefaultConfig()
            val dialog = JDialog()
            be.populateTabs(ConfigModel(cfg), dialog)
            showModalDialog(900, 600, be.uiComponent, NAME, dialog, null)
        }
    }
}

class ConfigModel(config: Piper.Config = Piper.Config.getDefaultInstance()) {
    val enabledMacros get() = macrosModel.toIterable().filter(Piper.MinimalTool::getEnabled)
    val enabledMessageViewers get() = messageViewersModel.toIterable().filter { it.common.enabled }
    val enabledMenuItems get() = menuItemsModel.toIterable().filter { it.common.enabled }
    val enabledHttpListeners get() = httpListenersModel.toIterable().filter { it.common.enabled }
    val enabledCommentators get() = commentatorsModel.toIterable().filter { it.common.enabled }

    val macrosModel = DefaultListModel<Piper.MinimalTool>()
    val messageViewersModel = DefaultListModel<Piper.MessageViewer>()
    val menuItemsModel = DefaultListModel<Piper.UserActionTool>()
    val httpListenersModel = DefaultListModel<Piper.HttpListener>()
    val commentatorsModel = DefaultListModel<Piper.Commentator>()

    init { fillModels(config) }

    fun fillModels(config: Piper.Config) {
        fillDefaultModel(config.macroList,                  macrosModel)
        fillDefaultModel(config.messageViewerList,  messageViewersModel)
        fillDefaultModel(config.menuItemList,            menuItemsModel)
        fillDefaultModel(config.httpListenerList,    httpListenersModel)
        fillDefaultModel(config.commentatorList,      commentatorsModel)
    }

    fun serialize(): Piper.Config = Piper.Config.newBuilder()
            .addAllMacro(macrosModel.toIterable())
            .addAllMessageViewer(messageViewersModel.toIterable())
            .addAllMenuItem(menuItemsModel.toIterable())
            .addAllHttpListener(httpListenersModel.toIterable())
            .addAllCommentator(commentatorsModel.toIterable())
            .build()
}

private fun createLoadSaveUI(cfg: ConfigModel, parent: Component?): Component {
    return JPanel().apply {
        add(JButton("Load/restore default config").apply {
            addActionListener {
                if (JOptionPane.showConfirmDialog(parent,
                                "This will overwrite your currently loaded configuration with the default one. Are you sure?",
                                "Confirm restoring default configuration", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    cfg.fillModels(loadDefaultConfig())
                }
            }
        })
        add(JButton("Export to YAML file"      ).apply { addActionListener { exportConfig(ConfigFormat.YAML,     cfg, parent) } })
        add(JButton("Export to ProtoBuf file"  ).apply { addActionListener { exportConfig(ConfigFormat.PROTOBUF, cfg, parent) } })
        add(JButton("Import from YAML file"    ).apply { addActionListener { importConfig(ConfigFormat.YAML,     cfg, parent) } })
        add(JButton("Import from ProtoBuf file").apply { addActionListener { importConfig(ConfigFormat.PROTOBUF, cfg, parent) } })
        }
    }

private fun exportConfig(fmt: ConfigFormat, cfg: ConfigModel, parent: Component?) {
    val fc = JFileChooser()
    fc.fileFilter = FileNameExtensionFilter(fmt.name, fmt.fileExtension)
    if (fc.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
        fc.selectedFile.writeBytes(fmt.serialize(cfg.serialize()))
    }
}

private fun importConfig(fmt: ConfigFormat, cfg: ConfigModel, parent: Component?) {
    val fc = JFileChooser()
    fc.fileFilter = FileNameExtensionFilter(fmt.name, fmt.fileExtension)
    if (fc.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
        cfg.fillModels(fmt.parse(fc.selectedFile.readBytes()))
    }
}

private fun loadDefaultConfig(): Piper.Config {
    // TODO use more efficient Protocol Buffers encoded version
    val cfg = configFromYaml(BurpExtender::class.java.classLoader
            .getResourceAsStream("defaults.yaml").reader().readText())
    return Piper.Config.newBuilder()
            .addAllMacro(cfg.macroList.map { it.buildEnabled() })
            .addAllMenuItem(cfg.menuItemList.map {
                it.toBuilder().setCommon(it.common.buildEnabled()).build()
            })
            .addAllMessageViewer(cfg.messageViewerList.map {
                it.toBuilder().setCommon(it.common.buildEnabled()).build()
            })
            .addAllHttpListener(cfg.httpListenerList.map {
                it.toBuilder().setCommon(it.common.buildEnabled()).build()
            })
            .addAllCommentator(cfg.commentatorList.map {
                it.toBuilder().setCommon(it.common.buildEnabled()).build()
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