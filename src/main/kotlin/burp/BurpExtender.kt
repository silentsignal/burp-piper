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
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import javax.swing.*
import javax.swing.event.ListDataEvent
import javax.swing.event.ListDataListener
import javax.swing.event.ListSelectionEvent
import javax.swing.event.ListSelectionListener
import javax.swing.filechooser.FileNameExtensionFilter
import kotlin.concurrent.thread


const val NAME = "Piper"
const val EXTENSION_SETTINGS_KEY = "settings"

data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?, val url: URL?)

class BurpExtender : IBurpExtender, ITab, ListDataListener {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var configModel: ConfigModel
    private val queue = Queue()
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

        configModel.addPropertyChangeListener(PropertyChangeListener { saveConfig() })

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory {
            val messages = it.selectedMessages
            if (messages.isNullOrEmpty()) return@registerContextMenuFactory emptyList()
            val topLevel = JMenu(NAME)
            generateContextMenu(messages.asList(), topLevel::add, topLevel::addSeparator)
            if (topLevel.subElements.isEmpty()) return@registerContextMenuFactory emptyList()
            return@registerContextMenuFactory Collections.singletonList(topLevel as JMenuItem)
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
                if (it.usesColors) TerminalEditor(it, helpers, callbacks)
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
        if (this.hasFilter() && !this.filter.matches(MessageInfo(body, helpers.bytesToString(body),
                        headers, helpers.analyzeRequest(messageInfo).url), helpers, callbacks)) return
        val replacement = this.cmd.execute(body).processOutput { process ->
            if (configModel.developer) {
                val stderr = process.errorStream.readBytes()
                if (stderr.isNotEmpty()) {
                    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    val ts = LocalDateTime.now().format(formatter)
                    callbacks.stderr.buffered().use {
                        it.bufferedWriter().use { w ->
                            w.newLine()
                            w.write("$name called ${cmd.commandLine} at $ts and stderr was not empty:")
                            w.newLine()
                            w.newLine()
                        }
                        it.write(stderr)
                    }
                }
            }
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
        tabs.addTab("Queue", queue)
        tabs.addTab("Load/Save configuration", createLoadSaveUI(cfg, parent))
        tabs.addTab("Developer", createDeveloperUI(cfg))
    }

    private fun createDeveloperUI(cfg: ConfigModel): Component =
            JCheckBox("show user interface elements suited for developers").apply {
                isSelected = cfg.developer
                cfg.addPropertyChangeListener(PropertyChangeListener { isSelected = cfg.developer })
                addChangeListener { cfg.developer = isSelected }
            }

    // ITab members
    override fun getTabCaption(): String = NAME
    override fun getUiComponent(): Component = tabs

    private data class MessageSource(val direction: RequestResponse, val includeHeaders: Boolean)

    private fun generateContextMenu(messages: Collection<IHttpRequestResponse>, add: (JMenuItem) -> JMenuItem, addSeparator: () -> Unit) {
        val msize = messages.size
        val plural = if (msize == 1) "" else "s"

        val messageDetails = messagesToMap(messages)

        for (cfgItem in configModel.enabledMenuItems) {
            // TODO check dependencies
            if ((cfgItem.maxInputs != 0 && cfgItem.maxInputs < msize) || cfgItem.minInputs > msize) continue
            for ((msrc, md) in messageDetails) {
                val menuItem = createMenuItem(cfgItem.common, null, msrc, md, plural) { performMenuAction(cfgItem, md) }
                if (menuItem != null) add(menuItem)
                if (!cfgItem.common.cmd.passHeaders && !cfgItem.common.hasFilter()) {
                    configModel.enabledMessageViewers.forEach { mv ->
                        add(createMenuItem(mv.common, cfgItem.common, msrc, md, plural) {
                            performMenuAction(cfgItem, md, mv)
                        } ?: return@forEach)
                    }
                }
            }
        }

        val commentatorMenuItems = configModel.enabledCommentators.flatMap { cfgItem ->
            messageDetails.map { (msrc, md) ->
                createMenuItem(cfgItem.common, null, msrc, md, plural) {
                    performCommentator(cfgItem, md zip messages)
                }
            }
        }.filterNotNull()

        if (commentatorMenuItems.isNotEmpty()) {
            addSeparator()
            commentatorMenuItems.map(add)
        }

        addSeparator()
        add(JMenuItem("Add to queue").apply { addActionListener { queue.add(messages) } })
    }

    private fun messagesToMap(messages: Collection<IHttpRequestResponse>): Map<MessageSource, List<MessageInfo>> {
        val messageDetails = HashMap<MessageSource, List<MessageInfo>>()
        for (rr in RequestResponse.values()) {
            val miWithHeaders = ArrayList<MessageInfo>(messages.size)
            val miWithoutHeaders = ArrayList<MessageInfo>(messages.size)
            messages.forEach {
                val bytes = rr.getMessage(it) ?: return@forEach
                val headers = rr.getHeaders(bytes, helpers)
                val url = helpers.analyzeRequest(it).url
                miWithHeaders.add(MessageInfo(bytes, helpers.bytesToString(bytes), headers, url))
                val bo = rr.getBodyOffset(bytes, helpers)
                if (bo < bytes.size - 1) {
                    // if the request has no body, passHeaders=false actions have no use for it
                    val body = bytes.copyOfRange(bo, bytes.size)
                    miWithoutHeaders.add(MessageInfo(body, helpers.bytesToString(body), headers, url))
                }
            }
            messageDetails[MessageSource(rr, true)] = miWithHeaders
            if (miWithoutHeaders.isNotEmpty()) {
                messageDetails[MessageSource(rr, false)] = miWithoutHeaders
            }
        }
        return messageDetails
    }

    private fun createMenuItem(tool: Piper.MinimalTool, pipe: Piper.MinimalTool?, msrc: MessageSource, md: List<MessageInfo>, plural: String, action: () -> Unit): JMenuItem? {
        if (tool.cmd.passHeaders == msrc.includeHeaders && tool.canProcess(md, helpers, callbacks)) {
            val noun = msrc.direction.name.toLowerCase()
            return JMenuItem(tool.name + (if (pipe == null) "" else " | ${pipe.name}") + " ($noun$plural)").apply {
                addActionListener { action() }
            }
        } else return null
    }

    inner class Queue : JPanel(BorderLayout()), ListDataListener, ListCellRenderer<IHttpRequestResponse>, ListSelectionListener {
        private val model = DefaultListModel<IHttpRequestResponse>()
        private val pnToolbar = JPanel()
        private val listWidget = JList(model)
        private val btnProcess = JButton("Process")
        private val cr = DefaultListCellRenderer()

        fun add(values: Iterable<IHttpRequestResponse>) = values.forEach(model::addElement)

        private fun toHumanReadable(value: IHttpRequestResponse): String {
            val req = helpers.analyzeRequest(value)
            val resp = helpers.analyzeResponse(value.response)
            return "${resp.statusCode} ${req.url} (response size = ${value.response.size - resp.bodyOffset} byte(s))"
        }

        private fun addButtons() {
            btnProcess.addActionListener {
                val pm = JPopupMenu()
                generateContextMenu(listWidget.selectedValuesList, pm::add, pm::addSeparator)
                val b = it.source as Component
                val loc = b.locationOnScreen
                pm.show(this, 0, 0)
                pm.setLocation(loc.x, loc.y + b.height)
            }

            listOf(createRemoveButton(listWidget, model), btnProcess).map(pnToolbar::add)
        }

        override fun getListCellRendererComponent(list: JList<out IHttpRequestResponse>?, value: IHttpRequestResponse, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
            val c = cr.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
            cr.text = toHumanReadable(value)
            return c
        }

        override fun valueChanged(p0: ListSelectionEvent?) { updateBtnEnableDisableState() }
        override fun contentsChanged(p0: ListDataEvent?)   { updateBtnEnableDisableState() }
        override fun intervalAdded  (p0: ListDataEvent?)   { updateBtnEnableDisableState() }
        override fun intervalRemoved(p0: ListDataEvent?)   { updateBtnEnableDisableState() }

        private fun updateBtnEnableDisableState() {
            btnProcess.isEnabled = !listWidget.isSelectionEmpty
        }

        init {
            listWidget.cellRenderer = this
            listWidget.addListSelectionListener(this)
            model.addListDataListener(this)

            addButtons()
            updateBtnEnableDisableState()
            add(pnToolbar, BorderLayout.NORTH)
            add(JScrollPane(listWidget), BorderLayout.CENTER)
        }
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
    private val pcs = PropertyChangeSupport(this)

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

    private var _developer = config.developer
    var developer: Boolean
        get() = _developer
        set(value) {
            val old = _developer
            _developer = value
            pcs.firePropertyChange("developer", old, value)
        }

    init { fillModels(config) }

    fun addPropertyChangeListener(listener: PropertyChangeListener) {
        pcs.addPropertyChangeListener(listener)
    }

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
            .setDeveloper(developer)
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
        try {
            cfg.fillModels(fmt.parse(fc.selectedFile.readBytes()))
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(parent, e.message, "Error while importing ${fc.selectedFile}", JOptionPane.ERROR_MESSAGE)
        }
    }
}

private fun loadDefaultConfig(): Piper.Config {
    // TODO use more efficient Protocol Buffers encoded version
    val cfg = configFromYaml(BurpExtender::class.java.classLoader
            .getResourceAsStream("defaults.yaml").reader().readText())
    return Piper.Config.newBuilder()
            .addAllMacro        (cfg.macroList        .map { it.buildEnabled() })
            .addAllMenuItem     (cfg.menuItemList     .map { it.buildEnabled() })
            .addAllMessageViewer(cfg.messageViewerList.map { it.buildEnabled() })
            .addAllHttpListener (cfg.httpListenerList .map { it.buildEnabled() })
            .addAllCommentator  (cfg.commentatorList  .map { it.buildEnabled() })
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