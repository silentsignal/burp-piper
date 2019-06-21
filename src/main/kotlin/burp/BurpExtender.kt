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
import org.zeromq.codec.Z85
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.*
import javax.swing.*
import kotlin.concurrent.thread


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

    private fun populateTabs(cfg: Piper.Config) {
        tabs.addTab("Message viewers", createMessageViewersTab(cfg.messageViewerList))
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

        for (cfgItem in cfg.menuItemList) {
            // TODO check dependencies
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
            val be = BurpExtender()
            val cfg = loadDefaultConfig()
            be.populateTabs(cfg)
            val dialog = JDialog()
            with(dialog) {
                defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
                add(be.uiComponent)
                setSize(800, 600)
                isModal = true
                title = NAME
                isVisible = true
            }
        }
    }
}

private fun createMessageViewersTab(messageViewers: List<Piper.MessageViewer>): Component {
    val listWidget = JList<MessageViewerWrapper>(messageViewers.map(::MessageViewerWrapper).toTypedArray())
    listWidget.addDoubleClickListener {
        showMessageViewerDialog(messageViewers[it])
        // TODO handle return value
    }
    return listWidget
}

fun <E> JList<E>.addDoubleClickListener(listener: (Int) -> Unit) {
    this.addMouseListener(object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
            if (e.clickCount == 2) {
                listener(this@addDoubleClickListener.locationToIndex(e.point))
            }
        }
    })
}

data class MessageViewerDialogState(var result: Piper.MessageViewer? = null, var filter: Piper.MessageMatch?)

private fun showMessageViewerDialog(messageViewer: Piper.MessageViewer): Piper.MessageViewer? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MessageViewerDialogState(filter=messageViewer.common.filter)

    with(cs) {
        fill = GridBagConstraints.HORIZONTAL
        gridx = 0
        gridy = 0
        gridwidth = 1
    }

    panel.add(JLabel("Name: "), cs)

    cs.gridx = 1
    cs.gridwidth = 2

    val tfName = JTextField()
    tfName.text = messageViewer.common.name
    panel.add(tfName, cs)

    cs.gridwidth = 1
    cs.gridy = 1
    cs.gridx = 0

    panel.add(JLabel("Filter: "), cs)

    cs.gridx = 1

    val lbFilter = JLabel(if (messageViewer.common.hasFilter())
        messageViewer.common.filter.toHumanReadable(false, true) + " " else "(no filter) ")
    panel.add(lbFilter, cs)

    cs.gridx = 2

    val btnEditFilter = JButton("Edit...")
    btnEditFilter.addActionListener {
        val filter = showMessageMatchDialog(messageViewer.common.filter) ?: return@addActionListener
        lbFilter.text = filter.toHumanReadable(false, true) + " "
        state.filter = filter
    }
    panel.add(btnEditFilter, cs)

    cs.gridy = 2
    cs.gridx = 0 ; panel.add(JLabel("Command: "), cs)
    cs.gridx = 1 ; panel.add(JLabel(messageViewer.common.cmd.commandLine + " "), cs)
    cs.gridx = 2 ; panel.add(JButton("Edit..."), cs) // TODO handle click

    cs.gridy = 3
    cs.gridx = 0
    cs.gridwidth = 3

    val cbEnabled = JCheckBox("Enabled")
    cbEnabled.isSelected = messageViewer.common.enabled
    panel.add(cbEnabled, cs)

    cs.gridy = 4

    val cbUsesColors = JCheckBox("Uses ANSI (color) escape sequences")
    cbUsesColors.isSelected = messageViewer.usesColors
    panel.add(cbUsesColors, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        if (tfName.text.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "The message viewer name cannot be empty.")
            return@createOkCancelButtonsPanel false
        }

        with (Piper.MessageViewer.newBuilder()) {
            common = with (Piper.MinimalTool.newBuilder()) {
                name = tfName.text
                if (cbEnabled.isSelected) enabled = true
                if (state.filter != null) filter = state.filter
                // TODO cmd
                build()
            }
            if (cbUsesColors.isSelected) usesColors = true
            state.result = build()
        }
        true
    }

    addFullWidthComponent(pnButtons, panel, cs)
    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(800, 600)
        title = "Edit message editor \"${messageViewer.common.name}\""
        isModal = true
        isVisible = true
    }

    return state.result
}

fun createLabeledTextField(caption: String, initialValue: String, panel: Container, cs: GridBagConstraints): JTextField {
    val tf = JTextField(initialValue)

    cs.gridwidth = 1 ; cs.gridx = 0 ; panel.add(JLabel(caption), cs)
    cs.gridwidth = 3 ; cs.gridx = 1 ; panel.add(tf, cs)

    return tf
}

data class HeaderMatchDialogState(var result: Piper.HeaderMatch? = null)

fun showHeaderMatchDialog(hm: Piper.HeaderMatch): Piper.HeaderMatch? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = HeaderMatchDialogState()

    cs.fill = GridBagConstraints.HORIZONTAL

    cs.gridy = 0 ; val tfHeader = createLabeledTextField("Header name: ", hm.header, panel, cs)
    cs.gridy = 1 ; val regExpWidget = RegExpWidget.create(hm.regex, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        if (tfHeader.text.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "The header name cannot be empty.")
            return@createOkCancelButtonsPanel false
        }

        with (Piper.HeaderMatch.newBuilder()) {
            header = tfHeader.text
            regex = regExpWidget.toRegularExpression()
            state.result = build()
        }
        true
    }
    addFullWidthComponent(pnButtons, panel, cs)

    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(480, 320)
        title = "Edit header filter"
        isModal = true
        isVisible = true
    }

    return state.result
}

private fun Container.createOkCancelButtonsPanel(okHandler: () -> Boolean): Component {
    val pnButtons = JPanel()
    val btnOK = JButton("OK")
    val btnCancel = JButton("Cancel")
    pnButtons.add(btnOK)
    pnButtons.add(btnCancel)

    btnOK.addActionListener {
        if (okHandler()) isVisible = false
    }

    btnCancel.addActionListener {
        isVisible = false
    }

    return pnButtons
}

private fun addFullWidthComponent(c: Component, panel: Container, cs: GridBagConstraints) {
    cs.gridx = 0
    cs.gridy++
    cs.gridwidth = 4

    panel.add(c, cs)
}

class HexASCIITextField(private val tf: JTextField = JTextField(),
                        private val rbHex: JRadioButton = JRadioButton("Hex"),
                        private val rbASCII: JRadioButton = JRadioButton("ASCII"),
                        private val field: String, private var isASCII: Boolean) {

    constructor(field: String, source: ByteString, dialog: Component) : this(field=field, isASCII=source.isValidUtf8) {
        if (isASCII) {
            tf.text = source.toStringUtf8()
            rbASCII.isSelected = true
        } else {
            tf.text = source.toHexPairs()
            rbHex.isSelected = true
        }

        with(ButtonGroup()) { add(rbHex); add(rbASCII); }

        rbASCII.addActionListener {
            if (isASCII) return@addActionListener
            val bytes = parseHex(dialog)
            if (bytes == null) {
                rbHex.isSelected = true
                return@addActionListener
            }
            tf.text = String(bytes, Charsets.UTF_8)
            isASCII = true
        }

        rbHex.addActionListener {
            if (!isASCII) return@addActionListener
            tf.text = tf.text.toByteArray(/* default is UTF-8 */).toHexPairs()
            isASCII = false
        }
    }

    private fun parseHex(dialog: Component): ByteArray? {
        val hexstring = tf.text.filter { c -> c.isDigit() || c in 'A'..'F' || c in 'a'..'f' }
        if (hexstring.length % 2 != 0) {
            JOptionPane.showMessageDialog(dialog, "Error in $field field: hexadecimal string needs to contain an even number of hex digits")
            return null
        }
        return hexstring.chunked(2).map { ds -> ds.toInt(16).toByte() }.toByteArray()
    }

    fun getByteString(dialog: Component): ByteString? {
        return if (isASCII) ByteString.copyFromUtf8(tf.text) else ByteString.copyFrom(parseHex(dialog) ?: return null)
    }

    fun addWidgets(caption: String, cs: GridBagConstraints, panel: Container) {
        cs.gridy++
        cs.gridx = 0 ; panel.add(JLabel(caption), cs)
        cs.gridx = 1 ; panel.add(tf,      cs)
        cs.gridx = 2 ; panel.add(rbASCII, cs)
        cs.gridx = 3 ; panel.add(rbHex,   cs)
    }
}

data class MessageMatchDialogState(var result: Piper.MessageMatch? = null, var header: Piper.HeaderMatch? = null)

class RegExpWidget(private val tfPattern: JTextField, private val cbFlags: Map<RegExpFlag, JCheckBox>) {
    fun hasPattern(): Boolean {
        return tfPattern.text.isNotEmpty()
    }

    fun toRegularExpression(): Piper.RegularExpression {
        val flagSet = cbFlags.filter { e -> e.value.isSelected }.keys
        return Piper.RegularExpression.newBuilder().setPattern(tfPattern.text).setFlagSet(flagSet).build()
    }

    companion object {
        fun create(regex: Piper.RegularExpression, panel: Container, cs: GridBagConstraints): RegExpWidget {
            val tf = createLabeledTextField("Matches regular expression: ", regex.pattern, panel, cs)

            addFullWidthComponent(JLabel("Regular expression flags: (see JDK documentation)"), panel, cs)

            cs.gridy++
            cs.gridwidth = 1

            val fs = regex.flagSet
            val cbFlags = EnumMap<RegExpFlag, JCheckBox>(RegExpFlag::class.java)
            RegExpFlag.values().forEach {
                val cb = JCheckBox(it.toString())
                cb.isSelected = fs.contains(it)
                panel.add(cb, cs)
                cbFlags[it] = cb
                if (cs.gridx == 0) {
                    cs.gridx = 1
                } else {
                    cs.gridy++
                    cs.gridx = 0
                }
            }
            return RegExpWidget(tf, cbFlags)
        }
    }
}

fun showMessageMatchDialog(mm: Piper.MessageMatch): Piper.MessageMatch? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val prefixField  = HexASCIITextField("prefix",  mm.prefix,  dialog)
    val postfixField = HexASCIITextField("postfix", mm.postfix, dialog)
    val state = MessageMatchDialogState()

    with(cs) {
        fill = GridBagConstraints.HORIZONTAL
        gridx = 0
        gridy = 0
        gridwidth = 4
    }

    val cbNegation = JComboBox<MatchNegation>(MatchNegation.values())
    panel.add(cbNegation, cs)

    cs.gridwidth = 1

    prefixField .addWidgets("Starts with: ", cs, panel)
    postfixField.addWidgets(  "Ends with: ", cs, panel)

    cs.gridy = 3
    val regExpWidget = RegExpWidget.create(mm.regex, panel, cs)

    cs.gridy++
    cs.gridx = 0

	panel.add(JLabel("Header: "), cs)

    cs.gridx = 1

    val lbHeader = JLabel(if (mm.hasHeader()) mm.header.toHumanReadable(false) else "(no header match)")
    if (mm.hasHeader()) state.header = mm.header
	panel.add(lbHeader, cs)

	cs.gridx = 2

    val btnHeaderEdit = JButton("Edit...")
	panel.add(btnHeaderEdit, cs)

    cs.gridx = 3

    val btnHeaderRemove = JButton("Remove")
    panel.add(btnHeaderRemove, cs)
    btnHeaderRemove.isEnabled = mm.hasHeader()

    btnHeaderEdit.addActionListener {
        val current = state.header ?: Piper.HeaderMatch.getDefaultInstance()
        val header = showHeaderMatchDialog(current) ?: return@addActionListener
        lbHeader.text = header.toHumanReadable(false)
        state.header = header
        btnHeaderRemove.isEnabled = true
    }

    btnHeaderRemove.addActionListener {
        lbHeader.text = "(no header match)"
        state.header = null
        btnHeaderRemove.isEnabled = false
    }

    val spList = JSplitPane()
    val (andAlsoPanel, andAlsoModel) = createMatchListWidget("All of these apply: [AND]", mm.andAlsoList)
    val ( orElsePanel,  orElseModel) = createMatchListWidget("Any of these apply: [OR]",  mm.orElseList)
    spList.leftComponent = andAlsoPanel
    spList.rightComponent = orElsePanel

    addFullWidthComponent(spList, panel, cs)

    cs.gridy++
    val pnButtons = dialog.createOkCancelButtonsPanel {
        val builder = Piper.MessageMatch.newBuilder()

        if ((cbNegation.selectedItem as MatchNegation).negation) builder.negation = true

        builder.postfix = postfixField.getByteString(dialog) ?: return@createOkCancelButtonsPanel false
        builder.prefix  =  prefixField.getByteString(dialog) ?: return@createOkCancelButtonsPanel false

        if (regExpWidget.hasPattern()) builder.regex = regExpWidget.toRegularExpression()

        if (state.header != null) builder.header = state.header

        for (i in 0 until andAlsoModel.size) builder.addAndAlso(andAlsoModel.getElementAt(i).cfgItem)
        for (i in 0 until  orElseModel.size) builder.addOrElse(  orElseModel.getElementAt(i).cfgItem)

        state.result = builder.build()
        true
    }
    panel.add(pnButtons, cs)

    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(800, 600)
        title = "Edit filter"
        isModal = true
        isVisible = true
    }

    return state.result
}

private fun createMatchListWidget(caption: String, source: List<Piper.MessageMatch>): Pair<Component, ListModel<MessageMatchWrapper>> {
    val model = DefaultListModel<MessageMatchWrapper>()
    source.forEach { model.addElement(MessageMatchWrapper(it)) }

    val list = JList<MessageMatchWrapper>(model)
    val toolbar = JPanel()

    val btnAdd = JButton("+")
    val btnRemove = JButton("--")
    val btnEdit = JButton("Edit")

    btnAdd.addActionListener {
        model.addElement(MessageMatchWrapper(
                showMessageMatchDialog(Piper.MessageMatch.getDefaultInstance()) ?: return@addActionListener))
    }

    btnRemove.addActionListener {
        if (list.selectedIndex >= 0) model.remove(list.selectedIndex)
    }

    btnEdit.addActionListener {
        val edited = showMessageMatchDialog(list.selectedValue?.cfgItem ?: return@addActionListener)
        if (edited != null) model.set(list.selectedIndex, MessageMatchWrapper(edited))
    }

    with (toolbar) {
        layout = BoxLayout(toolbar, BoxLayout.LINE_AXIS)
        add(btnAdd)
        add(Box.createRigidArea(Dimension(4, 0)))
        add(btnRemove)
        add(Box.createRigidArea(Dimension(4, 0)))
        add(btnEdit)
    }

    val panel = JPanel()

    with (panel) {
        layout = BorderLayout()
        border = BorderFactory.createEmptyBorder(4, 4, 4, 4)
        add(JLabel(caption), BorderLayout.NORTH)
        add(JScrollPane(list), BorderLayout.CENTER)
        add(toolbar, BorderLayout.SOUTH)
    }

    list.addDoubleClickListener {
        showMessageMatchDialog(source[it])
    }

    return panel to model
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