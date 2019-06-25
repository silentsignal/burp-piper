package burp

import com.google.protobuf.ByteString
import java.awt.*
import java.awt.event.*
import java.util.*
import javax.swing.*
import javax.swing.event.ListDataEvent
import javax.swing.event.ListDataListener

data class MessageInfo(val content: ByteArray, val text: String, val headers: List<String>?)
data class MessageViewerWrapper(val cfgItem: Piper.MessageViewer) {
    override fun toString(): String = cfgItem.common.name
}

data class MinimalToolWrapper(val cfgItem: Piper.MinimalTool) {
    override fun toString(): String = cfgItem.name
}

data class UserActionToolWrapper(val cfgItem: Piper.UserActionTool) {
    override fun toString(): String = cfgItem.common.name
}

data class MessageMatchWrapper(val cfgItem: Piper.MessageMatch) {
    override fun toString(): String = cfgItem.toHumanReadable(false, true)
}

fun createMessageViewersTab(messageViewers: List<Piper.MessageViewer>): Component {
    val listWidget = JList<MessageViewerWrapper>(messageViewers.map(::MessageViewerWrapper).toTypedArray())
    listWidget.addDoubleClickListener {
        showMessageViewerDialog(messageViewers[it])
        // TODO handle return value
    }
    return listWidget
}

fun createMacrosTab(macros: List<Piper.MinimalTool>): Component {
    val listWidget = JList<MinimalToolWrapper>(macros.map(::MinimalToolWrapper).toTypedArray())
    listWidget.addDoubleClickListener {
        showMacroDialog(macros[it])
        // TODO handle return value
    }
    return listWidget
}

fun createMenuItemsTab(menuItems: List<Piper.UserActionTool>): Component {
    val listWidget = JList<UserActionToolWrapper>(menuItems.map(::UserActionToolWrapper).toTypedArray())
    listWidget.addDoubleClickListener {
        showMenuItemDialog(menuItems[it])
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

class MinimalToolWidget(private val tfName: JTextField = JTextField(), private var filter: Piper.MessageMatch?,
                        private val cbEnabled: JCheckBox = JCheckBox("Enabled"),
                        private val cciw: CollapsedCommandInvocationWidget) {
    fun toMinimalTool(dialog: Component): Piper.MinimalTool? {
        if (tfName.text.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "Name cannot be empty.")
            return null
        }
        if (cciw.cmd.prefixCount + cciw.cmd.postfixCount == 0) {
            JOptionPane.showMessageDialog(dialog, "The command must contain at least one argument.")
            return null
        }

        val f = filter
        with (Piper.MinimalTool.newBuilder()) {
            name = tfName.text
            if (cbEnabled.isSelected) enabled = true
            if (f != null) filter = f
            cmd = cciw.cmd
            return build()
        }
    }

    companion object {
        fun create(tool: Piper.MinimalTool, panel: Container, cs: GridBagConstraints): MinimalToolWidget {
            val mtw = MinimalToolWidget(filter = tool.filter, cciw = CollapsedCommandInvocationWidget.create(tool.cmd))

            with(cs) {
                fill = GridBagConstraints.HORIZONTAL
                gridx = 0
                gridy = 0
                gridwidth = 1
            }

            panel.add(JLabel("Name: "), cs)

            cs.gridx = 1
            cs.gridwidth = 2

            mtw.tfName.text = tool.name
            panel.add(mtw.tfName, cs)

            cs.gridwidth = 1
            cs.gridy = 1
            cs.gridx = 0

            panel.add(JLabel("Filter: "), cs)

            cs.gridx = 1

            val lbFilter = JLabel(if (tool.hasFilter())
                tool.filter.toHumanReadable(false, true) + " " else "(no filter) ")
            panel.add(lbFilter, cs)

            cs.gridx = 2

            val btnEditFilter = JButton("Edit...")
            btnEditFilter.addActionListener {
                val filter = showMessageMatchDialog(tool.filter) ?: return@addActionListener
                lbFilter.text = filter.toHumanReadable(false, true) + " "
                mtw.filter = filter
            }
            panel.add(btnEditFilter, cs)

            cs.gridy = 2 ; mtw.cciw.buildGUI(panel, cs)

            cs.gridy = 3
            cs.gridx = 0
            cs.gridwidth = 3

            mtw.cbEnabled.isSelected = tool.enabled
            panel.add(mtw.cbEnabled, cs)

            cs.gridy = 4

            return mtw
        }
    }
}

class CollapsedCommandInvocationWidget(private val label: JLabel = JLabel(),
                                       private val btnEdit: JButton = JButton("Edit..."),
                                       var cmd: Piper.CommandInvocation) {
    private fun update() {
        label.text = cmd.commandLine + " "
    }

    fun buildGUI(panel: Container, cs: GridBagConstraints) {
        cs.gridx = 0 ; panel.add(JLabel("Command: "), cs)
        cs.gridx = 1 ; panel.add(label, cs)
        cs.gridx = 2 ; panel.add(btnEdit, cs)
    }

    companion object {
        fun create(cmd: Piper.CommandInvocation): CollapsedCommandInvocationWidget {
            val cciw = CollapsedCommandInvocationWidget(cmd = cmd)
            cciw.update()

            cciw.btnEdit.addActionListener {
                val edited = showCommandInvocationDialog(cciw.cmd) ?: return@addActionListener
                cciw.cmd = edited
                cciw.update()
            }

            return cciw
        }
    }
}

data class MessageViewerDialogState(var result: Piper.MessageViewer? = null)

private fun showMessageViewerDialog(messageViewer: Piper.MessageViewer): Piper.MessageViewer? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MessageViewerDialogState()

    val mtw = MinimalToolWidget.create(messageViewer.common, panel, cs)

    val cbUsesColors = createCheckBox("Uses ANSI (color) escape sequences", messageViewer.usesColors, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false

        with (Piper.MessageViewer.newBuilder()) {
            common = mt
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

private fun createCheckBox(caption: String, initialValue: Boolean, panel: Container, cs: GridBagConstraints): JCheckBox {
    val cb = JCheckBox(caption)
    cb.isSelected = initialValue
    panel.add(cb, cs)
    return cb
}

data class MenuItemDialogState(var result: Piper.UserActionTool? = null)

private fun showMenuItemDialog(menuItem: Piper.UserActionTool): Piper.UserActionTool? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MenuItemDialogState()

    val mtw = MinimalToolWidget.create(menuItem.common, panel, cs)

    val cbHasGUI = createCheckBox("Has its own GUI (no need for a console window)", menuItem.hasGUI, panel, cs)

    val smMinInputs = createSpinner("Minimum required number of selected items: ",
            Math.max(menuItem.minInputs, 1), 1, panel, cs)
    val smMaxInputs = createSpinner("Maximum allowed number of selected items: (0 = no limit) ",
            menuItem.maxInputs, 0, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false
        val minInputsValue = smMinInputs.number.toInt()
        val maxInputsValue = smMaxInputs.number.toInt()

        if (maxInputsValue in 1 until minInputsValue) {
            JOptionPane.showMessageDialog(dialog, "Maximum allowed number of selected items cannot " +
                    "be lower than minimum required number of selected items.")
            return@createOkCancelButtonsPanel false
        }

        with (Piper.UserActionTool.newBuilder()) {
            common = mt
            if (cbHasGUI.isSelected) hasGUI = true
            if (minInputsValue > 1) minInputs = minInputsValue
            if (maxInputsValue > 0) maxInputs = maxInputsValue
            state.result = build()
        }
        true
    }

    addFullWidthComponent(pnButtons, panel, cs)
    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(800, 600)
        title = "Edit menu item \"${menuItem.common.name}\""
        isModal = true
        isVisible = true
    }

    return state.result
}

private fun createSpinner(caption: String, initial: Int, minimum: Int, panel: Container, cs: GridBagConstraints): SpinnerNumberModel {
    val model = SpinnerNumberModel(initial, minimum, Integer.MAX_VALUE, 1)

    cs.gridy++
    cs.gridx = 0 ; cs.gridwidth = 2 ; panel.add(JLabel(caption), cs)
    cs.gridx = 2 ; cs.gridwidth = 1 ; panel.add(JSpinner(model), cs)

    return model
}

data class MacroState(var result: Piper.MinimalTool? = null)

private fun showMacroDialog(macro: Piper.MinimalTool): Piper.MinimalTool? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MacroState()

    val mtw = MinimalToolWidget.create(macro, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false
        state.result = mt
        true
    }

    addFullWidthComponent(pnButtons, panel, cs)
    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(800, 600)
        title = "Edit macro \"${macro.name}\""
        isModal = true
        isVisible = true
    }

    return state.result
}

fun createLabeledTextField(caption: String, initialValue: String, panel: Container, cs: GridBagConstraints): JTextField {
    return createLabeledWidget(caption, JTextField(initialValue), panel, cs)
}

fun <E> createLabeledComboBox(caption: String, initialValue: String, panel: Container, cs: GridBagConstraints, choices: Array<E>): JComboBox<E> {
    val cb = JComboBox(choices)
    cb.isEditable = true
    cb.selectedItem = initialValue
    return createLabeledWidget(caption, cb, panel, cs)
}

fun <T : Component> createLabeledWidget(caption: String, widget: T, panel: Container, cs: GridBagConstraints): T {
    cs.gridwidth = 1 ; cs.gridx = 0 ; panel.add(JLabel(caption), cs)
    cs.gridwidth = 3 ; cs.gridx = 1 ; panel.add(widget, cs)
    return widget
}

data class HeaderMatchDialogState(var result: Piper.HeaderMatch? = null)

fun showHeaderMatchDialog(hm: Piper.HeaderMatch): Piper.HeaderMatch? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = HeaderMatchDialogState()
    val commonHeaders = arrayOf("Content-Disposition", "Content-Type", "Cookie",
            "Host", "Origin", "Referer", "Server", "User-Agent", "X-Requested-With")

    cs.fill = GridBagConstraints.HORIZONTAL

    cs.gridy = 0 ; val cbHeader = createLabeledComboBox("Header name: (case insensitive) ", hm.header, panel, cs, commonHeaders)
    cs.gridy = 1 ; val regExpWidget = RegExpWidget.create(hm.regex, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val text = cbHeader.selectedItem?.toString()
        if (text.isNullOrEmpty()) {
            JOptionPane.showMessageDialog(dialog, "The header name cannot be empty.")
            return@createOkCancelButtonsPanel false
        }

        with (Piper.HeaderMatch.newBuilder()) {
            header = text
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

data class CommandInvocationDialogState(var result: Piper.CommandInvocation? = null)

data class CommandLineParameter(val value: String?) { // null = input file name
    fun isInputFileName(): Boolean {
        return value == null
    }

    override fun toString(): String {
        return if (isInputFileName()) "<INPUT>" else value!!
    }
}

fun showCommandInvocationDialog(ci: Piper.CommandInvocation): Piper.CommandInvocation? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = CommandInvocationDialogState()

    val hasFileName = ci.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME

    val paramsModel = DefaultListModel<CommandLineParameter>()
    ci.prefixList.forEach { paramsModel.addElement(CommandLineParameter(it)) }
    if (hasFileName) paramsModel.addElement(CommandLineParameter(null))
    ci.postfixList.forEach { paramsModel.addElement(CommandLineParameter(it)) }
    val lsParams = JList<CommandLineParameter>(paramsModel)
    lsParams.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION

    lsParams.cellRenderer = object : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(list: JList<*>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
            val c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
            val v = value as CommandLineParameter
            if (v.isInputFileName()) {
                c.background = Color.RED
                c.foreground = if (isSelected) Color.YELLOW else Color.WHITE
            }
            return c
        }
    }

    cs.fill = GridBagConstraints.HORIZONTAL
    cs.gridy = 0
    cs.gridx = 0
    cs.gridwidth = 3

    panel.add(JLabel("Command line parameters: (one per line)"), cs)

    cs.gridy = 1
    cs.gridheight = 3

    panel.add(JScrollPane(lsParams), cs)

    val btnMoveUp = JButton("Move up")
    btnMoveUp.addActionListener {
        val si = lsParams.selectedIndices
        if (si.isEmpty() || si[0] == 0) return@addActionListener
        si.forEach {
            paramsModel.insertElementAt(paramsModel.remove(it - 1), it)
        }
    }

    val btnMoveDown = JButton("Move down")
    btnMoveDown.addActionListener {
        val si = lsParams.selectedIndices
        if (si.isEmpty() || si.last() == paramsModel.size - 1) return@addActionListener
        si.reversed().forEach {
            paramsModel.insertElementAt(paramsModel.remove(it + 1), it)
        }
        lsParams.selectedIndices = si.map { it + 1 }.toIntArray()
    }

    cs.gridx = 3
    cs.gridwidth = 1
    cs.gridheight = 1

    panel.add(createRemoveButton("Remove", lsParams, paramsModel), cs)

    cs.gridy = 2

    panel.add(btnMoveUp, cs)

    cs.gridy = 3

    panel.add(btnMoveDown, cs)

    val tfParam = JTextField()
    val cbSpace = JCheckBox("Auto-add upon pressing space or closing quotes")
    val btnAdd = JButton("Add")

    btnAdd.addActionListener {
        paramsModel.addElement(CommandLineParameter(tfParam.text))
        tfParam.text = ""
    }

    tfParam.addKeyListener(object : KeyAdapter() {
        override fun keyTyped(e: KeyEvent) {
            if (cbSpace.isSelected) {
                val t = tfParam.text
                if (t.startsWith('"')) {
                    if (e.keyChar == '"') {
                        tfParam.text = t.substring(1)
                        btnAdd.doClick()
                        e.consume()
                    }
                } else if (t.startsWith('\'')) {
                    if (e.keyChar == '\'') {
                        tfParam.text = t.substring(1)
                        btnAdd.doClick()
                        e.consume()
                    }
                } else if (e.keyChar == ' ') {
                    btnAdd.doClick()
                    e.consume()
                }
            }
        }
    })

    cbSpace.isSelected = true

    cs.gridy = 4
    cs.gridwidth = 1

    cs.gridx = 0 ; cs.gridwidth = 1; panel.add(JLabel("Add parameter: "), cs)
    cs.gridx = 1 ; cs.gridwidth = 2; panel.add(tfParam, cs)
    cs.gridx = 3 ; cs.gridwidth = 1; panel.add(btnAdd, cs)

    cs.gridy = 5
    cs.gridx = 0
    cs.gridwidth = 3
    panel.add(cbSpace, cs)

    cs.gridy = 6

    InputMethodWidget.create(panel, cs, hasFileName, paramsModel)

    cs.gridy = 7
    cs.gridx = 0

    val cbPassHeaders = createCheckBox("Pass HTTP headers to command", ci.passHeaders, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        with (Piper.CommandInvocation.newBuilder()) {
            // TODO 5-8
            var pre = true
            for (i in 0 until paramsModel.size) {
                val item = paramsModel.getElementAt(i)!!
                if (pre) {
                    if (item.value == null) {
                        pre = false
                        inputMethod = Piper.CommandInvocation.InputMethod.FILENAME
                    }
                    else addPrefix(item.value)
                }
                else addPostfix(item.value)
            }
            if (cbPassHeaders.isSelected) passHeaders = true
            state.result = build()
        }
        true
    }
    addFullWidthComponent(pnButtons, panel, cs)

    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(640, 480)
        title = "Edit command invocation"
        isModal = true
        isVisible = true
    }

    return state.result
}

private class InputMethodWidget(private val label: JLabel = JLabel(),
                                private val button: JButton = JButton(),
                                private var hasFileName: Boolean) {
    fun update() {
        label.text = "Input method: " + (if (hasFileName) "filename" else "standard input") + " "
        button.text = if (hasFileName) "Set to stdin (remove <INPUT>)" else "Set to filename (add <INPUT>)"
    }

    companion object {
        fun create(panel: Container, cs: GridBagConstraints, hasFileName: Boolean, paramsModel: DefaultListModel<CommandLineParameter>): InputMethodWidget {
            val imw = InputMethodWidget(hasFileName = hasFileName)
            imw.update()
            cs.gridwidth = 3
            cs.gridx = 0 ; panel.add(imw.label, cs)
            cs.gridwidth = 1
            cs.gridx = 3 ; panel.add(imw.button, cs)

            paramsModel.addListDataListener(object : ListDataListener {
                override fun intervalRemoved(p0: ListDataEvent?) {
                    if (!imw.hasFileName) return
                    for (i in 0 until paramsModel.size) {
                        if (paramsModel.getElementAt(i)!!.isInputFileName()) return
                    }
                    imw.hasFileName = false
                    imw.update()
                }

                override fun contentsChanged(p0: ListDataEvent?) { /* ignore */ }
                override fun intervalAdded(p0: ListDataEvent?) { /* ignore */ }
            })

            imw.button.addActionListener {
                if (imw.hasFileName) {
                    for (i in 0 until paramsModel.size) {
                        val item = paramsModel.getElementAt(i)!!
                        if (item.isInputFileName()) {
                            paramsModel.remove(i) // this triggers intervalRemoved above, no explicit update() necessary
                            break
                        }
                    }
                } else {
                    paramsModel.addElement(CommandLineParameter(null))
                    imw.hasFileName = true
                    imw.update()
                }
            }

            return imw
        }
    }
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
        val hexstring = tf.text.filter(Char::isLetterOrDigit)
        if (hexstring.length % 2 != 0) {
            JOptionPane.showMessageDialog(dialog, "Error in $field field: hexadecimal string needs to contain an even number of hex digits")
            return null
        }
        if (hexstring.any { c -> c in 'g'..'z' || c in 'G'..'Z' }) {
            JOptionPane.showMessageDialog(dialog, "Error in $field field: hexadecimal string contains non-hexadecimal letters (maybe typo?)")
            return null
        }
        return hexstring.chunked(2).map { ds -> ds.toInt(16).toByte() }.toByteArray()
    }

    fun getByteString(dialog: Component): ByteString? {
        return if (isASCII) ByteString.copyFromUtf8(tf.text) else ByteString.copyFrom(parseHex(dialog)
                ?: return null)
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

            val selectedFlags = regex.flagSet
            val cbFlags = EnumMap<RegExpFlag, JCheckBox>(RegExpFlag::class.java)
            RegExpFlag.values().forEach { flag ->
                cbFlags[flag] = createCheckBox(flag.toString(), flag in selectedFlags, panel, cs)
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

    val cbNegation = JComboBox(MatchNegation.values())
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
    val btnEdit = JButton("Edit")

    list.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION

    btnAdd.addActionListener {
        model.addElement(MessageMatchWrapper(
                showMessageMatchDialog(Piper.MessageMatch.getDefaultInstance()) ?: return@addActionListener))
    }

    btnEdit.addActionListener {
        val edited = showMessageMatchDialog(list.selectedValue?.cfgItem ?: return@addActionListener)
        if (edited != null) model.set(list.selectedIndex, MessageMatchWrapper(edited))
    }

    with (toolbar) {
        layout = BoxLayout(toolbar, BoxLayout.LINE_AXIS)
        add(btnAdd)
        add(Box.createRigidArea(Dimension(4, 0)))
        add(createRemoveButton("--", list, model))
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

private fun <E> createRemoveButton(caption: String, listWidget: JList<E>, listModel: DefaultListModel<E>): JButton {
    val btn = JButton(caption)
    btn.addActionListener {
        listWidget.selectedIndices.reversed().forEach(listModel::removeElementAt)
    }
    return btn
}