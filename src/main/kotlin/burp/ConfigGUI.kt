package burp

import com.google.protobuf.ByteString
import java.awt.*
import java.awt.event.*
import java.util.*
import javax.swing.*
import javax.swing.event.ListDataEvent
import javax.swing.event.ListDataListener
import kotlin.math.max

data class MessageViewerWrapper(val cfgItem: Piper.MessageViewer) {
    override fun toString(): String = cfgItem.common.name
}

data class MinimalToolWrapper(val cfgItem: Piper.MinimalTool) {
    override fun toString(): String = cfgItem.name
}

data class UserActionToolWrapper(val cfgItem: Piper.UserActionTool) {
    override fun toString(): String = cfgItem.common.name
}

data class HttpListenerWrapper(val cfgItem: Piper.HttpListener) {
    override fun toString(): String = cfgItem.common.name
}

data class MessageMatchWrapper(val cfgItem: Piper.MessageMatch) {
    override fun toString(): String = cfgItem.toHumanReadable(negation = false, hideParentheses = true)
}

fun <S, W> createListEditor(model: DefaultListModel<W>, parent: Component?, wrap: (S) -> W, unwrap: (W) -> S,
                            dialog: (S, Component?) -> S?, default: () -> S): Component {
    val listWidget = JList(model)
    listWidget.addDoubleClickListener {
        model[it] = wrap(dialog(unwrap(model[it]), parent) ?: return@addDoubleClickListener)
    }
    val btnAdd = JButton("Add")
    btnAdd.addActionListener {
        model.addElement(wrap(dialog(default(), parent) ?: return@addActionListener))
    }
    val pnToolbar = JPanel().apply {
        add(btnAdd)
        add(createRemoveButton("Remove", listWidget, model))
    }
    return JPanel(BorderLayout()).apply {
        add(pnToolbar, BorderLayout.PAGE_START)
        add(listWidget, BorderLayout.CENTER)
    }
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

class MinimalToolWidget(tool: Piper.MinimalTool, panel: Container, cs: GridBagConstraints) {
    private val tfName: JTextField
    private val cbEnabled: JCheckBox
    private val cciw: CollapsedCommandInvocationWidget = CollapsedCommandInvocationWidget(cmd = tool.cmd, parent = panel)
    private val ccmw: CollapsedMessageMatchWidget = CollapsedMessageMatchWidget(mm = tool.filter, showHeaderMatch = true, caption = "Filter: ")

    fun toMinimalTool(dialog: Component): Piper.MinimalTool? {
        if (tfName.text.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "Name cannot be empty.")
            return null
        }
        if (cciw.cmd.prefixCount + cciw.cmd.postfixCount == 0) {
            JOptionPane.showMessageDialog(dialog, "The command must contain at least one argument.")
            return null
        }

        val f = ccmw.mm
        with (Piper.MinimalTool.newBuilder()) {
            name = tfName.text
            if (cbEnabled.isSelected) enabled = true
            if (f != null) filter = f
            cmd = cciw.cmd
            return build()
        }
    }

    init {
        cs.fill = GridBagConstraints.HORIZONTAL

        cs.gridy = 0 ; tfName = createLabeledTextField("Name: ", tool.name, panel, cs)
        cs.gridy = 1 ; ccmw.buildGUI(panel, cs)
        cs.gridy = 2 ; cciw.buildGUI(panel, cs)
        cs.gridy = 3 ; cs.gridx = 0 ; cbEnabled = createCheckBox("Enabled", tool.enabled, panel, cs)
        cs.gridy = 4
    }
}

class CollapsedMessageMatchWidget(var mm: Piper.MessageMatch?, val showHeaderMatch: Boolean, val caption: String) {
    private val label: JLabel = JLabel()
    private val btnRemoveFilter = JButton("Remove")

    private fun update() {
        val f = mm
        label.text = if (f == null) "(no filter) " else f.toHumanReadable(negation = false, hideParentheses = true) + " "
        btnRemoveFilter.isEnabled = (f != null)
    }

    fun buildGUI(panel: Container, cs: GridBagConstraints) {
        val btnEditFilter = JButton("Edit...")
        btnEditFilter.addActionListener {
            val filter = showMessageMatchDialog(mm ?: Piper.MessageMatch.getDefaultInstance(),
                    showHeaderMatch = showHeaderMatch, parent = panel) ?: return@addActionListener
            mm = filter
            update()
        }

        btnRemoveFilter.addActionListener {
            mm = null
            update()
        }

        update()
        cs.gridwidth = 1

        cs.gridx = 0 ; panel.add(JLabel(caption), cs)
        cs.gridx = 1 ; panel.add(label, cs)
        cs.gridx = 2 ; panel.add(btnEditFilter, cs)
        cs.gridx = 3 ; panel.add(btnRemoveFilter, cs)
    }

    init {
        if (mm == Piper.MessageMatch.getDefaultInstance()) mm = null
    }
}

open class CollapsedCommandInvocationWidget(var cmd: Piper.CommandInvocation, protected val parent: Component) {
    private val label: JLabel = JLabel()
    private val btnEdit: JButton = JButton("Edit...")

    protected open fun update() {
        label.text = if (cmd == Piper.CommandInvocation.getDefaultInstance()) "(no command)" else stringRepr
    }

    protected open val stringRepr: String
        get() = cmd.commandLine + " "

    open fun buildGUI(panel: Container, cs: GridBagConstraints) {
        update()
        cs.gridx = 0 ; panel.add(JLabel("Command: "), cs)
        cs.gridx = 1 ; panel.add(label, cs)
        cs.gridx = 2 ; panel.add(btnEdit, cs)
    }

    open fun showDialog(): Piper.CommandInvocation? = showCommandInvocationDialog(cmd, showFilters = false, parent = parent)

    init {
        btnEdit.addActionListener {
            val edited = showDialog() ?: return@addActionListener
            cmd = edited
            update()
        }
    }
}

class CollapsedCommandInvocationMatchWidget(initialValue: Piper.CommandInvocation, parent: Component) : CollapsedCommandInvocationWidget(initialValue, parent) {
    private val btnRemove: JButton = JButton("Remove")

    override fun update() {
        super.update()
        btnRemove.isEnabled = cmd != Piper.CommandInvocation.getDefaultInstance()
    }

    override val stringRepr: String
        get() = cmd.toHumanReadable(false)

    init {
        btnRemove.addActionListener {
            cmd = Piper.CommandInvocation.getDefaultInstance()
            update()
        }
    }

    override fun showDialog(): Piper.CommandInvocation? = showCommandInvocationDialog(cmd, showFilters = true, parent = parent)

    override fun buildGUI(panel: Container, cs: GridBagConstraints) {
        super.buildGUI(panel, cs)
        cs.gridx = 3 ; panel.add(btnRemove, cs)
    }
}

data class MessageViewerDialogState(var result: Piper.MessageViewer? = null)

fun showMessageViewerDialog(messageViewer: Piper.MessageViewer, parent: Component?): Piper.MessageViewer? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MessageViewerDialogState()

    val mtw = MinimalToolWidget(messageViewer.common, panel, cs)

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
    showModalDialog(800, 600, panel, "Edit message editor \"${messageViewer.common.name}\"", dialog, parent)

    return state.result
}

data class HttpListenerDialogState(var result: Piper.HttpListener? = null)

fun showHttpListenerDialog(httpListener: Piper.HttpListener, parent: Component?): Piper.HttpListener? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = HttpListenerDialogState()

    val mtw = MinimalToolWidget(httpListener.common, panel, cs)

    val lsScope = createLabeledWidget("Listen to ", JComboBox(HttpListenerRequestResponse.values()), panel, cs)
    var btw = BurpToolWidget(httpListener.flagSet, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false
        val bt = btw.toBurpToolSet()

        with (Piper.HttpListener.newBuilder()) {
            common = mt
            scope = (lsScope.selectedItem as HttpListenerRequestResponse).rr
            if (bt.size < BurpTool.values().size) setToolSet(bt)
            state.result = build()
        }
        true
    }

    addFullWidthComponent(pnButtons, panel, cs)
    showModalDialog(800, 600, panel, "Edit HTTP listener \"${httpListener.common.name}\"", dialog, parent)

    return state.result
}

private fun createCheckBox(caption: String, initialValue: Boolean, panel: Container, cs: GridBagConstraints): JCheckBox {
    val cb = JCheckBox(caption)
    cb.isSelected = initialValue
    panel.add(cb, cs)
    return cb
}

data class MenuItemDialogState(var result: Piper.UserActionTool? = null)

fun showMenuItemDialog(menuItem: Piper.UserActionTool, parent: Component?): Piper.UserActionTool? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MenuItemDialogState()

    val mtw = MinimalToolWidget(menuItem.common, panel, cs)

    val cbHasGUI = createCheckBox("Has its own GUI (no need for a console window)", menuItem.hasGUI, panel, cs)

    val smMinInputs = createSpinner("Minimum required number of selected items: ",
            max(menuItem.minInputs, 1), 1, panel, cs)
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
    showModalDialog(800, 600, panel, "Edit menu item \"${menuItem.common.name}\"", dialog, parent)

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

fun showMacroDialog(macro: Piper.MinimalTool, parent: Component?): Piper.MinimalTool? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MacroState()

    val mtw = MinimalToolWidget(macro, panel, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false
        state.result = mt
        true
    }

    addFullWidthComponent(pnButtons, panel, cs)
    showModalDialog(800, 600, panel, "Edit macro \"${macro.name}\"", dialog, parent)

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

fun showHeaderMatchDialog(hm: Piper.HeaderMatch, parent: Component): Piper.HeaderMatch? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = HeaderMatchDialogState()
    val commonHeaders = arrayOf("Content-Disposition", "Content-Type", "Cookie",
            "Host", "Origin", "Referer", "Server", "User-Agent", "X-Requested-With")

    cs.fill = GridBagConstraints.HORIZONTAL

    cs.gridy = 0 ; val cbHeader = createLabeledComboBox("Header name: (case insensitive) ", hm.header, panel, cs, commonHeaders)
    cs.gridy = 1 ; val regExpWidget = RegExpWidget(hm.regex, panel, cs)

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
    showModalDialog(480, 320, panel, "Edit header filter", dialog, parent)

    return state.result
}

data class CommandInvocationDialogState(var result: Piper.CommandInvocation? = null, var tfExitCode: JTextField? = null)

data class CommandLineParameter(val value: String?) { // null = input file name
    fun isInputFileName(): Boolean {
        return value == null
    }

    override fun toString(): String {
        return if (isInputFileName()) "<INPUT>" else value!!
    }
}

fun showCommandInvocationDialog(ci: Piper.CommandInvocation, showFilters: Boolean, parent: Component): Piper.CommandInvocation? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = CommandInvocationDialogState()
    val ccmwStdout = CollapsedMessageMatchWidget(mm = ci.stdout, showHeaderMatch = false, caption = "Match on stdout: ")
    val ccmwStderr = CollapsedMessageMatchWidget(mm = ci.stderr, showHeaderMatch = false, caption = "Match on stderr: ")

    val hasFileName = ci.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME

    val paramsModel = fillDefaultModel(sequence {
        yieldAll(ci.prefixList)
        if (hasFileName) yield(null)
        yieldAll(ci.postfixList)
    }, ::CommandLineParameter)
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

    lsParams.addDoubleClickListener {
        if (paramsModel[it].isInputFileName()) {
            JOptionPane.showMessageDialog(dialog,
                    "<INPUT> is a special placeholder for the names of the input file(s), and thus cannot be edited.")
            return@addDoubleClickListener
        }
        paramsModel[it] = CommandLineParameter(
                JOptionPane.showInputDialog(dialog, "Edit command line parameter no. ${it + 1}:", paramsModel[it].value)
                        ?: return@addDoubleClickListener)
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
    cs.gridwidth = 4

    val cbPassHeaders = createCheckBox("Pass HTTP headers to command", ci.passHeaders, panel, cs)

    if (showFilters) {
        val exitValues = ci.exitCodeList.joinToString(", ")

        cs.gridy = 8 ; ccmwStdout.buildGUI(panel, cs)
        cs.gridy = 9 ; ccmwStderr.buildGUI(panel, cs)
        cs.gridy = 10 ; val tfExitCode = createLabeledTextField("Match on exit code: (comma separated) ", exitValues, panel, cs)

        tfExitCode.inputVerifier = object : InputVerifier() {
            override fun verify(input: JComponent?): Boolean = tfExitCode.text.isEmpty() ||
                    tfExitCode.text.filterNot(Char::isWhitespace).split(',').all { it.isNotEmpty() && it.all(Char::isDigit) }
        }

        state.tfExitCode = tfExitCode
    }

    val pnButtons = dialog.createOkCancelButtonsPanel {
        with (Piper.CommandInvocation.newBuilder()) {
            if (showFilters) {
                if (ccmwStdout.mm != null) stdout = ccmwStdout.mm
                if (ccmwStderr.mm != null) stderr = ccmwStderr.mm
                try {
                    addAllExitCode(state.tfExitCode!!.text.filterNot(Char::isWhitespace).split(',').map(String::toInt))
                } catch (e: NumberFormatException) {
                    JOptionPane.showMessageDialog(dialog, "Exit codes should contain numbers separated by commas only. (Whitespace is ignored.)")
                    return@createOkCancelButtonsPanel false
                }
                if (ccmwStdout.mm == null && ccmwStderr.mm == null && state.tfExitCode!!.text.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "No filters are defined for stdio or exit code.")
                    return@createOkCancelButtonsPanel  false
                }
            }
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
    showModalDialog(800, 600, panel, "Edit command invocation", dialog, parent)

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
            cs.gridwidth = 2
            cs.gridx = 0 ; panel.add(imw.label, cs)
            cs.gridwidth = 2
            cs.gridx = 2 ; panel.add(imw.button, cs)

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

private fun JDialog.createOkCancelButtonsPanel(okHandler: () -> Boolean): Component {
    val pnButtons = JPanel()
    val btnOK = JButton("OK")
    val btnCancel = JButton("Cancel")
    pnButtons.add(btnOK)
    pnButtons.add(btnCancel)
    rootPane.defaultButton = btnOK

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

class RegExpWidget(regex: Piper.RegularExpression, panel: Container, cs: GridBagConstraints) {
    private val tfPattern: JTextField = createLabeledTextField("Matches regular expression: ", regex.pattern, panel, cs)
    private val cbFlags: Map<RegExpFlag, JCheckBox>

    fun hasPattern(): Boolean {
        return tfPattern.text.isNotEmpty()
    }

    fun toRegularExpression(): Piper.RegularExpression {
        val flagSet = cbFlags.filter { e -> e.value.isSelected }.keys
        return Piper.RegularExpression.newBuilder().setPattern(tfPattern.text).setFlagSet(flagSet).build()
    }

    init {
        addFullWidthComponent(JLabel("Regular expression flags: (see JDK documentation)"), panel, cs)
        cbFlags = createCheckBoxSet(RegExpFlag.values(), regex.flagSet, panel, cs)
    }
}

class BurpToolWidget(tools: Set<BurpTool>, panel: Container, cs: GridBagConstraints) {
    private val cbTools: Map<BurpTool, JCheckBox>

    fun toBurpToolSet(): Set<BurpTool> {
        return cbTools.filter { e -> e.value.isSelected }.keys
    }

    init {
        addFullWidthComponent(JLabel("sent/received by"), panel, cs)
        cbTools = createCheckBoxSet(BurpTool.values(), tools, panel, cs)
    }
}

fun <E> createCheckBoxSet(items: Array<E>, selected: Set<E>, panel: Container, cs: GridBagConstraints): Map<E, JCheckBox> {
    cs.gridy++
    cs.gridwidth = 1

    return items.map {
        val cb = createCheckBox(it.toString(), it in selected, panel, cs)
        if (cs.gridx == 0) {
            cs.gridx = 1
        } else {
            cs.gridy++
            cs.gridx = 0
        }
        it to cb
    }.toMap()
}

fun showMessageMatchDialog(mm: Piper.MessageMatch, showHeaderMatch: Boolean, parent: Component): Piper.MessageMatch? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val prefixField  = HexASCIITextField("prefix",  mm.prefix,  dialog)
    val postfixField = HexASCIITextField("postfix", mm.postfix, dialog)
    val state = MessageMatchDialogState()
    val cciw = CollapsedCommandInvocationMatchWidget(mm.cmd, dialog)

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
    val regExpWidget = RegExpWidget(mm.regex, panel, cs)

    if (showHeaderMatch) {
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
            val header = showHeaderMatchDialog(current, dialog) ?: return@addActionListener
            lbHeader.text = header.toHumanReadable(false)
            state.header = header
            btnHeaderRemove.isEnabled = true
        }

        btnHeaderRemove.addActionListener {
            lbHeader.text = "(no header match)"
            state.header = null
            btnHeaderRemove.isEnabled = false
        }
    }

    cs.gridy++
    cs.gridx = 0
    cciw.buildGUI(panel, cs)

    val spList = JSplitPane()
    val (andAlsoPanel, andAlsoModel) = createMatchListWidget("All of these apply: [AND]", mm.andAlsoList, showHeaderMatch, dialog)
    val ( orElsePanel,  orElseModel) = createMatchListWidget("Any of these apply: [OR]",  mm.orElseList,  showHeaderMatch, dialog)
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

        // TODO cciw.cmd -> builder.cmd

        for (i in 0 until andAlsoModel.size) builder.addAndAlso(andAlsoModel.getElementAt(i).cfgItem)
        for (i in 0 until  orElseModel.size) builder.addOrElse(  orElseModel.getElementAt(i).cfgItem)

        state.result = builder.build()
        true
    }
    panel.add(pnButtons, cs)
    showModalDialog(800, 600, panel, "Edit filter", dialog, parent)

    return state.result
}

private fun createMatchListWidget(caption: String, source: List<Piper.MessageMatch>, showHeaderMatch: Boolean, parent: Component): Pair<Component, ListModel<MessageMatchWrapper>> {
    val model = fillDefaultModel(source, ::MessageMatchWrapper)

    val list = JList<MessageMatchWrapper>(model)
    val toolbar = JPanel()

    val btnAdd = JButton("+")
    val btnEdit = JButton("Edit")

    list.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION

    btnEdit.isEnabled = list.selectedIndices.isNotEmpty()
    list.addListSelectionListener {
        btnEdit.isEnabled = list.selectedIndices.isNotEmpty()
    }

    btnAdd.addActionListener {
        model.addElement(MessageMatchWrapper(
                showMessageMatchDialog(Piper.MessageMatch.getDefaultInstance(),
                        showHeaderMatch = showHeaderMatch, parent = parent) ?: return@addActionListener))
    }

    btnEdit.addActionListener {
        val edited = showMessageMatchDialog(list.selectedValue?.cfgItem ?: return@addActionListener,
                showHeaderMatch = showHeaderMatch, parent = parent)
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
        btnEdit.doClick()
    }

    return panel to model
}

private fun <E> createRemoveButton(caption: String, listWidget: JList<E>, listModel: DefaultListModel<E>): JButton {
    val btn = JButton(caption)
    btn.isEnabled = listWidget.selectedIndices.isNotEmpty()
    listWidget.addListSelectionListener {
        btn.isEnabled = listWidget.selectedIndices.isNotEmpty()
    }
    btn.addActionListener {
        listWidget.selectedIndices.reversed().forEach(listModel::removeElementAt)
    }
    return btn
}

fun <S, D> fillDefaultModel(source: Iterable<S>, transform: (S) -> D): DefaultListModel<D> =
        fillDefaultModel(source.asSequence(), transform)
fun <S, D> fillDefaultModel(source: Sequence<S>, transform: (S) -> D): DefaultListModel<D> {
    val model = DefaultListModel<D>()
    source.map(transform).forEach(model::addElement)
    return model
}

fun showModalDialog(width: Int, height: Int, widget: Component, caption: String, dialog: JDialog, parent: Component?) {
    with(dialog) {
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(widget)
        setSize(width, height)
        setLocationRelativeTo(parent)
        title = caption
        isModal = true
        isVisible = true
    }
}