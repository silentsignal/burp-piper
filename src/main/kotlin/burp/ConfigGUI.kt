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
    override fun toString(): String = minimalToolHumanReadableName(cfgItem.common)
}

data class MinimalToolWrapper(val cfgItem: Piper.MinimalTool) {
    override fun toString(): String = minimalToolHumanReadableName(cfgItem)
}

data class UserActionToolWrapper(val cfgItem: Piper.UserActionTool) {
    override fun toString(): String = minimalToolHumanReadableName(cfgItem.common)
}

data class HttpListenerWrapper(val cfgItem: Piper.HttpListener) {
    override fun toString(): String = minimalToolHumanReadableName(cfgItem.common)
}

data class MessageMatchWrapper(val cfgItem: Piper.MessageMatch) {
    override fun toString(): String = cfgItem.toHumanReadable(negation = false, hideParentheses = true)
}

data class CommentatorWrapper(val cfgItem: Piper.Commentator) {
    override fun toString(): String = minimalToolHumanReadableName(cfgItem.common)
}

private fun minimalToolHumanReadableName(cfgItem: Piper.MinimalTool) = if (cfgItem.enabled) cfgItem.name else cfgItem.name + " [disabled]"

const val TOGGLE_DEFAULT = "Toggle enabled"

fun <S, W> createListEditor(model: DefaultListModel<W>, parent: Component?, wrap: (S) -> W, unwrap: (W) -> S,
                            dialog: (S, Component?) -> ConfigDialog<S>, default: () -> S,
                            isEnabled: S.() -> Boolean, enabler: S.(Boolean) -> S): Component {
    val listWidget = JList(model)
    listWidget.addDoubleClickListener {
        model[it] = wrap(dialog(unwrap(model[it]), parent).showGUI() ?: return@addDoubleClickListener)
    }
    val btnAdd = JButton("Add")
    btnAdd.addActionListener {
        model.addElement(wrap(dialog(enabler(default(), true), parent).showGUI() ?: return@addActionListener))
    }
    val btnEnableDisable = JButton(TOGGLE_DEFAULT)
    btnEnableDisable.isEnabled = false
    btnEnableDisable.addActionListener {
        (listWidget.selectedValuesList.asSequence() zip listWidget.selectedIndices.asSequence()).forEach { (value, index) ->
            val entry = unwrap(value)
            model[index] = wrap(enabler(entry, !isEnabled(entry)))
        }
    }
    val btnClone = JButton("Clone")
    btnClone.isEnabled = false
    btnClone.addActionListener {
        (listWidget.selectedValuesList.reversed().asSequence() zip listWidget.selectedIndices.reversed().asSequence()).forEach {(value, index) ->
            model.insertElementAt(value, index)
        }
    }
    listWidget.addListSelectionListener {
        val selection = listWidget.selectedValuesList
        btnEnableDisable.isEnabled = selection.isNotEmpty()
        btnClone.isEnabled = selection.isNotEmpty()
        val states = selection.asSequence().map(unwrap).map(isEnabled).toSet()
        btnEnableDisable.text = if (states.size == 1) (if (states.first()) "Disable" else "Enable") else TOGGLE_DEFAULT
    }
    val pnToolbar = JPanel().apply {
        add(btnAdd)
        add(createRemoveButton("Remove", listWidget, model))
        add(btnEnableDisable)
        add(btnClone)
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
    private val tfName = createLabeledTextField("Name: ", tool.name, panel, cs)
    private val cbEnabled: JCheckBox
    private val cciw: CollapsedCommandInvocationWidget = CollapsedCommandInvocationWidget(cmd = tool.cmd, parent = panel)
    private val ccmw: CollapsedMessageMatchWidget = CollapsedMessageMatchWidget(mm = tool.filter, showHeaderMatch = true, caption = "Filter: ")

    fun toMinimalTool(): Piper.MinimalTool {
        if (tfName.text.isEmpty()) throw RuntimeException("Name cannot be empty.")
        if (cciw.cmd.prefixCount + cciw.cmd.postfixCount == 0) throw RuntimeException("The command must contain at least one argument.")

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
            val filter = MessageMatchDialog(mm ?: Piper.MessageMatch.getDefaultInstance(),
                    showHeaderMatch = showHeaderMatch, parent = panel).showGUI() ?: return@addActionListener
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

    open fun showDialog(): Piper.CommandInvocation? = CommandInvocationDialog(cmd, showFilters = false, parent = parent).showGUI()

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

    override fun showDialog(): Piper.CommandInvocation? = CommandInvocationDialog(cmd, showFilters = true, parent = parent).showGUI()

    override fun buildGUI(panel: Container, cs: GridBagConstraints) {
        super.buildGUI(panel, cs)
        cs.gridx = 3 ; panel.add(btnRemove, cs)
    }
}

abstract class ConfigDialog<E>(private val parent: Component?) : JDialog() {
    protected val panel = JPanel(GridBagLayout())
    protected val cs = GridBagConstraints().apply {
        fill = GridBagConstraints.HORIZONTAL
        gridx = 0
        gridy = 0
    }
    protected var state: E? = null

    fun showGUI(): E? {
        addFullWidthComponent(createOkCancelButtonsPanel(), panel, cs)
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        setSize(width, height)
        setLocationRelativeTo(parent)
        isModal = true
        isVisible = true
        return state
    }

    private fun createOkCancelButtonsPanel(): Component {
        val btnOK = JButton("OK")
        val btnCancel = JButton("Cancel")
        rootPane.defaultButton = btnOK

        btnOK.addActionListener {
            try {
                processGUI()
                isVisible = false
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(this, e.message)
            }
        }

        btnCancel.addActionListener {
            isVisible = false
        }

        return JPanel().apply {
            add(btnOK)
            add(btnCancel)
        }
    }

    abstract fun processGUI()
}

abstract class MinimalToolDialog<E>(common: Piper.MinimalTool, parent: Component?) : ConfigDialog<E>(parent) {
    private val mtw = MinimalToolWidget(common, panel, cs)

    override fun processGUI() {
        processGUI(mtw.toMinimalTool())
    }

    abstract fun processGUI(mt: Piper.MinimalTool)
}

class MessageViewerDialog(messageViewer: Piper.MessageViewer, parent: Component?) : MinimalToolDialog<Piper.MessageViewer>(messageViewer.common, parent) {
    private val cbUsesColors = createCheckBox("Uses ANSI (color) escape sequences", messageViewer.usesColors, panel, cs)

    override fun processGUI(mt: Piper.MinimalTool) {
        with (Piper.MessageViewer.newBuilder()) {
            common = mt
            if (cbUsesColors.isSelected) usesColors = true
            state = build()
        }
    }

    init {
        setSize(800, 600)
        title = generateCaption("message editor", messageViewer.common.name)
    }
}

class HttpListenerDialog(httpListener: Piper.HttpListener, parent: Component?) : MinimalToolDialog<Piper.HttpListener>(httpListener.common, parent) {
    private val lsScope = createLabeledWidget("Listen to ", JComboBox(ConfigRequestResponse.values()), panel, cs)
    private val btw = EnumSetWidget(httpListener.toolSet, panel, cs, "sent/received by", BurpTool::class.java)

    override fun processGUI(mt: Piper.MinimalTool) {
        val bt = btw.toSet()
        with (Piper.HttpListener.newBuilder()) {
            common = mt
            scope = (lsScope.selectedItem as ConfigRequestResponse).rr
            if (bt.size < BurpTool.values().size) setToolSet(bt)
            state = build()
        }
    }

    init {
        setSize(800, 600)
        title = generateCaption("HTTP listener", httpListener.common.name)
    }
}

class CommentatorDialog(commentator: Piper.Commentator, parent: Component?) : MinimalToolDialog<Piper.Commentator>(commentator.common, parent) {
    private val cbOverwrite: JCheckBox
    private val lsSource: JComboBox<ConfigRequestResponse>

    override fun processGUI(mt: Piper.MinimalTool) {
        with (Piper.Commentator.newBuilder()) {
            common = mt
            source = (lsSource.selectedItem as ConfigRequestResponse).rr
            if (cbOverwrite.isSelected) overwrite = true
            state = build()
        }
    }

    init {
        cs.gridwidth = 4
        cbOverwrite = createCheckBox("Overwrite comments on items that already have one", commentator.overwrite, panel, cs)

        cs.gridy++
        lsSource = createLabeledWidget("Data source: ", JComboBox(ConfigRequestResponse.values()), panel, cs)

        setSize(800, 600)
        title = generateCaption("commentator", commentator.common.name)
    }
}

private fun createCheckBox(caption: String, initialValue: Boolean, panel: Container, cs: GridBagConstraints): JCheckBox {
    val cb = JCheckBox(caption)
    cb.isSelected = initialValue
    panel.add(cb, cs)
    return cb
}

class MenuItemDialog(menuItem: Piper.UserActionTool, parent: Component?) : MinimalToolDialog<Piper.UserActionTool>(menuItem.common, parent) {
    private val cbHasGUI: JCheckBox
    private val smMinInputs: SpinnerNumberModel
    private val smMaxInputs: SpinnerNumberModel

    override fun processGUI(mt: Piper.MinimalTool) {
        val minInputsValue = smMinInputs.number.toInt()
        val maxInputsValue = smMaxInputs.number.toInt()

        if (maxInputsValue in 1 until minInputsValue) throw RuntimeException(
            "Maximum allowed number of selected items cannot be lower than minimum required number of selected items.")

        with (Piper.UserActionTool.newBuilder()) {
            common = mt
            if (cbHasGUI.isSelected) hasGUI = true
            if (minInputsValue > 1) minInputs = minInputsValue
            if (maxInputsValue > 0) maxInputs = maxInputsValue
            state = build()
        }
    }

    init {
        cs.gridwidth = 4
        cbHasGUI = createCheckBox("Has its own GUI (no need for a console window)", menuItem.hasGUI, panel, cs)

        smMinInputs = createSpinner("Minimum required number of selected items: ",
                max(menuItem.minInputs, 1), 1, panel, cs)
        smMaxInputs = createSpinner("Maximum allowed number of selected items: (0 = no limit) ",
                menuItem.maxInputs, 0, panel, cs)
        setSize(800, 600)
        title = generateCaption("menu item", menuItem.common.name)
    }
}

private fun createSpinner(caption: String, initial: Int, minimum: Int, panel: Container, cs: GridBagConstraints): SpinnerNumberModel {
    val model = SpinnerNumberModel(initial, minimum, Integer.MAX_VALUE, 1)

    cs.gridy++
    cs.gridx = 0 ; cs.gridwidth = 2 ; panel.add(JLabel(caption), cs)
    cs.gridx = 2 ; cs.gridwidth = 2 ; panel.add(JSpinner(model), cs)

    return model
}

class MacroDialog(macro: Piper.MinimalTool, parent: Component?) : MinimalToolDialog<Piper.MinimalTool>(macro, parent) {
    override fun processGUI(mt: Piper.MinimalTool) {
        state = mt
    }

    init {
        setSize(800, 600)
        title = generateCaption("macro", macro.name)
    }
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

class HeaderMatchDialog(hm: Piper.HeaderMatch, parent: Component) : ConfigDialog<Piper.HeaderMatch>(parent) {
    private val commonHeaders = arrayOf("Content-Disposition", "Content-Type", "Cookie",
            "Host", "Origin", "Referer", "Server", "User-Agent", "X-Requested-With")
    private val cbHeader = createLabeledComboBox("Header name: (case insensitive) ", hm.header, panel, cs, commonHeaders)
    private val regExpWidget: RegExpWidget

    init {
        cs.gridy = 1 ; regExpWidget = RegExpWidget(hm.regex, panel, cs)

        setSize(480, 320)
        title = "Header filter editor"
    }

    override fun processGUI() {
        val text = cbHeader.selectedItem?.toString()
        if (text.isNullOrEmpty()) throw RuntimeException("The header name cannot be empty.")

        with(Piper.HeaderMatch.newBuilder()) {
            header = text
            regex = regExpWidget.toRegularExpression()
            state = build()
        }
    }
}

const val CMDLINE_INPUT_FILENAME_PLACEHOLDER = "<INPUT>"

data class CommandLineParameter(val value: String?) { // null = input file name
    fun isInputFileName(): Boolean = value == null
    override fun toString(): String = if (isInputFileName()) CMDLINE_INPUT_FILENAME_PLACEHOLDER else value!!
}

class CommandInvocationDialog(ci: Piper.CommandInvocation, private val showFilters: Boolean, parent: Component) : ConfigDialog<Piper.CommandInvocation>(parent) {
    private val ccmwStdout = CollapsedMessageMatchWidget(mm = ci.stdout, showHeaderMatch = false, caption = "Match on stdout: ")
    private val ccmwStderr = CollapsedMessageMatchWidget(mm = ci.stderr, showHeaderMatch = false, caption = "Match on stderr: ")
    private val monospaced12 = Font("monospaced", Font.PLAIN, 12)
    private var tfExitCode: JTextField? = null
    private val cbPassHeaders: JCheckBox

    private val hasFileName = ci.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME
    private val paramsModel = fillDefaultModel(sequence {
        yieldAll(ci.prefixList)
        if (hasFileName) yield(null)
        yieldAll(ci.postfixList)
    }, ::CommandLineParameter)

    fun parseExitCodeList(): Iterable<Int> {
        val text = tfExitCode!!.text
        return if (text.isEmpty()) emptyList()
        else text.filterNot(Char::isWhitespace).split(',').map(String::toInt)
    }

    init {
        val lsParams = JList<CommandLineParameter>(paramsModel)
        lsParams.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        lsParams.font = monospaced12

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
                JOptionPane.showMessageDialog(this, CMDLINE_INPUT_FILENAME_PLACEHOLDER +
                        " is a special placeholder for the names of the input file(s), and thus cannot be edited.")
                return@addDoubleClickListener
            }
            paramsModel[it] = CommandLineParameter(
                    JOptionPane.showInputDialog(this, "Edit command line parameter no. ${it + 1}:", paramsModel[it].value)
                            ?: return@addDoubleClickListener)
        }

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

        cs.gridy = 2; panel.add(btnMoveUp, cs)
        cs.gridy = 3; panel.add(btnMoveDown, cs)

        val tfParam = JTextField()
        val cbSpace = JCheckBox("Auto-add upon pressing space or closing quotes")
        val btnAdd = JButton("Add")

        btnAdd.addActionListener {
            paramsModel.addElement(CommandLineParameter(tfParam.text))
            tfParam.text = ""
        }

        tfParam.font = monospaced12
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

        cs.gridx = 0; cs.gridwidth = 1; panel.add(JLabel("Add parameter: "), cs)
        cs.gridx = 1; cs.gridwidth = 2; panel.add(tfParam, cs)
        cs.gridx = 3; cs.gridwidth = 1; panel.add(btnAdd, cs)

        cs.gridy = 5
        cs.gridx = 0
        cs.gridwidth = 3
        panel.add(cbSpace, cs)

        cs.gridy = 6

        InputMethodWidget.create(panel, cs, hasFileName, paramsModel)

        cs.gridy = 7
        cs.gridx = 0
        cs.gridwidth = 4

        cbPassHeaders = createCheckBox("Pass HTTP headers to command", ci.passHeaders, panel, cs)

        if (showFilters) {
            val exitValues = ci.exitCodeList.joinToString(", ")

            cs.gridy = 8; ccmwStdout.buildGUI(panel, cs)
            cs.gridy = 9; ccmwStderr.buildGUI(panel, cs)
            cs.gridy = 10;
            val tfExitCode = createLabeledTextField("Match on exit code: (comma separated) ", exitValues, panel, cs)

            tfExitCode.inputVerifier = object : InputVerifier() {
                override fun verify(input: JComponent?): Boolean =
                        try {
                            parseExitCodeList(); true
                        } catch (e: NumberFormatException) {
                            false
                        }
            }

            this.tfExitCode = tfExitCode
        }

        setSize(800, 600)
        title = "Command invocation editor"
    }

    override fun processGUI() {
        with (Piper.CommandInvocation.newBuilder()) {
            if (showFilters) {
                if (ccmwStdout.mm != null) stdout = ccmwStdout.mm
                if (ccmwStderr.mm != null) stderr = ccmwStderr.mm
                try {
                    addAllExitCode(parseExitCodeList())
                } catch (e: NumberFormatException) {
                    throw RuntimeException("Exit codes should contain numbers separated by commas only. (Whitespace is ignored.)")
                }
                if (ccmwStdout.mm == null && ccmwStderr.mm == null && exitCodeCount == 0) {
                    throw RuntimeException("No filters are defined for stdio or exit code.")
                }
            }
            val params = paramsModel.map(CommandLineParameter::value)
            addAllPrefix(params.takeWhile(Objects::nonNull))
            if (prefixCount < paramsModel.size) {
                inputMethod = Piper.CommandInvocation.InputMethod.FILENAME
                addAllPostfix(params.drop(prefixCount + 1))
            }
            if (cbPassHeaders.isSelected) passHeaders = true
            state = build()
        }
    }
}

private class InputMethodWidget(private val label: JLabel = JLabel(),
                                private val button: JButton = JButton(),
                                private var hasFileName: Boolean) {
    fun update() {
        label.text = "Input method: " + (if (hasFileName) "filename" else "standard input") + " "
        button.text = if (hasFileName) "Set to stdin (remove $CMDLINE_INPUT_FILENAME_PLACEHOLDER)"
        else "Set to filename (add $CMDLINE_INPUT_FILENAME_PLACEHOLDER)"
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
                    if (!imw.hasFileName || paramsModel.toIterable().any(CommandLineParameter::isInputFileName)) return
                    imw.hasFileName = false
                    imw.update()
                }

                override fun contentsChanged(p0: ListDataEvent?) { /* ignore */ }
                override fun intervalAdded(p0: ListDataEvent?) { /* ignore */ }
            })

            imw.button.addActionListener {
                if (imw.hasFileName) {
                    val iof = paramsModel.toIterable().indexOfFirst(CommandLineParameter::isInputFileName)
                    if (iof >= 0) paramsModel.remove(iof) // this triggers intervalRemoved above, no explicit update() necessary
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
            val bytes = try { parseHex() } catch(e: NumberFormatException) {
                JOptionPane.showMessageDialog(dialog, "Error in $field field: hexadecimal string ${e.message}")
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

    private fun parseHex(): ByteArray = tf.text.filter(Char::isLetterOrDigit).run {
        if (length % 2 != 0) {
            throw NumberFormatException("needs to contain an even number of hex digits")
        }
        if (any { c -> c in 'g'..'z' || c in 'G'..'Z' }) {
            throw NumberFormatException("contains non-hexadecimal letters (maybe typo?)")
        }
        chunked(2, ::parseHexByte).toByteArray()
    }

    fun getByteString(): ByteString = if (isASCII) ByteString.copyFromUtf8(tf.text) else try {
        ByteString.copyFrom(parseHex())
    } catch (e: NumberFormatException) {
        throw RuntimeException("Error in $field field: hexadecimal string ${e.message}")
    }

    fun addWidgets(caption: String, cs: GridBagConstraints, panel: Container) {
        cs.gridy++
        cs.gridx = 0 ; panel.add(JLabel(caption), cs)
        cs.gridx = 1 ; panel.add(tf,      cs)
        cs.gridx = 2 ; panel.add(rbASCII, cs)
        cs.gridx = 3 ; panel.add(rbHex,   cs)
    }
}

private fun parseHexByte(cs: CharSequence): Byte = (parseHexNibble(cs[0]) shl 4 or parseHexNibble(cs[1])).toByte()

private fun parseHexNibble(c: Char): Int = if (c in '0'..'9') (c - '0')
else ((c.toLowerCase() - 'a') + 0xA)

class RegExpWidget(regex: Piper.RegularExpression, panel: Container, cs: GridBagConstraints) {
    private val tfPattern = createLabeledTextField("Matches regular expression: ", regex.pattern, panel, cs)
    private val esw = EnumSetWidget(regex.flagSet, panel, cs, "Regular expression flags: (see JDK documentation)", RegExpFlag::class.java)

    fun hasPattern(): Boolean = tfPattern.text.isNotEmpty()

    fun toRegularExpression(): Piper.RegularExpression {
        return Piper.RegularExpression.newBuilder().setPattern(tfPattern.text).setFlagSet(esw.toSet()).build().apply { compile() }
    }
}

class EnumSetWidget<E : Enum<E>>(set: Set<E>, panel: Container, cs: GridBagConstraints, caption: String, enumClass: Class<E>) {
    private val cbMap: Map<E, JCheckBox>

    fun toSet(): Set<E> = cbMap.filterValues(JCheckBox::isSelected).keys

    init {
        addFullWidthComponent(JLabel(caption), panel, cs)
        cs.gridy++
        cs.gridwidth = 1

        cbMap = enumClass.enumConstants.asIterable().associateWithTo(EnumMap(enumClass)) {
            val cb = createCheckBox(it.toString(), it in set, panel, cs)
            if (cs.gridx == 0) {
                cs.gridx = 1
            } else {
                cs.gridy++
                cs.gridx = 0
            }
            cb
        }.toMap() as Map<E, JCheckBox>
    }
}

class MessageMatchDialog(mm: Piper.MessageMatch, private val showHeaderMatch: Boolean, parent: Component) : ConfigDialog<Piper.MessageMatch>(parent) {
    private val prefixField  = HexASCIITextField("prefix",  mm.prefix,  this)
    private val postfixField = HexASCIITextField("postfix", mm.postfix, this)
    private val cciw = CollapsedCommandInvocationMatchWidget(mm.cmd, this)
    private val cbNegation = JComboBox(MatchNegation.values())
    private val regExpWidget: RegExpWidget
    private var header: Piper.HeaderMatch? = null
    private val andAlsoModel: DefaultListModel<MessageMatchWrapper>
    private val orElseModel: DefaultListModel<MessageMatchWrapper>

    init {
        cs.gridwidth = 4

        panel.add(cbNegation, cs)

        cs.gridwidth = 1

        prefixField .addWidgets("Starts with: ", cs, panel)
        postfixField.addWidgets(  "Ends with: ", cs, panel)

        cs.gridy = 3
        regExpWidget = RegExpWidget(mm.regex, panel, cs)

        if (showHeaderMatch) {
            cs.gridy++
            cs.gridx = 0

            panel.add(JLabel("Header: "), cs)

            cs.gridx = 1

            val lbHeader = JLabel(if (mm.hasHeader()) mm.header.toHumanReadable(false) else "(no header match)")
            if (mm.hasHeader()) header = mm.header
            panel.add(lbHeader, cs)

            cs.gridx = 2

            val btnHeaderEdit = JButton("Edit...")
            panel.add(btnHeaderEdit, cs)

            cs.gridx = 3

            val btnHeaderRemove = JButton("Remove")
            panel.add(btnHeaderRemove, cs)
            btnHeaderRemove.isEnabled = mm.hasHeader()

            btnHeaderEdit.addActionListener {
                val current = header ?: Piper.HeaderMatch.getDefaultInstance()
                val header = HeaderMatchDialog(current, this).showGUI() ?: return@addActionListener
                lbHeader.text = header.toHumanReadable(false)
                this.header = header
                btnHeaderRemove.isEnabled = true
            }

            btnHeaderRemove.addActionListener {
                lbHeader.text = "(no header match)"
                header = null
                btnHeaderRemove.isEnabled = false
            }
        }

        cs.gridy++
        cs.gridx = 0
        cciw.buildGUI(panel, cs)

        val spList = JSplitPane()
        val (andAlsoPanel, andAlsoModelLocal) = createMatchListWidget("All of these apply: [AND]", mm.andAlsoList)
        val ( orElsePanel,  orElseModelLocal) = createMatchListWidget("Any of these apply: [OR]",  mm.orElseList)
        spList.leftComponent = andAlsoPanel
        spList.rightComponent = orElsePanel
        andAlsoModel = andAlsoModelLocal
        orElseModel = orElseModelLocal

        addFullWidthComponent(spList, panel, cs)

        cs.gridy++

        setSize(800, 600)
        title = "Filter editor"
    }

    override fun processGUI() {
        val builder = Piper.MessageMatch.newBuilder()

        if ((cbNegation.selectedItem as MatchNegation).negation) builder.negation = true

        builder.postfix = postfixField.getByteString()
        builder.prefix  =  prefixField.getByteString()

        if (regExpWidget.hasPattern()) builder.regex = regExpWidget.toRegularExpression()

        if (header != null) builder.header = header

        if (cciw.cmd != Piper.CommandInvocation.getDefaultInstance()) builder.cmd = cciw.cmd

        builder.addAllAndAlso(andAlsoModel.map(MessageMatchWrapper::cfgItem))
        builder.addAllOrElse (orElseModel .map(MessageMatchWrapper::cfgItem))

        state = builder.build()
    }

    private fun createMatchListWidget(caption: String, source: List<Piper.MessageMatch>): Pair<Component, DefaultListModel<MessageMatchWrapper>> {
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
                    MessageMatchDialog(Piper.MessageMatch.getDefaultInstance(),
                            showHeaderMatch = showHeaderMatch, parent = this).showGUI() ?: return@addActionListener))
        }

        btnEdit.addActionListener {
            val edited = MessageMatchDialog(list.selectedValue?.cfgItem ?: return@addActionListener,
                    showHeaderMatch = showHeaderMatch, parent = this).showGUI()
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

fun <S, D> fillDefaultModel(source: Iterable<S>, transform: (S) -> D, model: DefaultListModel<D> = DefaultListModel()): DefaultListModel<D> =
        fillDefaultModel(source.asSequence(), transform, model)
fun <S, D> fillDefaultModel(source: Sequence<S>, transform: (S) -> D, model: DefaultListModel<D> = DefaultListModel()): DefaultListModel<D> {
    model.clear()
    source.map(transform).forEach(model::addElement)
    return model
}

fun generateCaption(noun: String, name: String): String = if (name.isEmpty()) "Add $noun" else "Edit $noun \"$name\""

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