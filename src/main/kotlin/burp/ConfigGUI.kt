package burp

import com.google.protobuf.ByteString
import java.awt.*
import java.awt.event.*
import java.util.*
import javax.swing.*
import javax.swing.event.ListDataEvent
import javax.swing.event.ListDataListener
import javax.swing.event.ListSelectionEvent
import javax.swing.event.ListSelectionListener
import kotlin.math.max

private fun minimalToolHumanReadableName(cfgItem: Piper.MinimalTool) = if (cfgItem.enabled) cfgItem.name else cfgItem.name + " [disabled]"

const val TOGGLE_DEFAULT = "Toggle enabled"

abstract class ListEditor<E>(protected val model: DefaultListModel<E>, protected val parent: Component?,
                             caption: String?) : JPanel(BorderLayout()), ListDataListener, ListCellRenderer<E>, ListSelectionListener {
    protected val pnToolbar = JPanel()
    protected val listWidget = JList(model)
    private val btnClone = JButton("Clone")
    private val cr = DefaultListCellRenderer()

    abstract fun editDialog(value: E): E?
    abstract fun addDialog(): E?
    abstract fun toHumanReadable(value: E): String

    private fun addButtons() {
        val btnAdd = JButton("Add")
        btnAdd.addActionListener {
            model.addElement(addDialog() ?: return@addActionListener)
        }
        btnClone.addActionListener {
            (listWidget.selectedValuesList.reversed().asSequence() zip listWidget.selectedIndices.reversed().asSequence()).forEach {(value, index) ->
                model.insertElementAt(value, index)
            }
        }

        listOf(btnAdd, createRemoveButton(listWidget, model), btnClone).map(pnToolbar::add)
    }

    override fun getListCellRendererComponent(list: JList<out E>?, value: E, index: Int, isSelected: Boolean, cellHasFocus: Boolean): Component {
        val c = cr.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
        cr.text = toHumanReadable(value)
        return c
    }

    override fun valueChanged(p0: ListSelectionEvent?) { updateBtnEnableDisableState() }
    override fun contentsChanged(p0: ListDataEvent?)   { updateBtnEnableDisableState() }
    override fun intervalAdded  (p0: ListDataEvent?)   { updateBtnEnableDisableState() }
    override fun intervalRemoved(p0: ListDataEvent?)   { updateBtnEnableDisableState() }

    private fun updateCloneBtnState() {
        btnClone.isEnabled = !listWidget.isSelectionEmpty
    }

    open fun updateBtnEnableDisableState() {
        updateCloneBtnState()
    }

    init {
        listWidget.addDoubleClickListener {
            model[it] = editDialog(model[it]) ?: return@addDoubleClickListener
        }
        listWidget.cellRenderer = this

        listWidget.addListSelectionListener(this)
        model.addListDataListener(this)

        addButtons()
        updateCloneBtnState()
        if (caption == null) {
            add(pnToolbar, BorderLayout.PAGE_START)
        } else {
            add(pnToolbar, BorderLayout.SOUTH)
            add(JLabel(caption), BorderLayout.PAGE_START)
        }
        add(JScrollPane(listWidget), BorderLayout.CENTER)
    }
}

class MinimalToolListEditor<E>(model: DefaultListModel<E>, parent: Component?, private val dialog: (E, Component?) -> MinimalToolDialog<E>,
                               private val default: () -> E) : ListEditor<E>(model, parent, null) {

    private val btnEnableDisable = JButton()

    override fun addDialog(): E? {
        val enabledDefault = dialog(default(), parent).buildEnabled(true)
        return dialog(enabledDefault, parent).showGUI()
    }

    override fun editDialog(value: E): E? = dialog(value, parent).showGUI()
    override fun toHumanReadable(value: E): String = dialog(value, parent).toHumanReadable()

    override fun updateBtnEnableDisableState() {
        super.updateBtnEnableDisableState()
        updateEnableDisableBtnState()
    }

    private fun updateEnableDisableBtnState() {
        val selection = listWidget.selectedValuesList
        btnEnableDisable.isEnabled = selection.isNotEmpty()
        val states = selection.map { dialog(it, parent).isToolEnabled() }.toSet()
        btnEnableDisable.text = if (states.size == 1) (if (states.first()) "Disable" else "Enable") else TOGGLE_DEFAULT
    }

    init {
        btnEnableDisable.addActionListener {
            (listWidget.selectedValuesList.asSequence() zip listWidget.selectedIndices.asSequence()).forEach { (value, index) ->
                model[index] = dialog(value, parent).buildEnabled(!dialog(value, parent).isToolEnabled())
            }
        }
        pnToolbar.add(btnEnableDisable)
        updateEnableDisableBtnState()
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

class CancelClosingWindow() : RuntimeException()

class MinimalToolWidget(tool: Piper.MinimalTool, private val panel: Container, cs: GridBagConstraints, w: Window) {
    private val tfName = createLabeledTextField("Name: ", tool.name, panel, cs)
    private val cbEnabled: JCheckBox
    private val cciw: CollapsedCommandInvocationWidget = CollapsedCommandInvocationWidget(w, cmd = tool.cmd, match = false)
    private val ccmw: CollapsedMessageMatchWidget = CollapsedMessageMatchWidget(w, mm = tool.filter, showHeaderMatch = true, caption = "Filter: ")

    fun toMinimalTool(): Piper.MinimalTool {
        if (tfName.text.isEmpty()) throw RuntimeException("Name cannot be empty.")
        val command = cciw.value ?: throw RuntimeException("Command must be specified")
        try {
            if (cbEnabled.isSelected) command.checkDependencies()
        } catch (c: DependencyException) {
            when (JOptionPane.showConfirmDialog(panel, "${c.message}\n\nAre you sure you want this enabled?")) {
                JOptionPane.NO_OPTION -> cbEnabled.isSelected = false
                JOptionPane.CANCEL_OPTION -> throw CancelClosingWindow()
            }
        }

        return Piper.MinimalTool.newBuilder().apply {
            name = tfName.text
            if (cbEnabled.isSelected) enabled = true
            if (ccmw.value != null) filter = ccmw.value
            cmd = command
        }.build()
    }

    init {
        ccmw.buildGUI(panel, cs)
        cciw.buildGUI(panel, cs)
        cbEnabled = createFullWidthCheckBox("Enabled", tool.enabled, panel, cs)
    }
}

abstract class CollapsedWidget<E>(private val w: Window, var value: E?, private val caption: String, val removable: Boolean) {
    private val label: JLabel = JLabel()
    private val btnRemove = JButton("Remove")

    abstract fun editDialog(value: E, parent: Component): E?
    abstract fun toHumanReadable(): String
    abstract val default: E

    private fun update() {
        label.text = toHumanReadable() + " "
        btnRemove.isEnabled = value != null
        w.repack()
    }

    fun buildGUI(panel: Container, cs: GridBagConstraints) {
        val btnEditFilter = JButton("Edit...")
        btnEditFilter.addActionListener {
            value = editDialog(value ?: default, panel) ?: return@addActionListener
            update()
        }

        update()
        cs.gridwidth = 1
        cs.gridy++

        cs.gridx = 0 ; panel.add(JLabel(caption), cs)
        cs.gridx = 1 ; panel.add(label, cs)
        cs.gridx = 2 ; panel.add(btnEditFilter, cs)

        if (removable) {
            cs.gridx = 3; panel.add(btnRemove, cs)
            btnRemove.addActionListener {
                value = null
                update()
            }
        }
    }

    init {
        if (value == default) value = null
    }
}

class CollapsedMessageMatchWidget(w: Window, mm: Piper.MessageMatch?, val showHeaderMatch: Boolean, caption: String) :
        CollapsedWidget<Piper.MessageMatch>(w, mm, caption, removable = true) {

    override fun editDialog(value: Piper.MessageMatch, parent: Component): Piper.MessageMatch? =
            MessageMatchDialog(value, showHeaderMatch = showHeaderMatch, parent = parent).showGUI()

    override fun toHumanReadable(): String =
            value?.toHumanReadable(negation = false, hideParentheses = true) ?: "(no filter)"

    override val default: Piper.MessageMatch
        get() = Piper.MessageMatch.getDefaultInstance()
}

class CollapsedCommandInvocationWidget(w: Window, cmd: Piper.CommandInvocation, private val match: Boolean) :
        CollapsedWidget<Piper.CommandInvocation>(w, cmd, "Command: ", removable = match) {

    override fun toHumanReadable(): String = (if (match) value?.toHumanReadable(negation = false) else value?.commandLine) ?: "(no command)"
    override fun editDialog(value: Piper.CommandInvocation, parent: Component): Piper.CommandInvocation? =
            CommandInvocationDialog(value, showFilters = match, parent = parent).showGUI()

    override val default: Piper.CommandInvocation
        get() = Piper.CommandInvocation.getDefaultInstance()
}

abstract class ConfigDialog<E>(private val parent: Component?, private val caption: String) : JDialog() {
    protected val panel = JPanel(GridBagLayout())
    protected val cs = GridBagConstraints().apply {
        fill = GridBagConstraints.HORIZONTAL
        gridx = 0
        gridy = 0
    }
    private var state: E? = null

    fun showGUI(): E? {
        addFullWidthComponent(createOkCancelButtonsPanel(), panel, cs)
        title = caption
        defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
        add(panel)
        rootPane.border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        pack()
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
                state = processGUI()
                isVisible = false
            } catch (e: CancelClosingWindow) {
                /* do nothing, just skip closing the window */
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

    abstract fun processGUI(): E
}

abstract class MinimalToolDialog<E>(private val common: Piper.MinimalTool, parent: Component?, noun: String) :
        ConfigDialog<E>(parent, if (common.name.isEmpty()) "Add $noun" else "Edit $noun \"${common.name}\"") {
    private val mtw = MinimalToolWidget(common, panel, cs, this)

    override fun processGUI(): E = processGUI(mtw.toMinimalTool())

    fun isToolEnabled() : Boolean = common.enabled
    fun toHumanReadable(): String = minimalToolHumanReadableName(common)

    abstract fun buildEnabled(value: Boolean) : E
    abstract fun processGUI(mt: Piper.MinimalTool): E
}

class MessageViewerDialog(private val messageViewer: Piper.MessageViewer, parent: Component?) :
        MinimalToolDialog<Piper.MessageViewer>(messageViewer.common, parent, "message viewer") {

    private val cbUsesColors = createFullWidthCheckBox("Uses ANSI (color) escape sequences", messageViewer.usesColors, panel, cs)

    override fun processGUI(mt: Piper.MinimalTool): Piper.MessageViewer = Piper.MessageViewer.newBuilder().apply {
        common = mt
        if (cbUsesColors.isSelected) usesColors = true
    }.build()

    override fun buildEnabled(value: Boolean): Piper.MessageViewer = messageViewer.buildEnabled(value)
}

class HttpListenerDialog(private val httpListener: Piper.HttpListener, parent: Component?) :
        MinimalToolDialog<Piper.HttpListener>(httpListener.common, parent, "HTTP listener") {

    private val lsScope = createLabeledWidget("Listen to ",
            JComboBox(ConfigRequestResponse.values()).apply { selectedItem = ConfigRequestResponse.fromRequestResponse(httpListener.scope) }, panel, cs)
    private val btw = EnumSetWidget(httpListener.toolSet, panel, cs, "sent/received by", BurpTool::class.java)

    override fun processGUI(mt: Piper.MinimalTool): Piper.HttpListener {
        val bt = btw.toSet()
        return Piper.HttpListener.newBuilder().apply {
            common = mt
            scope = (lsScope.selectedItem as ConfigRequestResponse).rr
            if (bt.size < BurpTool.values().size) setToolSet(bt)
        }.build()
    }

    override fun buildEnabled(value: Boolean): Piper.HttpListener = httpListener.buildEnabled(value)
}

class CommentatorDialog(private val commentator: Piper.Commentator, parent: Component?) :
        MinimalToolDialog<Piper.Commentator>(commentator.common, parent, "commentator") {

    private val cbOverwrite: JCheckBox = createFullWidthCheckBox("Overwrite comments on items that already have one", commentator.overwrite, panel, cs)

    override fun processGUI(mt: Piper.MinimalTool): Piper.Commentator = Piper.Commentator.newBuilder().apply {
        common = mt
        if (cbOverwrite.isSelected) overwrite = true
    }.build()

    override fun buildEnabled(value: Boolean): Piper.Commentator = commentator.buildEnabled(value)
}

private fun createFullWidthCheckBox(caption: String, initialValue: Boolean, panel: Container, cs: GridBagConstraints): JCheckBox {
    cs.gridwidth = 4
    cs.gridx = 0
    cs.gridy++
    return createCheckBox(caption, initialValue, panel, cs)
}

private fun createCheckBox(caption: String, initialValue: Boolean, panel: Container, cs: GridBagConstraints): JCheckBox {
    val cb = JCheckBox(caption)
    cb.isSelected = initialValue
    panel.add(cb, cs)
    return cb
}

class MenuItemDialog(private val menuItem: Piper.UserActionTool, parent: Component?) :
        MinimalToolDialog<Piper.UserActionTool>(menuItem.common, parent, "menu item") {

    private val cbHasGUI: JCheckBox = createFullWidthCheckBox("Has its own GUI (no need for a console window)", menuItem.hasGUI, panel, cs)
    private val smMinInputs: SpinnerNumberModel = createSpinner("Minimum required number of selected items: ",
            max(menuItem.minInputs, 1), 1, panel, cs)
    private val smMaxInputs: SpinnerNumberModel = createSpinner("Maximum allowed number of selected items: (0 = no limit) ",
            menuItem.maxInputs, 0, panel, cs)

    override fun processGUI(mt: Piper.MinimalTool): Piper.UserActionTool {
        val minInputsValue = smMinInputs.number.toInt()
        val maxInputsValue = smMaxInputs.number.toInt()

        if (maxInputsValue in 1 until minInputsValue) throw RuntimeException(
            "Maximum allowed number of selected items cannot be lower than minimum required number of selected items.")

        return Piper.UserActionTool.newBuilder().apply {
            common = mt
            if (cbHasGUI.isSelected) hasGUI = true
            if (minInputsValue > 1) minInputs = minInputsValue
            if (maxInputsValue > 0) maxInputs = maxInputsValue
        }.build()
    }

    override fun buildEnabled(value: Boolean): Piper.UserActionTool = menuItem.buildEnabled(value)
}

private fun createSpinner(caption: String, initial: Int, minimum: Int, panel: Container, cs: GridBagConstraints): SpinnerNumberModel {
    val model = SpinnerNumberModel(initial, minimum, Integer.MAX_VALUE, 1)

    cs.gridy++
    cs.gridwidth = 2
    cs.gridx = 0 ; panel.add(JLabel(caption), cs)
    cs.gridx = 2 ; panel.add(JSpinner(model), cs)

    return model
}

class MacroDialog(private val macro: Piper.MinimalTool, parent: Component?) :
        MinimalToolDialog<Piper.MinimalTool>(macro, parent, "macro") {

    override fun processGUI(mt: Piper.MinimalTool): Piper.MinimalTool = mt
    override fun buildEnabled(value: Boolean): Piper.MinimalTool = macro.buildEnabled(value)
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
    cs.gridy++
    cs.gridwidth = 1 ; cs.gridx = 0 ; panel.add(JLabel(caption), cs)
    cs.gridwidth = 3 ; cs.gridx = 1 ; panel.add(widget, cs)
    return widget
}

class HeaderMatchDialog(hm: Piper.HeaderMatch, parent: Component) : ConfigDialog<Piper.HeaderMatch>(parent, "Header filter editor") {
    private val commonHeaders = arrayOf("Content-Disposition", "Content-Type", "Cookie",
            "Host", "Origin", "Referer", "Server", "User-Agent", "X-Requested-With")
    private val cbHeader = createLabeledComboBox("Header name: (case insensitive) ", hm.header, panel, cs, commonHeaders)
    private val regExpWidget: RegExpWidget = RegExpWidget(hm.regex, panel, cs)

    override fun processGUI(): Piper.HeaderMatch {
        val text = cbHeader.selectedItem?.toString()
        if (text.isNullOrEmpty()) throw RuntimeException("The header name cannot be empty.")

        return Piper.HeaderMatch.newBuilder().apply {
            header = text
            regex = regExpWidget.toRegularExpression()
        }.build()
    }
}

const val CMDLINE_INPUT_FILENAME_PLACEHOLDER = "<INPUT>"

data class CommandLineParameter(val value: String?) { // null = input file name
    fun isInputFileName(): Boolean = value == null
    override fun toString(): String = if (isInputFileName()) CMDLINE_INPUT_FILENAME_PLACEHOLDER else value!!
}

class CommandInvocationDialog(ci: Piper.CommandInvocation, private val showFilters: Boolean, parent: Component) : ConfigDialog<Piper.CommandInvocation>(parent, "Command invocation editor") {
    private val ccmwStdout = CollapsedMessageMatchWidget(this, mm = ci.stdout, showHeaderMatch = false, caption = "Match on stdout: ")
    private val ccmwStderr = CollapsedMessageMatchWidget(this, mm = ci.stderr, showHeaderMatch = false, caption = "Match on stderr: ")
    private val monospaced12 = Font("monospaced", Font.PLAIN, 12)
    private var tfExitCode: JTextField? = null
    private val cbPassHeaders: JCheckBox
    private val tfDependencies = JTextField()

    private val hasFileName = ci.inputMethod == Piper.CommandInvocation.InputMethod.FILENAME
    private val paramsModel = fillDefaultModel(sequence {
        yieldAll(ci.prefixList)
        if (hasFileName) yield(null)
        yieldAll(ci.postfixList)
    }.map(::CommandLineParameter))

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

        cs.gridwidth = 4

        panel.add(JLabel("Command line parameters: (one per line)"), cs)

        cs.gridy = 1
        cs.gridwidth = 3
        cs.gridheight = 3
        cs.fill = GridBagConstraints.BOTH

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
        cs.fill = GridBagConstraints.HORIZONTAL

        panel.add(createRemoveButton(lsParams, paramsModel), cs)

        cs.gridy = 2; panel.add(btnMoveUp, cs)
        cs.gridy = 3; panel.add(btnMoveDown, cs)

        val tfParam = JTextField()
        val btnAdd = JButton("Add")

        btnAdd.addActionListener {
            paramsModel.addElement(CommandLineParameter(tfParam.text))
            tfParam.text = ""
        }

        cs.gridy = 4

        cs.gridx = 0; cs.gridwidth = 1; panel.add(JLabel("Add parameter: "), cs)
        cs.gridx = 1; cs.gridwidth = 2; panel.add(tfParam, cs)
        cs.gridx = 3; cs.gridwidth = 1; panel.add(btnAdd, cs)

        val cbSpace = createFullWidthCheckBox("Auto-add upon pressing space or closing quotes", true, panel, cs)

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

        cs.gridy = 6

        InputMethodWidget.create(this, panel, cs, hasFileName, paramsModel)

        cbPassHeaders = createFullWidthCheckBox("Pass HTTP headers to command", ci.passHeaders, panel, cs)

        addFullWidthComponent(JLabel("Binaries required in PATH: (comma separated)"), panel, cs)
        addFullWidthComponent(tfDependencies, panel, cs)
        tfDependencies.text = ci.requiredInPathList.joinToString(separator = ", ")

        if (showFilters) {
            val exitValues = ci.exitCodeList.joinToString(", ")

            ccmwStdout.buildGUI(panel, cs)
            ccmwStderr.buildGUI(panel, cs)
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
    }

    override fun processGUI(): Piper.CommandInvocation = Piper.CommandInvocation.newBuilder().apply {
        if (showFilters) {
            if (ccmwStdout.value != null) stdout = ccmwStdout.value
            if (ccmwStderr.value != null) stderr = ccmwStderr.value
            try {
                addAllExitCode(parseExitCodeList())
            } catch (e: NumberFormatException) {
                throw RuntimeException("Exit codes should contain numbers separated by commas only. (Whitespace is ignored.)")
            }
            if (ccmwStdout.value == null && ccmwStderr.value == null && exitCodeCount == 0) {
                throw RuntimeException("No filters are defined for stdio or exit code.")
            }
        }
        val d = tfDependencies.text.replace("\\s".toRegex(), "")
        if (d.isNotEmpty()) addAllRequiredInPath(d.split(','))
        if (paramsModel.isEmpty) throw RuntimeException("The command must contain at least one argument.")
        val params = paramsModel.map(CommandLineParameter::value)
        addAllPrefix(params.takeWhile(Objects::nonNull))
        if (prefixCount < paramsModel.size) {
            inputMethod = Piper.CommandInvocation.InputMethod.FILENAME
            addAllPostfix(params.drop(prefixCount + 1))
        }
        if (cbPassHeaders.isSelected) passHeaders = true
    }.build()
}

private class InputMethodWidget(private val w: Window, private val label: JLabel = JLabel(),
                                private val button: JButton = JButton(),
                                private var hasFileName: Boolean) {
    fun update() {
        label.text = "Input method: " + (if (hasFileName) "filename" else "standard input") + " "
        button.text = if (hasFileName) "Set to stdin (remove $CMDLINE_INPUT_FILENAME_PLACEHOLDER)"
        else "Set to filename (add $CMDLINE_INPUT_FILENAME_PLACEHOLDER)"
        w.repack()
    }

    companion object {
        fun create(w: Window, panel: Container, cs: GridBagConstraints, hasFileName: Boolean, paramsModel: DefaultListModel<CommandLineParameter>): InputMethodWidget {
            val imw = InputMethodWidget(w = w, hasFileName = hasFileName)
            imw.update()
            cs.gridwidth = 2
            cs.gridx = 0 ; panel.add(imw.label, cs)
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

private fun <E : Component> addFullWidthComponent(c: E, panel: Container, cs: GridBagConstraints): E {
    cs.gridx = 0
    cs.gridy++
    cs.gridwidth = 4

    panel.add(c, cs)
    return c
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

class CollapsedHeaderMatchWidget(w: Window, hm: Piper.HeaderMatch?) :
        CollapsedWidget<Piper.HeaderMatch>(w, hm, "Header: ", removable = true) {

    override fun editDialog(value: Piper.HeaderMatch, parent: Component): Piper.HeaderMatch? =
            HeaderMatchDialog(value, parent = parent).showGUI()

    override fun toHumanReadable(): String = value?.toHumanReadable(negation = false) ?: "(no header match)"

    override val default: Piper.HeaderMatch
        get() = Piper.HeaderMatch.getDefaultInstance()
}

class MessageMatchDialog(mm: Piper.MessageMatch, private val showHeaderMatch: Boolean, parent: Component) : ConfigDialog<Piper.MessageMatch>(parent, "Filter editor") {
    private val prefixField  = HexASCIITextField("prefix",  mm.prefix,  this)
    private val postfixField = HexASCIITextField("postfix", mm.postfix, this)
    private val cciw = CollapsedCommandInvocationWidget(this, mm.cmd, match = true)
    private val chmw = CollapsedHeaderMatchWidget(this, mm.header)
    private val cbNegation = JComboBox(MatchNegation.values())
    private val regExpWidget: RegExpWidget
    private val cbInScope: JCheckBox?
    private val andAlsoPanel = MatchListEditor("All of these apply: [AND]", mm.andAlsoList)
    private val  orElsePanel = MatchListEditor("Any of these apply: [OR]",  mm.orElseList)

    init {
        cs.gridwidth = 4

        panel.add(cbNegation, cs)
        cbNegation.selectedItem = if (mm.negation) MatchNegation.NEGATED else MatchNegation.NORMAL

        cs.gridwidth = 1

        prefixField .addWidgets("Starts with: ", cs, panel)
        postfixField.addWidgets(  "Ends with: ", cs, panel)
        regExpWidget = RegExpWidget(mm.regex, panel, cs)

        if (showHeaderMatch) chmw.buildGUI(panel, cs)

        cciw.buildGUI(panel, cs)

        cbInScope = if (showHeaderMatch) createFullWidthCheckBox("request is in Burp Suite scope", mm.inScope, panel, cs) else null

        val spList = JSplitPane()
        spList.leftComponent = andAlsoPanel
        spList.rightComponent = orElsePanel

        addFullWidthComponent(spList, panel, cs)

        cs.gridy++
    }

    override fun processGUI(): Piper.MessageMatch {
        val builder = Piper.MessageMatch.newBuilder()

        if ((cbNegation.selectedItem as MatchNegation).negation) builder.negation = true

        builder.postfix = postfixField.getByteString()
        builder.prefix  =  prefixField.getByteString()

        if (regExpWidget.hasPattern()) builder.regex = regExpWidget.toRegularExpression()

        if (chmw.value != null) builder.header = chmw.value

        if (cbInScope != null && cbInScope.isSelected) builder.inScope = true

        val cmd = cciw.value
        if (cmd != null) {
            try {
                cmd.checkDependencies()
            } catch (c: DependencyException) {
                if (JOptionPane.showConfirmDialog(panel, "${c.message}\n\nAre you sure you want to save this?",
                                "Confirmation", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) throw CancelClosingWindow()
            }
            builder.cmd = cmd
        }

        builder.addAllAndAlso(andAlsoPanel.items)
        builder.addAllOrElse ( orElsePanel.items)

        return builder.build()
    }

    inner class MatchListEditor(caption: String, source: List<Piper.MessageMatch>) : ListEditor<Piper.MessageMatch>(fillDefaultModel(source), this, caption) {
        override fun addDialog(): Piper.MessageMatch? = MessageMatchDialog(Piper.MessageMatch.getDefaultInstance(),
                showHeaderMatch = showHeaderMatch, parent = this).showGUI()

        override fun editDialog(value: Piper.MessageMatch): Piper.MessageMatch? =
                MessageMatchDialog(value, showHeaderMatch = showHeaderMatch, parent = this).showGUI()

        override fun toHumanReadable(value: Piper.MessageMatch): String =
                value.toHumanReadable(negation = false, hideParentheses = true)

        val items: Iterable<Piper.MessageMatch>
            get() = model.toIterable()
    }
}

fun <E> createRemoveButton(listWidget: JList<E>, listModel: DefaultListModel<E>): JButton {
    val btn = JButton("Remove")
    btn.isEnabled = listWidget.selectedIndices.isNotEmpty()
    listWidget.addListSelectionListener {
        btn.isEnabled = listWidget.selectedIndices.isNotEmpty()
    }
    btn.addActionListener {
        listWidget.selectedIndices.reversed().forEach(listModel::removeElementAt)
    }
    return btn
}

fun <E> fillDefaultModel(source: Iterable<E>, model: DefaultListModel<E> = DefaultListModel()): DefaultListModel<E> =
        fillDefaultModel(source.asSequence(), model)
fun <E> fillDefaultModel(source: Sequence<E>, model: DefaultListModel<E> = DefaultListModel()): DefaultListModel<E> {
    model.clear()
    source.forEach(model::addElement)
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