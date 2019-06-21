package burp

import com.google.protobuf.ByteString
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.*
import javax.swing.*

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
                        private val cbEnabled: JCheckBox = JCheckBox("Enabled")) {
    fun toMinimalTool(dialog: Component): Piper.MinimalTool? {
        if (tfName.text.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "The message viewer name cannot be empty.")
            return null
        }

        val f = filter
        with (Piper.MinimalTool.newBuilder()) {
            name = tfName.text
            if (cbEnabled.isSelected) enabled = true
            if (f != null) filter = f
            // TODO cmd
            return build()
        }
    }

    companion object {
        fun create(tool: Piper.MinimalTool, panel: Container, cs: GridBagConstraints): MinimalToolWidget {
            val mtw = MinimalToolWidget(filter = tool.filter)

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
            tfName.text = tool.name
            panel.add(tfName, cs)

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

            cs.gridy = 2
            cs.gridx = 0 ; panel.add(JLabel("Command: "), cs)
            cs.gridx = 1 ; panel.add(JLabel(tool.cmd.commandLine + " "), cs)
            cs.gridx = 2 ; panel.add(JButton("Edit..."), cs) // TODO handle click

            cs.gridy = 3
            cs.gridx = 0
            cs.gridwidth = 3

            val cbEnabled = JCheckBox("Enabled")
            cbEnabled.isSelected = tool.enabled
            panel.add(cbEnabled, cs)

            cs.gridy = 4

            return mtw
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

    val cbUsesColors = JCheckBox("Uses ANSI (color) escape sequences")
    cbUsesColors.isSelected = messageViewer.usesColors
    panel.add(cbUsesColors, cs)

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

data class MenuItemDialogState(var result: Piper.UserActionTool? = null)

private fun showMenuItemDialog(menuItem: Piper.UserActionTool): Piper.UserActionTool? {
    val dialog = JDialog()
    val panel = JPanel(GridBagLayout())
    val cs = GridBagConstraints()
    val state = MenuItemDialogState()

    val mtw = MinimalToolWidget.create(menuItem.common, panel, cs)

    val cbHasGUI = JCheckBox("Has its own GUI (no need for a console window)")
    cbHasGUI.isSelected = menuItem.hasGUI
    panel.add(cbHasGUI, cs)

    val pnButtons = dialog.createOkCancelButtonsPanel {
        val mt = mtw.toMinimalTool(dialog) ?: return@createOkCancelButtonsPanel false

        with (Piper.UserActionTool.newBuilder()) {
            common = mt
            if (cbHasGUI.isSelected) hasGUI = true
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