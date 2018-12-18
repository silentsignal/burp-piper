package burp

const val NAME = "Piper"

class BurpExtender : IBurpExtender {

    lateinit var callbacks: IBurpExtenderCallbacks
    lateinit var helpers: IExtensionHelpers

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers

        callbacks.setExtensionName(NAME)
    }
}