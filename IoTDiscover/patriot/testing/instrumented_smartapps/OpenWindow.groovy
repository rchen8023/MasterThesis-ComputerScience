
definition(
    name: "OpenWindow",
    namespace: "smartthings",
    author: "SmartThings",
    parent: "ruichenpolicy:PolicyManager",
    description: "Turn your lights on when motion is detected.",
    category: "Convenience",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Meta/light_motion-outlet.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Meta/light_motion-outlet@2x.png"
)

preferences {
	    page(name:"SetupPage", install: true, uninstall: true)
}

def installed() {
    subscribe(switch1, 'switch.on', motionActiveHandler)
}

def updated() {
    unsubscribe()
    subscribe(switch1, 'switch.on', motionActiveHandler)
}

def motionActiveHandler(evt) {
    parent.verify(app.getLabel(), evt , switch2.getDisplayName(), 'on', null) == true ? switch2.on() : log.debug('Invariants Violation!')
}



def getChildAppDevices() {
	return settings
}

def SetupPage() {
    dynamicPage(name:"SetupPage") {
        section("When ligth is on...") {
    		input "switch1", "capability.switch", multiple: true, submitOnChange: true
    	}
    	section("Open the window...") {
    		input "switch2", "capability.switch", title: "Where?", multiple: true, submitOnChange: true
    	}
        section("App Description:") {
            paragraph "Turn your lights on when motion is detected."
        }
        section("Single App Policy:") {
            paragraph title: "Action Found:","<${app.name}> will \"on\" <${switch2}>when <${switch1}> is \"switch.on\""
            input(name: "rule0", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
        }
    }
}
