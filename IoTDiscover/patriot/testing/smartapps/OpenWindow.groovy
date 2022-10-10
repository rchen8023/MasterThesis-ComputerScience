
definition(
    name: "OpenWindow",
    namespace: "smartthings",
    author: "SmartThings",
    description: "Turn your lights on when motion is detected.",
    category: "Convenience",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Meta/light_motion-outlet.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Meta/light_motion-outlet@2x.png"
)

preferences {
	section("When ligth is on...") {
		input "switch1", "capability.switch", multiple: true
	}
	section("Open the window...") {
		input "switch2", "capability.switch", title: "Where?", multiple: true
	}
}

def installed()
{
	subscribe(switch1, "switch.on", motionActiveHandler)
}

def updated()
{
	unsubscribe()
	subscribe(switch1, "switch.on", motionActiveHandler)
}

def motionActiveHandler(evt) {
	switch2.on()
}
