/**
 *  Copyright 2015 SmartThings
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 *  It's Too Cold
 *
 *  Author: SmartThings
 */
definition(
    name: "Its Too Cold",
    namespace: "smartthings",
    author: "SmartThings",
    parent: "ruichenpolicy:PolicyManager",
    description: "Monitor the temperature and when it drops below your setting get a text and/or turn on a heater or additional appliance.",
    category: "Convenience",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Meta/temp_thermo-switch.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Meta/temp_thermo-switch@2x.png",
    pausable: true
)

preferences {
	    page(name:"SetupPage", install: true, uninstall: true)
}

def installed() {
    subscribe(temperatureSensor1, 'temperature', temperatureHandler)
}

def updated() {
    unsubscribe()
    subscribe(temperatureSensor1, 'temperature', temperatureHandler)
}

def temperatureHandler(evt) {
    log.trace("temperature: $evt.value, $evt")
    def tooCold = temperature1 
    def mySwitch = settings .switch1
    if ( evt .doubleValue <= tooCold ) {
        log.debug("Checking how long the temperature sensor has been reporting <= $tooCold")
        def deltaMinutes = 10
        def timeAgo = new java.util.Date(now() - 1000 * 60 * deltaMinutes .toLong())
        def recentEvents = temperatureSensor1.eventsSince(timeAgo)?.findAll({ 
            it .name == 'temperature'
        })
        log.trace("Found $(recentEvents?.size()) ? recentEvents?.size() : 0 events in the last $deltaMinutes minutes")
        def alreadySentSms = recentEvents.count({ 
            it .doubleValue <= tooCold 
        }) > 1
        if ( alreadySentSms ) {
            log.debug("SMS already sent within the last $deltaMinutes minutes")
        } else {
            log.debug("Temperature dropped below $tooCold:  sending SMS and activating $mySwitch")
            def tempScale = location .temperatureScale ? location .temperatureScale : 'F'
            send("$temperatureSensor1.displayName is too cold, reporting a temperature of $evt.value$(evt.unit) ? evt.unit : tempScale")
            parent.verify(app.getLabel(), evt , switch1.getDisplayName(), 'on', null) == true ? switch1?.on() : log.debug('Invariants Violation!')
        }
    }
}

private send(msg) {
    if ( location .contactBookEnabled) {
        log.debug("sending notifications to: $recipients?.size()")
        parent.verify(app.getLabel(), msg , getDisplayName(), 'sending_notification', msg ) == true ? sendNotificationToContacts(msg, recipients) : log.debug('Invariants Violation!')
    } else {
        if ( sendPushMessage != 'No') {
            log.debug('sending push message')
            parent.verify(app.getLabel(), msg , getDisplayName(), 'sending_notification', msg ) == true ? sendPush(msg) : log.debug('Invariants Violation!')
        }
        if ( phone1 ) {
            log.debug('sending text message')
            parent.verify(app.getLabel(), msg , getDisplayName(), 'sending_sms', phone1 ) == true ? sendSms(phone1, msg) : log.debug('Invariants Violation!')
        }
    }
    log.debug(msg)
}



def getChildAppDevices() {
	return settings
}

def SetupPage() {
    dynamicPage(name:"SetupPage") {
        section("Monitor the temperature...") {
    		input "temperatureSensor1", "capability.temperatureMeasurement", submitOnChange: true
    	}
    	section("When the temperature drops below...") {
    		input "temperature1", "number", title: "Temperature?", submitOnChange: true
    	}
        section( "Notifications" ) {
            input("recipients", "contact", title: "Send notifications to") {, submitOnChange: true
                input "sendPushMessage", "enum", title: "Send a push notification?", options: ["Yes", "No"], required: false, submitOnChange: true
                input "phone1", "phone", title: "Send a Text Message?", required: false, submitOnChange: true
            }
        }
    	section("Turn on a heater...") {
    		input "switch1", "capability.switch", required: false, submitOnChange: true
    	}
        section("App Description:") {
            paragraph "Monitor the temperature and when it drops below your setting get a text and/or turn on a heater or additional appliance."
        }
        section("Single App Policy:") {
            paragraph title: "Action Found:","<${app.name}> will \"on\" <${switch1}>when <${temperatureSensor1}> is \"temperature <= temperature1\""
            input(name: "rule185", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
            paragraph title: "Action Found:","<${app.name}> will \"sending_sms\" when <${temperatureSensor1}> is \"temperature\""
            input(name: "rule186", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
            paragraph title: "Action Found:","<${app.name}> will \"sending_notification\" when <${temperatureSensor1}> is \"temperature\""
            input(name: "rule187", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])
        }
    }
}
