definition(
    //name: "@{POLICY_MANAGER_APP_NAME}",
    //author: "Rui Chen",
    description: "This PolicyManager is used to collect user defined policies and discover conflicts",
    //namespace: "ruichenpolicy",
    singleInstance: true,
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png"
)
preferences {
    page(name: "page1", title: "Set up Instrumented SmartApps", nextPage: "page2", uninstall: true) {
        section ("Instrumented SmartApps:") {

			app(name: "ChildApp", appName: "Brighten My Path", namespace: "smartthings", title: "Brighten My Path", defaultValue: "Brighten My Path")
			app(name: "ChildApp", appName: "Darken Behind Me", namespace: "smartthings", title: "Darken Behind Me", defaultValue: "Darken Behind Me")
			app(name: "ChildApp", appName: "Its Too Cold", namespace: "smartthings", title: "Its Too Cold", defaultValue: "Its Too Cold")
			app(name: "ChildApp", appName: "Its Too Hot", namespace: "smartthings", title: "Its Too Hot", defaultValue: "Its Too Hot")
			app(name: "ChildApp", appName: "OpenWindow", namespace: "smartthings", title: "OpenWindow", defaultValue: "OpenWindow")
			app(name: "ChildApp", appName: "Permission Abuse", namespace: "uiuc", title: "Permission Abuse", defaultValue: "Permission Abuse")
  
            
      }
        section ("Enter phone number") {
            input "phone1", "phone", title: "Send TEXT message?", required: true
        }
    }
    page(name: "page2", title: "Specify interaction policies", install: true, uninstall: true)
}

def page2() {
    state.temp_policy = " "
    state.allDevices = getAllDevices()
    def allInteractions = identifyInteractions()
    def FinalMessage = " "
    
    dynamicPage(name: "page2") {
        
        if(allInteractions.size == 0) {
            section("Found Interactions: ") {
                paragraph "No Interaction Threats found! All permitted rules are accepted!"
            }
        } else {
            
            def conditionCount = 0
            def interactionCount = 0
            for (interaction in allInteractions) {
                interactionCount += 1
                def rule1 = interaction[1]
                def rule2 = interaction[2]
                def message = "${interaction[0]} Found: \n"
                message += "${rule1.ruleID}: <${rule1.appName}> will \"${rule1.action_cmd}\" <${rule1.action_device}> when <${rule1.trigger_device}> is \"${rule1.trigger_attr}\"\n"
                message += "${rule2.ruleID}: <${rule2.appName}> will \"${rule2.action_cmd}\" <${rule2.action_device}> when <${rule2.trigger_device}> is \"${rule2.trigger_attr}\""
                def optionName = "option_" + "${interactionCount}"
                
                if(interaction[0][0] == "A") {
                    //A.2 resolution
                    if(interaction[0][2] == "2") {
                        def blockR1 = ["ruleID":optionName, "action_cmd":rule1.action_cmd,"action_device":rule1.action_device, "trigger_attr":rule2.trigger_attr, "trigger_device":rule2.trigger_device, "action_channel":"-1","trgger_channel":"-1"]
                        def blockR2 = ["ruleID":optionName, "action_cmd":rule2.action_cmd,"action_device":rule2.action_device, "trigger_attr":rule1.trigger_attr, "trigger_device":rule1.trigger_device, "action_channel":"-1","trgger_channel":"-1"]
                        getUserPolicies("Deny", blockR1, "None")
                        getUserPolicies("Deny", blockR2, "None")

                        def a2Message = "Actions willbe restricted:\n"
                        a2Message += "Deny <${rule1.action_device}> to be \"${rule1.action_cmd}\" when <${rule2.trigger_device}> is \"${rule2.trigger_attr}\"\n"
                        a2Message += "Deny <${rule2.action_device}> to be \"${rule2.action_cmd}\" when <${rule1.trigger_device}> is \"${rule1.trigger_attr}\""
                        section("Found Interactions: ") {
                            paragraph "${message}"
                            paragraph "${a2Message}"
                        }
                    } else { //other A-type resolution
                        def blockRule1 = "Deny <${rule1.action_device}> to be \"${rule1.action_cmd}\" when <${rule1.trigger_device}> is \"${rule1.trigger_attr}\"\n"
                        def blockRule2 = "Deny <${rule1.action_device}> to be \"${rule2.action_cmd}\" when <${rule2.trigger_device}> is \"${rule2.trigger_attr}\""
                        section("Found Interactions: ") {
                            paragraph "${message}"
                            input (name:optionName, type: "enum", title: "Select to block one action:", options:["${blockRule1}", "${blockRule2}"])
                        }
                        if(settings[optionName] == blockRule1) {
                            getUserPolicies("Deny", rule1, "None")
                        }
                        else if(settings[optionName] == blockRule2) {
                            getUserPolicies("Deny", rule2, "None")
                        }
                    }
                    
                }
                //T-type resolution
                else if(interaction[0][0] == "T") {
                    def option = possibleConditionOptions(rule1, rule2)
                    section("Found Interactions: ") {
                        paragraph "${message}"
                        input (name:optionName, type: "enum", title: "Select a condition to restrict an action:", options:option[2], required: true, submitOnChange: true)
                    }
                    if(settings[optionName] == "add new condition") {
                        section("Add new conditions: ") {
                            input(name: "rules", type: "enum", title: "Which rule?", options:["1 : ${rule1.ruleID}", "2 : ${rule2.ruleID}"], required: true)
                            input(name: "conditionObject", type: "enum", title: "Condition Object:", options:possibleConditionObjects(), required: true)
                            def capability = getDeviceCapabilities(conditionObject)
                            def eventOption = getCapabilityValues(capability)
                            if(eventOption == null){
                                input(name:"conditionEvent", type: "text", title: "Condition Event:", required: true)
                            } else {
                                input(name:"conditionEvent", type: "enum", title: "Condition Event:", options:eventOption, required: true)
                            }
                            input(name:"conditionState", type: "enum", title: "Condition State:", options:['is','is not'], required: true)
                        }

                        def r = settings["rules"].split()[0]
                        def selectedRule
                        def selectedCondition = ["condition_device": settings["conditionObject"], "condition_cmd":settings["conditionEvent"], "condition_state":settings["conditionState"]]
                        if(r == "1") {
                            selectedRule = rule1
                        } else {
                            selectedRule = rule2
                        }
                        getUserPolicies("Allow", selectedRule, selectedCondition)
                    } else if(settings[optionName] != null) {
                        
                        def s = settings[optionName].split()[0].toInteger()
                        def selectedRule = option[0][s]
                        def selectedCondition = option[1][s]
                        getUserPolicies("Allow", selectedRule, selectedCondition)
                    }
                }
            
            }
        }
        FinalMessage = "[${state.temp_policy.substring(0,state.temp_policy.length()-1)}]"
        state.PoliciesJSON = FinalMessage
    }
}

private getCapabilityValues(capability) {
	def theCommands = null
	def params = [
    	uri: "https://api.smartthings.com",
        path: "/v1/capabilities/${capability}/1",
        headers: ["Content-Type":"application/json", "Authorization": "Bearer 0e11eabf-6f7a-4c37-9c9d-86f066769568"]
    ]
	try{
    	httpGet(params) { resp ->
        	for(item in resp.data.attributes){
                theCommands = item.value.schema.properties.value.enum
            }
        }
    } catch (e) {
    	log.error("Something wrong: ${e}")
    }
    return theCommands
}

private getDeviceCapabilities(deviceName) {
	def allDevice = state.allDevices
    for(device in allDevice){
    	for(singleDevice in device){
        	if(singleDevice.value == deviceName){return singleDevice.key}
        }
    }
    return null
}

private possibleConditionObjects() {
    def allDevice = state.allDevices
    def allDeviceInfo = []
    for(device in allDevice){
    	for(singleDevice in device){
            allDeviceInfo.addAll(singleDevice.value)
        }
    }
    def conditionObjects = allDeviceInfo + ["currentTime"]
    return conditionObjects
}

private possibleConditionOptions(r1, r2) {
    def newRuleOption = []
    def newRule = []
    def sr = []
    def conditionR1 = recommendedConditions(r1);
    def conditionR2 = recommendedConditions(r2);

    def count = 0
    for(def c1 in conditionR1) {
        def conditionDevice = getDeviceNameByType(c1.condition_device)
        for(device in conditionDevice) {
            def op1 = "${count} : Allow <${r1.action_device}> to be \"${r1.action_cmd}\" ONLY IF <${device}> ${c1.condition_state} \"${c1.condition_cmd}\""
            def nr1 = ["condition_device": device, "condition_cmd":c1.condition_cmd, "condition_state":c1.condition_state]
            newRuleOption.addAll(op1)
            newRule.addAll(nr1)
            sr.addAll(r1)
            count += 1
        }
    }
    for(def c2 in conditionR2) {
        def conditionDevice = getDeviceNameByType(c2.condition_device)
        for(device in conditionDevice) {
            def op2 = "${count} : Allow <${r2.action_device}> to be \"${r2.action_cmd}\" ONLY IF <${device}> ${c2.condition_state} \"${c2.condition_cmd}\""
            def nr2 = ["condition_device": device, "condition_cmd":c2.condition_cmd, "condition_state":c2.condition_state]
            newRuleOption.addAll(op2)
            newRule.addAll(nr2)
            sr.addAll(r2)
            count += 1
        }
    }
    newRuleOption.addAll("add new condition")
    return [sr, newRule, newRuleOption]
}

def installed() {
	initialize()
}

def updated() {
	unsubscribe()
	initialize()
}

def initialize() {
    sendPolicies()
}

def getTriggerActions() {
    def ta = [
        "Brighten My Path":[
            ["ruleID":"rule36", "action_cmd":"on","action_device":"switch1", "trigger_attr":"motion.active", "trigger_device":"motion1", "action_channel":"-1","trgger_channel":"-1"],],
        "Darken Behind Me":[
            ["ruleID":"rule52", "action_cmd":"off","action_device":"switch1", "trigger_attr":"motion.inactive", "trigger_device":"motion1", "action_channel":"-1","trgger_channel":"-1"],],
        "Its Too Cold":[
            ["ruleID":"rule185", "action_cmd":"on","action_device":"switch1", "trigger_attr":"temperature <= temperature1", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"['temperature', 0]"],
            ["ruleID":"rule186", "action_cmd":"sending_sms","action_device":"its-too-cold", "trigger_attr":"temperature", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"-1"],
            ["ruleID":"rule187", "action_cmd":"sending_notification","action_device":"its-too-cold", "trigger_attr":"temperature", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"-1"],],
        "Its Too Hot":[
            ["ruleID":"rule188", "action_cmd":"sending_sms","action_device":"its-too-hot", "trigger_attr":"temperature", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"-1"],
            ["ruleID":"rule189", "action_cmd":"on","action_device":"switch1", "trigger_attr":"temperature >= temperature1", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"['temperature', 1]"],
            ["ruleID":"rule190", "action_cmd":"sending_notification","action_device":"its-too-hot", "trigger_attr":"temperature", "trigger_device":"temperatureSensor1", "action_channel":"-1","trgger_channel":"-1"],],
        "OpenWindow":[
            ["ruleID":"rule0", "action_cmd":"on","action_device":"switch2", "trigger_attr":"switch.on", "trigger_device":"switch1", "action_channel":"-1","trgger_channel":"-1"],],
        "Permission Abuse":[
            ["ruleID":"rule00", "action_cmd":"sending_sms","action_device":"permission-abuse", "trigger_attr":"battery", "trigger_device":"thebatterymo", "action_channel":"-1","trgger_channel":"-1"],
            ["ruleID":"rule00", "action_cmd":"unlock","action_device":"thebatterymo", "trigger_attr":"battery", "trigger_device":"thebatterymo", "action_channel":"-1","trgger_channel":"-1"],],]
    
    return ta
}

def allDevicesTypes() {
	def allDevices = ["fan":"fan",
		"HueMotionSensor 1":"motionSensor",
		"HueWhiteLamp1":"light",
		"smart-plug-1":"switch",
		"smart-plug-2":"window",
		"temp":"temperatureSensor",
		"heater":"heater"]
    
    return allDevices
}

def getDeviceNameByType(deviceType) {
	def allDevices = allDevicesTypes()
    def devices = allDevices.findAll{ it.value == deviceType}
    def deviceNames = [ ]
    for(device in devices) {
    	deviceNames.addAll(device.key)
    }
    return deviceNames
}

def getPermittedRule() {
    def taWithConfig = getChildAppConfig()
    def childApps = getChildApps()
    def allPermittedRules = []
    def allDeniedRules = []
    
    for(def child in childApps) {
        def childName = child.name
        def appTA = taWithConfig.find { it.key == childName }
        def childAppDevices = child.getChildAppDevices()
        def appAcceptRules = []
        def appDeniedRules = []

        for(def input in childAppDevices) {
            if(appTA) {
                for(def ta in appTA.value) {
                    if(input.key == ta.ruleID) {
                        //Accepted rules
                        if(input.value == "Accept") {
                            //wrap device list with [ ]
                            def action_dev 
                            def trigger_dev 
                            //action_device
                            try {
                                if(ta.action_device.size != 0) {
                                    action_dev = ta.action_device
                                }
                            } catch (MissingPropertyException ex) {
                                action_dev = [ta.action_device]
                            }
                            //trigger_device
                            try {
                                if(ta.trigger_device.size != 0) {
                                    trigger_dev = ta.trigger_device
                                }
                            } catch (MissingPropertyException ex) {
                                trigger_dev = [ta.trigger_device]
                            }
                            ta.action_device = action_dev
                            ta.trigger_device = trigger_dev
                            
                            appAcceptRules.addAll(ta)
                        } else {
                            appDeniedRules.addAll(ta)
                        }
                    }
                }
            }
        }
        //update all permitted rules
        if(appAcceptRules.size != 0) {
            allPermittedRules.addAll("${childName}" : appAcceptRules)
        }
        //update all denied rules
        if(appDeniedRules.size != 0) {
            allDeniedRules.addAll("${childName}" : appDeniedRules)
        }
    }
    //for all denided rules, directly generate policies to block such actions
    if(allDeniedRules.size != 0) {
        allDeniedRules.each {deniedRules ->
            //log.debug("denied rules -- ${deniedRules}")
            deniedRules.each { app ->
                app.value.each { rules ->
                    //wrap device list with [ ]
                    def action_dev
                    def trigger_dev
                    try {
                        if(rules.action_device.size != 0) {
                            action_dev = rules.action_device
                        }
                    } catch (MissingPropertyException ex) {
                        action_dev = [rules.action_device]
                    }
                    try {
                        if(rules.trigger_device.size != 0){
                            trigger_dev = rules.trigger_device
                        }
                    } catch (MissingPropertyException ex) {
                        trigger_dev = [rules.trigger_device]
                    }  

                    for(ad in action_dev) {
                        def adName = findDeviceNameByID(ad)
                        for(td in trigger_dev) {
                            def tdName = findDeviceNameByID(td)
                            def tempRule = ["ruleID":rules.ruleID, "appName":app.key,"action_cmd":rules.action_cmd,"action_device":adName, "trigger_device":tdName, "trigger_attr":rules.trigger_attr]
                            getUserPolicies("Deny", tempRule, "None")
                        }
                    }
                }
            }
        }
    }
    return allPermittedRules
}

//config with user selected devices and inputs
def getChildAppConfig() {
    def triggerActions = getTriggerActions()
    def childApps = getChildApps()
    childApps.each {child ->
        def childName = child.name
        def appTA = triggerActions.find{ it.key == childName }
        def childAppDevices = child.getChildAppDevices()
        childAppDevices.each { input ->
            if(appTA) {
                appTA.value.each { ta -> 
                    //config action device
                    if(ta.action_device == input.key) {
                        try{
                            if(input.value.id.size != 0) {
                                ta.action_device = input.value.id
                            }
                        } catch (MissingPropertyException ex) {
                            ta.action_device = [input.value.id]
                        }
                    }
                    //config trigger device
                    if(ta.trigger_device == input.key) {
                        try{
                            if(input.value.id.size != 0) {
                                ta.trigger_device = input.value.id
                            }
                        } catch (MissingPropertyException ex) {
                            ta.trigger_device = [input.value.id]
                        }
                    }
                    //config trigger attributes
                    def attr = ta.trigger_attr.tokenize(" ")
                    if(attr.size() == 3) {
                        if(attr[2] == input.key) {
                            attr[2] = input.value
                            ta.trigger_attr = attr.join(" ")
                        }
                    }

                    def attr2 = ta.trigger_attr.tokenize(".")
                    if(attr2.size() == 2) {
                        ta.trigger_attr = attr2[1]
                    }

                    def cmd = ta.action_cmd.tokenize(".")
                    if(cmd.size() == 2) {
                        ta.action_cmd = cmd[1]
                    }
                }
            }
        }
    }
    return triggerActions
}

def findDeviceNameByID(deviceID) {
	def childApps = getChildApps()
    for(def child in childApps) {
        def childAppDevices = child.getChildAppDevices()
        for(def input in childAppDevices){
        	try {
            	for(def values in input.value) {
                	if(values.id == deviceID){
            			return values
                    }
                }
            } catch (e) {}
            
        }
	}
    return deviceID
}

//some app may allow users to select multiple action device or trigger device
//this function is used to split the rules with multiple devices
def processTARules(ta) {
    def taRules = []
    for(def appRules in ta) {
        def app
        for(def tempapp in appRules){
            app = tempapp
        }
        //for each rule in this app
        for(def nonConfigTA in app.value) {

            for(def ad in nonConfigTA.action_device) {
                for(def td in nonConfigTA.trigger_device) {
                    taRules.addAll(["ruleID":nonConfigTA.ruleID, "appName":app.key, "action_cmd":nonConfigTA.action_cmd, "action_device":ad, "trigger_device":td, "trigger_attr":nonConfigTA.trigger_attr, "trigger_channel":nonConfigTA.trigger_channel, "action_channel":nonConfigTA.action_channel])
                }
            }
        }
    }
    return taRules
}

def identifyInteractions() {
    
    def taInApp = getPermittedRule()
    def pTA = processTARules(taInApp)
    //compare two rules
    def rule1 = pTA
    def rule2 = pTA

    def inferenceResult = []
    def checked = []
    for(def i = 0; i < pTA.size; i++) {
        def noInteraction = true
        //def tempRule1 = ["ruleID":rule1[i].ruleID, "appName":rule1[i].appName, "action_cmd":rule1[i].action_cmd, "action_device":rule1[i].action_device, "trigger_device":rule1[i].trigger_device, "trigger_attr":rule1[i].trigger_attr]
        def tempRule1 = rule1[i]
        for(def j = 0; j < rule2.size; j++) {
            def tempRule2 = rule2[j]

            // if(tempRule1.ruleID == tempRule2.ruleID && !notChecked(checked, tempRule2.ruleID)) continue;

            def resultConflict = defineConflictInteractions(tempRule1, tempRule2)
            def resultInteract = defineChainedInteractions(tempRule1, tempRule2)

            if(resultConflict[0]) {
                
                def ad1 = tempRule1.action_device 
                def td1 = tempRule1.trigger_device
                tempRule1.action_device = findDeviceNameByID(ad1)
                tempRule1.trigger_device = findDeviceNameByID(td1)

                def ad2 = tempRule2.action_device 
                def td2 = tempRule2.trigger_device
                tempRule2.action_device = findDeviceNameByID(ad2)
                tempRule2.trigger_device = findDeviceNameByID(td2)

                def thisResult = [resultConflict[1], tempRule1, tempRule2]
                inferenceResult.addAll([thisResult])
                noInteraction = false
                
            }

            if(resultInteract[0]) {
                
                def ad1 = tempRule1.action_device 
                def td1 = tempRule1.trigger_device
                tempRule1.action_device = findDeviceNameByID(ad1)
                tempRule1.trigger_device = findDeviceNameByID(td1)

                def ad2 = tempRule2.action_device 
                def td2 = tempRule2.trigger_device
                tempRule2.action_device = findDeviceNameByID(ad2)
                tempRule2.trigger_device = findDeviceNameByID(td2)

                def thisResult = [resultInteract[1], tempRule1, tempRule2]
                log.debug(thisResult)
                inferenceResult.addAll([thisResult])
                noInteraction = false
                
            }
        }
        if(noInteraction) {
            def ad1 = tempRule1.action_device 
            def td1 = tempRule1.trigger_device
            tempRule1.action_device = findDeviceNameByID(ad1)
            tempRule1.trigger_device = findDeviceNameByID(td1)

            getUserPolicies("Allow", tempRule1, "None")
        }
        checked.addAll(tempRule1.ruleID)
    }
    
    return inferenceResult
}

def notChecked(checked, ruleID) {
    for(checkedRule in checked) {
        if(checkedRule == ruleID) {
            return false
        }
    }
    return true
}

def defineConflictInteractions(r1, r2) {
    def found = false 
    def result

    if(r1.action_device == r2.action_device && r1.action_cmd != r2.action_cmd) {
        //A.1
        if(r1.trigger_device == r2.trigger_device && r1.trigger_attr == r2.trigger_attr) {
            result = "A.1 Conflict"
            found = true
        } 
        //A.2
        else if(r1.trigger_device != r2.trigger_device) {
            result = "A.2 Conflict"
            found = true
        }
    }
    //A.3
    else if(r1.action_device == r2.action_device && r1.action_cmd == r2.action_cmd) {
        if(r1.trigger_device == r2.trigger_device && r1.trigger_attr != r2.trigger_attr) {
            result = "A.3 Conflict"
            found = true
        }
    } 
    //A.4
    else if(r1.action_device != r2.action_device) {
        if(r1.action_channel != null  && r2.action_channel != null && r1.action_channel != -1 && r2.action_channel != -1) {
            if(r1.action_channel[0] == r2.action_channel[0] && r1.action_channel[1] != r2.action_channel[1]) {
                if(r1.trigger_device == r2.trigger_device && r1.trigger_attr == r2.trigger_attr) {
                    result = "A.4 Conflict"
                    found = true
                }
            }
        }
    }

    return [found, result]
}

def defineChainedInteractions(r1, r2) {
    
    def found = false
    def result 

    if(r1.action_device == r2.trigger_device && r1.action_cmd == r2.trigger_attr) {
        if(r1.trigger_device != r2.action_device) {
            //T.1
            if(r1.action_device != r2.action_device) {
                result = "T.1 Chained Interaction"
                found = true
            }
            //T.2
            else if(r1.action_cmd != r2.action_cmd) {
                result = "T.2 Self Disabling"
                found = true
            }
        } 
        //T.3
        else if(r1.trigger_device == r2.action_device && r1.trigger_attr == r2.action_cmd && r1.action_device != r2.action_device) {
            result = "T.3 Loop-triggering"
            found = true
        }
    }
    else if(r1.action_device != r2.action_device && r1.action_channel == r2.trigger_channel) {
        if(r1.action_channel != null || r1.action_channel != -1){
            if(r1.trigger_device != r2.action_device) {
                //T.4
                if(r1.action_device != r2.action_device) {
                    result = "T.4 Chained Interaction"
                    found = true
                }
                //T.5
                else if(r1.action_cmd != r2.action_cmd) {
                    result = "T.5 Self Disabling"
                    found = true
                }
            }
            //T.6
            else if(r1.trigger_device != r2.action_device && r1.trigger_channel == r2.action_channel) {
                if(r1.trigger_channel != null || r1.trigger_channel != -1) {
                    if(r1.action_device == r2.action_device && r1.action_cmd != r2.action_cmd) {
                        result = "T.6 Loop-triggering"
                        found = true
                    }
                }
            }
        }
    
    }
    return [found, result]
}

def recommendedConditions(rule) {
    def definedConditions = 		[
		"light": [ 
			"on" : [
				["condition_device":"motionSensor","condition_cmd":"active","condition_state":"is"],
				["condition_device":"presenceSenosr","condition_cmd":"present","condition_state":"is"]
			],
			"off" : [
				["condition_device":"light","condition_cmd":"on","condition_state":"within 30s"],
				["condition_device":"motionSensor","condition_cmd":"inactive","condition_state":"is"]
			]
		],
		"fan": [
			"on" : [
				["condition_device":"heater", "condition_cmd":"off","condition_state":"is"],
	       		["condition_device":"temperatureSensor","conditino_cmd":"> 75","condition_state":"is"]
			]
		],
		"window": [
			"open": [
				["condition_device":"switch", "condition_cmd":"on","condition_state":"is"]
			]
			
		]
	]

    def actionDeviceType = getDeviceType(rule.action_device)
    return definedConditions[actionDeviceType][rule.action_cmd]
}

def getDeviceType(deviceName) {
    def allDevices = allDevicesTypes()
    return allDevices["${deviceName}"]
}

def getUserPolicies(permission, theRule, condition) {
	def rule = "{"
    for(property in theRule){
    	rule = rule + "\"${property.key}\":\"${property.value}\","
    }
    rule = rule.substring(0,rule.length()-1) + "}"
	def policy = "{\"permission\": \"${permission}\", \"rule\": ${rule}, \"condition\":${condition}}"
    if(state.temp_policy == null) {state.temp_policy = policy + ","}
    else{state.temp_policy = state.temp_policy + policy + ","}
}

def getAllDevices() {
	def allDevices = []
	def params = [
    	uri: "https://api.smartthings.com",
        path: "/v1/devices",
        headers: ["Content-Type":"application/json", "Authorization": "Bearer 0e11eabf-6f7a-4c37-9c9d-86f066769568"]
    ]
	try{
    	httpGet(params) { resp ->
            resp.data.items.each{ device ->
            	def cap = device.components[0].capabilities[0].id
                allDevices.addAll(["${cap}":device.label])
            }
        }
    } catch (e) {
    	log.error("something went wrong: ${e}")
    }
    return allDevices
}

def sendPolicies(){
	def message = state.PoliciesJSON
    def i = 0
    while(i < message.length()){
        def j = i + 1500
        if(j > message.length()){
        	sendSms(phone1,message.substring(i,message.length()))
        } else{
    		sendSms(phone1,message.substring(i,j))
         }
         i = j
    }
}




