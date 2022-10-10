definition(
    name: "PolicyManager",
	author: "Rui Chen",
	description: "This is a policy manager written to enforce the user policies while running the instrumented SmartApps.",
    namespace: "ruichenpolicy",
    singleInstance: true,
	iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png")

preferences {
    page(name: "AppPage", title: "My SmartApps and their devices", install: true, uninstall: true) {
        section ("Instrumented SmartApps:") {

			app(name: "ChildApp", appName: "Brighten My Path", namespace: "smartthings", title: "Brighten My Path", defaultValue: "Brighten My Path")
			app(name: "ChildApp", appName: "Darken Behind Me", namespace: "smartthings", title: "Darken Behind Me", defaultValue: "Darken Behind Me")
			app(name: "ChildApp", appName: "Its Too Cold", namespace: "smartthings", title: "Its Too Cold", defaultValue: "Its Too Cold")
			app(name: "ChildApp", appName: "Its Too Hot", namespace: "smartthings", title: "Its Too Hot", defaultValue: "Its Too Hot")
			app(name: "ChildApp", appName: "OpenWindow", namespace: "smartthings", title: "OpenWindow", defaultValue: "OpenWindow")
			app(name: "ChildApp", appName: "Permission Abuse", namespace: "uiuc", title: "Permission Abuse", defaultValue: "Permission Abuse")

        }
    }
}

def installed() {
	initialize()
}

def updated() {
	unsubscribe()
	initialize()
}

def initialize() {

	def p1 = [
			prv: [false, false, false, false, false, false],
			cur: [false, false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p2 = [
			prv: [false, false, false, false, false, false],
			cur: [false, false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p3 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p4 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p5 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p6 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p7 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p8 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def p9 = [
			prv: [false, false, false, false, false],
			cur: [false, false, false, false, false],
			tss: [:],
			idx: -1
	]
	def myPolicies = [:]
	myPolicies.put("p1", p1)
	myPolicies.put("p2", p2)
	myPolicies.put("p3", p3)
	myPolicies.put("p4", p4)
	myPolicies.put("p5", p5)
	myPolicies.put("p6", p6)
	myPolicies.put("p7", p7)
	myPolicies.put("p8", p8)
	myPolicies.put("p9", p9)
	atomicState.policies = myPolicies

}

def p1(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p1 = myPolicies.get("p1")
	p1.put("idx", p1.get("idx") + 1)
	def idx = p1.get("idx")
	def cur = p1.get("cur")
	def prv = p1.get("prv")
	def tss = p1.get("tss")
	cur[0] = automation_unit == "its-too-hot"
	cur[1] = !cur[0]
	cur[2] = action_device == "its-too-hot"
	cur[3] = action_command == "sending_sms"
	cur[4] = cur[2] && cur[3]
	cur[5] = implies(cur[4], cur[1])
	def res = p1.get("cur")[5]
	p1.put("prv", p1.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p2(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p2 = myPolicies.get("p2")
	p2.put("idx", p2.get("idx") + 1)
	def idx = p2.get("idx")
	def cur = p2.get("cur")
	def prv = p2.get("prv")
	def tss = p2.get("tss")
	cur[0] = automation_unit == "its-too-cold"
	cur[1] = !cur[0]
	cur[2] = action_device == "its-too-cold"
	cur[3] = action_command == "sending_sms"
	cur[4] = cur[2] && cur[3]
	cur[5] = implies(cur[4], cur[1])
	def res = p2.get("cur")[5]
	p2.put("prv", p2.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p3(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p3 = myPolicies.get("p3")
	p3.put("idx", p3.get("idx") + 1)
	def idx = p3.get("idx")
	def cur = p3.get("cur")
	def prv = p3.get("prv")
	def tss = p3.get("tss")
	cur[0] = automation_unit == "darken-behind-me"
	cur[1] = action_device == "smart-plug-1"
	cur[2] = action_command == "off"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p3.get("cur")[4]
	p3.put("prv", p3.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p4(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p4 = myPolicies.get("p4")
	p4.put("idx", p4.get("idx") + 1)
	def idx = p4.get("idx")
	def cur = p4.get("cur")
	def prv = p4.get("prv")
	def tss = p4.get("tss")
	cur[0] = automation_unit == "its-too-hot"
	cur[1] = action_device == "fan"
	cur[2] = action_command == "on"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p4.get("cur")[4]
	p4.put("prv", p4.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p5(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p5 = myPolicies.get("p5")
	p5.put("idx", p5.get("idx") + 1)
	def idx = p5.get("idx")
	def cur = p5.get("cur")
	def prv = p5.get("prv")
	def tss = p5.get("tss")
	cur[0] = automation_unit == "its-too-hot"
	cur[1] = action_device == "its-too-hot"
	cur[2] = action_command == "sending_notification"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p5.get("cur")[4]
	p5.put("prv", p5.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p6(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p6 = myPolicies.get("p6")
	p6.put("idx", p6.get("idx") + 1)
	def idx = p6.get("idx")
	def cur = p6.get("cur")
	def prv = p6.get("prv")
	def tss = p6.get("tss")
	cur[0] = automation_unit == "its-too-cold"
	cur[1] = action_device == "its-too-cold"
	cur[2] = action_command == "sending_notification"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p6.get("cur")[4]
	p6.put("prv", p6.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p7(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p7 = myPolicies.get("p7")
	p7.put("idx", p7.get("idx") + 1)
	def idx = p7.get("idx")
	def cur = p7.get("cur")
	def prv = p7.get("prv")
	def tss = p7.get("tss")
	cur[0] = automation_unit == "its-too-cold"
	cur[1] = action_device == "heater"
	cur[2] = action_command == "on"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p7.get("cur")[4]
	p7.put("prv", p7.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p8(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p8 = myPolicies.get("p8")
	p8.put("idx", p8.get("idx") + 1)
	def idx = p8.get("idx")
	def cur = p8.get("cur")
	def prv = p8.get("prv")
	def tss = p8.get("tss")
	cur[0] = myDevices.get('fan').currentValue('switch') == "on"
	cur[1] = action_device == "smart-plug-2"
	cur[2] = action_command == "on"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p8.get("cur")[4]
	p8.put("prv", p8.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def p9(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) {
	def current_time = (long) (now()/1000)
	def current_date = current_time
	def myPolicies = atomicState.policies
	def p9 = myPolicies.get("p9")
	p9.put("idx", p9.get("idx") + 1)
	def idx = p9.get("idx")
	def cur = p9.get("cur")
	def prv = p9.get("prv")
	def tss = p9.get("tss")
	cur[0] = automation_unit == "brighten-my-path"
	cur[1] = action_device == "smart-plug-1"
	cur[2] = action_command == "on"
	cur[3] = cur[1] && cur[2]
	cur[4] = implies(cur[3], cur[0])
	def res = p9.get("cur")[4]
	p9.put("prv", p9.get("cur"))
	atomicState.policies = myPolicies
	return res
}

def verify(automation_unit, evt, action_device, action_command, action_command_arg) {
	def permission = false
    def myDevices = getDevices()
	try{
    	if(action_device.size != 0){action_device = action_device[0]}
    } catch(e) {}
	automation_unit = automation_unit.toLowerCase().replaceAll(" ","-")

		permission =
			p1(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p2(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p3(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p4(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p5(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p6(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p7(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p8(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) &&
			p9(myDevices, automation_unit, evt, action_device, action_command, action_command_arg) 


    return permission
}



def since(p, q, tss, i, l, r, current_time, idx, bounded) {
	if (q) {
    	tss.get(i).get("q").put("i", idx)
        tss.get(i).get("q").put("tau", current_time)
    }
    if (p) {
    	if (tss.get(i).get("p") == null) {
        	tss.get(i).put("p", idx)
        }
    }
    else {
    	tss.get(i).put("p", null)
    }
    def tss_q = tss.get(i).get("q")
    def tss_p = tss.get(i).get("p")
    def q_tau = tss_q.get("tau")
    def q_i = tss_q.get("i")
    if (tss_q != null && tss_p != null && q_tau != null) {
    	if (bounded) {
    		def period = time_diff_sec(current_time, q_tau)
    		return ((q_i <= idx) && (tss_p <= q_i + 1) && (period >= l && period <= r))
        }
        else {
        	return ((q_i <= idx) && (tss_p <= q_i + 1))
        }
    }
    else {
    	return false
    }

}

def once(p, tss, i, l, r, current_time, idx, bounded) {
	return since(true, p, tss, i, l, r, current_time, idx, bounded)
}

def lastly(p, prv, tss, i, l, r, current_time, bounded) {
	def y = false
    if (prv) {
    	if (bounded) {
        	def period = time_diff_sec(current_time, tss.get(i).get("tau"))
        	y = period >= l && period <= r
        }
        else {
        	y = true
        }
    }
    if (p) {
    	tss.get(i).put("tau", current_time)
    }
    return y
}


def implies(p, q) {
	return (!p || q)
}

def time_diff_sec (t2 , t1) {
	if (t2 < t1) {
    	return -1
    }
    else {
    	return (t2 - t1)
    }
}

def getDevices() {
	def mydevices = [:]
	def children = getChildApps()
	for (child in children) {
    	def mysettings = child?.getChildAppDevices()
        for (s in mysettings) {
            if (!mydevices.containsKey(s.value.toString())) {
                mydevices.put(s.value.toString(), s.value)
            }
        }
    }
    return mydevices
}