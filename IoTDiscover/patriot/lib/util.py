import argparse
import os
import yaml
import re
import base64
import threading
import queue
import time
import json


# ST_REGEX_DICT = {
    # 'app_name': re.compile(r'\sname\s*:\s*\"(?P<app_name>.*)\"\s*', re.IGNORECASE),
    # 'author_name': re.compile(r'\s*author\s*:\s*\"(?P<author_name>.*)\"\s*', re.IGNORECASE),
    # 'author_namespace': re.compile(r'\s*namespace\s*:\s*\"(?P<author_namespace>.*)\"\s*', re.IGNORECASE),
    # 'rdlm_uri': re.compile(r'\s*def\s*uri\s*\=\s*\"(?P<rdlm_uri>.*)\"\s*', re.IGNORECASE),
    # 'rdlm_http_auth': re.compile(r'\s*headers\.put\s*\(\s*\"Authorization\s*\"\s*\,\s*\"\s*Basic\s*(?P<rdlm_http_auth>.*)\"\s*', re.IGNORECASE),
    # 'rdlm_lock_path': re.compile(r'\s*def\s*rdlm_lock_path\s*\=\s*\"(?P<rdlm_lock_path>.*)\"\s*', re.IGNORECASE),
    # 'rdlm_lock_lifetime': re.compile(r'\s*lifetime\s*:\s*(?P<rdlm_lock_lifetime>.*),\s*', re.IGNORECASE),
    # 'instrumented_smartapps_list_section': re.compile(r'\s*(?P<instrumented_smartapps_list_section>//@{INSTRUMENTED_SMARTAPPS_LIST_SECTION})\s*', re.IGNORECASE),
    # 'initializing_policies_section': re.compile(r'\s*(?P<initializing_policies_section>//@{INITIALIZING_POLICIES_SECTION})\s*', re.IGNORECASE),
    # 'encoded_policies_section': re.compile(r'\s*(?P<encoded_policies_section>//@{ENCODED_POLICIES_SECTION})\s*', re.IGNORECASE),
    # 'policies_permission_section': re.compile(r'\s*(?P<policies_permission_section>//@{POLICIES_PERMISSION_SECTION})\s*', re.IGNORECASE),
    # 'smartapp_definition': re.compile(r'\s*.*definition\s*\(\s*(?P<smartapp_definition>(.|\n)*)\s*\)\s*preferences(.|\n)*', re.IGNORECASE),
# }

ST_REGEX_DICT = {
    'app_name': re.compile(r'\sname\s*:\s*\"(?P<app_name>.*)\"\s*', re.IGNORECASE),
    'author_name': re.compile(r'\s*author\s*:\s*\"(?P<author_name>.*)\"\s*', re.IGNORECASE),
    'author_namespace': re.compile(r'\s*namespace\s*:\s*\"(?P<author_namespace>.*)\"\s*', re.IGNORECASE),
    'app_description':re.compile(r'\s*description\s*:\s*\"(?P<app_description>.*)\"\s*', re.IGNORECASE),
    'instrumented_smartapps_list_section': re.compile(r'\s*(?P<instrumented_smartapps_list_section>//@{INSTRUMENTED_SMARTAPPS_LIST_SECTION})\s*', re.IGNORECASE),
    'initializing_policies_section': re.compile(r'\s*(?P<initializing_policies_section>//@{INITIALIZING_POLICIES_SECTION})\s*', re.IGNORECASE),
    'encoded_policies_section': re.compile(r'\s*(?P<encoded_policies_section>//@{ENCODED_POLICIES_SECTION})\s*', re.IGNORECASE),
    'policies_permission_section': re.compile(r'\s*(?P<policies_permission_section>//@{POLICIES_PERMISSION_SECTION})\s*', re.IGNORECASE),
    'trigger_action_lists': re.compile(r'\s*(?P<trigger_action_lists>@{TRIGGER_ACTION_LISTS})\s*', re.IGNORECASE),
    'authentication_token': re.compile(r'\s*\"Bearer\s*(?P<authentication_token>.*)\"\s*', re.IGNORECASE),
    'smartapp_definition': re.compile(r'\s*.*definition\s*\((?P<smartapp_definition>(.|\n)*)\s*\)\s*preferences(.|\n)*', re.IGNORECASE),
    'smartapp_preference': re.compile(r'\s*.*preferences\s*\{\s*(?P<smartapp_preference>(.|\n)*)\s*\}\s*def installed(.|\n)*', re.IGNORECASE),
    'app_input': re.compile(r'\s*input\s*(?P<app_input>.*)\s*', re.IGNORECASE),
    'device_type_lists': re.compile(r'\s*(?P<device_type_lists>@{DEVICE_TYPE_LISTS})\s*', re.IGNORECASE),
    'defined_condition_lists': re.compile(r'\s*(?P<defined_condition_lists>@{DEFINED_CONDITION_LISTS})\s*', re.IGNORECASE),
}



def os_cmd(cmd, q):
    os_out = os.system(cmd)
    q.put(os_out)


def check_file(file_name):
    if os.path.exists(file_name):
        return True
    else:
        print("The file, %s, does not exist!" % file_name)
        return False


def setup_args():
    arg_parser = argparse.ArgumentParser(description="PATRIOT - Policy Assisted Threat-Resilient Internet of Things")
    arg_parser.add_argument('target', choices=['st', 'oh', 'eva'])
    arg_parser.add_argument('task', choices=['analysis', 'instrument', 'createParent'])
    arg_parser.add_argument("policy", help="The input file containing user policies.", nargs='?')
    arg_parser.add_argument("app_folder", help="The folder path containing automation units.", nargs='?')
    arg_parser.add_argument("inst_app_folder",
                            help="The folder path containing instrumented version of automation units.",
                            nargs='?')
    args = arg_parser.parse_args()
    return args


def get_config():
    with open("conf/conf.yml", 'r') as ymlfile:
        return yaml.load(ymlfile, Loader=yaml.FullLoader)


def get_base64_auth_string(username, password):
    return base64.b64encode(('%s:%s' % (username, password)).encode()).decode()


def get_child_app_encoding(app_names):
    conf = get_config()
    encoded_string = "\n"
    for app in app_names:
        encoded_string += '\t\t\tapp(name: "ChildApp", appName: "' + app['app_name'] + '", namespace: "' + app['author_namespace'] + '", title: "'+app['app_name']+'", defaultValue: "' + app['app_name'] + '")\n'
    return encoded_string


def parse_line(line, regex_dict):
    for key, rx in regex_dict.items():
        match = rx.search(line)
        if match:
            return key, match
    return None, None

def create_policy_manager_1(file_name, inst_file_path, app_names, trigger_action_file):
    if check_file(file_name):
        conf = get_config()
        with open(file_name, 'r') as template_file:
            with open(os.path.join(inst_file_path, os.path.splitext(os.path.basename(file_name))[0] + ".groovy"), 'w+') as tmp_file:
                line = template_file.readline()
                while line:
                    key, match = parse_line(line, ST_REGEX_DICT)
                    if key == 'app_name':
                        tmp_file.write(line.replace(match.group('app_name'),
                                                    conf['smart_things']['policy_manager_appname']))
                    elif key == 'author_name':
                        tmp_file.write(line.replace(match.group('author_name'),
                                                    conf['smart_things']['author_name']))
                    elif key == 'author_namespace':
                        tmp_file.write(line.replace(match.group('author_namespace'),
                                                    conf['smart_things']['author_namespace']))
                    elif key == 'instrumented_smartapps_list_section':
                        tmp_file.write(line.replace(match.group('instrumented_smartapps_list_section'),
                                                    get_child_app_encoding(app_names)))
                    elif key == 'trigger_action_lists':
                        tmp_file.write(line.replace(match.group('trigger_action_lists'),
                                                    get_trigger_action_lists(app_names,trigger_action_file)))
                    elif key == 'authentication_token':
                        tmp_file.write(line.replace(match.group('authentication_token'),
                                                    conf['smart_things']['authentication_token']))
                    elif key == 'device_type_lists':
                        tmp_file.write(line.replace(match.group('device_type_lists'),
                                                    get_device_type_lists(conf['smart_things']['device_type_file'])))
                    elif key == 'defined_condition_lists':
                        tmp_file.write(line.replace(match.group('defined_condition_lists'),
                                                    get_defined_condition_lists(conf['smart_things']['condition_file'])))
                    
                    else:
                        tmp_file.write(line)
                    line = template_file.readline()

def create_policy_manager_2(file_name, inst_file_path, app_names, policies):
    if check_file(file_name):
        conf = get_config()
        with open(file_name, 'r') as template_file:
            with open(os.path.join(inst_file_path, os.path.splitext(os.path.basename(file_name))[0] + ".groovy"), 'w+') as tmp_file:
                line = template_file.readline()
                while line:
                    key, match = parse_line(line, ST_REGEX_DICT)
                    if key == 'app_name':
                        tmp_file.write(line.replace(match.group('app_name'),
                                                    conf['smart_things']['policy_manager_appname']))
                    elif key == 'author_name':
                        tmp_file.write(line.replace(match.group('author_name'),
                                                    conf['smart_things']['author_name']))
                    elif key == 'author_namespace':
                        tmp_file.write(line.replace(match.group('author_namespace'),
                                                    conf['smart_things']['author_namespace']))
                    elif key == 'instrumented_smartapps_list_section':
                        tmp_file.write(line.replace(match.group('instrumented_smartapps_list_section'),
                                                    get_child_app_encoding(app_names)))
                    elif key == 'initializing_policies_section':
                        tmp_file.write(line.replace(match.group('initializing_policies_section'),
                                                    get_st_encoded_policy_initialization(policies)))
                    elif key == 'encoded_policies_section':
                        tmp_file.write(line.replace(match.group('encoded_policies_section'),
                                                    get_st_encoded_policy_function(policies)))
                    elif key == 'policies_permission_section':
                        tmp_file.write(line.replace(match.group('policies_permission_section'),
                                                    get_st_encoded_policy_permission(policies)))
                    else:
                        tmp_file.write(line)
                    line = template_file.readline()
                    
def get_device_type_lists(device_type_list_file):
    typeList = '['
    with open(device_type_list_file,'r') as dfile:
        devtypes = dfile.readlines()
#         devtypes = csv.DictReader(dfile)
        for dev in devtypes:
            w = dev.replace('\n','')
            x = w.split(',')
            typeList += '"'+x[0]+'":"'+x[1]+'",\n\t\t'
        typeList = typeList[:-4] + ']'
    return typeList

def get_defined_condition_lists(defined_condition_file):
    with open(defined_condition_file,'r') as cfile:
        
        #conditions = json.load(cfile)
        conditions = cfile.readlines()
        output = ''
        for lines in conditions:
            output += '\t' + lines.replace('\'','"').replace('{','[').replace('}',']')
    return output
    
def get_trigger_action_lists(appName,trigger_action_file):
    file = open(trigger_action_file)
    triggerActions = json.load(file)
    ta_string = '['
    for apps in appName:
        app = apps['app_name'].lower().replace(' ','-').replace('\'','')
        ta_string += '\n\t\t"'.expandtabs(4)+ apps['app_name'] +'":['
        app_string = ''
        for rules in triggerActions[app]:
            if rules['action_device'] == 'app': 
                action_device = apps['app_name']
            else:
                action_device = rules['action_device']
            if rules['trigger_device'] == 'app':
                trigger_device = apps['app_name']
            else:
                trigger_device = rules['trigger_device']
            app_string += '\n\t\t\t["ruleID":"'.expandtabs(4)+rules['ruleID']+'", "action_cmd":"'+rules['action_cmd']+'","action_device":"'+action_device+'", "trigger_attr":"'+rules['trigger_attr']+'", "trigger_device":"'+trigger_device+'", "action_channel":"'+str(rules['action_channel'])+'","trgger_channel":"'+str(rules['trigger_channel'])+'"],'
        ta_string += app_string + '],'
    ta_string += ']'
    return ta_string
    
def preprocess_st_smartapps(source_path, destination_path, trigger_action_file): 
    apps = []
    for smartapp in os.listdir(source_path):
        if smartapp.endswith(".groovy"):
            source = ""
            with open(os.path.join(source_path, smartapp), 'r') as smartapp_file:
                source = smartapp_file.read()
            source += "\n\ndef getChildAppDevices() {\n\treturn settings\n}\n\n"
            match_def = ST_REGEX_DICT['smartapp_definition'].search(source)
            if match_def:
                app = {}
                definition = match_def.group('smartapp_definition')
                modified_def = ""
                for line in definition.splitlines():
                    key, line_match = parse_line(line, ST_REGEX_DICT)
                    if key == 'app_name':
                        app['app_name'] = line_match.group('app_name')
                        modified_def += line + '\n'
                    elif key == 'author_name':
                        app['author_name'] = line_match.group('author_name')
                        modified_def += line + '\n'
                    elif key == 'author_namespace':
                        app['author_namespace'] = line_match.group('author_namespace')
                        modified_def += line + '\n'
                    elif key == 'app_description':
                        app['app_description'] = line_match.group('app_description')
                        modified_def += '\tparent: "ruichenpolicy:PolicyManager",\n'.expandtabs(4)
                        modified_def += line + '\n'
                    else:
                        modified_def += line + '\n'
                apps.append(app)
                with open(os.path.join(destination_path, smartapp), 'w+') as prep_smartapp_file:
                    prep_smartapp_file.write(source.replace(definition, modified_def))
                    
                
                with open(os.path.join(destination_path, smartapp), 'r') as smartapp_file:
                    newSource = smartapp_file.read()
            match_pre = ST_REGEX_DICT['smartapp_preference'].search(newSource)
            if match_pre:
                preference = match_pre.group('smartapp_preference')
                page_preference = ''
                modified_pre = '\tpage(name:"SetupPage", install: true, uninstall: true)\n'.expandtabs(4)
                for line in preference.splitlines():
                    key, line_match = parse_line(line, ST_REGEX_DICT)
                    if key == 'app_input':
                        page_preference += '    ' + line + ', submitOnChange: true\n'
                    else:
                        page_preference += '    ' + line + '\n'
                        
                dynamic_page = 'def SetupPage() {\n\tdynamicPage(name:"SetupPage") {\n'.expandtabs(4)
                dynamic_page += '\t'.expandtabs(4) + page_preference
                dynamic_page += '\t\tsection("App Description:") {\n'.expandtabs(4)
                dynamic_page += '\t\t\tparagraph "'.expandtabs(4) + app['app_description'] + '"\n\t\t}\n'.expandtabs(4)
                dynamic_page += '\t\tsection("Single App Policy:") {\n'.expandtabs(4) 
                app_actions = findTriggerAction(app['app_name'],trigger_action_file)
                for app_action in app_actions:
                    dynamic_page += '\t\t\tparagraph title: "Action Found:",'.expandtabs(4) 
                    if app_action['action_device'] == 'app' : 
                        actionDev = '<${app.name}> '
                    elif app_action['action_device'] == app['app_name'].lower().replace(' ','-'):
                        actionDev = ''
                    else:
                        actionDev = '<${' + app_action['action_device'] + '}>'
                        
                    if app_action['trigger_device'] == 'app' : 
                        triggerDev = '<${app.name}>'
                    elif app_action['trigger_device'] == app['app_name'].lower().replace(' ','-'):
                        triggerDev = ''
                    else:
                        triggerDev = '<${' + app_action['trigger_device'] + '}>'
                    
                    dynamic_page += '"<${app.name}> will \\"' + app_action['action_cmd'] +'\\" ' + actionDev
                    dynamic_page += 'when ' + triggerDev + ' is \\"' + app_action['trigger_attr'] + '\\""\n'
                    dynamic_page += '\t\t\tinput(name: "'.expandtabs(4) + app_action['ruleID'] + '", type: "enum", title: "Accept/Deny?", options:["Accept" , "Deny"])\n'
                dynamic_page += '\t\t}\n\t}\n}\n'.expandtabs(4)
                newSource += dynamic_page
#                 print(source)
                with open(os.path.join(destination_path, smartapp), 'w+') as prep_smartapp_file:
                    prep_smartapp_file.write(newSource.replace(preference, modified_pre))
        else:
            continue
    return apps

def findTriggerAction(app, trigger_action_file):
    appName = app.lower().replace(' ','-')
    file = open(trigger_action_file)
    triggerActions = json.load(file)
    
    return triggerActions[appName]

def guard_smartapps_actions(source_path, destination_path, action_list_path, log_path):
    cmd = 'groovy testing/res/instrumentor.groovy ' + action_list_path + ' ' + source_path + ' ' + destination_path + ' ' + '> ' + log_path + ' 2>&1'
    res = queue.Queue()
    task1 = threading.Thread(target=os_cmd,
                             args=(cmd, res))
    task1.start()
    print('please wait... ')
    task1.join()

def get_st_encoded_policy_initialization(policies):
    decl_string = ""
    for policy in policies:
        decl_string += "\tdef " + str(policy.name) + " = [\n\t\t\tprv: " + str(policy.prv).lower() + ",\n"
        decl_string += "\t\t\tcur: " + str(policy.cur).lower() + ",\n"
        decl_string += "\t\t\ttss: " + str(policy.tss).replace('{', '[').replace('}', ']').replace("'", "").replace('None', 'null').replace('[]', '[:]') + ",\n"
        decl_string += "\t\t\tidx: " + str(policy.idx) + "\n\t]"
        decl_string += "\n"
    decl_string += "\tdef myPolicies = [:]\n"
    for policy in policies:
        decl_string += '\tmyPolicies.put("{}", {})\n'.format(policy.name, policy.name)
    decl_string += "\tatomicState.policies = myPolicies"
    return decl_string


def get_st_encoded_policy_permission(policies):
    argument = "(myDevices, automation_unit, evt, action_device, action_command, action_command_arg)"
    permission = "\t\tpermission =\n"
    for policy in policies:
        permission += "\t\t\t{}{} &&\n".format(policy.name, argument)
    return permission[:-3]


def get_st_encoded_policy_function(policies):
    device_type = {}
    cap_attribute = {}
    with open('testing/res/device_type.csv', 'r') as dfile:
        devs = dfile.readlines()
        for dev in devs:
            x = dev.split(',')
            device_type[x[0].strip()] = x[1].strip()
    with open('testing/res/cap_attribute.csv', 'r') as cfile:
        caps = cfile.readlines()
        for cap in caps:
            if ',' in cap:
                x = cap.strip().split(',')
                cap_attribute[x[0].strip()] = x[1].strip()

    signature = "(myDevices, automation_unit, evt, action_device, action_command, action_command_arg)"
    functions = ""
    for policy in policies:
        functions += "def {}{} {}\n".format(policy.name, signature, "{")
        functions += "\tdef current_time = (long) (now()/1000)\n"
        functions += "\tdef current_date = current_time\n"
        functions += "\tdef myPolicies = atomicState.policies\n"
        functions += '\tdef {} = myPolicies.get("{}")\n'.format(policy.name, policy.name)
        functions += '\t{}.put("idx", {}.get("idx") + 1)\n'.format(policy.name, policy.name)
        functions += '\tdef idx = {}.get("idx")\n'.format(policy.name)
        functions += '\tdef cur = {}.get("cur")\n'.format(policy.name)
        functions += '\tdef prv = {}.get("prv")\n'.format(policy.name)
        functions += '\tdef tss = {}.get("tss")\n'.format(policy.name)
        i = 0
        for subformula in policy.enc:
            functions += '\tcur[{}] = '.format(i)
            if subformula.type == 'attribute':
                if subformula.children[0] in ['automation_unit', 'current_time', 'current_date']:
                    functions += subformula.children[0] + ' '
                    functions += subformula.value.replace('=', '==') + ' '
                    value = ""
                    if subformula.children[1].type == 'number':
                        value = subformula.children[1].value
                    elif subformula.children[1].type == 'boolean':
                        value = subformula.children[1].value.lower()
                    elif subformula.children[1].type == 'string': # needed for date and time
                        value = '"{}"'.format(subformula.children[1].value)
                    elif subformula.children[1].type == 'time':
                        value = '((long) (timeToday("{}", location.timeZone).getTime()/1000))'.format(subformula.children[1].value)
                    elif subformula.children[1].type == 'date':
                        value = "((long) (Date.parse('MM-dd-yyyy', '{}').getTime()/1000))".format(subformula.children[1].value)
                    functions += value + '\n'
                else:
                    functions += "myDevices.get('{}').currentValue('{}') ".format(subformula.children[0].split('#')[1], cap_attribute[device_type[subformula.children[0].split('#')[1]]])
                    functions += subformula.value.replace('=', '==') + ' '
                    value = ""
                    if subformula.children[1].type == 'number':
                        value = subformula.children[1].value
                    elif subformula.children[1].type == 'boolean':
                        value = subformula.children[1].value.lower()
                    elif subformula.children[1].type == 'string':  # needed for date and time
                        value = '"{}"'.format(subformula.children[1].value)
                    elif subformula.children[1].type == 'time':
                        value = '((long) (timeToday("{}", location.timeZone).getTime()/1000))'.format(
                            subformula.children[1].value)
                    elif subformula.children[1].type == 'date':
                        value = "((long) (Date.parse('MM-dd-yyyy', '{}').getTime()/1000))".format(
                            subformula.children[1].value)
                    functions += value + '\n'
            elif subformula.type in ['not_prop', 'not_mtl']:
                functions += "!cur[{}]\n".format(i-1)
            elif subformula.type == 'everything':
                functions += "true\n"
            elif subformula.type in ['bexp_prop', 'bexp_prop_mlt', 'bexp_mlt_prop', 'bexp_mlt', 'bexp_act']:
                functions += "cur[{}] ".format(i - int(subformula.children[0]))
                functions += subformula.value.replace('and', '&&').replace('or', '||') + ' '
                functions += "cur[{}]\n".format(i - 1)
            elif subformula.type == 'mlt_lastly_interval':
                interval = subformula.value.split(':')
                functions += "lastly(cur[{}], prv[{}], tss, '{}', {}, {}, current_time, true)\n".format(i-1, i-1, i, interval[0], interval[1])
            elif subformula.type == 'mlt_lastly':
                functions += "lastly(cur[{}], prv[{}], tss, '{}', 0, 0, current_time, false)\n".format(i-1, i-1, i)
            elif subformula.type == 'mlt_once_interval':
                interval = subformula.value.split(':')
                functions += "once(cur[{}], tss, '{}', {}, {}, current_time, idx, true)\n".format(i-1, i, interval[0], interval[1])
            elif subformula.type == 'mlt_once':
                functions += "once(cur[{}], tss, '{}', 0, 0, current_time, idx, false)\n".format(i-1, i)
            elif subformula.type == 'mlt_since_interval':
                interval = subformula.value.split(':')
                functions += "since(cur[{}], cur[{}], tss, '{}', {}, {}, current_time, idx, true)\n".format(i - int(subformula.children[0]), i-1, i, interval[0], interval[1])
            elif subformula.type == 'mlt_since':
                functions += "since(cur[{}], cur[{}], tss, '{}', 0, 0, current_time, idx, false)\n".format(i - int(subformula.children[0]), i-1, i)
            elif subformula.type == 'action':
                functions += subformula.children[0] + ' '
                functions += subformula.value.replace('=', '==') + ' '
                functions += '"{}"\n'.format(subformula.children[1])
            elif subformula.type == 'action_arg':
                functions += subformula.children[0] + ' '
                functions += subformula.value.replace('=', '==') + ' '
                value = ""
                if subformula.children[1].type == 'number':
                    value = subformula.children[1].value
                elif subformula.children[1].type == 'boolean':
                    value = subformula.children[1].value.lower()
                elif subformula.children[1].type == 'string':  # needed for date and time
                    value = '"{}"'.format(subformula.children[1].value)
                elif subformula.children[1].type == 'time':
                    value = '((long) (timeToday("{}", location.timeZone).getTime()/1000))'.format(
                        subformula.children[1].value)
                elif subformula.children[1].type == 'date':
                    value = "((long) (Date.parse('MM-dd-yyyy', '{}').getTime()/1000))".format(
                        subformula.children[1].value)
                functions += value + '\n'
            elif subformula.type == 'implies':
                functions += "implies(cur[{}], cur[{}])\n".format(i - 1, i - int(subformula.children[0]))
            i += 1

        functions += '\tdef res = {}.get("cur")[{}]\n'.format(policy.name, i - 1)
        functions += '\t{}.put("prv", {}.get("cur"))\n'.format(policy.name, policy.name)
        functions += '\tatomicState.policies = myPolicies\n'
        functions += '\treturn res\n'
        functions += "}\n\n"
    return functions[:-2]

def parse_n_instrument(filepath, header, inst_file_path):
    with open(filepath, 'r') as file_object:
        with open(inst_file_path, 'w+') as tmp_file:
            tmp_file.write(header)
            line = file_object.readline()
            rule_name_stmt = ''
            triggered_event_device_stmt = ''
            triggered_event_stmt = ''
            while line:
                key, match = parse_line(line, OH_REGEX_DICT)
                if key == 'rule':
                    rule_name_stmt = "\tval automation_unit = '" + match.group('rule_name').lower() + "'\n"
                    tmp_file.write(line)
                elif key == 'trigger':
                    triggered_event_device_stmt = "\tval triggered_device = " + match.group('item_name') + "\n"
                    triggered_event_stmt = "\tval triggered_event = {}\n".format('null' if not match.group(
                        'cmd') else match.group('cmd').strip())
                    tmp_file.write(line)
                elif key == 'then':
                    tmp_file.write(line)
                    tmp_file.write(rule_name_stmt)
                    tmp_file.write(triggered_event_device_stmt)
                    tmp_file.write(triggered_event_stmt)
                elif key == 'action':
                    action_item = match.group('action_item')
                    action_cmd = match.group('action_cmd')
                    indent = line.split(action_item)
                    tmp_file.write(indent[0] + 'lock.lock()\n')
                    tmp_file.write(indent[0] + 'try {\n')
                    tmp_file.write(indent[
                                       0] + '\tif (verify.apply(policies, automation_unit, triggered_device, triggered_event, ' + action_item + ', ' + action_cmd + ')) {\n')
                    tmp_file.write('\t\t' + line)
                    tmp_file.write(indent[0] + '\t}\n')
                    tmp_file.write(indent[0] + '} finally{\n')
                    tmp_file.write(indent[0] + '\tlock.unlock()\n')
                    tmp_file.write(indent[0] + '}\n')
                else:
                    tmp_file.write(line)
                line = file_object.readline()

