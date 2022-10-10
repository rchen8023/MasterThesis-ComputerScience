#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 15 15:31:47 2019

@author: rsambouncer
"""


import z3
import datetime #conversion of dates to ints
import time     #to time how long it takes z3 to run


def createEnum(EnumName, function_name, list_of_enums):
    createdEnum = z3.Datatype(EnumName)
    for a in list_of_enums:
        createdEnum.declare(a)
    createdEnum = createdEnum.create()
    createdFunction = z3.Function(function_name, z3.IntSort(), createdEnum)
    return (createdEnum, createdFunction)

timegradation = 10 
#maximum times per second states can exist
def timeToInt(timestr):
    hours = int(timestr[0:2])
    minutes = int(timestr[3:5])
    seconds = int(timestr[6:8])
    return timegradation*(seconds+60*(minutes+60*hours))
    #in gradations*seconds since midnight
    
def dateToInt(datestr):
    month = int(datestr[0:2])
    day = int(datestr[3:5])
    year = int(datestr[6:10])
    return datetime.date(year,month,day).toordinal()

stringToIntStrings = []
def stringToInt(myString):
    if myString in stringToIntStrings:
        return stringToIntStrings.index(myString)
    else:
        stringToIntStrings.append(myString)
        return len(stringToIntStrings)-1

def boolStringToInt(boolStr):
    return 1 if boolStr=='true' else 0

def getValueType(string):
    return {
        "number":ValueType.int, 
        "string":ValueType.str, 
        "time":ValueType.time,
        "date":ValueType.date, 
        "boolean":ValueType.bool
    }.get(string)
    
def getValueConvert(stringtype, stringval):
    return {
        "number":int,
        "time":timeToInt,
        "date":dateToInt,
        "string":stringToInt,
        "boolean":boolStringToInt
    }.get(stringtype)(stringval)
    
def formulaWithOp(thing1, op, thing2):
    if op == '=':
        return thing1 == thing2
    elif op == '!=':
        return thing1 != thing2
    elif op == '>':
        return thing1 > thing2
    elif op == '<':
        return thing1 < thing2
    elif op == '>=':
        return thing1 >= thing2
    elif op == '<=':
        return thing1 <= thing2
    else:
        print("Unknown operator: "+str(op))
        return False


action_device  = z3.Function("action_device", z3.IntSort(), z3.StringSort())
action_command = z3.Function("action_command",z3.IntSort(), z3.StringSort())
(ValueType, action_wca) = \
    createEnum("ValueType","action_wca",["int","str","time","date","bool","null"])
action_vca = z3.Function("action_vca", z3.IntSort(), z3.IntSort())

automation_unit = z3.Function("automation_unit", z3.IntSort(), z3.StringSort())
current_time = z3.Int("current_time")
current_date = z3.Int("current_date")
attribute_type = z3.Function("attribute_type", z3.IntSort(), z3.StringSort(), ValueType)
attribute_value = z3.Function("attribute_value", z3.IntSort(), z3.StringSort(), z3.IntSort())

isState = z3.Function("isState",z3.IntSort(), z3.BoolSort())

def max_time(policies):
    return max([construct_time(
            p.enc,
            len(p.enc)-1-p.enc[len(p.enc)-1].children[0]
            ) for p in policies])

def construct_time(tree,ind):
    if tree[ind].type in ("mlt_once_interval", "mlt_since_interval", "mlt_lastly_interval"):
        b1 = int(tree[ind].value.split(':')[0])*timegradation
        b2 = int(tree[ind].value.split(':')[1])*timegradation
        if b1>b2:
            b3 = b1; b1 = b2; b2 = b3; #so b1<=b2
        if tree[ind].type == "mlt_since_interval":
            c1 = ind-1
            c2 = ind-tree[ind].children[0]
            return b2+max(construct_time(tree,c1), construct_time(tree,c2))
        else:
            return b2+construct_time(tree,ind-1)
    elif tree[ind].type.startswith("not_"):
        return construct_time(tree,ind-1)
    elif tree[ind].type.startswith("bexp_"):
        c1 = ind-1
        c2 = ind-tree[ind].children[0]
        return max(construct_time(tree,c1), construct_time(tree,c2))
    else: 
        return 0
    


def construct_policy(tree, tt, ttn, ad0, ac0, awca0, avca0):
    aInd = len(tree)-2
    cInd = len(tree)-1-tree[len(tree)-1].children[0]
    return z3.Implies(
        construct_action(tree, aInd, ad0, ac0, awca0, avca0), 
        construct_condition(tree, cInd, tt, ttn)
    )
    #true is allow, false is deny
    
def construct_action(tree, ind, ad0, ac0, awca0, avca0):
    if tree[ind].type == "action":
        op = tree[ind].value
        nodeval = z3.StringVal(tree[ind].children[1])
        if tree[ind].children[0] == 'action_device':
            return formulaWithOp(ad0, op, nodeval) #ex: action_device != door1
        elif tree[ind].children[0] == 'action_command': 
            return formulaWithOp(ac0, op, nodeval) #ex: action_command != open
    elif tree[ind].type == "action_arg":
        op = tree[ind].value
        node = tree[ind].children[1]
        nodetype = getValueType(node.type)
        nodeval = getValueConvert(node.type,node.value)
        if op == '!=':
            return z3.Not(z3.And(awca0 == nodetype, avca0 == nodeval))
            #we want a != b to be equivalent to Not(a == b)
            #meaning that a != b is true if a and b are different types
        else:
            return z3.And(awca0 == nodetype, formulaWithOp(avca0, op, nodeval))
    elif tree[ind].type == "bexp_act":
        c1 = ind-1
        c2 = ind-tree[ind].children[0]
        bexp = z3.And if tree[ind].value == 'and' else z3.Or
        return bexp(
                construct_action(tree, c1, ad0, ac0, awca0, avca0),
                construct_action(tree, c2, ad0, ac0, awca0, avca0)
        )
    elif tree[ind].type == "everything":
        if tree[ind].value == 'true':
            return True
    
    print("Unknown node in action: " + str(ind) +" "+
          str(tree[ind].type)+" "+str(tree[ind].value)+" "+str(tree[ind].children)
    )
    return False

def construct_condition(tree, ind, tt,ttn):
    if tree[ind].type == "attribute" and tree[ind].children[0] == "automation_unit":
        if tree[ind].value == '=':
            return automation_unit(tt) == z3.StringVal(tree[ind].children[1].value)
        elif tree[ind].value == '!=':
            return z3.Not(automation_unit(tt) == z3.StringVal(tree[ind].children[1].value))
    elif tree[ind].type == "attribute" and \
         tree[ind].children[0] in ("current_time","current_date"):
        op = tree[ind].value
        if tree[ind].children[0] == "current_time":
            nodeval = timeToInt(tree[ind].children[1].value) 
            curval = ((current_time-tt) % (86400*timegradation)) 
        else:
            nodeval = dateToInt(tree[ind].children[1].value)
            curval = current_date + ((current_time-tt) / (86400*timegradation))
        return formulaWithOp(curval, op, nodeval)
    elif tree[ind].type == "attribute":
        op = tree[ind].value
        node = tree[ind].children[1] 
        name = z3.StringVal(tree[ind].children[0])
        funType = attribute_type(tt,name)
        funValue = attribute_value(tt,name)
        nodevalue = getValueConvert(node.type,tree[ind].children[1].value)
        nodetype = getValueType(node.type)
        if tree[ind].value == '!=':
            return z3.Not(z3.And(funType == nodetype, funValue == nodevalue))
        else:
            return z3.And(funType == nodetype, formulaWithOp(funValue, op, nodevalue))
        
    elif tree[ind].type in ("mlt_once_interval", "mlt_since_interval", "mlt_lastly_interval"):
        ttn1 = ttn[0]+str(int(ttn[1:])+1)
        tt1 = z3.Int(ttn1)
        b1 = int(tree[ind].value.split(':')[0])*timegradation
        b2 = int(tree[ind].value.split(':')[1])*timegradation
        if b1>b2:
            b3 = b1; b1 = b2; b2 = b3; #so b1<=b2
        
        if tree[ind].type == "mlt_once_interval":
            extracondition = True
        else:
            ttn2 = ttn[0]+str(int(ttn[1:])+2)
            tt2 = z3.Int(ttn2)
            if tree[ind].type == "mlt_since_interval":
                c2 = ind-tree[ind].children[0]
                extracondition = z3.ForAll(tt2, z3.Implies(
                    z3.And(isState(tt2), tt2>=tt, tt2<tt1),
                    construct_condition(tree, c2, tt2, ttn2)
                ))
            if tree[ind].type == "mlt_lastly_interval":
                extracondition = z3.And(tt1 > tt, z3.ForAll(tt2, z3.Implies(
                    z3.And(tt2>tt, tt2<tt1),
                    z3.Not(isState(tt2))
                )))
        return z3.Exists(tt1,z3.And(
            isState(tt1), tt1>=tt+b1, tt1<=tt+b2, 
            construct_condition(tree,ind-1,tt1,ttn1),
            extracondition
        ))

    elif tree[ind].type.startswith("not_"):
        return z3.Not(construct_condition(tree, ind-1, tt,ttn))
    elif tree[ind].type.startswith("bexp_"):
        c1 = ind-1
        c2 = ind-tree[ind].children[0]
        bexp = z3.And if tree[ind].value == 'and' else z3.Or
        return bexp(
            construct_condition(tree, c1, tt,ttn),
            construct_condition(tree, c2, tt,ttn)
        )
    elif tree[ind].type == "everything":
        if tree[ind].value == 'true':
            return True
    
    print("Unknown node in condition: " +str(ind) +" "+ 
          str(tree[ind].type)+" "+str(tree[ind].value)+" "+str(tree[ind].children)
    )
    return False



def analyze_policies(policies):    
    s = z3.Solver()
    booleanCores = z3.BoolVector("booleanCore",len(policies))
    #true means that policy is disabled
    #false means that the policy is enabled
    s.add(isState(0)) #current time is a state
    t0 = z3.Int('t0')
    s.add(z3.ForAll(t0, z3.Implies(t0 > max_time(policies), z3.Not(isState(t0)))))
    #time is bounded: proof comes from fact that a valid, stuck trace can be generated
    #from any stuck trace
    s.add(current_time >= 0)
    s.add(current_time < 86400*timegradation) #current_time represents the time at t=0
    s.add(current_date > (datetime.datetime.now().toordinal()-365*10))
    s.add(current_date < (datetime.datetime.now().toordinal()+365*100))
    #assume the system runs sometime in the next 100 years
    

    s.add(z3.ForAll(t0, z3.Implies(
        z3.And(t0 > 0, isState(t0)), 
        z3.And([
            z3.Implies(z3.Not(booleanCores[p]), construct_policy(
                policies[p].enc,
                t0,'t0', 
                action_device(t0), 
                action_command(t0), 
                action_wca(t0),
                action_vca(t0)
            )) for p in range(len(policies))
        ])
    )))
    
    ad0 = z3.String('ad0')
    ac0 = z3.String('ac0')
    awca0 = z3.Const('awca0', ValueType)
    avca0 = z3.Int('avca0')
    s.add(t0 == 0) #t0 is different t0 than the loop variable
    s.add(z3.Not(z3.Exists([ad0,ac0,awca0,avca0], z3.And(
        z3.Or( 
            awca0 == ValueType.int, 
            awca0 == ValueType.str,
            z3.And(awca0 == ValueType.time, avca0 >= 0, avca0 < 86400*timegradation),
            #time is in milliseconds
            z3.And(awca0 == ValueType.date, avca0 >= 0),
            #date is in days since year 1. Assume dates < 01_01_0001 are invalid
            z3.And(awca0 == ValueType.bool, z3.Or(avca0 == 0, avca0 == 1)),
            #boolean is 0 or 1
            z3.And(awca0 == ValueType.null, avca0 == 0)
            #no argument provided
        ),
        z3.And([
            z3.Implies(z3.Not(booleanCores[p]), construct_policy(
                policies[p].enc,
                t0,'t0',
                ad0,
                ac0,
                awca0,
                avca0
            )) for p in range(len(policies))
        ])
    ))))
    
    s.check(booleanCores) 
    #always unsat, because this is equivalent to having no policies
    resultCore = s.unsat_core()  
    s.add([z3.Not(b) for b in booleanCores])       
    print("Finding model (this might take a while)...")
    t = time.time()
    r = str(s.check())
    if r=="sat":
        if(len(resultCore)>0):
            print("Warning: system may get stuck.")
        else:
            print("Warning: the combination of the following policies may cause the system to get stuck:")
            print([policies[booleanCores.index(rc)].name for rc in resultCore])
        #print("Stuck model:")
        #print(s.model())
    else:
        print("Passed! System can not get stuck.")
    print("Time taken: "+str(time.time()-t))
        
        