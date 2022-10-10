from lib.PATRIOTVisitor import PATRIOTVisitor
from lib.PATRIOTParser import PATRIOTParser

import enum


class Policy:
    pass


class Permission(enum.Enum):
    DENY = 0
    ALLOW = 1


class AST_Node:
    def __init__(self):
        self.type = None
        self.value = None
        self.children = []

    def get_reverse_children(self):
        children = self.children[:]
        children.reverse()
        return children


class PolicyVisitor(PATRIOTVisitor):
    def __init__(self):
        self.policies = []

    def visitPolicy_statement(self, ctx: PATRIOTParser.Policy_statementContext):
        pol = ctx.body().accept(self)
        pol.name = ctx.STRING().getText().lower()
        self.policies.append(pol)

    def visitBody(self, ctx:PATRIOTParser.BodyContext):
        permission = ctx.permission_clause().accept(self)
        condition = Policy()
        if ctx.getChildCount() > 4:
            condition = ctx.getChild(4).accept(self)
        else:
            condition.prv = [False]
            condition.cur = [False]
            condition.tss = {}
            condition.idx = -1
            true_node = AST_Node()
            true_node.type = 'everything'
            true_node.value = 'true'
            condition.enc = [true_node]
        except_cond = None
        if ctx.EXCEPT():
            if ctx.getChildCount() == 7:
                except_cond = ctx.getChild(6).accept(self)
            else:
                except_cond = ctx.getChild(3).accept(self)
            except_cond.prv.append(False)
            except_cond.cur.append(False)
            not_node = AST_Node()
            not_node.type = 'not_prop'
            not_node.value = 'not'
            except_cond.enc.append(not_node)

            for key in except_cond.tss.keys():
                condition.tss[(key + len(condition.prv))] = except_cond.tss[key]
            condition.prv.extend(except_cond.prv)
            condition.prv.append(False)
            condition.cur.extend(except_cond.cur)
            condition.cur.append(False)
            condition.enc.extend(except_cond.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_prop'
            bexp_node.value = 'and'
            bexp_node.children.append(len(except_cond.enc) + 1)  # index from last
            condition.enc.append(bexp_node)
        if permission == Permission.DENY:
            condition.prv.append(False)
            condition.cur.append(False)
            not_node = AST_Node()
            not_node.type = 'not_prop'
            not_node.value = 'not'
            condition.enc.append(not_node)
        target = ctx.target_clause().accept(self)
        condition.prv.extend(target.prv)
        condition.prv.append(False)
        condition.cur.extend(target.cur)
        condition.cur.append(False)
        condition.enc.extend(target.enc)
        bexp_node = AST_Node()
        bexp_node.type = 'implies'
        bexp_node.value = 'implies'
        bexp_node.children.append(len(target.enc) + 1)  # index from last
        condition.enc.append(bexp_node)
        return condition

    def visitPermission_clause(self, ctx:PATRIOTParser.Permission_clauseContext):
        if ctx.ALLOW():
            return Permission.ALLOW
        else:
            return Permission.DENY

    def visitTarget_clause(self, ctx: PATRIOTParser.Target_clauseContext):
        if ctx.EVERYTHING():
            p = Policy()
            p.prv = [False]
            p.cur = [False]
            p.tss = {}
            p.idx = -1
            everything_node = AST_Node()
            everything_node.type = 'everything'
            everything_node.value = 'true'
            p.enc = [everything_node]
            return p
        else:
            return ctx.action_clause().accept(self)

    def visitAction_clause(self, ctx:PATRIOTParser.Action_clauseContext):
        if ctx.ACTION_COMMAND() or ctx.ACTION_DEVICE():
            p = Policy()
            p.prv = [False]
            p.cur = [False]
            p.tss = {}
            p.idx = -1
            action_node = AST_Node()
            action_node.type = 'action'
            action_node.value = ctx.operator().getText()
            action_node.children.append(ctx.getChild(0).getText())
            action_node.children.append(ctx.getChild(2).getText())
            p.enc = [action_node]
            return p
        elif ctx.ACTION_COMMAND_ARG():
            p = Policy()
            p.prv = [False]
            p.cur = [False]
            p.tss = {}
            p.idx = -1
            action_node = AST_Node()
            action_node.type = 'action_arg'
            action_node.value = ctx.operator().getText()
            action_node.children.append(ctx.getChild(0).getText())
            action_node.children.append(ctx.value().accept(self))
            p.enc = [action_node]
            return p
        else:
            lhs = ctx.getChild(0).accept(self)
            rhs = ctx.getChild(2).accept(self)
            for key in rhs.tss.keys():
                lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
            lhs.prv.extend(rhs.prv)
            lhs.prv.append(False)
            lhs.cur.extend(rhs.cur)
            lhs.cur.append(False)
            lhs.enc.extend(rhs.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_act'
            bexp_node.value = ctx.boolean_operator().getText().lower()
            bexp_node.children.append(len(rhs.enc) + 1)  # index from last
            lhs.enc.append(bexp_node)
            return lhs

    def visitPropositional_clause(self, ctx:PATRIOTParser.Propositional_clauseContext):
        if ctx.attribute():
            p = Policy()
            p.prv = [False]
            p.cur = [False]
            p.tss = {}
            p.idx = -1
            attribute_node = AST_Node()
            attribute_node.type = 'attribute'
            attribute_node.value = ctx.operator().getText()
            name = ctx.attribute().accept(self)
            attribute_node.children.append(name)
            value = ctx.value().accept(self)
            attribute_node.children.append(value)
            p.enc =[attribute_node]
            return p
        if ctx.NOT():
            p = ctx.getChild(1).accept(self)
            p.prv.append(False)
            p.cur.append(False)
            not_node = AST_Node()
            not_node.type = 'not_prop'
            not_node.value = 'not'
            p.enc.append(not_node)
            return p
        else:
            lhs = ctx.getChild(0).accept(self)
            rhs = ctx.getChild(2).accept(self)
            for key in rhs.tss.keys():
                lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
            lhs.prv.extend(rhs.prv)
            lhs.prv.append(False)
            lhs.cur.extend(rhs.cur)
            lhs.cur.append(False)
            lhs.enc.extend(rhs.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_prop'
            bexp_node.value = ctx.boolean_operator().getText().lower()
            bexp_node.children.append(len(rhs.enc)+1) # index from last
            lhs.enc.append(bexp_node)
            return lhs

    def visitCondition_clause(self, ctx: PATRIOTParser.Condition_clauseContext):
        if (ctx.getChildCount() > 2) and type(ctx.getChild(0)).__name__ == "Propositional_clauseContext":
            lhs = ctx.getChild(0).accept(self)
            rhs = ctx.getChild(2).accept(self)
            for key in rhs.tss.keys():
                lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
            lhs.prv.extend(rhs.prv)
            lhs.prv.append(False)
            lhs.cur.extend(rhs.cur)
            lhs.cur.append(False)
            lhs.enc.extend(rhs.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_prop_mlt'
            bexp_node.value = ctx.boolean_operator().getText().lower()
            bexp_node.children.append(len(rhs.enc) + 1)  # index from last
            lhs.enc.append(bexp_node)
            return lhs
        elif (ctx.getChildCount() > 2) and type(ctx.getChild(0)).__name__ == "Mtl_clauseContext":
            lhs = ctx.getChild(0).accept(self)
            rhs = ctx.getChild(2).accept(self)
            for key in rhs.tss.keys():
                lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
            lhs.prv.extend(rhs.prv)
            lhs.prv.append(False)
            lhs.cur.extend(rhs.cur)
            lhs.cur.append(False)
            lhs.enc.extend(rhs.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_mlt_prop'
            bexp_node.value = ctx.boolean_operator().getText().lower()
            bexp_node.children.append(len(rhs.enc) + 1)  # index from last
            lhs.enc.append(bexp_node)
            return lhs
        else:
            return ctx.getChild(0).accept(self)

    def visitMtl_clause(self, ctx: PATRIOTParser.Mtl_clauseContext):
        if ctx.NOT():
            p = ctx.getChild(1).accept(self)
            p.prv.append(False)
            p.cur.append(False)
            not_node = AST_Node()
            not_node.type = 'not_mlt'
            not_node.value = 'not'
            p.enc.append(not_node)
            return p
        elif ctx.boolean_operator():
            lhs = ctx.getChild(0).accept(self)
            rhs = ctx.getChild(2).accept(self)
            for key in rhs.tss.keys():
                lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
            lhs.prv.extend(rhs.prv)
            lhs.prv.append(False)
            lhs.cur.extend(rhs.cur)
            lhs.cur.append(False)
            lhs.enc.extend(rhs.enc)
            bexp_node = AST_Node()
            bexp_node.type = 'bexp_mlt'
            bexp_node.value = ctx.boolean_operator().getText().lower()
            bexp_node.children.append(len(rhs.enc) + 1)  # index from last
            lhs.enc.append(bexp_node)
            return lhs
        else:
            return ctx.getChild(0).accept(self)

    def visitSince_clause(self, ctx: PATRIOTParser.Since_clauseContext):
        lhs = ctx.getChild(2).accept(self)
        rhs = ctx.getChild(4).accept(self)
        for key in rhs.tss.keys():
            lhs.tss[(key + len(lhs.prv))] = rhs.tss[key]
        lhs.prv.extend(rhs.prv)
        lhs.prv.append(False)
        lhs.cur.extend(rhs.cur)
        lhs.cur.append(False)
        lhs.tss[(len(lhs.prv)-1)] = {'q': {'i': None, 'tau': None}, 'p': None}
        lhs.enc.extend(rhs.enc)
        since_node = AST_Node()
        if ctx.WITHIN():
            since_node.type = 'mlt_since_interval'
            since_node.value = '{}:{}'.format(ctx.getChild(8).getText(), ctx.getChild(10).getText())
        else:
            since_node.type = 'mlt_since'
        since_node.children.append(len(rhs.enc) + 1)  # index from last
        lhs.enc.append(since_node)
        return lhs

    def visitOnce_clause(self, ctx: PATRIOTParser.Once_clauseContext):
        p = ctx.getChild(2).accept(self)
        p.tss[len(p.prv)] = {'q': {'i': None, 'tau': None}, 'p': None}
        p.prv.append(False)
        p.cur.append(False)
        once_node = AST_Node()
        if ctx.WITHIN():
            once_node.type = 'mlt_once_interval'
            once_node.value = '{}:{}'.format(ctx.getChild(6).getText(), ctx.getChild(8).getText())
        else:
            once_node.type = 'mlt_once'
        p.enc.append(once_node)
        return p

    def visitLastly_clause(self, ctx: PATRIOTParser.Lastly_clauseContext):
        p = ctx.getChild(2).accept(self)
        p.tss[len(p.prv)] = {'tau': None}
        p.prv.append(False)
        p.cur.append(False)
        lastly_node = AST_Node()
        if ctx.WITHIN():
            lastly_node.type = 'mlt_lastly_interval'
            lastly_node.value = '{}:{}'.format(ctx.getChild(6).getText(), ctx.getChild(8).getText())
        else:
            lastly_node.type = 'mlt_lastly'
        p.enc.append(lastly_node)
        return p

    def visitAttribute(self, ctx: PATRIOTParser.AttributeContext):
        if ctx.device_state() or ctx.device_value() or ctx.date_time_key():
            return ctx.getChild(0).accept(self)
        else:
            return ctx.getChild(0).getText()

    def visitDevice_state(self, ctx: PATRIOTParser.Device_stateContext):
        return 'state#{}'.format(ctx.getChild(2).getText())

    def visitDevice_value(self, ctx: PATRIOTParser.Device_valueContext):
        return 'value#{}'.format(ctx.getChild(2).getText())

    def visitDate_time_key(self, ctx:PATRIOTParser.Date_time_keyContext):
        return ctx.getChild(0).getText()

    def visitValue(self, ctx: PATRIOTParser.ValueContext):
        value_node = AST_Node()
        if ctx.NUMBER():
            value_node.type = 'number'
            value_node.value = ctx.getText()
        elif ctx.BOOLEAN():
            value_node.type = 'boolean'
            value_node.value = ctx.getText().lower()
        elif ctx.TIME():
            value_node.type = 'time'
            value_node.value = ctx.getText()
        elif ctx.DATE():
            value_node.type = 'date'
            value_node.value = ctx.getText()
        else:
            value_node.type = 'string'
            value_node.value = ctx.getText()
        return value_node