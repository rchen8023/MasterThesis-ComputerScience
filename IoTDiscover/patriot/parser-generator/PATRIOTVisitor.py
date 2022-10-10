# Generated from PATRIOT.g4 by ANTLR 4.7.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .PATRIOTParser import PATRIOTParser
else:
    from PATRIOTParser import PATRIOTParser

# This class defines a complete generic visitor for a parse tree produced by PATRIOTParser.

class PATRIOTVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by PATRIOTParser#policy_language.
    def visitPolicy_language(self, ctx:PATRIOTParser.Policy_languageContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#policy_statement.
    def visitPolicy_statement(self, ctx:PATRIOTParser.Policy_statementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#body.
    def visitBody(self, ctx:PATRIOTParser.BodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#permission_clause.
    def visitPermission_clause(self, ctx:PATRIOTParser.Permission_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#target_clause.
    def visitTarget_clause(self, ctx:PATRIOTParser.Target_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#action_clause.
    def visitAction_clause(self, ctx:PATRIOTParser.Action_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#condition_clause.
    def visitCondition_clause(self, ctx:PATRIOTParser.Condition_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#propositional_clause.
    def visitPropositional_clause(self, ctx:PATRIOTParser.Propositional_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#mtl_clause.
    def visitMtl_clause(self, ctx:PATRIOTParser.Mtl_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#since_clause.
    def visitSince_clause(self, ctx:PATRIOTParser.Since_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#once_clause.
    def visitOnce_clause(self, ctx:PATRIOTParser.Once_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#lastly_clause.
    def visitLastly_clause(self, ctx:PATRIOTParser.Lastly_clauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#boolean_operator.
    def visitBoolean_operator(self, ctx:PATRIOTParser.Boolean_operatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#attribute.
    def visitAttribute(self, ctx:PATRIOTParser.AttributeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#device_state.
    def visitDevice_state(self, ctx:PATRIOTParser.Device_stateContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#device_value.
    def visitDevice_value(self, ctx:PATRIOTParser.Device_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#date_time_key.
    def visitDate_time_key(self, ctx:PATRIOTParser.Date_time_keyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#operator.
    def visitOperator(self, ctx:PATRIOTParser.OperatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by PATRIOTParser#value.
    def visitValue(self, ctx:PATRIOTParser.ValueContext):
        return self.visitChildren(ctx)



del PATRIOTParser