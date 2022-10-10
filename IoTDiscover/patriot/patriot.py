from lib.util import *
import sys
import traceback

from antlr4 import *
from lib.PATRIOTLexer import PATRIOTLexer
from lib.policy import *
from lib.z3_policy_analysis import analyze_policies


class Patriot:
    app_names = []
    def __init__(self):
        args = setup_args()
        if check_file(args.policy):
            getattr(self, args.target)(args)

    def st(self, args):
        tree, err = self.get_parse_tree(args.policy)
        if err == 0:
            visitor = PolicyVisitor()
            try:
                tree.accept(visitor)
            except Exception as e:
                print(e)
                print("\nSyntax error occurred in the policy file!\n")
                sys.exit(1)
            policies = visitor.policies
            if args.task == 'analysis':
                try:
                    self.policy_analysis(policies)
                except Exception as e:
                    print("\nAn error occurred in analyzing the policies!\n")
                    sys.exit(1)
                print('Analysis done!')
            elif args.task == 'instrument':
                try:
                    self.instrument_smartapps(args.app_folder, args.inst_app_folder)
                except Exception as e:
                    print(e)
                    #traceback.print_exc()
                    print("\nAn error occurred in instrumenting the apps!\n")
                    sys.exit(1)
                print('Instrumentation done!')
            else:
                try:
                    self.create_second_Parent(policies, args.app_folder, args.inst_app_folder)
                except Exception as e:
                    print(e)
                    #traceback.print_exc()
                    print("\nAn error occurred in instrumenting the apps!\n")
                    sys.exit(1)
                print('Instrumentation done!')


    def get_parse_tree(self, file_name):
        pol_src_code = FileStream(file_name)
        lexer = PATRIOTLexer(pol_src_code)
        stream = CommonTokenStream(lexer)
        parser = PATRIOTParser(stream)
        tree = parser.policy_language()
        return tree, parser.getNumberOfSyntaxErrors()

    def policy_analysis(self, policies):
        analyze_policies(policies)

    def instrument_smartapps(self, app_folder, inst_app_folder):
        conf = get_config()
        guard_smartapps_actions(app_folder,
                                conf['smart_things']['preprocessed_smartapps_folder'],
                                conf['smart_things']['actions_list'],
                                conf['smart_things']['instrumentation_log_path'])
        app_names = preprocess_st_smartapps( conf['smart_things']['preprocessed_smartapps_folder'],inst_app_folder,
                                            conf['smart_things']['trigger_actions'])
                                            
        create_policy_manager_1(conf['smart_things']['policy_manager_template_file_path_1'],
                                 inst_app_folder,
                                 app_names, conf['smart_things']['trigger_actions'])
        
        #guard_smartapps_actions(conf['smart_things']['preprocessed_smartapps_folder'],
        

    
    def create_second_Parent(self, policies, app_folder, inst_app_folder):
        conf = get_config()
        app_names = preprocess_st_smartapps(app_folder, conf['smart_things']['preprocessed_smartapps_folder'],
                                            conf['smart_things']['trigger_actions'])
        create_policy_manager_2(conf['smart_things']['policy_manager_template_file_path_2'],
                                 inst_app_folder,
                                 app_names,
                                 policies)
if __name__ == '__main__':
    Patriot()
