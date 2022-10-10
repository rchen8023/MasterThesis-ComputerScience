grammar PATRIOT;

policy_language: (policy_statement)+ EOF;

policy_statement: POLICY STRING COLON body;

body: permission_clause target_clause
    | permission_clause target_clause EXCEPT condition_clause
    | permission_clause target_clause ONLY IF condition_clause
    | permission_clause target_clause ONLY IF condition_clause EXCEPT condition_clause;

permission_clause: ALLOW
			     | DENY;

target_clause: EVERYTHING
		     | action_clause;

action_clause: ACTION_COMMAND operator STRING
             | ACTION_DEVICE operator STRING
             | ACTION_COMMAND_ARG operator value
             | action_clause boolean_operator action_clause;

condition_clause: propositional_clause boolean_operator mtl_clause
                | mtl_clause boolean_operator propositional_clause
                | mtl_clause
                | propositional_clause;

propositional_clause: attribute operator value
				    | NOT propositional_clause
				    | propositional_clause boolean_operator propositional_clause;

mtl_clause: since_clause
          | once_clause
          | lastly_clause
          | NOT mtl_clause
          | mtl_clause boolean_operator mtl_clause;

since_clause: SINCE LPARAN condition_clause COMMA condition_clause RPARAN WITHIN LBRACKET NUMBER COMMA NUMBER RBRACKET
            | SINCE LPARAN condition_clause COMMA condition_clause RPARAN;

once_clause: ONCE LPARAN condition_clause RPARAN WITHIN LBRACKET NUMBER COMMA NUMBER RBRACKET
           | ONCE LPARAN condition_clause RPARAN;

lastly_clause: LASTLY LPARAN condition_clause RPARAN WITHIN LBRACKET NUMBER COMMA NUMBER RBRACKET
             | LASTLY LPARAN condition_clause RPARAN;

boolean_operator: AND 
				| OR;

attribute: AUTOMATION_UNIT
         | device_state
         | device_value
		 | date_time_key;

device_state: STATE LPARAN STRING RPARAN;

device_value: KVALUE LPARAN STRING RPARAN;

date_time_key: CURRENT_TIME
			 | CURRENT_DATE;

operator: EQ 
		| NEQ
		| GT
		| GTE
		| LT
		| LTE;

value: TIME
	 | DATE
	 | NUMBER
	 | BOOLEAN
	 | STRING;


fragment A:('a'|'A');
fragment B:('b'|'B');
fragment C:('c'|'C');
fragment D:('d'|'D');
fragment E:('e'|'E');
fragment F:('f'|'F');
fragment G:('g'|'G');
fragment H:('h'|'H');
fragment I:('i'|'I');
fragment J:('j'|'J');
fragment K:('k'|'K');
fragment L:('l'|'L');
fragment M:('m'|'M');
fragment N:('n'|'N');
fragment O:('o'|'O');
fragment P:('p'|'P');
fragment Q:('q'|'Q');
fragment R:('r'|'R');
fragment S:('s'|'S');
fragment T:('t'|'T');
fragment U:('u'|'U');
fragment V:('v'|'V');
fragment W:('w'|'W');
fragment X:('x'|'X');
fragment Y:('y'|'Y');
fragment Z:('z'|'Z');

POLICY: P O L I C Y;
ALLOW: A L L O W;
DENY: D E N Y;
ONLY: O N L Y;
IF: I F;
EVERYTHING: E V E R Y T H I N G;
NOT: N O T;
AND: A N D;
OR: O R;
SINCE: S I N C E;
ONCE: O N C E;
LASTLY: L A S T L Y;
WITHIN: W I T H I N;
EXCEPT: E X C E P T;

BOOLEAN: T R U E
	   | F A L S E;


STATE: 'state';
KVALUE: 'value';
AUTOMATION_UNIT: 'automation_unit';
CURRENT_TIME: 'current_time';
CURRENT_DATE: 'current_date';
ACTION_COMMAND: 'action_command';
ACTION_DEVICE: 'action_device';
ACTION_COMMAND_ARG: 'action_command_arg';


EQ: '=';
NEQ: '!=';
GT: '>';
GTE: '>=';
LT: '<';
LTE: '<=';

COLON: ':';
LPARAN: '(';
RPARAN: ')';
LBRACKET: '[';
RBRACKET: ']';
COMMA: ',';
FSLASH: '/';

TIME: DIGIT DIGIT COLON DIGIT DIGIT COLON DIGIT DIGIT;
DATE: DIGIT DIGIT UNDERSCORE DIGIT DIGIT UNDERSCORE DIGIT DIGIT DIGIT DIGIT;
UNDERSCORE: ('_' | '-');
fragment DIGIT: [0-9];
NUMBER: '-'? (DIGIT)+;
STRING: ([a-zA-Z]|UNDERSCORE)([a-zA-Z0-9]|UNDERSCORE|COLON|FSLASH)*([a-zA-Z0-9]|UNDERSCORE);
WS: [ \r\n\t]+ -> skip;
ErrorChar : . ;