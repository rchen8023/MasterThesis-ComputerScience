

POLICY P1:
DENY	action_device = its-too-hot AND
		action_command = sending_sms
ONLY IF automation_unit = its-too-hot

POLICY P2:
DENY	action_device = its-too-cold AND
		action_command = sending_sms
ONLY IF automation_unit = its-too-cold

POLICY P3:
ALLOW	action_device = smart-plug-1 AND
		action_command = off
ONLY IF automation_unit = darken-behind-me

POLICY P4:
ALLOW	action_device = fan AND
		action_command = on
ONLY IF automation_unit = its-too-hot

POLICY P5:
ALLOW	action_device = its-too-hot AND
		action_command = sending_notification
ONLY IF automation_unit = its-too-hot

POLICY P6:
ALLOW	action_device = its-too-cold AND
		action_command = sending_notification
ONLY IF automation_unit = its-too-cold

POLICY P7:
ALLOW	action_device = heater AND
		action_command = on
ONLY IF automation_unit = its-too-cold

POLICY P8:
ALLOW	action_device = smart-plug-2 AND
		action_command = on
ONLY IF state(fan) = on

POLICY P9:
ALLOW	action_device = smart-plug-1 AND
		action_command = on
ONLY IF automation_unit = brighten-my-path