"""
Step 07b (2024): Count MITRE ATT&CK technique frequencies.

For each session, weights every technique observed in that session by the
number of commands in the session, then aggregates the weighted counts across
all sessions and prints them in descending order.

Input  : DATA_DIR/5-session归类.json , DATA_DIR/7-session_tech.json
Output : printed sorted technique-frequency dict (no file written)
"""
# --coding:utf-8--
import os
import json,re,ast
from itertools import chain,groupby

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

with open(os.path.join(DATA_DIR, '5-session归类.json'), 'r') as file:
    session_dict = json.load(file)

with open(os.path.join(DATA_DIR, '7-session_tech.json'), 'r') as file:
    session_tech = json.load(file)
tech_sequence= {}
for session,comd_techs in session_tech.items():
    for tech in comd_techs:
        if tech not in tech_sequence:
            tech_sequence[tech]=len(session_dict[session])
        else:
            tech_sequence[tech]+=len(session_dict[session])

sorted_dict = dict(sorted(tech_sequence.items(), key=lambda item: item[1], reverse=True))
print(sorted_dict)

"""
sorted_dict={
'T1059 Command and Scripting Interpreter': 18360,
'T1082 System Information Discovery': 16723,
'T1087 Account Discovery': 12776,
'T1531 Account Access Removal': 11971,
'T1083 File and Directory Discovery': 4554,
'T1005 Data from Local System': 3984,
'T1222 File and Directory Permissions Modification': 3273,
'T1053 Scheduled Task/Job': 3220,
'T1057 Process Discovery': 3180,
'T1070 Indicator Removal': 1691,
'T1027 Obfuscated Files or Information': 1645,
'T1105 Ingress Tool Transfer': 1181,
'T1548 Abuse Elevation Control Mechanism': 97,
'T1016 System Network Configuration Discovery': 85,
'T1424 Process Discovery': 78,
'T1037 Boot or Logon Initialization Scripts': 39,
'T1655 Masquerading': 22,
'T1489 Service Stop': 19,
'T1098 Account Manipulation': 8,
'T1124 System Time Discovery': 7,
'T1518 Software Discovery': 3,
'T1120 Peripheral Device Discovery': 1}

"""
