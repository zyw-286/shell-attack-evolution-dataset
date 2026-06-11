"""
Step 06a (2024): Deduplicate sessions.

Merges sessions that share an identical command list: all source hosts that map
to the same command sequence are joined into a single '/'-separated key.

Input  : DATA_DIR/5-session_dict.json
Output : in-memory session_dict2 (see save_dict helper to persist if desired)
"""
import os
import json

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

with open(os.path.join(DATA_DIR, '5-session_dict.json'), 'r') as file:
    session_dict = json.load(file)
session_dict2={}

for key, values in session_dict.items():
    key_string = "/".join(sorted([k for k, v in session_dict.items() if v == values]))
    session_dict2[key_string] = values

def save_dict(dictname,save_path):
    with open(save_path, "w", encoding='utf-8') as file:
        json.dump(dictname, file, indent=4)
print(len(session_dict2))
