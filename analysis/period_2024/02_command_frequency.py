"""
Step 02 (2024): Count command frequencies across all sessions.

Reads the per-attacker session dictionary, counts how often each distinct
command string appears, and writes the commands sorted by descending frequency.
(Unlike the 2021/2022 variant, the 2024 commands have no "CMD: " prefix to strip.)

Input  : DATA_DIR/session_dict.json
Output : DATA_DIR/2-sorted_cmd_counter.json , DATA_DIR/2-sorted_cmd_counter.xlsx
"""
import os
import json
from collections import Counter

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Read the session_dict.json file
with open(os.path.join(DATA_DIR, 'session_dict.json'), 'r') as file:
    session_dict = json.load(file)

def save_xlsx(sorted_cmd_counter,dir):
    import openpyxl

    # Create a new Excel workbook
    wb = openpyxl.Workbook()
    # Get the default worksheet (sheet1)
    sheet1 = wb.active
    sheet1.title = "Sheet1"
    sheet1.cell(row=1, column=1, value="command")
    sheet1.cell(row=1, column=2, value="counte")
    current_row = 2
    for key, num in sorted_cmd_counter.items():
            sheet1.cell(row=current_row, column=1, value=key)
            sheet1.cell(row=current_row, column=2, value=num)
            current_row += 1

    wb.save(dir)

# Create an empty counter dictionary
cmd_counter = Counter()

# Iterate over each session
for session_id, commands in session_dict.items():
    # Iterate over each command
    for command in commands:
        # Extract the command part (strip the "CMD: " prefix)
        #cmd = command[5:]
        cmd = command
        # Increment the command's frequency count
        if cmd:
            cmd_counter[cmd] += 1

# Sort from highest to lowest frequency
sorted_cmd_counter = dict(sorted(cmd_counter.items(), key=lambda item: item[1], reverse=True))

# Output the result
print(sorted_cmd_counter)
with open(os.path.join(DATA_DIR, "2-sorted_cmd_counter.json"),"w") as f:
    #sorted_cmd_counter_json = json.dumps(sorted_cmd_counter, sort_keys=False, indent=4, separators=(',', ': '))
    json.dump(sorted_cmd_counter, f, indent=4)

save_xlsx(sorted_cmd_counter, os.path.join(DATA_DIR, "2-sorted_cmd_counter.xlsx"))
#top30
#  'cd ~; chattr -ia .ssh; lockr -ia .ssh',
#  'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~',
#  'shell',
#  'sh',
#  'enable',
#  'system',
#  'nan',
#  '/bin/busybox cat /proc/self/exe || cat /proc/self/exe',
#  'ping; sh',
#  'uname -a',
#  'cat /proc/cpuinfo | grep name | wc -l',
#  'ls -lh $(which ls)',
#  'which ls',
#  'whoami',
#  'uname',
#  "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'",
#  'cat /proc/cpuinfo | grep model | grep name | wc -l',
#  'lscpu | grep Model',
#  'rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;',
#  'uname -m',
#  'crontab -l',
#  'w',
#  'top',
#  "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
#  "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
#  'dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s',
#  'rm .s; exit',
#  'ping;sh',
#  'kill %%1',
#  'uname -s -m'
