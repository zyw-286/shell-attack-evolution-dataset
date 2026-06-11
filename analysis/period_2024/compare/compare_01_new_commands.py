"""
Compare step 01 (2024 vs 2021/2022): Find the newly-appearing command set.

Loads the simple-command groups and complex-command patterns for both periods,
flattens them into command lists, and prints the commands present only in 2024.

Input  : <period>/data/3-大类提取.json , <period>/data/4-复杂指令类型分析-sorted.json
         for both the 2024 and 2021/2022 pipelines.
Output : printed list of commands unique to 2024 (no file written)
"""
# --coding:utf-8--
import os
import json

# === Config ===
# Roots of each period's pipeline (the dir that contains a 'data' subfolder).
# Original (hardcoded) 2021 root: "D:/科研/Honey-GPT/Honeypot Data/Data-process-new"
# Original (hardcoded) 2024 root: "../../"  (this file lives in period_2024/compare/)
ROOT_2024 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_2021 = os.path.join(os.path.dirname(ROOT_2024), "period_2021_2022")

def get_sorted_comd_type_dict(path):
    with open(path + '/data/3-大类提取.json', 'r') as file:
        sample_dict = json.load(file)
    with open(path + '/data/4-复杂指令类型分析-sorted.json', 'r') as file:
        complex_dict = json.load(file)

    comd_type_dict={}

    for i in sample_dict:
        comd_type_dict[i] = sample_dict[i][-1]

    for i in complex_dict:
        comd_type_dict[i] = len(complex_dict[i])

    sorted_comd_type_dict = dict(sorted(comd_type_dict.items(), key=lambda item: item[1]))
    return sorted_comd_type_dict, {**sample_dict, **complex_dict}


def all_comd(dict_2021):

    simple_count=0
    complex_count=0
    # Use set operations to find the keys that belong only to dict_2024
    unique_keys = list(dict_2021.keys())
    comds_2021 = []
    for item in unique_keys:
        if isinstance(item, str) and not item.startswith("("):
            comds_2021.append(item)
            if len(item)>2 and item[:2]=="./":
                continue
            if len(item)>4 and item[:4]=="/tmp":
                continue
            print(item)
            simple_count+=1
        elif isinstance(item, str) and item.startswith("("):
            item = eval(item)
            comds_2021.extend(item)
            complex_count+=1
    return comds_2021

dict_2021,t = get_sorted_comd_type_dict(ROOT_2021)
dict_2024,t_2024 = get_sorted_comd_type_dict(ROOT_2024)

comds_2021 = all_comd(dict_2021)
comds_2024 = all_comd(dict_2024)

unique_keys = set(comds_2024) - set(comds_2021)
for i in unique_keys:
    if i[:5]!="/tmp/"  and i[:4]!="/bin" and i[:2]!="./":
        print(i)

# Output the result


"""
EHLO
openssl
hostname
whoami
install
HELP
?
nan
pkill
..
screen
o
touch
grep
chattr
lockr
unset
screen
la
export
"""
