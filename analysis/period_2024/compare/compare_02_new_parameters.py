"""
Compare step 02 (2024 vs 2021/2022): Find newly-appearing command parameters.

For command head-categories common to both periods, finds the parameter strings
that appear in 2021/2022 but not in 2024 (i.e. the per-category difference).

Input  : <period>/data/3-大类提取.json for both periods.
Output : new_entries dict (computed; not written/printed by default)
"""
# --coding:utf-8--
import os
import json

# === Config ===
# Original (hardcoded) 2021 root: "D:/科研/Honey-GPT/Honeypot Data/Data-process-new"
# Original (hardcoded) 2024 root: "../../"
ROOT_2024 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_2021 = os.path.join(os.path.dirname(ROOT_2024), "period_2021_2022")

def get_sorted_comd_type_dict(path):
    with open(path + '/data/3-大类提取.json', 'r') as file:
        sample_dict = json.load(file)

    return sample_dict

def extract_new_entries(dict_2021, dict_2024):
    # Initialize a dict to store the results
    new_entries = {}

    # Find the keys common to both dicts
    common_keys = set(dict_2021.keys()) & set(dict_2024.keys())

    # Iterate over each common key
    for key in common_keys:
        list_2021 = dict_2021[key]
        list_2024 = dict_2024[key]
        keys_2021 = {k for item in list_2021 if isinstance(item, dict) for k in item.keys()}
        keys_2024 = {k for item in list_2024 if isinstance(item, dict) for k in item.keys()}

        # Compute the part unique to 2024
        difference = keys_2021 - keys_2024
        if difference:
            # Convert the difference back to its original type (list or dict)
            new_entries[key] = [dict(item) if isinstance(item, tuple) else item for item in difference]

    return new_entries

simple_comd_dict_2021 = get_sorted_comd_type_dict(ROOT_2021)
simple_comd_dict_2024 = get_sorted_comd_type_dict(ROOT_2024)

extract_new_entries(simple_comd_dict_2021,simple_comd_dict_2024)


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
