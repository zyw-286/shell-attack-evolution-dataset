"""
Compare step 04 (2024 vs 2021/2022): Compare sessions.

Computes the average number of distinct commands per clustered session for each
period and prints both averages.

Input  : <period>/data/5-session归类.json for both periods.
Output : printed average session lengths (no file written)
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
    with open(path + '/data/5-session归类.json', 'r') as file:
        sample_dict = json.load(file)
    return sample_dict


def average_value_list_length(command_dict):
    # Return 0 if the dict is empty
    if not command_dict:
        return 0

    # Compute the length of each key's value, i.e. the length of each list
    #total_commands = sum(len(eval(commands)) for commands in command_dict.keys())
    # Get the number of keys (IP addresses) in the dict
    number_of_keys = len(command_dict)

    # Compute the average length of the command lists
    # if number_of_keys == 0:
    #     return 0  # avoid division by zero
    # average_length = total_commands * len / number_of_keys


    # total_count = 0
    # total_commands = 0
    # for commands in command_dict:
    #     count = len(command_dict[commands])
    #     total_count += 1
    #     total_commands +=len(eval(commands))
    # average_length = total_commands/total_count

    comds_list = list(command_dict.keys())

    # Note
    # import re
    # pattern = r'\s-[a-zA-Z\-]'
    # comds_list=[re.sub(pattern, '', comd) for comd in comds_list]

    comds_list = [set(eval(i)) for i in comds_list]
    average_length = sum(len(commands) for commands in comds_list)  /  len(comds_list)


    return average_length


# Example data


dict_2024 = get_sorted_comd_type_dict(ROOT_2024)
dict_2021 = get_sorted_comd_type_dict(ROOT_2021)
print(average_value_list_length(dict_2021))
print(average_value_list_length(dict_2024))
1
