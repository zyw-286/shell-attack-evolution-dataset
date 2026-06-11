"""
Step 03 (2021/2022): Classify commands into simple vs complex.

Splits the frequency-sorted commands into "simple" commands (no shell
operators) and "complex" commands (containing ; | & > < ()). Simple commands
are grouped by their head command, with the per-group total count appended.

Input  : DATA_DIR/sorted_cmd_counter.json
Output : DATA_DIR/3-大类提取.json (simple commands grouped by head),
         DATA_DIR/复杂指令.json (complex commands),
         DATA_DIR/3-简单命令按类型排序.xlsx , DATA_DIR/3-复杂命令数目排序.xlsx
"""
import os
import json
from collections import Counter
import re

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Read the frequency-sorted command file
with open(os.path.join(DATA_DIR, 'sorted_cmd_counter.json'), 'r') as file:
    cmd_dict = json.load(file)

def save_simple_command_xlsx(simple_command_dict,dir):
    import openpyxl

    # Create a new Excel workbook
    wb = openpyxl.Workbook()
    # Get the default worksheet (sheet1)
    sheet1 = wb.active
    sheet1.title = "Sheet1"
    sheet1.cell(row=1, column=1, value="command")
    sheet1.cell(row=1, column=2, value="count")
    current_row = 2
    for key, value in simple_command_dict.items():
            sheet1.cell(row=current_row, column=1, value=key)
            sheet1.cell(row=current_row, column=2, value=value[-1])
            current_row += 1

    wb.save(dir)

def save_Complex_command_xlsx(Complex_instruct_dict,dir):
    import openpyxl

    # Create a new Excel workbook
    wb = openpyxl.Workbook()
    # Get the default worksheet (sheet1)
    sheet1 = wb.active
    sheet1.title = "Sheet1"
    sheet1.cell(row=1, column=1, value="command")
    sheet1.cell(row=1, column=2, value="count")
    current_row = 2
    for key, value in Complex_instruct_dict.items():
            sheet1.cell(row=current_row, column=1, value=key)
            sheet1.cell(row=current_row, column=2, value=value)
            current_row += 1

    wb.save(dir)


# Initialize an empty result dictionary
result = {}
i=0
Complex_instruct_dict={}
# Iterate over the input dictionary
for command, count in cmd_dict.items():
    if not re.search(r'[;|&><()]', command):

        # Split the command into words using a regular expression
        words = re.split(r'\s+', command)
        # The first word is taken as the category
        category = words[0]
        # The rest is taken as the parameters
        parameters = " ".join(words[1:])

        # Look up whether a dict already exists for this category
        if category in result:
            category_dict = result[category]
        else:
            # If not, create a new dict
            category_dict = []
            result[category] = category_dict

        # Add the sub-dict to the category dict
        category_dict.append({parameters: count})
    else:
        i+=1
        print(f"Detected complex command #{i}: {command}")
        Complex_instruct_dict[command]=count
# Compute the total for each category dict based on the number of its sub-dicts
for category, category_dict in result.items():
    total_count = sum(list(sub_dict.values())[0] for sub_dict in category_dict )
    category_dict.append(total_count)

# Print the result
print(result)
print(result.keys())
print(len(result.keys()))
with open(os.path.join(DATA_DIR, '3-大类提取.json'), "w", encoding='utf-8') as file:
    json.dump(result, file, indent=4)


with open(os.path.join(DATA_DIR, '复杂指令.json'), "w", encoding='utf-8') as file:
    json.dump(Complex_instruct_dict, file, indent=4)

save_simple_command_xlsx(result, os.path.join(DATA_DIR, "3-简单命令按类型排序.xlsx"))
save_Complex_command_xlsx(Complex_instruct_dict, os.path.join(DATA_DIR, "3-复杂命令数目排序.xlsx"))
