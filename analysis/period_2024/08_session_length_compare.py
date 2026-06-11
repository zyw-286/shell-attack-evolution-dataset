"""
Step 08 (2024): Compare session-length distributions for 2021/2022 vs 2024.

Computes the session-length percentage distribution for both the 2024 dataset
and the 2021/2022 dataset and overlays them as two line plots.

Input  : DATA_DIR_2024/5-session归类.json , DATA_DIR_2021/5-session归类.json
Output : a matplotlib line chart (shown interactively; no file written)
"""
# --coding:utf-8--
import os
import json
import matplotlib.pyplot as plt

# === Config ===
# DATA_DIR_2024 is this period's data dir. DATA_DIR_2021 points at the
# 2021/2022 pipeline's data dir.
# Original (hardcoded) 2021 path:
#   'D:/科研/Honey-GPT/Honeypot Data/Data-process-new/data/5-session归类.json'
DATA_DIR_2024 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DATA_DIR_2021 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "period_2021_2022", "data")

def get_session_length(dir):
    # Read the JSON data from file
    with open(dir, 'r') as file:
        session_classfy = json.load(file)
    session_data= [eval(i) for i in list(session_classfy.keys())]
    # Compute the session length for each IP
    session_lengths = [len(list(commands)) for commands in session_data]
    for commands in session_data:
        if len(list(commands))> 30:
            print(commands)

    # Count the number of IPs for each length
    length_counts = {}
    for length in session_lengths:
        if length in length_counts:
            length_counts[length] += 1
        else:
            length_counts[length] = 1
    print(length_counts)
    # Prepare plotting data
    # Compute the total number of sessions
    total_sessions = sum(length_counts.values())

    # Compute percentages
    percentages = {length: (count / total_sessions) * 100 for length, count in length_counts.items()}
    return length_counts, percentages
length_counts_2024, percentages_2024 = get_session_length(os.path.join(DATA_DIR_2024, '5-session归类.json'))
length_counts_2022, percentages_2022 = get_session_length(os.path.join(DATA_DIR_2021, '5-session归类.json'))
lengths = (list(set(list(length_counts_2024.keys()) + list(length_counts_2022.keys()))))
lengths = sorted(lengths)

# Prepare plotting data, removing entries whose percentage is 0
# lengths = [length for length in sorted(length_counts_2024.keys()) if percentages_2024[length] > 0 or percentages_2022[length] > 0]

counts_2024 = [percentages_2024.get(length, 0) for length in lengths]
counts_2022 = [percentages_2022.get(length, 0) for length in lengths]


# Plot
plt.figure(figsize=(15, 6))
plt.plot(range(len(lengths)), counts_2024, color='green')  # set width to 1.0 to reduce gaps
plt.plot(range(len(lengths)), counts_2022, color='red')  # set width to 1.0 to reduce gaps

plt.xlabel('Number of Commands per Session', fontsize=16)
plt.ylabel('Percentage (%)', fontsize=16)
# # Adjust the x-axis label position
# plt.gca().xaxis.set_label_coords(0.8, -0.1)  # move the x-axis label to the outer end of the axis
# # Adjust the y-axis label position
# plt.gca().yaxis.set_label_coords(-0.03, 0.7)  # move the y-axis label to the outer end of the axis
plt.xticks(range(len(lengths)), lengths)  # show all session lengths as x-axis ticks
plt.grid(False)
#plt.legend()
plt.ylim(bottom=0)
plt.tight_layout()  # automatically adjust subplot params to fill the figure area
plt.show()

# # Prepare the data for plotting
# values1 ,keys1 = zip(*sorted(percentages_2022.items()))
# values2, keys2 = zip(*sorted(percentages_2024.items()))
#
# fig, ax = plt.subplots()
#
# # Plotting the lines
# ax.plot(values1, keys1, label='Data Set 1', marker='o')
# ax.plot(values2, keys2, label='Data Set 2', marker='o')
#
# # Adding labels and title
# ax.set_xlabel('Values')
# ax.set_ylabel('Keys')
# ax.set_title('Line Plot of Two Dictionaries')
# ax.legend()
#
# # Show the plot
# plt.show()
