"""
Step 08 (2024): Session-length distribution.

Computes the number of commands per clustered session, builds a histogram of
session lengths as a percentage of all sessions, and plots the distribution
(ported from 8-session-length-1.py, the styled plotting variant).

Input  : DATA_DIR/5-session归类.json
Output : a matplotlib bar chart (shown interactively; no file written)
"""
# --coding:utf-8--
import os
import json
import matplotlib.pyplot as plt

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Read the JSON data from file
with open(os.path.join(DATA_DIR, '5-session归类.json'), 'r') as file:
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

# Prepare plotting data, removing entries whose percentage is 0
lengths = [length for length in sorted(length_counts.keys()) if percentages[length] > 0]
counts = [percentages[length] for length in lengths]





# Set global font sizes
plt.rcParams['font.size'] = 16  # set the global base font size
# plt.rcParams['axes.titlesize'] = 18  # title font size
plt.rcParams['axes.labelsize'] = 18  # axis-label font size
plt.rcParams['xtick.labelsize'] = 16  # x-axis tick-label font size
plt.rcParams['ytick.labelsize'] = 16  # y-axis tick-label font size
plt.rcParams['legend.fontsize'] = 16  # legend font size

# Plot
plt.figure(figsize=(15, 6))
plt.bar(range(len(lengths)), counts, color='green', width=0.9)  # set width to 1.0 to reduce gaps
plt.xlabel('Number of Commands per Session', fontsize=18)
plt.ylabel('Percentage (%)', fontsize=18)
# Adjust the x-axis label position
plt.gca().xaxis.set_label_coords(0.8, -0.1)  # move the x-axis label to the outer end of the axis
# Adjust the y-axis label position
plt.gca().yaxis.set_label_coords(-0.025, 0.7)  # move the y-axis label to the outer end of the axis
#plt.title('Distribution of Session Lengths')
plt.xticks(range(len(lengths)), lengths)  # show all session lengths as x-axis ticks
plt.grid(False)
plt.tight_layout()  # automatically adjust subplot params to fill the figure area
plt.show()
