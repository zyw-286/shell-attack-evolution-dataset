"""
Step 01 (2024): Extract attacker sessions from the raw Cowrie dataset.

Iterates over all log files, builds one merged dataset, groups command-input
events by attacker host into per-attacker command sequences, and stores the
result as a session dictionary.

Input  : DATA_DIR/port_filterd.csv  (merged Cowrie events)
Output : DATA_DIR/session_dict.json , DATA_DIR/session_dict.npy

The commented-out block reads the raw cowrie logs directly from RAW_ROOT; the
merged result was cached to port_filterd.csv because reading them takes too long.
"""
import os
import json
import csv
import pandas as pd
from primary_process import PrimaryProcessing
import numpy as np
# Iterate over all log files and merge them into one large dataset -> session_dict.json, port_filterd.csv

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
# Original raw cowrie root (hardcoded): r'../cowrie'
RAW_ROOT = os.path.join(DATA_DIR, "cowrie")

# The block below reads the cowrie logs by directory; because it takes too long,
# the merged logs were stored to DATA_DIR/port_filterd.csv
# def read_dataset():
#     # Get the file storage directories of the 2021 and 2022 datasets separately
#     file_path1 = RAW_ROOT
#     file_name_list1 = os.listdir(file_path1)
#
#     obs_file_path = [file_path1 + i for i in file_name_list1]
#     print(obs_file_path)
#
#
#     dfs1 = []
#
#     for n in file_name_list1:
#         obs_file_path1 = os.path.join(file_path1, n)
#         # print(obs_file_path)
#         # Convert to absolute path, then open the file
#         try:
#             df = pd.read_json(obs_file_path1, lines=True)
#             dfs1.append(df)
#             print('[read success]', obs_file_path1)
#         except Exception as e:
#             print('[read failed]', e, obs_file_path1)
#
#
#
#     # Merge data
#     merged_df = pd.concat(dfs1, axis=0)
#
#
#     # Output the number of commands in the dataset
#     print(len(merged_df) )
#     return merged_df
#
# merged_df = read_dataset()
# # Store merged_df
# merged_df.to_csv(os.path.join(DATA_DIR, "merged_df.csv"))
# # Instantiate the object
# processor = PrimaryProcessing(merged_df)
# # Extract non-443-port attack sequences and store them
# port_filterd = processor.p_df
# port_filterd.to_csv(os.path.join(DATA_DIR, "port_filterd.csv"))
# Extract sessions
merged_df =pd.read_csv(os.path.join(DATA_DIR, "port_filterd.csv"))
processor = PrimaryProcessing(merged_df)
session_dict = processor.session_gather(os.path.join(DATA_DIR, "session_dict.json"))
print()

np.save(os.path.join(DATA_DIR, "session_dict.npy"), session_dict)
