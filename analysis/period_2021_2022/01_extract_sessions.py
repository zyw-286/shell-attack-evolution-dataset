"""
Step 01 (2021/2022): Extract attacker sessions from the raw Cowrie dataset.

Reads the merged/port-filtered Cowrie events, groups ``cowrie.command.input``
events by attacker source IP into per-attacker command sequences, and stores
the result as a session dictionary.

Input  : DATA_DIR/port_filterd.csv  (merged & non-443-port-filtered Cowrie events)
Output : DATA_DIR/session_dict.json , DATA_DIR/session_dict.npy

The commented-out block below shows how port_filterd.csv was originally built by
reading the raw cowrie JSON logs from RAW_ROOT (kept for reproducibility).
"""
import os
import json
import csv
import pandas as pd
from primary_process import PrimaryProcessing
import numpy as np

# === Config ===
# Relative paths under the analysis tree. Originals (hardcoded) are shown inline.
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
# Original raw cowrie roots:
#   RAW_ROOT1 = r'D:\科研\Honey-GPT\Honeypot Data\cowrie-20210406-20210611\data_content'
#   RAW_ROOT2 = r'D:\科研\Honey-GPT\Honeypot Data\cowrie-20220609-20220704\data_content'
RAW_ROOT1 = os.path.join(DATA_DIR, "cowrie-20210406-20210611", "data_content")
RAW_ROOT2 = os.path.join(DATA_DIR, "cowrie-20220609-20220704", "data_content")

# def read_dataset():
#     # Get the file storage directories of the 2021 and 2022 datasets separately
#     file_path1 = RAW_ROOT1
#     file_name_list1 = os.listdir(file_path1)
#     file_path2 = RAW_ROOT2
#     file_name_list2 = os.listdir(file_path2)
#     obs_file_path = [file_path1 + i for i in file_name_list1] + [file_path2 + j for j in file_name_list2]
#     print(obs_file_path)
#
#     # The reader function has a file-size limit, so read them separately and concatenate
#     # Read the 2021 dataset files
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
#     # Read the 2022 dataset files
#     dfs2 = []
#     for n in file_name_list2:
#         obs_file_path2 = os.path.join(file_path2, n)
#         # print(obs_file_path)
#         # Convert to absolute path, then open the file
#         try:
#             df = pd.read_json(obs_file_path2, lines=True)
#             dfs2.append(df)
#             print('[read success]', obs_file_path2)
#         except Exception as e:
#             print('[read failed]', e, obs_file_path2)
#
#     # Merge data
#     merged_df = pd.concat(dfs1+dfs2, axis=0)
#     #print(merged_df)
#     merged_df1 = pd.concat(dfs1, axis=0)
#     merged_df2 = pd.concat(dfs2, axis=0)
#     # Output the number of commands in the dataset
#     print(len(merged_df1) , len(merged_df2) , len(merged_df) )
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
