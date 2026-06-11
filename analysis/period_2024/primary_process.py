"""
Primary processing of the raw Cowrie honeypot dataset (2024 variant).

Provides the ``PrimaryProcessing`` class used by the 2024 pipeline. It filters
the merged DataFrame down to command-input events and groups them by attacker
host into per-attacker session command lists. The 2024 dataset uses a different
column schema (``info`` / ``tshark`` / ``src_host``) than the 2021/2022 one.

Input  : a pandas DataFrame of merged Cowrie log events.
Output : a session dictionary {src_host: [command, ..., 'END']} written to JSON.

NOTE: This is the 2024-specific variant; the 2021/2022 pipeline uses
analysis/common/primary_process.py instead.
"""
import os
import csv
import pandas as pd

import pandas as pd
import json

class PrimaryProcessing:
    def __init__(self, merged_df):
        self.merged_df = merged_df
        #self.p_df= self.merged_df[self.merged_df['dst_port'] != 443].sort_values(by='timestamp', ascending=True)
        self.p_df = self.merged_df[self.merged_df['info'] =="command.input"].sort_values(by='timestamp', ascending=True)


    def session_gather(self,file_dir):
        session_dict = dict()
        for index, row in self.p_df.iterrows():
            session_flag = False
            if row['info'] == 'command.input':

                if str(row['tshark'])[:18] == 'command  found [ b':
                    t_shark = str(row['tshark'])[19:-3]
                else:
                    t_shark = str(row['tshark'])
                if t_shark=="Enter":
                    continue
                if row['src_host'] in session_dict:
                    # remove consecutive duplicate commands
                    if t_shark not in session_dict[row['src_host']]:
                        session_dict[row['src_host']].append(t_shark)
                else:
                    session_dict[row['src_host']] = [t_shark]
            elif row['info'] == 'cowrie.session.closed':
                if row['src_host'] in session_dict:
                    session_dict[row['src_host']].append('END')
        with open(file_dir, "w") as f:
            json.dump(session_dict, f, indent=4)


        return session_dict



# Usage example
if __name__ == "__main__":
    # Create a PrimaryProcessing object and pass in a DataFrame
    merged_df = pd.DataFrame(...)  # replace with the actual DataFrame data
    processor = PrimaryProcessing(merged_df)

    # Call the class methods
    filtered_df = processor.filter_sequence()
    session_dict = processor.calculate_time_span()
    processor.store_to_file(session_dict, "output.json")
