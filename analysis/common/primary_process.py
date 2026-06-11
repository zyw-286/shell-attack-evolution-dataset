"""
Primary processing of the raw Cowrie honeypot dataset.

Provides the ``PrimaryProcessing`` class, which filters the merged DataFrame of
Cowrie events down to the relevant command-input events and groups them by
attacker source IP into per-attacker session command lists.

Input  : a pandas DataFrame of merged Cowrie log events (built by the
          ``01_extract_sessions`` pipeline step).
Output : a session dictionary {src_ip: [command, ...]} written to a JSON file.

NOTE: This is the 2021/2022 variant of the helper. The 2024 dataset uses a
slightly different DataFrame schema (see git history / the 2024 pipeline).
"""
import json
import os
import csv
import pandas as pd

import pandas as pd
import json

class PrimaryProcessing:
    def __init__(self, merged_df):
        self.merged_df = merged_df
        self.p_df= self.merged_df[self.merged_df['dst_port'] != 443].sort_values(by='timestamp', ascending=True)




    def session_gather(self,file_dir):
        session_dict = dict()
        for index, row in self.p_df.iterrows():
            if row['message'] =="Enter new UNIX password: ":
                continue
            if row['eventid'] == 'cowrie.command.input':
                if row['src_ip'] in session_dict:
                    ## remove consecutive duplicate commands
                    if row['message'] not in session_dict[row['src_ip']]:
                        session_dict[row['src_ip']].append(row['message'])
                else:
                    session_dict[row['src_ip']] = [row['message']]
            # elif row['eventid'] == 'cowrie.session.closed':
            #     if row['src_ip'] in session_dict:
            #         session_dict[row['src_ip']].append('END')
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
