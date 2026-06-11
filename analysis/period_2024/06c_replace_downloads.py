"""
Step 06c (2024): Replace file-download resources in commands.

Earlier draft of the download-resource replacement: rewrites download commands
so https->http and any real IP/host becomes 127.0.0.1. (The extract/write logic
here is largely a stub superseded by 06b; kept for fidelity with the paper's
pipeline.)

Input  : DATA_DIR/session_dict.json
Output : DATA_DIR/6-提取设备响应/1-下载命令.json,
         DATA_DIR/6-提取设备响应/2-url地址.json,
         DATA_DIR/6-提取设备响应/3-下载文件名.json
"""
import os
import json
import re

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

"""Load the command-type dictionary"""
def load_command_type_dict(file_path):

    with open(file_path, 'r') as file:
        return json.load(file)

"""Extract URLs from the command-type dictionary"""
def extract_urls(command_type_dict):

    ipaddress_pattern = r"([0-9a-zA-Z]+\.([0-9a-zA-Z]+\.)+[0-9a-zA-Z]+(:[0-9]+)?)"

    download_urls = []
    download_commands = []
    download_filenames = []
    curl_changed={}

    for command_type in command_type_dict:
        for command in command_type_dict[command_type]:
            command_changed = command.replace("https","http")
            command_changed = re.sub(ipaddress_pattern,'127.0.0.1', command_changed)
            command_changed = command_changed[5:]
            1



    return download_commands, download_urls, download_filenames

"""Write the commands and URLs to files"""
def write_to_file(commands, urls, filenames, commands_file_path, urls_file_path, file_name_path):
    with open(commands_file_path, "w") as file:
        for comd in commands:
            file.write(comd + "\n")

    with open(urls_file_path, "w") as file:
        for url in urls:
            file.write(url + "\n")

    with open(file_name_path, "w") as file:
        for filename in filenames:
            file.writelines(filename + "\n")



if __name__ == "__main__":
    command_type_dict = load_command_type_dict(os.path.join(DATA_DIR, 'session_dict.json'))
    download_commands, download_urls, download_filenames = extract_urls(command_type_dict)
    commands_file_path = os.path.join(DATA_DIR, "6-提取设备响应", "1-下载命令.json")
    urls_file_path = os.path.join(DATA_DIR, "6-提取设备响应", "2-url地址.json")
    file_name_path= os.path.join(DATA_DIR, "6-提取设备响应", "3-下载文件名.json")
    write_to_file(download_commands, download_urls, download_filenames, commands_file_path, urls_file_path, file_name_path)
    print(f"URLs extracted and written to {commands_file_path} and {urls_file_path}")
