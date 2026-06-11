"""
Step 06b (2021/2022): Build the file-download resource replacement dictionary.

Scans session commands for download URLs (wget/curl/etc.), extracts the URLs and
filenames, and builds a mapping from each original download command to a
"neutralised" version (https->http, real IP/host -> 127.0.0.1). This mapping is
later applied when replaying commands against the honeypot VM so that downloads
hit a local mirror instead of the live malware host.

Input  : DATA_DIR/session_dict_beifen.json
Output : DATA_DIR/6-提取设备响应/1-下载命令.json (download commands),
         DATA_DIR/6-提取设备响应/2-url地址.json (URLs),
         DATA_DIR/6-提取设备响应/3-下载文件名.json (download filenames),
         DATA_DIR/6-提取设备响应/4-命令更改情况.json (command-change info; written by
         write_to_file2, currently disabled because the file was hand-edited)
"""
import os
import json
import re

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

"""Load the command-type dictionary"""
def load_session_command_dict(file_path):

    with open(file_path, 'r') as file:
        return json.load(file)



def change_download_comd(command):
    ipaddress_pattern = r"([0-9a-zA-Z]+\.([0-9a-zA-Z]+\.)+[0-9a-zA-Z]+(:[0-9]+)?)"
    command_changed = command.replace("https", "http")
    command_changed = re.sub(ipaddress_pattern, '127.0.0.1', command_changed)
    command_changed = command_changed[5:]
    return  command_changed

"""Extract URLs from the command-type dictionary"""
def extract_urls(command_type_dict):

    url_pattern = r"(https?://\S+|([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\./\S+))"
    download_urls = []
    download_commands = []
    download_filenames = []


    for session in command_type_dict:
        for command in command_type_dict[session]:
            matches = re.findall(url_pattern, command)
            command = command[5:]
            if matches and command not in download_commands:
                download_commands.append(command)
                for match in matches:
                    for url in match:
                        if url :
                            url = url.split(';')[0]
                        if url and url not in download_urls:
                            download_urls.append(url)


    for url in download_urls:
        filename = url.split('/')[-1]
        if filename and (filename not in download_filenames) :
            download_filenames.append(filename)

    return download_commands, download_urls, download_filenames

def change_download_comds(command_type_dict):
    command_change_info={}
    for session in command_type_dict:
        for command in command_type_dict[session]:
            if command not in command_change_info and '.' in command:
                comd_changed=change_download_comd(command)
                command_change_info[command] = comd_changed
    return  command_change_info

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

def write_to_file2(command_change_info,command_change_info_path):
    with open(command_change_info_path, "w", encoding='utf-8') as file:
        json.dump(command_change_info, file, indent=4)


if __name__ == "__main__":
    command_type_dict = load_session_command_dict(os.path.join(DATA_DIR, 'session_dict_beifen.json'))
    download_commands, download_urls, download_filenames = extract_urls(command_type_dict)
    command_change_info = change_download_comds(command_type_dict)
    commands_file_path = os.path.join(DATA_DIR, "6-提取设备响应", "1-下载命令.json")
    urls_file_path = os.path.join(DATA_DIR, "6-提取设备响应", "2-url地址.json")
    file_name_path= os.path.join(DATA_DIR, "6-提取设备响应", "3-下载文件名.json")
    command_change_info_path= os.path.join(DATA_DIR, "6-提取设备响应", "4-命令更改情况.json")
    write_to_file(download_commands, download_urls, download_filenames, commands_file_path, urls_file_path, file_name_path)
    # The file was subsequently hand-edited a second time
    #write_to_file2(command_change_info,command_change_info_path)
    print(f"URLs extracted and written to {commands_file_path} and {urls_file_path}")
