"""
Command-pattern extraction helpers (2021/2022 variant).

Tokenizes shell commands into an abstract "command pattern": simple commands
collapse to their head command, while complex commands (containing shell
operators such as ; | & > < ()) are split into a sequence of recognised
command heads and operators. Used by the session-clustering and attack-mapping
steps to group structurally similar commands.

Input  : a session/command dictionary JSON file (loaded at import time).
Output : none directly — exposes complex_to_pattern / command_to_pattern /
          comds_to_patterns for use by other pipeline steps.

NOTE: The 2024 pipeline ships its own variant with a different command-head
vocabulary; keep them separate.
"""
# --coding:utf-8--
import os
import json
import re

# === Config ===
# Relative to this file's parent (the analysis/ root). Original (hardcoded):
#   '../data/session_dict_beifen.json'
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "period_2021_2022", "data")
SESSION_DICT_PATH = os.path.join(DATA_DIR, "session_dict_beifen.json")

with open(SESSION_DICT_PATH, 'r') as file:
    session_dict = json.load(file)
def complex_to_pattern(text):
    # Match whitespace, |, &, ;, {, [ and ( using a regular expression
    #pattern = r'\s+|\||&|;|{|}|\[|\]'
    # Use re.findall to extract words and symbols from the text
    #tokens = re.findall(r'[^\s\|&;{}()\[\]\']+', text)
    comd_head = ["&&", "||", "&", ";", "(", ")", "{", "}", "[", "]", "|", "\"",
                 'dd', 'do', 'done', 'while', 'if', 'print', 'free', 'wc', 'which', 'exit', '<', 'grep', 'head', 'tftp',
                 'awk',
                 'cp', "chpasswd", 'ping', 'curl', 'ftpget', 'cut', 'uniq', '>&',
                 'uname', 'which', 'w', 'crontab', 'top', 'echo', 'sh', 'shell', 'enable', 'system', 'linuxshell',
                 'cat', '/bin/busybox', 'debug', 'cmd', 'config', 'start', 'su', '/ip', 'ifconfig', 'ls', 'rm', 'cd',
                 'runshellcmd', 'mkdir', 'kill', 'wget', 'pwd', 'development', 'start-shell', 'vshell', 'exec',
                 'busybox', 'help', 'passwd', '/tmp/ntpclient', 'lscpu', 'curl:', '/system', 'ps', 'python', 'apt-get',
                 'screenfetch', 'sudo',
                 'https://cdn.discordapp.com/attachments/834709504049414155/836574658668265522/New_Text_Document.sh',
                 'bash', 'clear', './new', 'cdd', './ninfols', 'chmod', './686840', './595936', './812969', './253294',
                 './624818', './212630', './542492', './840190', './176844', 'admin', 'scp', './Lhtln3CT', './2p8unLIG',
                 './tZft1Zbk', '执行命令', './tseLLRfT', './5RcJ2tf9', './PHri0doL', './ePxJOVoq', 'sd',
                 "ip","docker","nproc","export","history", "apt","nvidia-smi","cat", "kill","scp","nohup","User-Agent:","Accept-Language:","lspci","sleep","chattr","unset","uptime","hive-passwd","pkill","systemctl","chsh","id","perl","chsh","df"]
    tokens = re.split(r'\s+|(>&)|(>>)|(\|\|)|(&&)|(\s&)|([|;>{}()\[\]\'\'])', text)

    result = []

    for sub_word in tokens:
        # remove consecutive duplicate elements
        if result and sub_word==result[-1]:
            continue
        # add non-consecutive-duplicate command types
        else:


            if sub_word and sub_word[:2] =='if':
                result.append("if")

            if sub_word and sub_word[0] =='-':
                result.append(sub_word)
            if sub_word and sub_word[0] =='+':
                result.append(sub_word)
            #'./ninfo',
            if sub_word and sub_word[:2] == './':
                result.append('./')
            elif sub_word in comd_head :
                result.append(sub_word)
            elif  sub_word and sub_word[:2] =='>>':
                result.append('>>')
            elif sub_word and sub_word[0] =='>':
                result.append('>')

    return ' '.join(result)

def command_to_pattern(command):
    if not re.search(r'[;|&><()]', command):

        # Split the command into words using a regular expression
        words = re.split(r'\s+', command)
        # The first word is taken as the category
        comd_pattern = words[0]
    else:
        comd_pattern = complex_to_pattern(command)
    return  comd_pattern

def comds_to_patterns(comds):
    d={}
    for comd in comds:
        pattern = command_to_pattern(comd)
        if pattern not in d:
            d[pattern] = [comd]
        else:
            d[pattern].append(comd)
    return d
