"""
Step 03-2 (2024): Build the system command vocabularies for 2022 vs 2024.

Defines the full recognised-command list and the commands that are absent from
the 2022 / 2024 datasets respectively, then derives and prints the per-period
command vocabularies. Pure constants + printing; no file I/O.

Input  : (none)
Output : printed 2022 / 2024 command lists
"""
# --coding:utf-8--
comd_all = [
                 'dd', 'free', 'wc', 'which', 'exit', 'grep', 'head', 'tftp',
                 'awk',
                 'cp', "chpasswd", 'ping', 'curl', 'ftpget', 'cut', 'uniq',
                 'uname', 'which', 'w', 'crontab', 'top', 'echo', 'sh', 'shell', 'enable', 'system', 'linuxshell',
                 'cat', '/bin/busybox', 'debug', 'cmd', 'config', 'start', 'su',  'ifconfig', 'ls', 'rm', 'cd',
                 'runshellcmd', 'mkdir', 'kill', 'wget', 'pwd', 'development', 'start-shell', 'vshell', 'exec',
                 'busybox', 'help', 'passwd', 'lscpu', 'ps', 'python', 'apt-get',
                 'screenfetch', 'sudo',
                 'bash', 'clear',  'chmod', 'admin', 'scp',
                 'pkill',  'nohup',   "id", "nproc", "unset", "history",
                 "export", "more", "whoami", "la", "lockr", "chattr",
                 "apt",  "yum", "perl", "chsh","df"]
# "timeout" is a manually added command, included to make capturing output easier
not_2022_comd=["la","whoami","hostname","HELP","EHLO","?","free","openssl","screen","install","touch", "perl", "chsh", "unset", "lockr"]
not_2024_comd=[ "ping", "debug", "cmd", "su", "runshellcmd",  "pwd", "start-shell", "vshell", "python", "apt-get", "screenfetch", "cdd", "admin", "sd", "killSTDIN;", "endScript;", "timeout", "yum"]
comd_2022 = [i for i in comd_all if i not in not_2022_comd]
comd_2024 = [i for i in comd_all if i not in not_2024_comd]
print(len(comd_2022),len(comd_2024))
print(f"2022 : {comd_2022}")
print(f"2024 : {comd_2024}")
