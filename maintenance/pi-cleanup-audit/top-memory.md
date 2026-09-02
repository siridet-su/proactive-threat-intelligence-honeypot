USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
cpe27       1227  0.0 18.2 2053792 1484584 ?     Ssl  Jul05   0:02 /home/cpe27/llama.cpp/build/bin/llama-server -m /home/cpe27/llama.cpp/models/llama_mysql_v3.gguf -c 4096 --host 0.0.0.0 --port 8080 --n-predict 384
root         493  0.1  3.1 449248 257336 ?       S<s  Jul05   3:40 /usr/lib/systemd/systemd-journald
root      113127  0.4  3.1 2228192 256608 ?      Sl   Jul06   5:57 /usr/local/zeek/bin/zeek -i wlan0 -U .status -p zeekctl -p zeekctl-live -p standalone -p local -p zeek local.zeek zeekctl zeekctl/standalone zeekctl/auto
root        1631  0.0  1.0 2127048 83188 ?       Ssl  Jul05   0:19 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1144  1.0  0.8 1354504 68448 ?       Ssl  Jul05  35:09 /usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641
cowrie    141995  0.0  0.8  75864 66476 ?        Ss   06:23   0:10 /home/cowrie/cowrie/cowrie-env/bin/python /home/cowrie/cowrie/cowrie-env/bin/twistd --umask=0022 --pidfile=var/run/cowrie.pid --logger cowrie.python.logfile.logger -n cowrie
root        1248  0.0  0.6 1938880 49136 ?       Ssl  Jul05   1:09 /usr/bin/containerd
root        6109  0.0  0.5 563296 44648 ?        Ssl  Jul05   0:06 /usr/libexec/fwupd/fwupd
root        1139  0.0  0.4 1996700 38720 ?       Ssl  Jul05   0:08 /usr/lib/snapd/snapd
root        1931  0.0  0.3 1854364 31780 ?       Ssl  Jul05   0:04 /bin/ollama serve
cpe27     141989  0.0  0.3  34088 25668 ?        Ss   06:23   0:04 /usr/bin/python3 /home/cpe27/llm_mysql.py
redis       1238  0.1  0.2 189752 23728 ?        Ssl  Jul05   4:56 /usr/bin/redis-server 127.0.0.1:6379
honeypo+  141981  0.1  0.2  29780 23124 ?        Ss   06:23   1:03 /usr/bin/python3 -m production.sensor_forwarder --config /etc/honeypot/production_config.json
honeypo+  141996  0.0  0.2  29788 23040 ?        Ss   06:23   0:17 /usr/bin/python3 -m production.sensor_forwarder
root        1246  0.0  0.2 107928 22076 ?        Ssl  Jul05   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root        1240  0.0  0.2 331060 17820 ?        Ssl  Jul05   0:20 /snap/network-manager/1021/usr/sbin/NetworkManager --config-dir=/var/snap/network-manager/1021/conf.d/ --config=/var/snap/network-manager/1021/NetworkManager.conf --log-level=INFO --no-daemon
root           1  0.1  0.1  23912 14484 ?        Ss   Jul05   4:04 /sbin/init fixrtc
root        1208  0.0  0.1 326528 13424 ?        Ssl  Jul05   0:00 /usr/sbin/ModemManager
cpe27     141990  0.0  0.1  19172 12988 ?        Ss   06:23   0:32 /usr/bin/python3 /home/cpe27/dashboard-honeypot/server/plugin/convertData/Honeypot_Log_Processor.py
root        1145  0.0  0.1 472528 12608 ?        Ssl  Jul05   0:02 /usr/libexec/udisks2/udisksd
systemd+     951  0.0  0.1  21488 12456 ?        Ss   Jul05   0:09 /usr/lib/systemd/systemd-resolved
cpe27      69259  0.0  0.1  21256 11904 ?        Ss   Jul06   0:00 /usr/lib/systemd/systemd --user
root        1162  0.0  0.1  17516 10792 ?        Ss   Jul05   0:01 /usr/sbin/wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev
root        1909  0.0  0.1 1233248 10596 ?       Sl   Jul05   0:12 /usr/bin/containerd-shim-runc-v2 -namespace moby -id 650a16e3a631dc6d8057d253454e4a74e26301ea87a926f1d63c3ef9ba6cd753 -address /run/containerd/containerd.sock
cpe27     188201  3.6  0.1  16092 10352 ?        Rs   21:27   0:00 /usr/bin/python3 /home/cpe27/discord-bot/bot.py
root        1143  0.0  0.1  19548  9712 ?        Ss   Jul05   0:19 /usr/lib/systemd/systemd-logind
root      186231  0.0  0.1  16296  8876 ?        Ss   20:57   0:00 sshd: cpe27 [priv]
cpe27     186315  0.0  0.1   9604  8804 pts/0    Ss   20:57   0:00 -bash
root         559  0.0  0.0  28788  7884 ?        Ss   Jul05   0:00 /usr/lib/systemd/systemd-udevd
polkitd     1135  0.0  0.0 309068  7492 ?        Ssl  Jul05   0:04 /usr/lib/polkit-1/polkitd --no-debug
root        6712  0.0  0.0  12048  7288 ?        Ss   Jul05   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
systemd+     959  0.0  0.0  90892  7116 ?        Ssl  Jul05   0:00 /usr/lib/systemd/systemd-timesyncd
cpe27     186312  0.0  0.0  16552  6456 ?        S    20:57   0:00 sshd: cpe27@pts/0
root       69321  0.0  0.0  14708  5804 ?        S    Jul06   0:00 sudo grep -RniE INGEST_URL|100\.122\.213\.37|8080/events /etc /opt/honeypot-forwarder /home/cowrie
syslog      1156  0.0  0.0 222812  5568 ?        Ssl  Jul05   1:03 /usr/sbin/rsyslogd -n -iNONE
message+    1132  0.0  0.0  10256  4992 ?        Ss   Jul05   1:02 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root        1957  0.0  0.0 1671360 4156 ?        Sl   Jul05   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 11434 -container-ip 172.17.0.2 -container-port 11434 -use-listen-fd
root        1964  0.0  0.0 1671360 4036 ?        Sl   Jul05   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 11434 -container-ip 172.17.0.2 -container-port 11434 -use-listen-fd
cpe27     188203  100  0.0   8164  3968 pts/0    R+   21:27   0:00 ps aux --sort=-%mem
