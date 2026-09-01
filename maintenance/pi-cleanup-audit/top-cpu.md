USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
cpe27     188205  100  0.0   8164  3964 pts/0    R+   21:27   0:00 ps aux --sort=-%cpu
cpe27     188201  5.9  0.1  17496 11888 ?        Rs   21:27   0:00 /usr/bin/python3 /home/cpe27/discord-bot/bot.py
root        1144  1.0  0.8 1354504 68448 ?       Ssl  Jul05  35:09 /usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641
root      113127  0.4  3.1 2228192 256608 ?      Sl   Jul06   5:57 /usr/local/zeek/bin/zeek -i wlan0 -U .status -p zeekctl -p zeekctl-live -p standalone -p local -p zeek local.zeek zeekctl zeekctl/standalone zeekctl/auto
redis       1238  0.1  0.2 189752 23728 ?        Ssl  Jul05   4:56 /usr/bin/redis-server 127.0.0.1:6379
root           1  0.1  0.1  23912 14484 ?        Ss   Jul05   4:04 /sbin/init fixrtc
honeypo+  141981  0.1  0.2  29780 23124 ?        Ss   06:23   1:03 /usr/bin/python3 -m production.sensor_forwarder --config /etc/honeypot/production_config.json
root      187797  0.1  0.0      0     0 ?        I    21:17   0:00 [kworker/0:3-events]
root         493  0.1  3.1 449248 257336 ?       S<s  Jul05   3:40 /usr/lib/systemd/systemd-journald
root          75  0.1  0.0      0     0 ?        I<   Jul05   3:36 [kworker/u9:0-brcmf_wq/mmc1:0001:1]
root      187539  0.0  0.0      0     0 ?        I    21:11   0:00 [kworker/0:0-events]
root      187219  0.0  0.0      0     0 ?        I    21:04   0:00 [kworker/0:1-cgroup_release]
cpe27     141990  0.0  0.1  19172 12988 ?        Ss   06:23   0:32 /usr/bin/python3 /home/cpe27/dashboard-honeypot/server/plugin/convertData/Honeypot_Log_Processor.py
root        1248  0.0  0.6 1938880 49136 ?       Ssl  Jul05   1:09 /usr/bin/containerd
honeypo+  141996  0.0  0.2  29788 23040 ?        Ss   06:23   0:17 /usr/bin/python3 -m production.sensor_forwarder
syslog      1156  0.0  0.0 222812  5568 ?        Ssl  Jul05   1:03 /usr/sbin/rsyslogd -n -iNONE
message+    1132  0.0  0.0  10256  4992 ?        Ss   Jul05   1:02 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root      187827  0.0  0.0      0     0 ?        I    21:18   0:00 [kworker/2:2-events]
root      188001  0.0  0.0      0     0 ?        I    21:22   0:00 [kworker/u8:0-ext4-rsv-conversion]
root      187622  0.0  0.0      0     0 ?        I    21:13   0:00 [kworker/u8:1-events_power_efficient]
root      187354  0.0  0.0      0     0 ?        I    21:07   0:00 [kworker/2:0-events]
cowrie    141995  0.0  0.8  75864 66476 ?        Ss   06:23   0:10 /home/cowrie/cowrie/cowrie-env/bin/python /home/cowrie/cowrie/cowrie-env/bin/twistd --umask=0022 --pidfile=var/run/cowrie.pid --logger cowrie.python.logfile.logger -n cowrie
root          17  0.0  0.0      0     0 ?        I    Jul05   0:37 [rcu_preempt]
root      182494  0.0  0.0      0     0 ?        I    19:38   0:01 [kworker/u8:3-events_power_efficient]
root      184420  0.0  0.0      0     0 ?        I    20:15   0:00 [kworker/u8:4-flush-179:0]
root      181375  0.0  0.0      0     0 ?        I    19:12   0:01 [kworker/u8:2-events_unbound]
root      188063  0.0  0.0      0     0 ?        I    21:24   0:00 [kworker/0:2-events]
root         416  0.0  0.0      0     0 ?        S    Jul05   0:27 [jbd2/mmcblk0p2-8]
root         824  0.0  0.0      0     0 ?        S    Jul05   0:24 [brcmf_wdog/mmc1:0001:1]
root      184247  0.0  0.0      0     0 ?        I<   20:11   0:00 [kworker/0:2H-mmc_complete]
root        1240  0.0  0.2 331060 17820 ?        Ssl  Jul05   0:20 /snap/network-manager/1021/usr/sbin/NetworkManager --config-dir=/var/snap/network-manager/1021/conf.d/ --config=/var/snap/network-manager/1021/NetworkManager.conf --log-level=INFO --no-daemon
root      185294  0.0  0.0      0     0 ?        I    20:35   0:00 [kworker/1:1-events]
root        1143  0.0  0.1  19548  9712 ?        Ss   Jul05   0:19 /usr/lib/systemd/systemd-logind
root      187220  0.0  0.0      0     0 ?        I    21:04   0:00 [kworker/1:2-mm_percpu_wq]
root      188125  0.0  0.0      0     0 ?        I    21:25   0:00 [kworker/2:1-events]
root        1631  0.0  1.0 2127048 83188 ?       Ssl  Jul05   0:19 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root      127757  0.0  0.0      0     0 ?        I<   02:12   0:06 [kworker/3:2H-kblockd]
cpe27     186312  0.0  0.0  16552  6456 ?        S    20:57   0:00 sshd: cpe27@pts/0
root        4312  0.0  0.0      0     0 ?        I<   Jul05   0:17 [kworker/1:2H-kblockd]
