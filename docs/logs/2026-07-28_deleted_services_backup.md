# Deleted Systemd Services Backup

This file contains the configuration of the systemd services that were deleted from `/etc/systemd/system/` during the cleanup process. You can use these details to recreate them if needed in the future.

## 1. backend.service
```ini
[Unit]
Description=My Node.js Backend Server

[Service]
ExecStart=/usr/bin/node /home/cpe27/dashboard-honeypot/server/API/socket/server.js
```

## 2. bot.service
```ini
[Unit]
Description=Discord Bot Service

[Service]
ExecStart=/usr/bin/python3 /home/cpe27/discord-bot/bot.py
```

## 3. ngrok.service
```ini
[Unit]
Description=Ngrok Tunnel

[Service]
ExecStart=/snap/bin/ngrok http 3000 --config /home/cpe27/snap/ngrok/current/.config/ngrok/ngrok.yml
```

## 4. honeypot-sensor-forwarder-main.service (Previously inactive)
```ini
[Unit]
Description=Honeypot Sensor Forwarder - Cowrie main log to GCP

[Service]
ExecStart=/usr/bin/python3 -m production.sensor_forwarder
```

## 5. wireshark-plugins.service (Previously inactive)
```ini
[Unit]
Description=Wireshark Honeypot Plugins

[Service]
ExecStart=/home/cpe27/dashboard-honeypot/server/plugin/wireshark/start_all.sh
```
