# Honeypot Node Cleanup & Migration Log
**Date:** 2026-07-12
**Objective:** Clean up the local edge node, remove unused services, and prepare the architecture for a Cloud migration (MongoDB Atlas, Redis, Zeek).

## 1. System Services Audit & Cleanup
Identified and completely removed old, unused systemd services to free up resources and prevent conflicts.

**Services Stopped & Disabled:**
- `backend.service` (Node.js Backend)
- `bot.service` (Discord Bot)
- `ngrok.service` (Ngrok Tunneling)

**Service Configuration Files Removed from `/etc/systemd/system/`:**
- `backend.service`
- `bot.service`
- `ngrok.service`
- `honeypot-sensor-forwarder-main.service` (Old inactive forwarder)
- `wireshark-plugins.service` (Replaced by Zeek plan)

*(Note: The exact contents of these removed service files were backed up safely before deletion).*

## 2. Source Code Backup
Before deleting any files, a full backup of the source code and database was created.
- **Backup File:** `full_backend_backup.tar.gz`
- **Contents:** 
  - `dashboard-honeypot/` (React Frontend + Node.js Backend)
  - `discord-bot/` (Python Bot)
  - `go-agent/` (Go Data Pipeline Agent)
  - `llm_mysql.py` (MySQL LLM Honeypot Script)
  - `HeneyPot.db` (The SQLite Database - 43MB)

## 3. Directory Cleanup
Removed the unused code directories from the `/home/cpe27/` root to reclaim space and maintain a clean environment.
- Deleted: `/home/cpe27/dashboard-honeypot/`
- Deleted: `/home/cpe27/discord-bot/`

**Preserved Directories:**
- `go-agent/`: Kept intact as it will be repurposed for filtering and pushing data to MongoDB Atlas.
- `llama.cpp/` & `cowrie/`: Core honeypot services running perfectly.

## 4. Audit Organization
- Moved `dashboard_backup.tar.gz` and `full_backend_backup.tar.gz` into `/home/cpe27/pi-cleanup-audit/` to keep the home directory clean and organized.

---
## Next Steps (Architecture V2)
1. Write Go logic in `go-agent` to connect to MongoDB Atlas.
2. Setup Redis as a buffer for LLM data ingestion.
3. Install and configure Zeek for Network Threat Intelligence.
