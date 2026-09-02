#!/bin/bash
# Script to update Honeypot Threat Intel Signatures (JA3, HASSH)
# Runs as cron job on Host OS (Isolated from Cowrie)

DIR="/home/cpe27/honeypot-pipeline/lookups"
mkdir -p "$DIR"

echo "[$(date)] Updating Threat Intel Signatures..."

# Download latest JA3 fingerprints
curl -sL "https://raw.githubusercontent.com/salesforce/ja3/master/lists/ja3_fingerprints.csv" -o "$DIR/ja3.csv.tmp"
if [ -s "$DIR/ja3.csv.tmp" ]; then
    mv "$DIR/ja3.csv.tmp" "$DIR/ja3.csv"
    echo "[+] JA3 updated successfully."
else
    echo "[-] Failed to download JA3."
fi

# Download latest HASSH fingerprints
curl -sL "https://raw.githubusercontent.com/salesforce/hassh/master/fingerprints/hassh_fingerprints.csv" -o "$DIR/hassh.csv.tmp"
if [ -s "$DIR/hassh.csv.tmp" ]; then
    mv "$DIR/hassh.csv.tmp" "$DIR/hassh.csv"
    echo "[+] HASSH updated successfully."
else
    echo "[-] Failed to download HASSH."
fi

# Restart processor-agent to reload lookups into memory
systemctl restart honeypot-processor
echo "[+] Processor agent restarted to load new signatures."
