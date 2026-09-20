#!/bin/bash
# Remove SelectMenu import from Calendar.tsx since we're writing a custom one
sed -i '/import { SelectMenu }/d' /home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/Calendar.tsx
