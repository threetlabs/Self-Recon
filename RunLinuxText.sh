#!/bin/bash
echo -e "\e[36m--- OSI Layer 1-7 System Audit ---\e[0m"

# L1: Physical
echo -e "\e[33m[L1] USB Devices:\e[0m"
lsusb | grep -iE "keyboard|storage|human"

# L2: Data Link
echo -e "\e[33m[L2] ARP Table (Check for duplicate HW addresses):\e[0m"
ip neigh show | awk '{print $5}' | sort | uniq -c | awk '$1 > 1 {print "WARNING: Duplicate MAC detected: "$2}'

# L3/4: Network & Transport
echo -e "\e[33m[L3/4] Active Network Sockets (Non-local):\e[0m"
ss -tunap | grep ESTAB | grep -v "127.0.0.1"

# L5-7: Application & Session
echo -e "\e[33m[L5-7] Suspicious Hidden Processes:\e[0m"
# Finds processes that are running but don't have a visible binary on disk (common in memory-only malware)
ls -la /proc/*/exe 2>/output.txt | grep "deleted"

echo -e "\e[33m[L5-7] Checking Cron Persistence:\e[0m"
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#'; done
ls -la /etc/cron.*
