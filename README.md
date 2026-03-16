Analyzing a system through the OSI (Open Systems Interconnection) model is a methodical way to hunt for compromises. It forces you to look beyond simple "malware scans" and examine the actual behavior of the machine from the physical wire up to the user interface. 

Layer 1: Physical
The Goal: Ensure no rogue hardware is attached (e.g., Keyloggers, USB Rubber Duckies, or unauthorized network taps).

Windows: Check Device Manager (devmgmt.msc) for "HID Keyboard Device" entries that don't match your hardware.
Linux: Use lsusb to list all USB devices. If you see a "Keyboard" or "Storage" device you don't recognize, it’s a red flag.
lsusb -v (For detailed descriptors).

Layer 2: Data Link
The Goal: Detect ARP Spoofing or Man-in-the-Middle (MitM) attacks where another device on the local network is impersonating your gateway.

Windows: Run arp -a. Look for multiple IP addresses sharing the same Physical (MAC) Address—specifically your default gateway.
Linux: Run ip neigh or arp -n. Similar to Windows, look for duplicate MAC addresses for different IPs on your local subnet.

Layers 3 & 4: Network and Transport
The Goal: Identify unauthorized outbound connections (Reverse Shells) or unexpected listening services (Backdoors).

Windows:
netstat -ano | findstr ESTABLISHED: Shows all active connections. Cross-reference the PID (Process ID) with Task Manager.
route print: Ensure no rogue persistent routes are redirecting your traffic.
Linux:
ss -tunap: (The modern netstat). This shows all TCP/UDP connections, the process name, and the PID.
ip route: Check for any "extra" gateways or static routes.

Layers 5, 6, & 7: Session, Presentation, and Application
The Goal: Find the "Brain" of the attack—malicious processes, unauthorized persistence (startup scripts), and tampered logs.

1. Process Hunting
Windows: Use PowerShell to find processes running from unusual locations (like \Temp\) or without a description:
Get-Process | Where-Object {$_.Path -notlike "C:\Windows*"}
Linux: Look for processes with high CPU usage or those hidden from the process tree.
ps -auxwf: Shows a forest view of processes. Look for "orphaned" processes or weird names like kworker (standard) vs kworker_net (potentially sus).

2. Persistence Mechanisms
Windows: Check the Registry and Task Scheduler.
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Linux: Check Cron jobs and Systemd services.
ls -la /etc/cron.*
systemctl list-unit-files --state=enabled

3. Log Integrity (The Paper Trail)
Windows: Check Event Viewer (eventvwr.msc). Look for "Event ID 1102" (The audit log was cleared)—a massive red flag.
Linux: Check /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS) for failed SSH attempts or unexpected sudo usage.
tail -n 100 /var/log/auth.log
