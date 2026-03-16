Write-Host "--- OSI Layer 1-7 System Audit ---" -ForegroundColor Cyan

# L1: Physical (Check for new HID/USB devices)
Write-Host "[L1] Checking for unauthorized USB/HID devices..." -NoNewline
$hid = Get-PnpDevice -Class 'Keyboard','Mouse' -Status OK | Select-Object FriendlyName
if ($hid) { $hid | Out-String } else { Write-Host " Clean" -ForegroundColor Green }

# L2: Data Link (ARP Spoofing Check)
Write-Host "[L2] Checking for ARP Spoofing (Duplicate MACs)..."
$arp = arp -a | Select-String "dynamic"
$duplicates = $arp | Group-Object { $_.ToString().Split()[-1] } | Where-Object { $_.Count -gt 1 }
if ($duplicates) { Write-Host "!! Warning: Duplicate MAC addresses found !!" -ForegroundColor Red } else { Write-Host " Clean" -ForegroundColor Green }

# L3/4: Network & Transport (Foreign Established Connections)
Write-Host "[L3/4] Scanning for active outbound connections..."
$conns = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike "127.0.0.1" -and $_.RemoteAddress -notlike "::1" }
foreach ($c in $conns) {
    $proc = Get-Process -Id $c.OwningProcess
    Write-Host " Connection: $($c.RemoteAddress):$($c.RemotePort) -> Process: $($proc.ProcessName) (PID: $($c.OwningProcess))" -ForegroundColor Yellow
}

# L5-7: Application/Session (Unsigned Processes & Scheduled Tasks)
Write-Host "[L5-7] Identifying unsigned processes in User Profile..."
Get-Process | Where-Object { $_.Path -like "*\Users\*" } | Select-Object ProcessName, Path | Out-String

Write-Host "[L5-7] Checking for suspicious Scheduled Tasks..."
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName, TaskPath
