# =====================================================================
# INTEGRATED SECURITY SUITE MODULE RULES (WINDOWS & LINUX)
# Safe, isolated manifest file to prevent main script indent corruption.
# =====================================================================

MODULE_RULES = [
    {
        "id": "SEC-001",
        "title": "Windows Defender System Monitoring",
        "platform": "Windows",
        "severity": "Critical",
        "description": "Verifies real-time behavioral anti-malware tracking is active.",
        "audit_cmd": 'powershell -Command "(Get-MpPreference).DisableRealtimeMonitoring"',
        "expected": "False",
        "fix_cmd": 'powershell -Command "Start-Process powershell -ArgumentList \'Set-MpPreference -DisableRealtimeMonitoring $false\' -Verb RunAs"'
    },
    {
        "id": "SEC-002",
        "title": "Legacy Network Sharing Protocols",
        "platform": "Windows",
        "severity": "Warning",
        "description": "Checks if insecure legacy SMBv1 communication pipelines remain active.",
        "audit_cmd": 'powershell -Command "(Get-SmbServerConfiguration).EnableSMB1Protocol"',
        "expected": "False",
        "fix_cmd": 'powershell -Command "Start-Process powershell -ArgumentList \'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\' -Verb RunAs"'
    },
    {
        "id": "SEC-002W-AV",
        "title": "Windows Defender Malware Scan Baseline",
        "platform": "Windows",
        "severity": "Critical",
        "description": "Checks the system event logs to verify that an explicit full or quick threat scan has completed within the last 7 days.",
        "audit_cmd": 'powershell -Command "$cutoff = (Get-Date).AddDays(-7); if (Get-WinEvent -LogName \'Microsoft-Windows-Windows Defender/Operational\' -FilterXPath \'*[System[(EventID=1001 or EventID=1011 or EventID=1116)]]\' -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $cutoff }) { echo \'Scan Active\' } else { echo \'No Recent Scans\' }"',
        "expected": "Scan Active",
        "fix_cmd": 'powershell -Command "Start-Process powershell -ArgumentList \'Start-MpScan -ScanType QuickScan\' -Verb RunAs"'
    },
    {
        "id": "SEC-003",
        "title": "SSH Direct Root Authentication",
        "platform": "Linux",
        "severity": "Critical",
        "description": "Verifies password-based administrative SSH entry is explicitly blocked.",
        "audit_cmd": "if [ ! -f /etc/ssh/sshd_config ]; then echo 'Not Installed'; elif [ ! -r /etc/ssh/sshd_config ]; then echo 'Access Denied'; else grep '^PermitRootLogin' /etc/ssh/sshd_config; fi",
        "expected": "PermitRootLogin no",
        "fix_cmd": "pkexec sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && pkexec systemctl restart sshd"
    },
    {
        "id": "SEC-004",
        "title": "Local Password Expiration Max Timeline",
        "platform": "Linux",
        "severity": "Warning",
        "description": "Audits if global system login credentials are set to expire within a secure 90-day threshold.",
        "audit_cmd": "grep '^PASS_MAX_DAYS' /etc/login.defs || echo 'PASS_MAX_DAYS 99999'",
        "expected": "PASS_MAX_DAYS 90",
        "fix_cmd": "pkexec sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"
    },
    {
        "id": "SEC-005L-RK",
        "title": "Rootkit Hunter System Scan Logs",
        "platform": "Linux",
        "severity": "Critical",
        "description": "Verifies that an external rootkit audit has run and parses log compliance warnings from rkhunter.",
        "audit_cmd": "if [ ! -f /var/log/rkhunter.log ]; then echo 'Not Installed'; elif grep -i 'warning' /var/log/rkhunter.log > /dev/null; then echo 'Warnings Found'; else echo 'Clean Baseline'; fi",
        "expected": "Clean Baseline",
        "fix_cmd": "pkexec rkhunter --propupd && pkexec rkhunter --check --sk"
    },
    {
        "id": "SEC-006L-AV",
        "title": "ClamAV Antivirus Daemon Status",
        "platform": "Linux",
        "severity": "Warning",
        "description": "Audits if the open-source ClamAV malware tracking infrastructure engine is actively running background tasks.",
        "audit_cmd": "systemctl is-active clamav-daemon 2>/dev/null || echo 'Not Installed'",
        "expected": "active",
        "fix_cmd": "pkexec systemctl enable --now clamav-daemon"
    }
]
