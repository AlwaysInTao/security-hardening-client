import os
import platform
import subprocess
import hashlib
import threading
import time
import flet as ft

DEFAULT_RULES = [
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
        },
    {
        "id": "SEC-007L-FW",
        "title": "Uncomplicated Firewall (UFW) Status",
        "platform": "Linux",
        "severity": "Critical",
        "description": "Audits whether the system-wide Uncomplicated Firewall configuration layer is operational and active.",
        "audit_cmd": "systemctl is-active ufw 2>/dev/null || echo 'inactive'",
        "expected": "active",
        "fix_cmd": "pkexec ufw enable"
        },
    {
        "id": "SEC-008L-NET",
        "title": "Unencrypted Listening Network Ports",
        "platform": "Linux",
        "severity": "Warning",
        "description": "Scans local listening network sockets to ensure insecure legacy management ports (80, 21, 23) are not exposed.",
        "audit_cmd": "ss -tlnp | grep -E ':(21|23|80) ' || echo 'No Insecure Ports'",
        "expected": "No Insecure Ports",
        "fix_cmd": "echo 'Manual investigation required: Use ss -tlnp to identify the active process.'"
    }
]

def main(page: ft.Page):
    page.title = "System Security Audit & Hardening Client"
    page.window_width = 1100
    page.window_height = 750
    page.window_resizable = False
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#12141c"

    current_os = platform.system()
    active_rules = [r for r in DEFAULT_RULES if r["platform"] == current_os]
    rule_controls = {}

    score_text = ft.Text("100%", size=38, weight=ft.FontWeight.BOLD, color="#22c55e")
    critical_count = ft.Text("0 Critical Alerts", color="#ef4444", size=14)
    warning_count = ft.Text("0 Warnings", color="#f59e0b", size=14)
    secure_count = ft.Text("0 Secure Items", color="#10b981", size=14)
    results_list = ft.ListView(expand=True, spacing=10, padding=10)
    audit_button = ft.Button("RUN SECURITY AUDIT", icon="refresh", width=280, height=50)
    
    # Visible-by-default tracking text, and blue loading bar indicator
    progress_bar = ft.ProgressBar(width=450, color="#3b82f6", bgcolor="#24293e", value=0)
    progress_status = ft.Text("System Idle", size=13, color="#9ca3af")

    def verify_license_key(username, key):
        username_clean = username.strip().lower()
        key_clean = key.strip().lower()
        if not username_clean or not key_clean: return False
        if "-" in key_clean: key_clean = key_clean.split("-")[-1]
        secret_salt = "HardeningClient2026_Secure"
        expected_hash = hashlib.sha256(f"{username_clean}{secret_salt}".encode()).hexdigest()[:8]
        return key_clean == expected_hash

    def check_registration(e):
        if verify_license_key(user_input.value, key_input.value):
            with open(".activated", "w") as f_act:
                f_act.write(f"{user_input.value.strip().lower()}\n{key_input.value.strip().lower()}")
            page.controls.clear()
            reveal_dashboard()
            trigger_audit_thread()
        else:
            error_text.visible = True
            page.update()

    user_input = ft.TextField(label="Registered Username/Email", width=300)
    key_input = ft.TextField(label="License Key", width=300)
    error_text = ft.Text("Invalid License Key or Username Combination", color="#ef4444", visible=False)

    def calculate_health():
        failed_critical = 0
        failed_warning = 0
        passed = 0
        for r_id, ctrl_set in rule_controls.items():
            status = ctrl_set["status_tag"].value
            if "FAIL" in status or "RESTRICTED" in status:
                if ctrl_set["severity"] == "Critical": failed_critical += 1
                else: failed_warning += 1
            else:
                passed += 1
        critical_count.value = f"{failed_critical} Critical Alerts"
        warning_count.value = f"{failed_warning} Warnings"
        secure_count.value = f"{passed} Secure Items"
        
        penalty = (failed_critical * 25) + (failed_warning * 15)
        final_score = max(0, 100 - penalty)
        score_text.value = f"{final_score}%"
        if final_score >= 80: score_text.color = "#22c55e"
        elif final_score >= 50: score_text.color = "#f59e0b"
        else: score_text.color = "#ef4444"
        page.update()

    def native_audit_worker():
        audit_button.disabled = True
        audit_button.text = "SCANNING SYSTEM..."
        progress_bar.value = 0
        results_list.controls.clear()
        page.update()
        
        total_rules = len(active_rules)
        
        for index, rule in enumerate(active_rules):
            # Controlled delay so the user registers the scanning behavior step-by-step
            progress_status.value = f"Analyzing module {index + 1}/{total_rules}: {rule['title']}..."
            page.update()
            time.sleep(0.6) 
            
            try:
                proc = subprocess.run(rule["audit_cmd"], shell=True, capture_output=True, text=True, timeout=5)
                output = proc.stdout.strip()
                if "Not Installed" in output:
                    status_str = "⚪ ABSENT (Service Missing)"
                    status_color = "#9ca3af"
                    show_fix = False
                elif "Access Denied" in output:
                    status_str = "🔒 RESTRICTED (Elevate to Scan)"
                    status_color = "#f59e0b"
                    show_fix = True
                elif rule["expected"].lower() in output.lower() or (rule["expected"] == "False" and not output):
                    status_str = "🟢 SECURE"
                    status_color = "#10b981"
                    show_fix = False
                else:
                    status_str = f"🔴 FAIL ({rule['severity']})"
                    status_color = "#ef4444"
                    show_fix = True
            except Exception:
                status_str = "⚠️ ERROR"
                status_color = "#f59e0b"
                show_fix = False

            status_tag = ft.Text(status_str, color=status_color, weight=ft.FontWeight.BOLD)
            btn_label = "Elevate & Scan" if "RESTRICTED" in status_str else "Fix Issue"
            fix_btn = ft.Button(btn_label, visible=show_fix, on_click=lambda x, r=rule: execute_remediation(r))
            rule_controls[rule["id"]] = {"status_tag": status_tag, "fix_btn": fix_btn, "severity": rule["severity"]}

            card = ft.Card(
                content=ft.Container(
                    bgcolor="#1e2230",
                    content=ft.Column([
                        ft.Row([ft.Text(rule["title"], size=16, weight=ft.FontWeight.W_600), status_tag], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(rule["description"], size=13, color="#9ca3af"),
                        ft.Row([fix_btn], alignment=ft.MainAxisAlignment.END)
                    ]),
                    padding=15
                )
            )
            results_list.controls.append(card)
            
            # Increment the visual loading bar increments perfectly based on item sequence
            progress_bar.value = (index + 1) / total_rules
            page.update()
        
        time.sleep(0.4)
        progress_status.value = "Scan Complete"
        progress_bar.value = 1.0
        audit_button.disabled = False
        audit_button.text = "RUN SECURITY AUDIT"
        calculate_health()
        page.update()

    def auto_refresh_worker():
        while True:
            # Sleep for 60 seconds before triggering the next audit pass
            time.sleep(60)
            # Only trigger if the button isn't currently disabled (meaning a scan is already running)
            if not audit_button.disabled:
                trigger_audit_thread()

    def trigger_audit_thread(e=None):
        # Utilizes Flet's internal window runner loop to bypass desktop window state freezing
        page.run_thread(native_audit_worker)

    audit_button.on_click = trigger_audit_thread

    def execute_remediation(rule):
        if "RESTRICTED" in rule_controls[rule["id"]]["status_tag"].value:
            elevated_cmd = f"pkexec grep '{rule['expected']}' /etc/ssh/sshd_config"
            proc = subprocess.run(elevated_cmd, shell=True, capture_output=True, text=True)
            if rule["expected"].lower() in proc.stdout.strip().lower():
                rule_controls[rule["id"]]["status_tag"].value = "🟢 SECURE"
                rule_controls[rule["id"]]["status_tag"].color = "#10b981"
                rule_controls[rule["id"]]["fix_btn"].visible = False
                calculate_health()
                return
        subprocess.run(rule["fix_cmd"], shell=True)
        trigger_audit_thread()

    left_panel = ft.Container(
        width=320, bgcolor="#161925", padding=25, border_radius=10,
        content=ft.Column([
            ft.Text("SYSTEM MONITOR", size=12, weight=ft.FontWeight.BOLD, color="#6b7280"),
            ft.Text(f"Host: {platform.node()}", size=16, weight=ft.FontWeight.BOLD),
            ft.Text(f"Platform: {current_os}", size=13, color="#9ca3af"),
            ft.Divider(color="#24293e", height=30),
            ft.Text("HEALTH SCORE", size=12, weight=ft.FontWeight.BOLD, color="#6b7280"),
            ft.Container(content=score_text, alignment=ft.Alignment(0, 0), padding=10),
            ft.Divider(color="#24293e", height=30),
            critical_count, warning_count, secure_count,
            ft.Container(expand=True),
            audit_button
        ], spacing=10)
    )

    right_panel = ft.Container(
        expand=True, bgcolor="#161925", padding=20, border_radius=10,
        content=ft.Column([
            ft.Row([
                ft.Text("DIAGNOSTIC COMPLIANCE LOGS", size=14, weight=ft.FontWeight.BOLD, color="#6b7280"),
                ft.Column([progress_status, progress_bar], horizontal_alignment=ft.CrossAxisAlignment.END, spacing=5)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#24293e"),
            results_list
        ])
    )

    main_layout_row = ft.Row([left_panel, right_panel], spacing=15)

    def reveal_dashboard():
        page.add(ft.Container(padding=15, expand=True, content=main_layout_row))
        page.update()
        # Start the background automatic refresh timer thread
        page.run_thread(auto_refresh_worker)

    if os.path.exists(".activated"):
        reveal_dashboard()
        trigger_audit_thread()
    else:
        page.add(
            ft.Container(
                expand=True, alignment=ft.Alignment(0, 0),
                content=ft.Card(
                    content=ft.Container(
                        bgcolor="#161925",
                        content=ft.Column([
                            ft.Text("🛡️ Product Registration Required", size=20, weight=ft.FontWeight.BOLD),
                            ft.Text("Please sign in with your license key to unlock the application panel.", size=13, color="#9ca3af"),
                            ft.Divider(color="#24293e"),
                            user_input, key_input, error_text,
                            ft.Container(height=10),
                            ft.Button("Activate Client", width=300, on_click=check_registration)
                        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                        padding=30
                    )
                )
            )
        )
        page.update()


def run_app():
    import flet as ft
    ft.app(target=main)

if __name__ == "__main__":
    run_app()
