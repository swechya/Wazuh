#!/usr/bin/env python3
"""
wazuh_windows_agent.py - installs and configures a Wazuh agent on Windows.

Does: downloads/installs the agent MSI, enables the audit policy via auditpol
(account logon, account management, logon/logoff, policy change, system),
adds event channels (Security, System, Application, Sysmon, PowerShell),
file integrity monitoring + registry monitoring, restarts WazuhSvc.
Optional: Sysmon.

Usage (elevated PowerShell / cmd, Python 3.8+ installed):
  python wazuh_windows_agent.py --manager 10.0.0.2 [--group default]
       [--agent-name NAME] [--version 4.14.7] [--with-sysmon]
       [--fim-test-mode] [--dry-run]

Safe to re-run: config lives in a marked block and is replaced each time.
(VirusTotal integration is configured on the MANAGER, not on Windows agents.)
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BEGIN = "<!-- BEGIN WAZUH-AUTOMATION (managed block, re-run safe) -->"
END = "<!-- END WAZUH-AUTOMATION -->"
MANAGED_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", re.S)

DRY = False
OSSEC_WIN = Path(r"C:\Program Files (x86)\ossec-agent\ossec.conf")

# --------------------------------------------------------------------------- helpers
def log(msg): print(f"[+] {msg}", flush=True)
def warn(msg): print(f"[!] {msg}", file=sys.stderr, flush=True)


def die(msg, code=1):
    print(f"[x] {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run(cmd, check=True, env=None, shell=False, capture=False):
    shown = cmd if isinstance(cmd, str) else " ".join(cmd)
    if DRY:
        log(f"(dry-run) $ {shown}")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    log(f"$ {shown}")
    p = subprocess.run(
        cmd, shell=shell, env={**os.environ, **(env or {})}, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if check and p.returncode:
        die(f"command failed ({p.returncode}): {shown}\n{p.stdout or ''}")
    return p


def read_conf(path: Path) -> str:
    if not path.exists():
        if DRY:
            return "<ossec_config>\n</ossec_config>\n"
        die(f"{path} not found - is Wazuh installed here?")
    return path.read_text(encoding="utf-8", errors="replace")


def check_xml(text, where):
    try:
        ET.fromstring("<root>" + re.sub(r"<\?xml[^>]*\?>", "", text) + "</root>")
    except ET.ParseError as e:
        die(f"generated XML for {where} is invalid: {e}")


def apply_managed_block(path: Path, inner: str, wrap_ossec_config=True, validate_cmd=None):
    """Replace/append our marked block in `path`; back up; validate; roll back on failure."""
    text = read_conf(path)
    base = MANAGED_RE.sub("", text).rstrip() + "\n"
    body = inner.strip()
    if wrap_ossec_config:
        body = f"<ossec_config>\n{body}\n</ossec_config>"
    new = f"{base}\n{BEGIN}\n{body}\n{END}\n"
    check_xml(new, str(path))
    if DRY:
        log(f"(dry-run) would write to {path}:\n{BEGIN}\n{body}\n{END}")
        return
    bak = path.with_name(path.name + time.strftime(".bak-%Y%m%d-%H%M%S"))
    shutil.copy2(path, bak)
    path.write_text(new, encoding="utf-8")
    log(f"updated {path} (backup: {bak})")
    if validate_cmd:
        p = run(validate_cmd, check=False, capture=True)
        if p.returncode:
            shutil.copy2(bak, path)
            die(f"validation failed, restored backup.\n{p.stdout}")
        log("configuration validation passed")


def unmanaged(text):
    return MANAGED_RE.sub("", text)


def localfile(fmt, location=None, command=None, frequency=None):
    x = f"<localfile>\n  <log_format>{fmt}</log_format>\n"
    if location:
        x += f"  <location>{location}</location>\n"
    if command:
        x += f"  <command>{command}</command>\n"
    if frequency:
        x += f"  <frequency>{frequency}</frequency>\n"
    return x + "</localfile>"


def add_localfiles(existing_text, items):
    """items: (fmt, location|None, command|None, freq|None). Skip ones already configured."""
    out = []
    for fmt, loc, cmd, freq in items:
        key = f"<location>{loc}</location>" if loc else f"<command>{cmd}</command>"
        if key in existing_text:
            log(f"already configured, skipping: {loc or cmd}")
            continue
        out.append(localfile(fmt, loc, cmd, freq))
    return out



AUDIT_CATEGORIES = ["Account Logon", "Account Management", "Logon/Logoff", "Policy Change", "System"]


def cmd_windows_agent(a):
    if os.name != "nt" and not DRY:
        die("windows-agent must be run on Windows")
    import ctypes
    if not DRY and not ctypes.windll.shell32.IsUserAnAdmin():
        die("run from an elevated (Administrator) prompt")
    host = a.agent_name or socket.gethostname()

    log("1/5 install agent MSI")
    msi = Path(tempfile.gettempdir()) / f"wazuh-agent-{a.version}-1.msi"
    url = f"https://packages.wazuh.com/4.x/windows/wazuh-agent-{a.version}-1.msi"
    if DRY:
        log(f"(dry-run) download {url}")
    elif not OSSEC_WIN.exists():
        urllib.request.urlretrieve(url, msi)
    args = ["msiexec.exe", "/i", str(msi), "/q", f'WAZUH_MANAGER={a.manager}',
            f"WAZUH_AGENT_NAME={host}"]
    if a.group:
        args.append(f"WAZUH_AGENT_GROUP={a.group}")
    if DRY or not OSSEC_WIN.exists():
        run(args)

    log("2/5 audit policy (account logon, account mgmt, logon/logoff, policy change, system)")
    for cat in AUDIT_CATEGORIES:
        run(["auditpol", "/set", f"/category:{cat}", "/success:enable", "/failure:enable"])

    if a.with_sysmon:
        log("optional: Sysmon")
        z = Path(tempfile.gettempdir()) / "Sysmon.zip"
        d = Path(tempfile.gettempdir()) / "Sysmon"
        if not DRY:
            urllib.request.urlretrieve("https://download.sysinternals.com/files/Sysmon.zip", z)
            shutil.unpack_archive(str(z), str(d))
        run([str(d / "Sysmon64.exe"), "-accepteula", "-i"], check=False)

    log("3/5 build ossec.conf block")
    existing = unmanaged(read_conf(OSSEC_WIN))
    chans = ["Security", "System", "Application",
             "Microsoft-Windows-Sysmon/Operational",
             "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"]
    blocks = add_localfiles(existing, [("eventchannel", c, None, None) for c in chans])
    freq = 60 if a.fim_test_mode else a.fim_frequency
    blocks.append(f"""<syscheck>
  <disabled>no</disabled>
  <frequency>{freq}</frequency>
  <alert_new_files>yes</alert_new_files>
  <directories check_all="yes">C:\\Wazuh-FIM-Test</directories>
  <directories check_all="yes">C:\\Users</directories>
  <directories check_all="yes">C:\\Program Files</directories>
  <directories check_all="yes">C:\\Windows\\System32</directories>
  <directories realtime="yes">%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup</directories>
  <ignore>%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini</ignore>
  <ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon</windows_registry>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
</syscheck>""")
    if not DRY:
        Path(r"C:\Wazuh-FIM-Test").mkdir(exist_ok=True)

    log("4/5 apply")
    apply_managed_block(OSSEC_WIN, "\n".join(blocks))

    log("5/5 restart service")
    run(["powershell", "-NoProfile", "-Command",
         "Restart-Service WazuhSvc; Get-Service WazuhSvc"])
    log("done. VirusTotal for Windows agents is configured on the manager (run `manager`).")




def main():
    global DRY
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manager", required=True, help="Wazuh manager IP/hostname")
    p.add_argument("--agent-name", help="default: hostname")
    p.add_argument("--group", help="agent group (must already exist on the manager)")
    p.add_argument("--version", default="4.14.7", help="agent MSI version (default 4.14.7)")
    p.add_argument("--fim-frequency", type=int, default=43200, help="FIM scan seconds (default 12h)")
    p.add_argument("--fim-test-mode", action="store_true", help="FIM every 60s for testing")
    p.add_argument("--with-sysmon", action="store_true", help="also install Sysmon")
    p.add_argument("--dry-run", action="store_true", help="print actions, change nothing")
    a = p.parse_args()
    DRY = a.dry_run
    cmd_windows_agent(a)


if __name__ == "__main__":
    main()
