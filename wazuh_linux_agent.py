#!/usr/bin/env python3
"""
wazuh_linux_agent.py - installs and configures a Wazuh agent on Ubuntu/Debian.

Does: agent install (apt, keyring-based), auditd wget rule (key wget_exec),
log sources (auth, syslog, kern, dpkg, apt, audit, journald, apache, df/last),
file integrity monitoring, realtime /tmp for VirusTotal, delete-vt-test.sh
active-response script. Optional: Sysmon for Linux, CloudStack log sources.

Usage (as root):
  sudo python3 wazuh_linux_agent.py --manager 10.0.0.2 [--group default]
       [--agent-name NAME] [--version 4.14.7-1] [--with-sysmon]
       [--cloudstack-logs] [--fim-test-mode] [--dry-run]

Safe to re-run: config lives in a marked block, files are backed up, and a
failed validation restores the backup.
(VirusTotal integration, rules and active-response commands are configured on
the MANAGER by wazuh_automate.py's `manager` subcommand.)
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

AR_TEST_FILE = "/tmp/vt-safe-test.txt"
DRY = False
OSSEC_LINUX = Path("/var/ossec/etc/ossec.conf")

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


def need_root():
    if not DRY and hasattr(os, "geteuid") and os.geteuid() != 0:
        die("run as root (sudo)")


def os_release():
    d = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k] = v.strip('"')
    except OSError:
        pass
    return d


def need_apt():
    if not shutil.which("apt-get") and not DRY:
        die("this script supports Debian/Ubuntu (apt) only")


_apt_updated = False


def apt_install(*pkgs, env=None):
    global _apt_updated
    if not _apt_updated:
        run(["apt-get", "update", "-y"])
        _apt_updated = True
    run(["apt-get", "install", "-y", *pkgs],
        env={"DEBIAN_FRONTEND": "noninteractive", **(env or {})})


def add_apt_repo(name, key_url, line):
    """Modern keyring-based repo (apt-key is deprecated on Ubuntu 22.04+/24.04)."""
    global _apt_updated
    keyring = f"/usr/share/keyrings/{name}.gpg"
    run(f"curl -fsSL {key_url} | gpg --dearmor --yes -o {keyring}", shell=True)
    entry = f"deb [signed-by={keyring}] {line}\n"
    if DRY:
        log(f"(dry-run) write /etc/apt/sources.list.d/{name}.list: {entry.strip()}")
    else:
        Path(f"/etc/apt/sources.list.d/{name}.list").write_text(entry)
    _apt_updated = False


def pkg_installed(pkg):
    return subprocess.run(["dpkg", "-s", pkg], capture_output=True).returncode == 0


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


def restart_linux(service):
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", service])
    run(["systemctl", "restart", service])



# --------------------------------------------------------------------------- Linux agent
WGET_AUDIT_RULE = ("-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -k wget_exec\n"
                   "-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/wget -k wget_exec\n")

DELETE_VT_SCRIPT = f"""#!/bin/bash
# Active response: delete ONLY the VirusTotal safe-test file, then log it.
LOG=/var/ossec/logs/active-responses.log
TARGET={AR_TEST_FILE}
read -r INPUT
if echo "$INPUT" | grep -q "\\"path\\":\\"$TARGET\\"" && [ -f "$TARGET" ]; then
  rm -f "$TARGET"
  echo "$(date '+%Y/%m/%d %H:%M:%S') delete-vt-test: SAFE TEST: Deleted $TARGET" >> "$LOG"
fi
exit 0
"""


def install_sysmon_linux():
    rel = os_release()
    if rel.get("ID") not in ("ubuntu", "debian"):
        warn("Sysmon for Linux step skipped: unsupported distro")
        return
    deb = "/tmp/packages-microsoft-prod.deb"
    run(f"curl -fsSL -o {deb} https://packages.microsoft.com/config/{rel['ID']}/"
        f"{rel.get('VERSION_ID', '')}/packages-microsoft-prod.deb", shell=True)
    run(["dpkg", "-i", deb])
    run(["apt-get", "update", "-y"])
    apt_install("sysmonforlinux")
    run(["sysmon", "-accepteula", "-i"], check=False)


def cmd_linux_agent(a):
    need_root()
    need_apt()
    host = a.agent_name or socket.gethostname()

    log("1/7 prerequisites")
    apt_install("gnupg", "apt-transport-https", "curl", "auditd", "audispd-plugins")

    log("2/7 Wazuh agent")
    if pkg_installed("wazuh-agent"):
        log("wazuh-agent already installed")
    else:
        add_apt_repo("wazuh", "https://packages.wazuh.com/key/GPG-KEY-WAZUH",
                     "https://packages.wazuh.com/4.x/apt/ stable main")
        env = {"WAZUH_MANAGER": a.manager, "WAZUH_AGENT_NAME": host}
        if a.group:
            env["WAZUH_AGENT_GROUP"] = a.group
        apt_install("wazuh-agent" + (f"={a.version}" if a.version else ""), env=env)

    log("3/7 auditd rule for wget (key wget_exec)")
    if DRY:
        log("(dry-run) write /etc/audit/rules.d/wazuh-wget.rules")
    else:
        Path("/etc/audit/rules.d/wazuh-wget.rules").write_text(WGET_AUDIT_RULE)
    run(["augenrules", "--load"], check=False)
    run(["systemctl", "enable", "--now", "auditd"], check=False)

    if a.with_sysmon:
        log("optional: Sysmon for Linux")
        install_sysmon_linux()

    log("4/7 active-response script (delete-vt-test.sh)")
    ar = Path("/var/ossec/active-response/bin/delete-vt-test.sh")
    if DRY:
        log(f"(dry-run) write {ar}")
    else:
        ar.write_text(DELETE_VT_SCRIPT)
        ar.chmod(0o750)
        shutil.chown(ar, "root", "wazuh")

    log("5/7 build ossec.conf block")
    existing = unmanaged(read_conf(OSSEC_LINUX))
    items = [
        ("syslog", "/var/log/auth.log", None, None),
        ("syslog", "/var/log/syslog", None, None),
        ("syslog", "/var/log/kern.log", None, None),
        ("syslog", "/var/log/dpkg.log", None, None),
        ("syslog", "/var/log/apt/history.log", None, None),
        ("audit", "/var/log/audit/audit.log", None, None),
        ("journald", "journald", None, None),
        ("syslog", "/var/ossec/logs/active-responses.log", None, None),
        ("command", None, "df -P", 360),
        ("full_command", None, "last -n 20", 360),
    ]
    if DRY or Path("/var/log/apache2").exists():
        items += [("apache", "/var/log/apache2/access.log", None, None),
                  ("apache", "/var/log/apache2/error.log", None, None)]
    if a.cloudstack_logs:
        items += [("syslog", "/var/log/cloudstack/management/management-server.log", None, None),
                  ("syslog", "/var/log/cloudstack/agent/agent.log", None, None)]
    blocks = add_localfiles(existing, items)

    freq = 60 if a.fim_test_mode else a.fim_frequency
    dirs = ["/etc,/usr/bin,/usr/sbin", "/bin,/sbin,/boot", "/home", "/var/www"]
    fim = [f'  <directories check_all="yes">{d}</directories>'
           for d in dirs if DRY or all(Path(p).exists() for p in d.split(","))]
    fim.append('  <directories realtime="yes" check_all="yes">/tmp</directories>  <!-- VirusTotal / AR -->')
    blocks.append(
        "<syscheck>\n  <disabled>no</disabled>\n"
        f"  <frequency>{freq}</frequency>\n  <scan_on_start>yes</scan_on_start>\n"
        "  <alert_new_files>yes</alert_new_files>\n" + "\n".join(fim) + "\n"
        '  <ignore type="sregex">.log$|.swp$</ignore>\n  <max_eps>50</max_eps>\n</syscheck>')

    log("6/7 apply + validate")
    apply_managed_block(OSSEC_LINUX, "\n".join(blocks),
                        validate_cmd=["/var/ossec/bin/wazuh-agentd", "-t"])

    log("7/7 start agent")
    restart_linux("wazuh-agent")
    log(f"done. Check '{host}' shows Active in the dashboard. "
        f"VirusTotal test:  echo 'X5O!P%@AP[4\\PZX54(P^)7CC)7}}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt")




def main():
    global DRY
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manager", required=True, help="Wazuh manager IP/hostname")
    p.add_argument("--agent-name", help="default: hostname")
    p.add_argument("--group", help="agent group (must already exist on the manager)")
    p.add_argument("--version", help="pin agent package version, e.g. 4.14.7-1")
    p.add_argument("--fim-frequency", type=int, default=43200, help="FIM scan seconds (default 12h)")
    p.add_argument("--fim-test-mode", action="store_true", help="FIM every 60s for testing")
    p.add_argument("--with-sysmon", action="store_true", help="also install Sysmon for Linux")
    p.add_argument("--cloudstack-logs", action="store_true", help="also collect CloudStack logs")
    p.add_argument("--dry-run", action="store_true", help="print actions, change nothing")
    a = p.parse_args()
    DRY = a.dry_run
    cmd_linux_agent(a)


if __name__ == "__main__":
    main()
