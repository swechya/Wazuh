#!/usr/bin/env python3
"""
wazuh_automate.py - automates the "Wazuh SIEM Deployment and Log Source
Configuration Guide" (agents, log sources, FIM, VirusTotal, active response,
custom rules, dashboard user, CloudStack).  Python 3.8+, standard library only.

Subcommands (run each on the machine it applies to):

  linux-agent     Ubuntu/Debian endpoint : install agent, auditd wget rule,
                  log sources, FIM, VirusTotal realtime dir, AR script
  manager         Wazuh manager          : custom rules, VirusTotal integration,
                  active-response (optionally installs Wazuh all-in-one first)
  windows-agent   Windows endpoint       : install MSI, audit policy, event
                  channels, FIM (run from an elevated prompt)
  dashboard-user  Create a dashboard (indexer internal) user through the REST API
  cloudstack      Ubuntu 24.04          : Java, MySQL, CloudStack, + Wazuh log sources

Examples:
  sudo python3 wazuh_automate.py manager --install
  sudo VT_API_KEY=xxxx python3 wazuh_automate.py manager
  sudo python3 wazuh_automate.py linux-agent --manager 10.0.0.2 --group default
  python  wazuh_automate.py windows-agent --manager 10.0.0.2
  python3 wazuh_automate.py dashboard-user --indexer https://10.0.0.2:9200 \
          --username analyst1 --role analyst
  sudo python3 wazuh_automate.py cloudstack --manager 10.0.0.2

Add --dry-run to any subcommand to print what would happen.
Secrets are read from environment variables / prompts, never hard-coded.
Re-running is safe: config goes in a marked block that is replaced each time,
every edited file is backed up, and a failed validation restores the backup.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import string
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BEGIN = "<!-- BEGIN WAZUH-AUTOMATION (managed block, re-run safe) -->"
END = "<!-- END WAZUH-AUTOMATION -->"
MANAGED_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", re.S)

OSSEC_LINUX = Path("/var/ossec/etc/ossec.conf")
RULES_FILE = Path("/var/ossec/etc/rules/local_rules.xml")
OSSEC_WIN = Path(r"C:\Program Files (x86)\ossec-agent\ossec.conf")
AR_TEST_FILE = "/tmp/vt-safe-test.txt"
DRY = False


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


def rand_pw(n=20):
    alpha = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(alpha + "!@#%^*-_") for _ in range(n))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p) and any(c in "!@#%^*-_" for c in p)):
            return p


def save_secret(name, value):
    if DRY:
        return
    p = Path("/root/.wazuh-automation-secrets")
    with open(p, "a") as f:
        f.write(f"{name}={value}\n")
    p.chmod(0o600)
    log(f"saved {name} to {p} (root only)")


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


# --------------------------------------------------------------------------- Manager
MANAGER_RULES = """
<group name="local,syslog,sshd,brute_force,">
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5716</if_matched_sid>
    <same_srcip />
    <description>Potential SSH brute-force attack: 5 failed attempts within 60 seconds</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failed,brute_force,syslog,sshd,</group>
  </rule>
</group>

<group name="local,privilege_escalation,sudo,command_execution,network_activity,auditd,">
  <rule id="100103" level="10">
    <if_sid>5402</if_sid>
    <description>Successful sudo to ROOT executed - Privilege Escalation</description>
    <group>privilege_escalation,sudo,authentication_success,</group>
  </rule>
  <rule id="100102" level="8">
    <if_sid>80700</if_sid>
    <match>key="wget_exec"</match>
    <description>Wget command executed - Network Download Activity</description>
    <mitre><id>T1105</id></mitre>
    <group>command_execution,wget,network_download,auditd,</group>
  </rule>
</group>

<group name="local,web_access,apache,">
  <rule id="100502" level="3">
    <if_sid>31108</if_sid>
    <description>Apache Web Access Log Detected</description>
    <group>web_access,apache,</group>
  </rule>
</group>

<group name="local,active_response,syscheck,">
  <rule id="100503" level="10">
    <match>SAFE TEST: Deleted /tmp/vt-safe-test.txt</match>
    <description>Active Response: Safe test file deleted</description>
    <group>active_response,syscheck,file_deleted,</group>
  </rule>
</group>

<group name="local,cloudstack,">
  <rule id="100700" level="5">
    <match>ClusterManagerImpl</match>
    <description>CloudStack management event detected</description>
    <group>cloudstack,</group>
  </rule>
  <rule id="100701" level="8">
    <match>failed to log in</match>
    <description>CloudStack user login failure</description>
    <group>cloudstack,authentication_failed,</group>
  </rule>
  <rule id="100702" level="8">
    <match>Authentication failure</match>
    <description>CloudStack authentication failure</description>
    <group>cloudstack,authentication_failed,</group>
  </rule>
</group>
"""


def cmd_manager(a):
    need_root()
    if a.install:
        log("installing Wazuh all-in-one (indexer + manager + dashboard) - takes several minutes")
        need_apt()
        apt_install("curl")
        run("curl -fsSL -o /tmp/wazuh-install.sh https://packages.wazuh.com/4.x/wazuh-install.sh", shell=True)
        run(["bash", "/tmp/wazuh-install.sh", "-a"])
        log("NOTE: the installer printed the generated admin password above - store it safely")

    log("1/3 custom rules -> local_rules.xml")
    analysisd = ["/var/ossec/bin/wazuh-analysisd", "-t"]
    apply_managed_block(RULES_FILE, MANAGER_RULES, wrap_ossec_config=False, validate_cmd=analysisd)

    log("2/3 VirusTotal integration + active response -> ossec.conf")
    existing = unmanaged(read_conf(OSSEC_LINUX))
    parts = []
    vt = a.vt_api_key or os.environ.get("VT_API_KEY")
    if vt:
        parts.append(f"<integration>\n  <name>virustotal</name>\n  <api_key>{vt}</api_key>\n"
                     "  <group>syscheck</group>\n  <alert_format>json</alert_format>\n"
                     "  <timeout>30</timeout>\n  <retries>3</retries>\n</integration>")
    else:
        warn("no VirusTotal key (set VT_API_KEY or --vt-api-key): integration skipped")
    if not a.no_active_response:
        for name, exe, rule in (("remove-threat", "remove-threat.sh", 87105),
                                ("delete-vt-test", "delete-vt-test.sh", 550)):
            if f"<name>{name}</name>" in existing:
                log(f"command {name} already defined, skipping")
                continue
            parts.append(f"<command>\n  <name>{name}</name>\n  <executable>{exe}</executable>\n"
                         "  <timeout_allowed>no</timeout_allowed>\n</command>\n"
                         f"<active-response>\n  <disabled>no</disabled>\n  <command>{name}</command>\n"
                         f"  <location>local</location>\n  <rules_id>{rule}</rules_id>\n</active-response>")
    if parts:
        apply_managed_block(OSSEC_LINUX, "\n".join(parts), validate_cmd=analysisd)

    log("3/3 restart manager")
    restart_linux("wazuh-manager")
    log("done. Test rules with: sudo /var/ossec/bin/wazuh-logtest")


# --------------------------------------------------------------------------- Windows agent
AUDIT_CATEGORIES = ["Account Logon", "Account Management", "Logon/Logoff", "Policy Change", "System"]


def cmd_windows_agent(a):
    if os.name != "nt":
        die("windows-agent must be run on Windows")
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
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


# --------------------------------------------------------------------------- Dashboard user
def http(method, url, user, pw, body=None, verify=False):
    ctx = None if verify else ssl._create_unverified_context()
    req = urllib.request.Request(
        url, method=method, data=None if body is None else json.dumps(body).encode())
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def cmd_dashboard_user(a):
    admin_pw = os.environ.get("INDEXER_ADMIN_PASSWORD") or getpass.getpass("Indexer admin password: ")
    pw = a.password or os.environ.get("NEW_USER_PASSWORD")
    generated = False
    if not pw:
        pw, generated = rand_pw(), True
    roles = ["all_access"] if a.role == "admin" else ["kibana_user", "readall"]
    base = a.indexer.rstrip("/") + "/_plugins/_security/api"
    if DRY:
        log(f"(dry-run) create user {a.username} with roles {roles} at {base}")
        return
    st, r = http("PUT", f"{base}/internalusers/{a.username}", a.admin_user, admin_pw,
                 {"password": pw, "backend_roles": [], "attributes": {}}, a.verify_tls)
    if st not in (200, 201):
        die(f"user creation failed ({st}): {r}")
    log(f"user '{a.username}' created")
    for role in roles:
        st, _ = http("GET", f"{base}/rolesmapping/{role}", a.admin_user, admin_pw, None, a.verify_tls)
        if st == 200:
            st, r = http("PATCH", f"{base}/rolesmapping/{role}", a.admin_user, admin_pw,
                         [{"op": "add", "path": "/users/-", "value": a.username}], a.verify_tls)
        else:
            st, r = http("PUT", f"{base}/rolesmapping/{role}", a.admin_user, admin_pw,
                         {"users": [a.username]}, a.verify_tls)
        if st not in (200, 201):
            die(f"role mapping '{role}' failed ({st}): {r}")
        log(f"mapped to role '{role}'")
    if generated:
        print(f"[!] generated password for {a.username}: {pw}  (change it after first login)")


# --------------------------------------------------------------------------- CloudStack
def cmd_cloudstack(a):
    need_root()
    need_apt()
    rel = os_release()
    if rel.get("VERSION_ID") != "24.04":
        warn(f"designed for Ubuntu 24.04, found {rel.get('PRETTY_NAME')}")
    codename = rel.get("VERSION_CODENAME", "noble")

    log("1/5 dependencies (Java, MySQL)")
    apt_install("curl", "gnupg", "openjdk-17-jre-headless", "mysql-server")

    log("2/5 CloudStack repo + packages")
    add_apt_repo("cloudstack", "https://download.cloudstack.org/release.asc",
                 f"http://download.cloudstack.org/ubuntu {codename} {a.cs_version}")
    pk = ["cloudstack-management"] + ([] if a.no_agent else ["cloudstack-agent"])
    apt_install(*pk)

    log("3/5 MySQL tuning + database")
    cnf = ("[mysqld]\ninnodb_rollback_on_timeout=1\ninnodb_lock_wait_timeout=600\n"
           "max_connections=350\nlog-bin=mysql-bin\nbinlog-format='ROW'\n")
    if DRY:
        log("(dry-run) write /etc/mysql/conf.d/cloudstack.cnf")
    else:
        Path("/etc/mysql/conf.d/cloudstack.cnf").write_text(cnf)
    run(["systemctl", "restart", "mysql"])
    root_pw = os.environ.get("MYSQL_ROOT_PASSWORD") or rand_pw()
    cs_pw = os.environ.get("CLOUDSTACK_DB_PASSWORD") or rand_pw()
    save_secret("MYSQL_ROOT_PASSWORD", root_pw)
    save_secret("CLOUDSTACK_DB_PASSWORD", cs_pw)
    run(["mysql", "-e", f"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{root_pw}';"],
        check=False)
    run(["cloudstack-setup-databases", f"cloud:{cs_pw}@localhost", f"--deploy-as=root:{root_pw}"])
    run(["cloudstack-setup-management"])

    log("4/5 verify management server (port 8080)")
    if not DRY:
        for _ in range(30):
            try:
                socket.create_connection(("127.0.0.1", 8080), 3).close()
                log("CloudStack UI reachable: http://<server>:8080/client")
                break
            except OSError:
                time.sleep(10)
        else:
            warn("port 8080 not up yet; check /var/log/cloudstack/management/management-server.log")

    log("5/5 Wazuh log sources for CloudStack")
    if pkg_installed("wazuh-agent") or DRY:
        existing = unmanaged(read_conf(OSSEC_LINUX))
        items = [("syslog", "/var/log/cloudstack/management/management-server.log", None, None),
                 ("syslog", "/var/log/cloudstack/agent/agent.log", None, None)]
        apply_managed_block(OSSEC_LINUX,
                            "\n".join(add_localfiles(existing, items)) or "<!-- nothing to add -->",
                            validate_cmd=["/var/ossec/bin/wazuh-agentd", "-t"])
        restart_linux("wazuh-agent")
    else:
        warn("wazuh-agent not installed; run `linux-agent --manager <ip> --cloudstack-logs`")


# --------------------------------------------------------------------------- CLI
def main():
    global DRY
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, agent=False):
        sp.add_argument("--dry-run", action="store_true", help="print actions, change nothing")
        if agent:
            sp.add_argument("--manager", required=True, help="Wazuh manager IP/hostname")
            sp.add_argument("--agent-name", help="default: hostname")
            sp.add_argument("--group", help="agent group (must already exist on the manager)")
            sp.add_argument("--fim-frequency", type=int, default=43200, help="FIM scan seconds (default 12h)")
            sp.add_argument("--fim-test-mode", action="store_true", help="FIM every 60s for testing")
            sp.add_argument("--with-sysmon", action="store_true", help="also install Sysmon")

    s = sub.add_parser("linux-agent", help="Ubuntu/Debian endpoint")
    common(s, True)
    s.add_argument("--version", help="pin agent package version, e.g. 4.14.7-1")
    s.add_argument("--cloudstack-logs", action="store_true", help="also collect CloudStack logs")
    s.set_defaults(fn=cmd_linux_agent)

    s = sub.add_parser("windows-agent", help="Windows endpoint")
    common(s, True)
    s.add_argument("--version", default="4.14.7", help="agent MSI version (default 4.14.7)")
    s.set_defaults(fn=cmd_windows_agent)

    s = sub.add_parser("manager", help="Wazuh manager: rules, VirusTotal, active response")
    common(s)
    s.add_argument("--install", action="store_true", help="install Wazuh all-in-one first")
    s.add_argument("--vt-api-key", help="or env VT_API_KEY")
    s.add_argument("--no-active-response", action="store_true")
    s.set_defaults(fn=cmd_manager)

    s = sub.add_parser("dashboard-user", help="create a dashboard user via the indexer API")
    common(s)
    s.add_argument("--indexer", required=True, help="e.g. https://10.0.0.2:9200")
    s.add_argument("--admin-user", default="admin")
    s.add_argument("--username", required=True)
    s.add_argument("--password", help="or env NEW_USER_PASSWORD; generated if omitted")
    s.add_argument("--role", choices=["analyst", "admin"], default="analyst")
    s.add_argument("--verify-tls", action="store_true", help="verify TLS (default off: self-signed certs)")
    s.set_defaults(fn=cmd_dashboard_user)

    s = sub.add_parser("cloudstack", help="install CloudStack + wire logs to Wazuh")
    common(s)
    s.add_argument("--cs-version", default="4.20", help="CloudStack repo release (default 4.20)")
    s.add_argument("--no-agent", action="store_true", help="skip cloudstack-agent (KVM host role)")
    s.add_argument("--manager", help="unused here; kept for symmetry")
    s.set_defaults(fn=cmd_cloudstack)

    a = p.parse_args()
    DRY = a.dry_run
    a.fn(a)


if __name__ == "__main__":
    main()
