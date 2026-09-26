"""
Derive the full output object for a training row.

train_final.jsonl carries a severity and a `provenance.rationale`, but the
rationale is a *provenance* note ("unique to this capture", "appears in 4
captures") -- a statement about the corpus, not about the event. 808 of 1993
rows say exactly that. Training a classifier to emit it would teach the model
to justify itself with a fact it cannot observe at inference time, and one
that correlates with the label. So reasoning is regenerated here, from the
event alone.

Everything below is a function of the rendered event text and nothing else.
That is the property that matters: at inference the model sees the same input
this file sees, so every field of the target is in principle derivable. The
one exception is `severity`, which comes from the label -- the model has to
learn the judgment, and the judgment is deliberately NOT a function of the
indicators (a signed vendor binary in AppData is benign; an unsigned one in
Temp is not; both emit `unsigned_binary`-adjacent evidence).

Indicator keys come from indicators.INDICATORS (R6, closed vocabulary).
Values are quoted evidence lifted from the event, which is what the shipped
HIRA schema's `{"key": "value"}` shape is for.
"""

import re

from indicators import INDICATORS

# ---------------------------------------------------------------- vocab

LOLBINS = {
    "rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "pcalua.exe",
    "odbcconf.exe", "xwizard.exe", "presentationhost.exe", "ieexec.exe",
    "msdt.exe", "hh.exe", "ftp.exe", "esentutl.exe", "extrac32.exe",
    "makecab.exe", "expand.exe", "replace.exe", "print.exe", "scriptrunner.exe",
    "mavinject.exe", "sc.exe", "schtasks.exe", "at.exe", "reg.exe",
    "csc.exe", "jsc.exe", "vbc.exe", "msxsl.exe",
}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
          "mshta.exe", "bash.exe", "wsl.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
          "msaccess.exe", "mspub.exe", "visio.exe", "onenote.exe"}
BROWSERS = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "brave.exe", "opera.exe", "vivaldi.exe"}
SERVICE_HOSTS = {"services.exe", "svchost.exe"}
# names a payload borrows to hide in a process list
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                "winlogon.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe",
                "dllhost.exe", "conhost.exe", "wininit.exe", "explorer.exe",
                "runtimebroker.exe", "sihost.exe", "ctfmon.exe"}

SYSTEM_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64",
               "c:\\program files", "c:\\program files (x86)",
               "c:\\windows\\winsxs", "c:\\windows\\microsoft.net")
# writable-by-user locations. \windows\temp is writable despite living under
# \windows, which is the whole reason contract.WRITABLE_WINDOWS_DIRS exists.
TEMP_DIRS = ("\\appdata\\local\\temp", "\\appdata\\roaming", "\\appdata\\local",
             "c:\\windows\\temp", "c:\\programdata", "c:\\temp", "c:\\users\\public",
             "\\downloads", "c:\\perflogs", "c:\\windows\\tasks",
             "c:\\windows\\debug", "c:\\windows\\tracing")

# parent -> children that are unremarkable for it
EXPECTED = {
    "explorer.exe": {"cmd.exe", "powershell.exe", "notepad.exe", "chrome.exe",
                     "msedge.exe", "firefox.exe", "code.exe", "winword.exe",
                     "excel.exe", "outlook.exe", "teams.exe", "slack.exe",
                     "mmc.exe", "taskmgr.exe", "control.exe", "regedit.exe"},
    "services.exe": {"svchost.exe", "spoolsv.exe", "msmpeng.exe", "searchindexer.exe",
                     "wmiprvse.exe", "vmtoolsd.exe", "sqlservr.exe", "w3wp.exe",
                     "dllhost.exe", "vgauthservice.exe", "securityhealthservice.exe"},
    "svchost.exe": {"taskhostw.exe", "runtimebroker.exe", "sihost.exe", "ctfmon.exe",
                    "dllhost.exe", "wmiprvse.exe", "audiodg.exe", "consent.exe",
                    "backgroundtaskhost.exe", "wuauclt.exe", "usoclient.exe"},
    "wininit.exe": {"services.exe", "lsass.exe", "lsm.exe"},
    "userinit.exe": {"explorer.exe"},
    "winlogon.exe": {"userinit.exe", "dwm.exe", "logonui.exe", "fontdrvhost.exe"},
    "taskeng.exe": {"cmd.exe", "powershell.exe", "msiexec.exe"},
    "msiexec.exe": {"msiexec.exe", "rundll32.exe"},
    "code.exe": {"code.exe", "cmd.exe", "powershell.exe", "node.exe", "git.exe"},
    # a build tool launching its own toolchain is what builds are
    "msbuild.exe": {"tracker.exe", "csc.exe", "vbcscompiler.exe", "cl.exe", "link.exe",
                    "msbuild.exe", "conhost.exe"},
}

RE_HIDDEN = re.compile(r"(?i)(-w(?:indow)?s?(?:tyle)?\s+h(?:idden)?\b|"
                       r"createnowindow|\bwindowstyle\s*=\s*hidden|"
                       r"\bconhost(?:\.exe)?\b[^\n]*--headless)")
RE_ENCODED = re.compile(r"(?i)(-e(?:nc|ncoded)?(?:command)?\s+[A-Za-z0-9+/=]{16,}|"
                        r"frombase64string|\[convert\]::|-enc\b|-encodedcommand\b)")
RE_CRADLE = re.compile(r"(?i)(invoke-webrequest|invoke-restmethod|\biwr\b|\bcurl\b|"
                       r"\bwget\b|downloadstring|downloadfile|downloaddata|"
                       r"net\.webclient|start-bitstransfer|bitsadmin[^|]*?/transfer|"
                       r"certutil[^|]*?-urlcache|\bhttps?://)")
RE_BYPASS = re.compile(r"(?i)(-ex(?:ec)?(?:utionpolicy)?\s+(bypass|unrestricted)|"
                       r"-nop\b|-noprofile\b)")
RE_DISCOVERY = re.compile(r"(?i)\b(whoami|systeminfo|nltest|net\s+(user|group|"
                          r"localgroup|view|share|accounts)|net1\s+(user|group)|"
                          r"ipconfig|arp\s+-a|nbtstat|quser|qwinsta|dsquery|"
                          r"tasklist|hostname|netstat|route\s+print|"
                          r"wmic(?:\.exe)?\s+(computersystem|os|process|qfe|useraccount))\b")
# `lsass` is deliberately NOT a bare term: it matched lsass.exe's own command
# line, reporting the process merely running as credential dumping. Access to
# it is caught by the dump tools (procdump, comsvcs MiniDump) and lsass.dmp.
RE_CRED = re.compile(r"(?i)(sekurlsa|logonpasswords|lsass\.dmp|mimikatz|ntds\.dit|"
                     r"\bsam\b\s+save|reg\s+save\s+hk\w*\\+(sam|security|system)|"
                     r"comsvcs\.dll[^|]*?minidump|vaultcmd|dpapi|ntdsutil[^|]*?\bifm\b|"
                     r"procdump[^|]*?lsass|\bsam\b[^|]*?\bsave\b)")
RE_ADMIN_SHARE = re.compile(r"(?i)\\\\[^\\]+\\(admin\$|ipc\$|c\$)")
RE_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# HKLM\...\Run, Winlogon shell/userinit, service ImagePath, IFEO debugger
RE_AUTORUN = re.compile(r"(?i)(\\currentversion\\run(once)?\b|\\winlogon\\(shell|userinit)|"
                        r"\\image file execution options\\|\\services\\[^\\]+\\imagepath|"
                        r"\\currentversion\\explorer\\shell\s?folders|"
                        r"\\policies\\explorer\\run|\\userinitmprlogonscript)")
RE_ANTIFOREN = re.compile(r"(?i)(vssadmin[^|]*?delete\s+shadows|wevtutil\s+cl|"
                          r"clear-eventlog|bcdedit[^|]*?(recoveryenabled|bootstatuspolicy)|"
                          r"wbadmin\s+delete|cipher\s+/w|fsutil\s+usn\s+deletejournal)")


# ---------------------------------------------------------------- technique rules
#
# Added after hallucination_check.py showed 56% of threat targets carried no
# incriminating indicator: 623 of those 661 rows were REAL captures of named
# techniques this file had no rule for. Every rule below matches a verb or a
# specific location, never a bare path -- a rule keyed on the Run-key path
# alone flagged `reg query` (a read) as persistence, twice.

# Auto-elevating binaries: the UACME class. Normal launchers are the shell and
# the service/AppInfo hosts; anything else launching them, or any of them
# spawning a shell, is how UAC is bypassed.
AUTO_ELEVATE = {"fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe",
                "compmgmtlauncher.exe", "wsreset.exe", "slui.exe", "changepk.exe",
                "sysprep.exe", "pkgmgr.exe", "wusa.exe", "consent.exe", "cliconfg.exe",
                "perfmon.exe", "colorcpl.exe", "iscsicpl.exe", "dccw.exe", "ieinstal.exe"}
ELEVATE_LAUNCHERS = {"explorer.exe", "svchost.exe", "services.exe", "mmc.exe", "winlogon.exe",
                     "msiexec.exe", "wuauclt.exe", "taskhostw.exe", "taskeng.exe"}
ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe",
                 "displayswitch.exe", "atbroker.exe"}
ACCESS_LAUNCHERS = {"winlogon.exe", "utilman.exe", "atbroker.exe", "explorer.exe"}
# the parent is the signal: whatever these launch was launched *through* them
PROXY_PARENTS = {"wmic.exe", "wmiprvse.exe", "pcalua.exe", "forfiles.exe", "mshta.exe",
                 "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe",
                 "cmstp.exe", "scriptrunner.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe"}
# binaries whose home is not System32 -- without this, every explorer.exe event
# was reported as masquerading, because C:\Windows is not a SYSTEM_DIR
HOME_DIR = {"explorer.exe": "c:\\windows", "psexesvc.exe": "c:\\windows"}
MASQ_NAMES = SYSTEM_NAMES | AUTO_ELEVATE | ACCESSIBILITY
PAYLOAD_EXT = (".exe", ".dll", ".scr", ".hta", ".js", ".jse", ".vbs", ".vbe", ".ps1",
               ".bat", ".cmd", ".sct", ".wsf", ".msi")
WRITABLE = TEMP_DIRS + ("\\desktop\\", "\\start menu\\")

RE_DECORATED = re.compile(r"^(?:\[\d+\]|\(\d+\)\s*)(.+)$")
RE_APPCMD_CRED = re.compile(r"(?i)\bappcmd(?:\.exe)?\b[^\n]*\blist\s+(?:apppool|vdir)\b[^\n]*/text:")
RE_REVSHELL = re.compile(r"(?i)(\b(?:nc|ncat|nc64|netcat)(?:\.exe)?\b[^\n]*\s-[ec]\s|"
                         r"net\.sockets\.tcpclient|/bin/(?:ba)?sh\s+-i)")
RE_ACCOUNT = re.compile(r"(?i)\bnet1?(?:\.exe)?\b[^\n]*\b(?:user|localgroup|group)\b[^\n]*/(?:add|delete)")
RE_SVC_CREATE = re.compile(r"(?i)\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:create|config)\b[^\n]*binpath")
RE_RECOVERY = re.compile(r"(?i)(vssadmin[^\n]*?delete\s+shadows|wbadmin\s+delete|"
                         r"bcdedit[^\n]*?(recoveryenabled|bootstatuspolicy))")
RE_EVASION_CMD = re.compile(r"(?i)(wevtutil\s+cl|clear-eventlog|cipher\s+/w|"
                            r"fsutil\s+usn\s+deletejournal|set-mppreference[^\n]*-disable|"
                            r"add-mppreference[^\n]*-exclusion|auditpol[^\n]*/(clear|remove)|"
                            r"netsh[^\n]*firewall[^\n]*\b(off|disable)\b)")
# registry: a WRITE (EventID 12/13/14) to these locations
RE_REG_PERSIST = re.compile(
    r"(?i)(\\currentversion\\run(once)?(ex)?\\|\\winlogon\\(shell|userinit|notify)|"
    r"\\image file execution options\\|\\silentprocessexit\\|"
    r"\\currentversion\\explorer\\(user )?shell folders|\\policies\\explorer\\run|"
    r"userinitmprlogonscript|\\inprocserver32|\\localserver32|\\appinit_dlls|"
    r"\\microsoft\\netsh\\|\\control\\lsa\\(security|notification|authentication) packages|"
    r"\\session manager\\bootexecute|\\print\\monitors\\|\\ntds\\directoryserviceextpt|"
    r"\\windowsupdate\\orchestrator\\uscheduler|\\ieak\\grouppolicy\\pendinggpos)")
RE_REG_SERVICE = re.compile(r"(?i)\\services\\[^\\]+\\(imagepath|parameters\\servicedll)")
RE_REG_UAC = re.compile(
    r"(?i)((ms-settings|folder|ms-browser|mscfile|exefile|launcher\.systemsettings|"
    r"appx[0-9a-z]+)\\shell\\open\\command|delegateexecute|\\environment\\(windir|systemroot))")
RE_REG_EVASION = re.compile(
    r"(?i)(windows defender\\(exclusions|.*disable)|\\powershell\\(scriptblocklogging|"
    r"modulelogging|transcription)|\\winevt\\channels\\[^\n]*\\enabled|"
    r"lanmanserver\\parameters\\nullsession(pipes|shares)|"
    r"\\policies\\system\\(enablelua|consentpromptbehavioradmin)|__pslockdownpolicy|"
    r"\\control\\lsa\\runasppl)")
RE_REG_SHIM = re.compile(r"(?i)\\appcompatflags\\(installedsdb|custom)\\")
RE_REG_SAM = re.compile(r"(?i)\\sam\\sam\\domains\\(account\\users|builtin\\aliases)\\")
RE_REG_CRED = re.compile(r"(?i)\\wdigest\\uselogoncredential")
RE_WUSA_EXTRACT = re.compile(r"(?i)/extract:?\S*")
RE_PRIV = re.compile(r"(?i)(sedebugprivilege|setcbprivilege)")
RE_SDB = re.compile(r"(?i)[^\s\"]+\.sdb\b")
RE_REMOTE_EXEC = re.compile(r"(?i)\b(psexec\w*|sc\s+\\\\\S+|wmic\s+/node:?\S*|winrs\w*|"
                            r"invoke-command\s+-computername\s+\S+)")
RE_APPCMD_TEXT = re.compile(r"(?i)/text:\S+")
# preferred quotes where the firing regex's leftmost match is the weaker one
RE_ENC_BLOB = re.compile(r"(?i)-e(?:nc|ncoded)?(?:command)?\s+[A-Za-z0-9+/=]{16,}")
RE_FROMB64 = re.compile(r"(?i)frombase64string")
RE_EXEC_BYPASS = re.compile(r"(?i)-ex(?:ec)?(?:utionpolicy)?\s+(?:bypass|unrestricted)")
RE_URL = re.compile(r"(?i)https?://[^\s'\"()]+")

# LOLBins named in a command line (cmd /c certutil ..., powershell bitsadmin ...).
# Short or English-word stems only count with the .exe suffix: `at`, `print`,
# `replace` and `expand` occur in ordinary text.
_WORDY = {"at", "print", "replace", "expand", "hh", "ftp", "sc", "reg", "msdt", "csc",
          "jsc", "vbc"}
RE_LOLBIN_CMD = re.compile(r"(?i)(" + "|".join(
    (rf"\b{re.escape(b[:-4])}\.exe\b" if b[:-4] in _WORDY else rf"\b{re.escape(b[:-4])}(?:\.exe)?\b")
    for b in sorted(LOLBINS, key=len, reverse=True))
    + r"|\breg(?:\.exe)?\s+(?:add|import|save|export|delete)\b"
    + r"|\bsc(?:\.exe)?\s+(?:create|config|start)\b)")

# Command-line rules: (key, regexes that fire it, regexes that pick the quote).
# The quote is the first match among the quote regexes, else the firing match.
# A cradle is quoted by its URL when it has one: the URL is the evidence, the
# verb is already in the key.
CMD_RULES = [
    ("credential_access", (RE_CRED, RE_APPCMD_CRED), (RE_CRED, RE_APPCMD_TEXT)),
    ("reverse_shell", (RE_REVSHELL,), ()),
    ("account_manipulation", (RE_ACCOUNT,), ()),
    ("service_binary_created", (RE_SVC_CREATE,), ()),
    ("defense_evasion", (RE_RECOVERY, RE_EVASION_CMD), ()),
    ("encoded_command", (RE_ENCODED,), (RE_ENC_BLOB, RE_FROMB64)),
    ("hidden_window", (RE_HIDDEN,), ()),
    ("download_cradle", (RE_CRADLE,), (RE_URL,)),
    ("exec_policy_bypass", (RE_BYPASS,), (RE_EXEC_BYPASS,)),
    ("discovery_command", (RE_DISCOVERY,), ()),
]

# incriminating keys, strongest first: the output is capped at four, and
# technique evidence must never be crowded out by generic properties
PRIORITY = ["credential_access", "reverse_shell", "uac_bypass", "accessibility_hijack",
            "app_shim_install", "persistence_autorun", "service_binary_created",
            "defense_evasion", "account_manipulation", "remote_service_install",
            "office_spawns_shell", "browser_spawns_shell", "proxy_execution",
            "download_cradle", "encoded_command", "payload_dropped", "masquerading_name",
            "service_host_spawns_proc", "temp_path_exec", "hidden_window",
            "exec_policy_bypass", "unsigned_binary", "lolbin_exec", "discovery_command",
            "smb_admin_share", "raw_ip_no_dns", "outbound_uncommon_port",
            "privilege_escalation", "new_credentials_logon", "remote_interactive_logon",
            "blank_or_guest_account", "legacy_auth_protocol", "failed_logon",
            "system_context_exec"]


def _undecorated(name):
    m = RE_DECORATED.match(name or "")
    return m.group(1) if m else name


def _at_home(name, d):
    return d == HOME_DIR.get(name) or _in(d, SYSTEM_DIRS)

# ---------------------------------------------------------------- parsing

_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9_]*): ?(.*)$")


def parse(event):
    """Rendered `Key: value` body back into a dict, tolerating wrapped values."""
    fields, last = {}, None
    for line in event.split("\n"):
        m = _KEY.match(line)
        if m:
            last = m.group(1)
            fields[last] = m.group(2)
        elif last is not None:
            fields[last] += "\n" + line
    return fields


def _base(p):
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower() if p else ""


def _dir(p):
    p = (p or "").replace("/", "\\")
    return p.rsplit("\\", 1)[0].lower() if "\\" in p else ""


def _in(d, prefixes):
    return any(x in d for x in prefixes)


def _clip(v, n=120):
    v = " ".join(str(v).split())
    return v if len(v) <= n else v[: n - 1] + "\u2026"


# A command-line indicator quotes what its rule matched (`-w hidden`,
# `-enc JABzAD0A…`, `vssadmin delete shadows`), not the command line. Quoting
# the whole line put the same 120-char prefix under three or four keys, and
# the model learned to copy: on a 700-char encoded PowerShell it wrote the
# full line under every key and ran out of tokens before closing the JSON.
SPAN = 48


def _span(rx, s, n=SPAN):
    m = rx.search(s or "")
    return _clip(m.group(0).strip("\"' "), n) if m else None

# ---------------------------------------------------------------- indicators


def extract(fields):
    """Ordered {indicator: evidence}. Incriminating first (by PRIORITY),
    exculpatory last -- the model reads its own output left to right when it
    writes `reasoning`. Every value is quoted from, or derived from, a field of
    this event; hallucination_check.py verifies that for all training targets."""
    eid = str(fields.get("EventID", ""))
    img = fields.get("Image", "")
    par = fields.get("ParentImage", "")
    cmd = fields.get("CommandLine", "")
    tgt = fields.get("TargetFilename", "") or fields.get("TargetObject", "")
    user = fields.get("User", "") or fields.get("TargetUser", "")
    signed = str(fields.get("Signed", "")).lower()
    signer = fields.get("Signer", "")
    ib, pb, idir = _base(img), _base(par), _dir(img)
    ibc = _undecorated(ib)
    t = (tgt or "").lower()
    reg_write = eid in ("12", "13", "14")
    bad, good = {}, {}

    def flag(k, v):
        bad.setdefault(k, v)

    # --- lineage: often the parent is the signal, not the child
    if pb in OFFICE and ib in SHELLS:
        flag("office_spawns_shell", f"{pb} -> {ib}")
    elif pb in BROWSERS and ib in SHELLS:
        flag("browser_spawns_shell", f"{pb} -> {ib}")
    elif pb in SERVICE_HOSTS and ib and ib not in EXPECTED.get(pb, ()):
        flag("service_host_spawns_proc", f"{pb} -> {ib}")
    elif pb and ib and ib in EXPECTED.get(pb, ()):
        good["expected_parent"] = f"{pb} -> {ib}"
    if pb in PROXY_PARENTS and ib and ib not in EXPECTED.get(pb, ()):
        flag("proxy_execution", f"{pb} -> {ib}")
    if ib in AUTO_ELEVATE and pb and pb not in ELEVATE_LAUNCHERS:
        flag("uac_bypass", f"{pb} -> {ib}")
    elif pb in AUTO_ELEVATE and ib in SHELLS:
        flag("uac_bypass", f"{pb} -> {ib}")
    # the COM surrogate hosting an elevation moniker (CMSTPLUA and friends):
    # a shell whose parent is dllhost.exe is a UAC bypass, not a COM object
    if pb == "dllhost.exe" and ib in SHELLS:
        flag("uac_bypass", f"{pb} -> {ib}")
    if ib == "wusa.exe" and "/extract" in (cmd or "").lower():
        flag("uac_bypass", _span(RE_WUSA_EXTRACT, cmd))
    if ibc in ACCESSIBILITY and (not _in(idir, SYSTEM_DIRS)
                                or (pb and pb not in ACCESS_LAUNCHERS)):
        flag("accessibility_hijack", f"{pb} -> {ib}" if pb else img)
    m = re.search(r'(?i)([a-z]:\\[^"\n]*\\(?:' + "|".join(
        re.escape(a[:-4]) for a in ACCESSIBILITY) + r')\.exe)', cmd or "")
    if m and "\\system32\\" not in m.group(1).lower():
        flag("accessibility_hijack", m.group(1))

    # --- identity
    ul = user.lower()
    logon = eid in ("4624", "4625")
    # a logon names the account that logged on, not a process running as it:
    # SYSTEM starting a service is the most ordinary logon there is
    if "system" in ul and "localsystem" not in ul and not logon:
        flag("system_context_exec", user)
    elif "local service" in ul or "network service" in ul:
        good["restricted_service_acct"] = user
    if re.search(r"(?i)\\(guest|anonymous|anonymous logon)$", user):
        flag("blank_or_guest_account", user)
    auth = str(fields.get("AuthPackage", ""))
    if logon and auth.upper() in ("NTLM", "NTLMV1", "MSV1_0",
                                  "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"):
        flag("legacy_auth_protocol", auth)
    if logon:
        lt = str(fields.get("LogonType", ""))
        if eid == "4625":
            flag("failed_logon", fields.get("EventType") or "Failed Logon")
        if lt == "9":
            flag("new_credentials_logon", f"LogonType: {lt}")
        elif lt == "10":
            flag("remote_interactive_logon", f"LogonType: {lt}")
        elif lt in ("2", "7", "11"):
            good["interactive_logon"] = f"LogonType: {lt}"
        elif lt in ("0", "4", "5"):
            good["service_logon"] = f"LogonType: {lt}"
        if auth.lower() == "kerberos":
            good["kerberos_auth"] = auth
    if v := _span(RE_PRIV, cmd):
        flag("privilege_escalation", v)

    # --- the process itself, for EVERY event that names one. Restricting these
    # to process creation missed binaries running from Temp whose only events
    # were image loads ([1]consent.exe from ...\Temp\IDC1.tmp\).
    if img:
        if _in(idir, TEMP_DIRS):
            # the directory is the evidence; the full path is masquerading's
            flag("temp_path_exec", img.rsplit("\\", 1)[0])
        if ibc != ib or (ibc in MASQ_NAMES and not _at_home(ibc, idir)):
            flag("masquerading_name", img)
        if ib in LOLBINS:
            flag("lolbin_exec", ib)
        if ib == "sdbinst.exe":
            flag("app_shim_install", _span(RE_SDB, cmd) or img)
    if signed == "false":
        flag("unsigned_binary", _base(tgt) or ib or "-")
    elif signed == "true" and signer:
        good["signed_microsoft" if "microsoft" in signer.lower()
             else "signed_known_vendor"] = signer
    if idir and _at_home(ibc, idir):
        good["system32_path"] = idir

    # --- command line
    if cmd:
        for key, fire, quote in CMD_RULES:
            if any(rx.search(cmd) for rx in fire):
                flag(key, next(v for rx in (*quote, *fire) if (v := _span(rx, cmd))))
        m = RE_LOLBIN_CMD.search(cmd)
        if m and "lolbin_exec" not in bad and _base(m.group(1).split()[0]) != ib:
            flag("lolbin_exec", m.group(1))

    # --- registry writes: the location says what the write is for
    if reg_write and t:
        if RE_REG_SERVICE.search(t):
            flag("service_binary_created", tgt)
        if RE_REG_PERSIST.search(t) or ("\\environment\\" in t
                                        and "userinitmprlogonscript" in t):
            flag("persistence_autorun", tgt)
        if RE_REG_UAC.search(t):
            flag("uac_bypass", tgt)
        if RE_REG_EVASION.search(t):
            flag("defense_evasion", tgt)
        if RE_REG_SHIM.search(t):
            flag("app_shim_install", tgt)
        if RE_REG_SAM.search(t):
            flag("account_manipulation", tgt)
        if RE_REG_CRED.search(t):
            flag("credential_access", tgt)

    # --- image loads: a DLL loaded from a user-writable path is code running
    # from there, whichever signed process loaded it (COM / DLL hijack)
    if eid == "7" and t and _in(t, WRITABLE):
        flag("temp_path_exec", tgt)

    # --- file writes
    if eid == "11" and t:
        if t.endswith(".sdb"):
            flag("app_shim_install", tgt)
        if "\\start menu\\programs\\startup\\" in t:
            flag("persistence_autorun", tgt)
        if t.endswith(PAYLOAD_EXT) and _in(t, WRITABLE):
            flag("payload_dropped", tgt)
        if "\\system32\\" in t and t.endswith(".exe"):
            flag("service_binary_created", tgt)

    # --- network
    if eid == "3":
        port = str(fields.get("DestinationPort", ""))
        dip = str(fields.get("DestinationIp", ""))
        dns = fields.get("DestinationHostname", "")
        try:
            pn = int(port)
        except ValueError:
            pn = -1
        if pn in (445, 139):
            flag("smb_admin_share", f"{dip}:{port}")
        if pn in (80, 443, 53, 123, 88, 389, 636, 3268):
            good["outbound_known_good"] = f"{dip}:{port}"
        elif pn >= 0 and pn not in (445, 139, 135, 3389, 5985, 5986):
            flag("outbound_uncommon_port", f"{dip}:{port}")
        if not dns and RE_IP.match(dip):
            flag("raw_ip_no_dns", dip)
    if v := _span(RE_ADMIN_SHARE, cmd) or _span(RE_REMOTE_EXEC, cmd):
        flag("remote_service_install", v)

    ranked = sorted(bad.items(), key=lambda kv: PRIORITY.index(kv[0])
                    if kv[0] in PRIORITY else len(PRIORITY))
    out = {}
    for k, v in ranked + list(good.items()):
        if k in INDICATORS and k not in out:
            out[k] = _clip(v)
        if len(out) == 4:                        # OUTPUT_SCHEMA maxItems
            break
    # No fallback. The old one filed any directory under `system32_path` when
    # nothing else fired -- 128 targets called a Desktop or Temp folder a
    # system path. An event with nothing notable now says nothing.
    return out

# ---------------------------------------------------------------- threatType

# first match wins; ordered by specificity, not severity. Types marked (v2)
# exist only in the strict2 prompt's vocabulary; under v1 they fall back to
# the nearest v1 type, see threat_type().
THREAT_RULES = [
    ("credential_stuffing", lambda f, i, c: str(f.get("EventID")) == "4625"),
    ("credential_access", lambda f, i, c: "credential_access" in i                  # (v2)
     or "account_manipulation" in i),
    ("ransomware", lambda f, i, c: bool(RE_RECOVERY.search(c))),
    ("privilege_escalation", lambda f, i, c: "uac_bypass" in i or "privilege_escalation" in i
     or "system_context_exec" in i and ("masquerading_name" in i or "temp_path_exec" in i)),
    ("lateral_movement", lambda f, i, c: "remote_service_install" in i
     or "smb_admin_share" in i or "new_credentials_logon" in i
     or "remote_interactive_logon" in i
     # NTLM on a network logon is the shape pass-the-hash leaves (T1550.002)
     or "legacy_auth_protocol" in i and str(f.get("LogonType")) == "3"),
    ("defense_evasion", lambda f, i, c: "defense_evasion" in i),                     # (v2)
    ("persistence", lambda f, i, c: "persistence_autorun" in i                       # (v2)
     or "app_shim_install" in i or "accessibility_hijack" in i
     or "service_binary_created" in i),
    ("rce", lambda f, i, c: "reverse_shell" in i),
    ("data_exfiltration", lambda f, i, c: bool(re.search(
        r"(?i)(compress-archive|\brar\s+a\b|7z\s+a\b|invoke-webrequest[^|]*-method\s+post|"
        r"\bftp\b|uploadfile)", c))),
    ("reconnaissance", lambda f, i, c: "discovery_command" in i),
    ("cryptomining", lambda f, i, c: bool(re.search(
        r"(?i)(xmrig|stratum\+tcp|minerd|nicehash)", c))),
    ("malware", lambda f, i, c: any(k in i for k in (
        "download_cradle", "encoded_command", "temp_path_exec", "masquerading_name",
        "office_spawns_shell", "browser_spawns_shell", "payload_dropped",
        "proxy_execution", "lolbin_exec", "unsigned_binary", "service_host_spawns_proc",
        "raw_ip_no_dns", "outbound_uncommon_port"))),
    # after malware on purpose: a hidden-window download cradle is malware; a
    # hidden window with nothing else is concealment (T1564.003)
    ("defense_evasion", lambda f, i, c: "hidden_window" in i                        # (v2)
     or "exec_policy_bypass" in i),
    ("unknown", lambda f, i, c: True),
]
V1_FALLBACK = {"credential_access": "unknown", "defense_evasion": "malware",
               "persistence": "malware"}


def threat_type(fields, ind, gold, vocab="v2"):
    if gold == "benign":
        return None
    cmd = " ".join(x for x in (fields.get("CommandLine", ""),
                               fields.get("TargetFilename", ""),
                               fields.get("TargetObject", ""),
                               fields.get("Details", "")) if x)
    for name, test in THREAT_RULES:
        try:
            if test(fields, ind, cmd):
                return V1_FALLBACK.get(name, name) if vocab == "v1" else name
        except Exception:
            continue
    return "unknown"

# ---------------------------------------------------------------- reasoning

BENIGN_KEYS = {"signed_microsoft", "signed_known_vendor", "system32_path",
               "expected_parent", "restricted_service_acct", "outbound_known_good",
               "interactive_logon", "service_logon", "kerberos_auth"}

PHRASE = {
    "office_spawns_shell": "an Office application spawned a shell",
    "browser_spawns_shell": "a browser spawned a shell",
    "service_host_spawns_proc": "a service host spawned an unexpected child",
    "system_context_exec": "it runs in SYSTEM context",
    "lolbin_exec": "the image is a living-off-the-land binary",
    "temp_path_exec": "the image runs from a user-writable path",
    "unsigned_binary": "the binary is unsigned",
    "signature_invalid": "the signature failed validation",
    "masquerading_name": "the filename mimics a system binary outside a system path",
    "service_binary_created": "a service or system binary was written to disk",
    "hidden_window": "the window is hidden",
    "encoded_command": "the command line is encoded",
    "download_cradle": "the command line fetches remote content",
    "exec_policy_bypass": "execution policy is bypassed",
    "discovery_command": "it enumerates hosts, users or domains",
    "outbound_uncommon_port": "the destination port is non-standard",
    "outbound_known_good": "the destination is a well-known service on its usual port",
    "raw_ip_no_dns": "it connects to a literal IP with no DNS resolution",
    "remote_service_install": "it acts against a remote host",
    "smb_admin_share": "it touches an SMB administrative share",
    "blank_or_guest_account": "the account is guest or blank-password",
    "legacy_auth_protocol": "authentication is downgraded",
    "privilege_escalation": "privileges are being elevated",
    "signed_microsoft": "the binary carries a valid Microsoft signature",
    "signed_known_vendor": "the binary is signed by a known vendor",
    "system32_path": "it executes from a system path",
    "expected_parent": "the parent-child relationship is normal",
    "restricted_service_acct": "it runs under a restricted service account",
    "credential_access": "it reads or dumps credential material",
    "account_manipulation": "it creates, hides or changes a local account",
    "uac_bypass": "an auto-elevating binary is used outside its normal launch context",
    "accessibility_hijack": "an accessibility binary is launched or replaced abnormally",
    "app_shim_install": "it installs an application-compatibility shim",
    "persistence_autorun": "it arranges for code to run later",
    "defense_evasion": "it weakens a security control, log or recovery mechanism",
    "proxy_execution": "the process was launched through a proxy binary",
    "payload_dropped": "an executable or script is written to a user-writable location",
    "reverse_shell": "a command shell is bound to a network connection",
    "new_credentials_logon": "it is a logon with alternate credentials for outbound use",
    "remote_interactive_logon": "it is a Remote Desktop logon",
    "failed_logon": "authentication failed",
    "interactive_logon": "it is an interactive logon at the console",
    "service_logon": "it is a system, scheduled-task or service logon",
    "kerberos_auth": "it authenticated with Kerberos",
}

VERDICT = {
    "malicious": "This matches a known attack technique and should be treated as malicious.",
    "suspicious": "This is consistent with legitimate administration but also with an "
                  "attack in progress, so it warrants review rather than a verdict.",
    "benign": "Nothing here departs from normal activity for this host.",
}
# used instead of VERDICT when no single field supports the verdict. Honest
# about where the verdict comes from, and still a checkable sentence.
VERDICT_CONTEXT = {
    "malicious": "It is classified as malicious on the pattern of the event as a whole, "
                 "not on any one indicator.",
    "suspicious": "It warrants review on the pattern of the event as a whole, "
                  "not on any one indicator.",
}
ACTION = {
    "EventID: 1": "Process creation", "EventID: 4688": "Process creation",
    "EventID: 3": "Network connection", "EventID: 7": "Image load",
    "EventID: 11": "File creation", "EventID: 12": "Registry key operation",
    "EventID: 13": "Registry value set", "EventID: 4624": "Successful logon",
    "EventID: 4625": "Failed logon",
}


def reasoning(fields, ind, gold):
    head = ACTION.get(f"EventID: {fields.get('EventID','')}", "Event")
    img = (_base(fields.get("Image", "")) or _base(fields.get("TargetFilename", ""))
           or fields.get("User") or "the subject")
    if "context_dependent" in ind and gold != "benign":
        facts = [PHRASE[k] for k in ind if k in BENIGN_KEYS and k in PHRASE]
        seen = f" What it does show ({facts[0]}) does not explain the verdict." if facts else ""
        return (f"{head} by {img}: no single field in this event is conclusive. "
                f"{VERDICT_CONTEXT[gold]}{seen}")
    incrim = [PHRASE[k] for k in ind if k not in BENIGN_KEYS and k in PHRASE]
    excul = [PHRASE[k] for k in ind if k in BENIGN_KEYS and k in PHRASE]
    obs = incrim or excul
    if len(obs) > 2:
        obs = obs[:2]
    joined = obs[0] if len(obs) == 1 else " and ".join(obs) if obs else "no notable properties"
    if incrim and excul and gold != "benign":
        tail = f" The mitigating evidence ({excul[0]}) does not outweigh it."
    elif incrim and gold == "benign":
        routine = (" On its own, for an ordinary account, this is routine."
                   if str(fields.get("EventID")) in ("4624", "4625")
                   else " The pattern is documented normal behaviour for this binary.")
        tail = f" {excul[0].capitalize()}, which accounts for it." if excul else routine
    else:
        tail = ""
    return f"{head} by {img}: {joined}. {VERDICT[gold]}{tail}"

# ---------------------------------------------------------------- assembly


def build(row, vocab="v2"):
    fields = parse(row["event"])
    ind = extract(fields)
    gold = row["gold"]
    # A threat verdict with no incriminating evidence used to be explained with
    # whatever reassuring evidence was left -- "signed by Microsoft, runs from
    # System32, therefore malicious" -- and the model learned to say that on
    # 67% of its alerts. Now the target says plainly that no field is
    # conclusive, first, so the model commits to that before anything else.
    if gold != "benign" and not any(k not in BENIGN_KEYS for k in ind):
        ind = dict([("context_dependent", "-")] + list(ind.items())[:3])
    return {
        "severity": row["severity"],
        "isThreat": gold != "benign",
        "threatType": threat_type(fields, ind, gold, vocab),
        "indicators": ind,
        "reasoning": reasoning(fields, ind, gold),
    }


if __name__ == "__main__":
    import json, sys, collections
    rows = [json.loads(l) for l in open(sys.argv[1] if len(sys.argv) > 1
                                        else "train_final.jsonl")]
    ik, tt = collections.Counter(), collections.Counter()
    for r in rows:
        t = build(r)
        ik.update(t["indicators"].keys())
        tt[t["threatType"]] += 1
    print(f"{len(rows)} rows\n\nindicator frequency:")
    for k, v in ik.most_common():
        print(f"  {v:5} {v/len(rows):6.1%}  {k}")
    print(f"\nunused: {sorted(set(INDICATORS) - set(ik))}")
    print(f"\nthreatType: {dict(tt)}")
    for r in rows[:3]:
        print("\n" + "-" * 70 + f"\n{r['event']}\n->\n"
              + json.dumps(build(r), indent=2))
