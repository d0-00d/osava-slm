"""Closed indicator vocabulary for the OSAVA classifier tier.
Replaces the free-text `reason` field. The model can be wrong, but it cannot
fabricate: every token comes from this list. Enforce with constrained decoding."""

INDICATORS = {
    # process lineage
    "office_spawns_shell":      "Office application parented a shell/script interpreter",
    "browser_spawns_shell":     "Browser parented a shell/script interpreter",
    "service_host_spawns_proc": "services.exe/svchost parented an unexpected child",
    "system_context_exec":      "Process running as NT AUTHORITY\\SYSTEM",
    "lolbin_exec":              "Living-off-the-land binary (rundll32, mshta, regsvr32, certutil)",
    # file / path
    "temp_path_exec":           "Executable launched from Temp / AppData / ProgramData",
    "unsigned_binary":          "Binary has no valid Authenticode signature",
    "signature_invalid":        "Signature present but failed validation",
    "masquerading_name":        "Filename mimics a system binary from a non-system path",
    "service_binary_created":   "Service created, or its binary written or repointed",
    # command line
    "hidden_window":            "-WindowStyle Hidden or equivalent concealment flag",
    "encoded_command":          "-EncodedCommand / base64 / obfuscated argument",
    "download_cradle":          "Inline remote-fetch-and-execute pattern",
    "exec_policy_bypass":       "ExecutionPolicy Bypass or equivalent",
    "discovery_command":        "Host/user/domain enumeration (whoami, net, nltest, systeminfo)",
    # network
    "outbound_uncommon_port":   "Outbound connection to a non-standard port",
    "outbound_known_good":      "Outbound to a well-known service on its standard port",
    "raw_ip_no_dns":            "Connection to a literal IP with no preceding DNS resolution",
    "remote_service_install":   "Service created or started on a remote host",
    "smb_admin_share":          "Access to ADMIN$ / IPC$ / C$",
    # identity
    "blank_or_guest_account":   "Guest or blank-password authentication",
    "legacy_auth_protocol":     "NTLMv1 or other downgraded authentication",
    "privilege_escalation":     "Token elevation or privilege assignment event",
    # technique families -- added after measuring that 56% of threat targets
    # had no incriminating indicator at all, because nothing in this list
    # described what the events were actually doing (osava-ft
    # hallucination_check.py, `supported`)
    "credential_access":        "Credential material read or dumped (LSASS, SAM, NTDS, IIS app-pool passwords)",
    "account_manipulation":     "Local account or group membership created, hidden or changed",
    "uac_bypass":               "Auto-elevating Windows binary used outside its normal launch context",
    "accessibility_hijack":     "Accessibility binary (sethc, osk, utilman...) launched or replaced abnormally",
    "app_shim_install":         "Application-compatibility shim installed (sdbinst, .sdb, AppCompatFlags)",
    "persistence_autorun":      "Arranges for code to run later: Run keys, startup folder, IFEO, COM, print or update hooks",
    "defense_evasion":          "Disables or weakens a security control, log, or recovery mechanism",
    "proxy_execution":          "Process launched through a proxy binary or WMI provider",
    "payload_dropped":          "Executable or script written to a user-writable location",
    "reverse_shell":            "Command shell bound to a network connection",
    # logons (4624/4625). With only User, LogonType, AuthPackage and a source
    # address to go on, the model had no words for what it saw and invented
    # `negotiate_auth` / `ntlm_auth`.
    "new_credentials_logon":    "LogonType 9: alternate credentials for outbound use (runas /netonly, pass-the-hash)",
    "remote_interactive_logon": "LogonType 10: Remote Desktop logon",
    "failed_logon":             "Authentication attempt failed",
    # honesty key: the verdict rests on the event as a whole, and no single
    # field supports it. Emitted instead of padding with reassuring evidence.
    "context_dependent":        "No single field is conclusive; the verdict rests on the event as a whole",
    # exculpatory
    "signed_microsoft":         "Valid Microsoft Authenticode signature",
    "signed_known_vendor":      "Valid signature from a recognised third-party vendor",
    "system32_path":            "Executed from System32 / Program Files",
    "expected_parent":          "Parent-child relationship is normal for this binary",
    "restricted_service_acct":  "Runs as LOCAL SERVICE / NETWORK SERVICE",
    "interactive_logon":        "LogonType 2/7/11: console logon, unlock, or cached interactive logon",
    "service_logon":            "LogonType 0/4/5: system, scheduled-task or service logon",
    "kerberos_auth":            "Authenticated with Kerberos",
}

CATEGORIES = ["benign", "suspicious", "malicious"]

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "category":   {"type": "string", "enum": CATEGORIES},
        "indicators": {"type": "array",
                       "items": {"type": "string", "enum": sorted(INDICATORS)},
                       "minItems": 1, "maxItems": 4},
    },
    "required": ["category", "indicators"],
    "additionalProperties": False,
}

if __name__ == "__main__":
    import json
    print(f"{len(INDICATORS)} indicators")
    print(json.dumps(OUTPUT_SCHEMA, indent=2))
