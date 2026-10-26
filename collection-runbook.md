# Collection runbooks — what each endpoint needs so the sensor can collect

One runbook per collection method. Each gives every step on the endpoint, on the sensor host and in the Console, the
checks, and how to revoke. Machine on every command: **Sensor host** (the sensor's Ubuntu / Debian host, installed in
`/opt/nis2inv-sensor`), **Linux target**, **Windows target**, **Domain admin workstation**, **Console**.

| Method | Targets | Account | Port | Status |
|---|---|---|---|---|
| §2 SSH collector | Linux (class `linux`; `apple` / `network` possible) | `nis2inv`, unprivileged, SSH key with `restrict,from=` | 22 | in use (lab: 7 Debian / Ubuntu hosts) |
| §3 WinRM collector — set up by hand | Windows workstations / servers, standalone or few | local `nis2inv`, **not** an administrator | 5986 (HTTPS) | in use (lab: .105, STIG hardened) |
| §4 WinRM collector — Active Directory (GPO) | domain members | domain account, **not** an administrator | 5986 | written from Microsoft's mechanisms; **not run on a domain yet** (no AD in the lab) |
| §5 WinRM collector — Microsoft Intune | Entra-joined / Intune-managed devices | to settle | 5986 | **later**: open questions only |
| §6 osquery over WinRM (optional) | Windows with osqueryd | dedicated **administrator** `nis2osq` | 5986 | in use on .105; comparison only |

What the customer's SOC will see from each method, and how to allow it: `sensor-deployment.md` §7.

## 1. Common to every method

- **The collector is switched on per scan profile** (Console → Settings → Scan profiles → the segment's profile → card
  *Software inventory over SSH / WinRM*, *osquery over WinRM*): Collect, credential `ref:<name>`, port. Never on OT
  profiles or OT-classed devices. Once a day per endpoint and method, plus **Run now** on the endpoint's collector card.
- **Targets** are the profile's endpoints of the right class with the port seen open (the probes find 22 / 5986), the
  MAC known, not opted out. Every endpoint that becomes a target is tried: one whose account isn't set up fails once a
  day (a failed login in its log) — set it up or **opt it out** on its collector card.
- **Secrets stay on the sensor host:** `/opt/nis2inv-sensor/config/credentials.yaml` (root, 600; key files next to it,
  root, 600). The profile only names `ref:<name>`. `sudo bash /opt/nis2inv-sensor/sensor.sh status` lists the refs
  the sensor has and the ones its profile needs.
- **First contact pins** the host's SSH key / TLS certificate (the backend). A changed key or certificate stops the
  collection before anything is sent; a person accepts or forgets the pin on the collector card (audited).
- **Fixed read-only commands only**; nothing typed in the Console reaches the endpoint. The command set is in the
  sensor release (`internal/sshinv`, `internal/winrminv`).
- **Revoking** an endpoint: remove the account (or its key) on the endpoint, then opt it out in the Console so it
  isn't tried again.

## 2. Linux — SSH collector

**What it reads** (unprivileged): os-release, kernel, host name, interface MACs, packages (dpkg / rpm / snap / Python),
DMI hardware, virtualisation, Secure Boot, sshd's effective settings, automatic updates, reboot needed, firewall /
audit / time services, sudo groups, uid-0 accounts. With the optional sudo rule also the serial number and product
UUID.

### 2.1 Sensor host — once per sensor (or per customer)

```bash
sudo ssh-keygen -t ed25519 -N '' -C "nis2inv@$(hostname)" -f /opt/nis2inv-sensor/config/nis2inv_ed25519
sudo chmod 600 /opt/nis2inv-sensor/config/nis2inv_ed25519
sudo cat /opt/nis2inv-sensor/config/nis2inv_ed25519.pub
```
Add the credential (the command opens `credentials.yaml` in an editor, then restarts the sensor):
```bash
sudo bash /opt/nis2inv-sensor/sensor.sh credentials
```
```yaml
linux-inventory:
  type: ssh_key
  username: nis2inv
  key_file: nis2inv_ed25519
```
The key has no passphrase (the sensor runs unattended) and is root-only; a key readable by others is refused.

### 2.2 Linux target — as root

`PUB` = the line printed above, `SENSOR` = the sensor's address on the segment:
```bash
PUB='ssh-ed25519 AAAA… nis2inv@<sensor host>'
SENSOR='172.16.10.101'
id nis2inv >/dev/null 2>&1 || useradd -m -s /bin/sh nis2inv
usermod -p '*' nis2inv
install -d -m 700 -o nis2inv -g nis2inv /home/nis2inv/.ssh
printf 'restrict,from="%s" %s\n' "$SENSOR" "$PUB" > /home/nis2inv/.ssh/authorized_keys
chown nis2inv:nis2inv /home/nis2inv/.ssh/authorized_keys && chmod 600 /home/nis2inv/.ssh/authorized_keys
```
- `usermod -p '*'`: no password, not locked (sshd refuses keys for a `!`-locked account when PAM is off).
- `restrict,from=`: no shell features (no forwarding, no pty), and the key works only from the sensor's address.
- No sudo, no groups. sshd: if `AllowUsers` / `AllowGroups` / a `Match` block limits logins, add `nis2inv` there.
- Host firewall: SSH from the sensor, e.g. `ufw allow from 172.16.10.101 to any port 22 proto tcp`; on Proxmox VE the
  datacenter / node firewall (pve-firewall) the same way.

Optional — **serial number** (the DMI serial and UUID files are root-only):
```bash
cat > /etc/sudoers.d/nis2inv <<'EOF'
nis2inv ALL=(root) NOPASSWD: /usr/bin/cat /sys/class/dmi/id/product_serial /sys/class/dmi/id/product_uuid
EOF
chmod 440 /etc/sudoers.d/nis2inv && visudo -cf /etc/sudoers.d/nis2inv
sudo -u nis2inv sudo -n /usr/bin/cat /sys/class/dmi/id/product_serial /sys/class/dmi/id/product_uuid
```
Exactly that command line (no other file, no shell). Then the profile's checkbox *Read the serial number (Linux)*.
Without the rule keep the checkbox off: sudo refuses and logs it on every run. VMs have no real serial.

The host-key fingerprint, to compare with the Console's pin after the first contact:
```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Many hosts: the same steps as a configuration-management state (Ansible, Salt): the account, the one
`authorized_keys` line, the optional sudoers file.

### 2.3 Console

Scan profile → *Software inventory over SSH*: Collect, credential `ref:linux-inventory`, classes (default Linux), port
(default 22) → Save.

### 2.4 Checks

1. Sensor log (`sudo bash /opt/nis2inv-sensor/sensor.sh status`): `inventory: ssh <ip> ok (…) in N ms (slowest: …)`.
2. Endpoint → Sources → *SSH collector*: Collected; host key pinned = the fingerprint from 2.2; package count.
3. With the sudo rule: Device → Serial number from the collector.
4. Failures on the card: `auth_failed` (key line missing / wrong, `from=` not the sensor's address, `AllowUsers`),
   `unreachable` (firewall), `host_key_changed` (accept or forget on the card after checking the host).

### 2.5 Revoke

`userdel -r nis2inv` and `rm -f /etc/sudoers.d/nis2inv` on the target (or delete the one `authorized_keys` line);
Console: opt the endpoint out. A stolen sensor key: remove its public key from every target and make a new one
(§2.1).

## 3. Windows — WinRM collector, set up by hand

For standalone machines and small sites (workgroup or a few domain members a person sets up one by one). Checked on
.105 (Windows 11 25H2, DISA STIG hardened).

**What it reads** (non-admin, registry and files only, no WMI): OS build + UBR, installed programs (HKLM, both views),
Store packages registered on the machine, updates from the servicing store, interface MACs, the SMBIOS table
(serial, UUID, board serial), Secure Boot, SMB1, RDP / NLA, firewall per profile, LSA protection, BitLocker, Security
Center antivirus, Defender versions and signature date, Device Guard (configured), local Administrators. Blind spot:
per-user programs (installed into a user's own profile).

**Transport:** HTTPS 5986 only, NTLMv2 bound to the TLS channel, the host's certificate pinned; one WinRS shell running
one fixed PowerShell script. The account gets the WinRS shell, not PowerShell remoting.

### 3.1 Sensor host — the credential

A long random password (one per profile; it is the same local account on every host of that profile):
```bash
openssl rand -base64 24
```
```bash
read -rs WINPW
```
```bash
printf '\nwindows-inventory:\n  type: winrm\n  username: nis2inv\n  password: "%s"\n' "$WINPW" | sudo tee -a /opt/nis2inv-sensor/config/credentials.yaml >/dev/null; unset WINPW
sudo chown root:root /opt/nis2inv-sensor/config/credentials.yaml && sudo chmod 600 /opt/nis2inv-sensor/config/credentials.yaml
sudo docker restart nis2inv-sensor
sudo bash /opt/nis2inv-sensor/sensor.sh status
```

### 3.2 Windows target — PowerShell as Administrator

The `Read-Host` line on its own (paste the password there); `$sensor` = the sensor's address:
```powershell
$pw = Read-Host -AsSecureString 'Password for nis2inv'
```
```powershell
$sensor = '172.16.10.101'

# 1. Local account, not an administrator; member of Remote Management Users (SID S-1-5-32-580: any UI language).
#    The description takes at most 48 characters.
New-LocalUser -Name nis2inv -Password $pw -FullName 'NIS2 inventory (read-only)' -Description 'WinRM inventory (nis2inv sensors)' -PasswordNeverExpires -UserMayNotChangePassword
Add-LocalGroupMember -SID 'S-1-5-32-580' -Member nis2inv
Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object Name -like '*nis2inv'   # Administrators: must print nothing

# 2. Certificate for the HTTPS listener (self-signed, 5 years, key not exportable)
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(5) -FriendlyName 'WinRM HTTPS (nis2inv)'

# 3. HTTPS listener; Negotiate on, Basic off, channel binding required (the collector sends it)
Set-Service WinRM -StartupType Automatic; Start-Service WinRM
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
Set-Item WSMan:\localhost\Service\Auth\Basic $false -Force
Set-Item WSMan:\localhost\Service\Auth\Negotiate $true -Force
Set-Item WSMan:\localhost\Service\Auth\CbtHardeningLevel Strict -Force

# 4. Remote Management Users may open the WinRM shell (WinRM's RootSDDL admits only Administrators by default).
#    WinRM refuses this change while a network is Public (laptops on Wi-Fi): it switches such networks to Private
#    for the change only and back right after.
$p = @(Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public')
$p | Set-NetConnectionProfile -NetworkCategory Private
$s = (Get-Item WSMan:\localhost\Service\RootSDDL).Value; $s
if ($s -notlike '*(A;;GA;;;RM)*') { $n = if ($s -match 'S:') { $s -replace 'S:', '(A;;GA;;;RM)S:' } else { $s + '(A;;GA;;;RM)' }; Set-Item WSMan:\localhost\Service\RootSDDL $n -Force }
$p | Set-NetConnectionProfile -NetworkCategory Public
Restart-Service WinRM
(Get-Item WSMan:\localhost\Service\RootSDDL).Value   # must contain (A;;GA;;;RM)
winrm get winrm/config/winrs | Select-String AllowRemoteShellAccess   # must be true

# 5. Firewall: 5986 from the sensor only (several sensors on the segment: -RemoteAddress 10.0.0.5,10.0.0.6)
New-NetFirewallRule -DisplayName 'WinRM HTTPS from nis2inv sensor' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $sensor -Action Allow -Profile Any

# 6. The certificate's fingerprint, in the form the Console shows
'x509 SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)).TrimEnd('=')
```
Recommended: deny `nis2inv` local and RDP logon (it needs only the network logon; merges with the existing lists):
```powershell
$sid = (Get-LocalUser nis2inv).SID.Value; $f = "$env:TEMP\nis2inv-rights.inf"; $db = "$env:TEMP\nis2inv-rights.sdb"
secedit /export /cfg $f /areas USER_RIGHTS | Out-Null
$c = [System.Collections.Generic.List[string]](Get-Content $f)
foreach ($r in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
  $i = $c.FindIndex([Predicate[string]]{ param($l) $l -like "$r *" })
  if ($i -ge 0) { if ($c[$i] -notlike "*$sid*") { $c[$i] = $c[$i] + ",*$sid" } } else { $c.Insert($c.IndexOf('[Privilege Rights]') + 1, "$r = *$sid") }
}
$c | Set-Content $f -Encoding Unicode
secedit /configure /db $db /cfg $f /areas USER_RIGHTS | Out-Null
Remove-Item $f, $db -ErrorAction SilentlyContinue
```
The fingerprint later, from a new window:
`$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'WinRM HTTPS (nis2inv)'`, then line 6.

### 3.3 Hardened hosts (DISA STIG / CIS)

- **"Access this computer from the network"** (`SeNetworkLogonRight`): STIG WN11-UR-000010 allows only Administrators
  and Remote Desktop Users. The card says "password isn't accepted" and the Security log has 4625 with status
  `0xC000015B` from workstation `NIS2INV`. Add Remote Management Users, keeping what is there (check first:
  `secedit /export /cfg $env:TEMP\sec.inf; Select-String SeNetworkLogonRight $env:TEMP\sec.inf`; when `gpresult
  /scope computer /z` shows the right from a GPO, change the GPO instead):
  ```powershell
  @'
  [Unicode]
  Unicode=yes
  [Version]
  signature="$CHICAGO$"
  Revision=1
  [Privilege Rights]
  SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-555,*S-1-5-32-580
  '@ | Set-Content -Encoding Unicode $env:TEMP\netlogon.inf
  secedit /configure /db $env:TEMP\netlogon.sdb /cfg $env:TEMP\netlogon.inf /areas USER_RIGHTS
  ```
  Record it as a documented exception: one read-only non-admin account, WinRM HTTPS only, firewall to the sensor,
  NTLMv2 bound to TLS, certificate pinned. Never use Remote Desktop Users instead (it adds RDP).
- **Domain members** under STIG deny network logon to every local account (WN11-UR-000070, "Deny access to this
  computer from the network" includes *Local account*): use §4 (a domain account) there.
- Script Block Logging, AppLocker / WDAC: the collector runs `powershell.exe` (Windows PowerShell 5.1) as the account;
  an allow-list that blocks PowerShell for non-admins blocks the collector — allow it for the account (path
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, user = the account), not for everyone.

### 3.4 Sensor host — reachability and the same fingerprint

```bash
nc -zv -w2 <windows ip> 5986
openssl s_client -connect <windows ip>:5986 </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256 -binary | base64 | tr -d '='
```

### 3.5 Console

Scan profile → *Software inventory over WinRM*: Collect, credential `ref:windows-inventory`, port empty (5986) → Save.
The Windows probe group finds 5986 open (or a targeted one-shot, `testing-probes.md` §1).

### 3.6 Checks

1. Sensor log: `inventory: winrm <ip> ok (windows 10.0.…, N packages, M updates) in N ms (slowest: …)`.
2. Endpoint → Sources → *WinRM collector*: Collected; certificate pinned = the fingerprint from 3.2 line 6; programs,
   Store packages, updates; Hygiene card filled.
3. Failures on the card: "password isn't accepted" (credential, or §3.3 network-logon right), "may not use WinRM"
   (Remote Management Users / RootSDDL, 3.2 steps 1 and 4), "didn't answer with an NTLM challenge" (`winrm get
   winrm/config/service/auth`), `unreachable` (listener or firewall), certificate changed (accept / forget on the card).

### 3.7 Revoke

`Remove-LocalUser nis2inv`; remove the firewall rule, and the listener and certificate if nothing else uses them
(`Get-ChildItem WSMan:\localhost\Listener`, `Remove-Item WSMan:\localhost\Listener\<name> -Recurse`). Console: opt
the endpoint out.

**Risk to state to the customer:** the account may open a WinRS shell, so with its password anyone could run programs
as that unprivileged user on every host where it exists — the reason for the firewall rule to the sensor's address,
the long random password, one credential per profile (segment), and the denied local / RDP logon.

## 4. Windows — WinRM collector in Active Directory (Group Policy)

**Not run on a domain yet** (the lab has no AD): the steps use Windows' own mechanisms (GPO settings, Group Policy
Preferences, AD CS auto-enrolment, a computer startup script). Pilot on one OU with one machine first; the checks in
§3.6 apply unchanged.

**Two limits of today's collector in a domain:**
- **NTLM only** (NTLMv2 bound to TLS; Kerberos isn't built). A domain that restricts NTLM ("Network security:
  Restrict NTLM: Incoming NTLM traffic" = deny domain accounts, or the account in *Protected Users*) refuses the
  collector. Each logon is validated by a domain controller (4776 there).
- **The certificate is pinned per host.** An auto-enrolled certificate is renewed before it expires; the new
  certificate stops the collection on that host until a person accepts it on the collector card. Use a template with
  a long validity (e.g. 2 years, renew at 6 weeks) and expect one accept per host per renewal. (Trusting the
  enterprise CA plus the host name instead of a pin is a possible product change, not built.)

### 4.1 Active Directory — account and group (Domain admin workstation, PowerShell with the AD module)

```powershell
$pw = Read-Host -AsSecureString 'Password for svc-nis2inv'
```
```powershell
New-ADGroup -Name 'NIS2 Inventory Collectors' -GroupScope Global -GroupCategory Security -Description 'WinRM inventory accounts (read-only, non-admin)'
New-ADUser -Name 'svc-nis2inv' -SamAccountName 'svc-nis2inv' -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -Description 'NIS2 inventory WinRM collector (read-only, non-admin)'
Set-ADAccountControl 'svc-nis2inv' -AccountNotDelegated $true
Add-ADGroupMember 'NIS2 Inventory Collectors' -Members 'svc-nis2inv'
```
Only Domain Users + this group; never an admin group; not in *Protected Users* (it blocks NTLM). A gMSA can't be
used: the sensor isn't a domain member and needs the password.

### 4.2 Certificate template (AD CS)

Duplicate *Web Server* (or *Computer*): name `WinRM HTTPS`, Enhanced Key Usage **Server Authentication**, subject
name **built from Active Directory: DNS name** (the WinRM listener's host name must be in the certificate), key not
exportable, validity 2 years / renewal 6 weeks, Security: *Domain Computers* Read + Enroll + Autoenroll. Publish it on
the issuing CA.

### 4.3 GPO `NIS2 inventory collection` (linked to the OUs with the target computers, not Domain Controllers)

Computer Configuration:

| Setting | Path | Value |
|---|---|---|
| Certificate auto-enrolment | Policies → Windows Settings → Security Settings → Public Key Policies → *Certificate Services Client – Auto-Enrollment* | Enabled, renew expired / update pending / remove revoked |
| WinRM service | Preferences → Control Panel Settings → Services → `WinRM` | Startup Automatic, action Start |
| Basic authentication off | Policies → Administrative Templates → Windows Components → Windows Remote Management (WinRM) → WinRM Service → *Allow Basic authentication* | Disabled |
| Channel binding | same folder → *Specify channel binding token hardening level* | Enabled, **Strict** |
| Unencrypted traffic off | same folder → *Allow unencrypted traffic* | Disabled |
| Remote Management Users | Preferences → Control Panel Settings → Local Users and Groups → New Local Group: `Remote Management Users (built-in)`, action **Update**, add member `<DOMAIN>\NIS2 Inventory Collectors`; Common tab: *Remove this item when it is no longer applied* | adds the group; keeps the other members (Restricted Groups would replace them) |
| Network logon | Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment → *Access this computer from the network* | the list the machines have today **plus** `<DOMAIN>\NIS2 Inventory Collectors` (a GPO replaces the whole list: copy the current one from `gpresult` / the baseline first; STIG: Administrators, Remote Desktop Users + the group — a documented WN11-UR-000010 exception) |
| No local / RDP logon for the account | same folder → *Deny log on locally*, *Deny log on through Remote Desktop Services* | add `<DOMAIN>\NIS2 Inventory Collectors` to the existing lists |
| Firewall | Policies → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security → Inbound Rules → New: TCP 5986, scope remote address = the sensors' addresses, Allow, all profiles | name `WinRM HTTPS from nis2inv sensors` |
| Startup script | Policies → Windows Settings → Scripts → Startup → PowerShell Scripts → `nis2inv-winrm-https.ps1` (below) | creates / renews the HTTPS listener, adds Remote Management Users to the RootSDDL |

Don't enable *Allow remote server management through WinRM* for this: it opens an HTTP listener (5985) for whatever
the IP filter allows; the collector uses HTTPS only.

**`nis2inv-winrm-https.ps1`** (runs as SYSTEM at startup; idempotent; does nothing until the certificate is there):
```powershell
$ErrorActionPreference = 'Stop'
Set-Service WinRM -StartupType Automatic; Start-Service WinRM
$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$cert = Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(1) -and
                 ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1') -and
                 ($_.DnsNameList.Unicode -contains $fqdn) } |
  Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { exit 0 }   # not enrolled yet: the next start tries again
$changed = $false
$l = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
if ($l) {
  $tp = (Get-ChildItem "WSMan:\localhost\Listener\$($l.Name)" | Where-Object Name -eq 'CertificateThumbprint').Value
  if ($tp -ne $cert.Thumbprint) { Remove-Item "WSMan:\localhost\Listener\$($l.Name)" -Recurse -Force; $l = $null }
}
if (-not $l) { New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null; $changed = $true }
$s = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
if ($s -notlike '*(A;;GA;;;RM)*') {
  $n = if ($s -match 'S:') { $s -replace 'S:', '(A;;GA;;;RM)S:' } else { $s + '(A;;GA;;;RM)' }
  Set-Item WSMan:\localhost\Service\RootSDDL $n -Force; $changed = $true
}
if ($changed) { Restart-Service WinRM }
```
A renewed certificate takes effect at the next start (or run the script by hand); the Console then shows the
certificate change on that host (accept it after checking the fingerprint, §3.2 line 6 with the new certificate).

Test on the pilot machine before linking the GPO wider (**Windows target**, PowerShell as Administrator):
`gpupdate /force`, `certutil -pulse`, restart, then `winrm enumerate winrm/config/listener` (an HTTPS listener with the
auto-enrolled certificate's thumbprint), `(Get-Item WSMan:\localhost\Service\RootSDDL).Value` (contains
`(A;;GA;;;RM)`), `Get-LocalGroupMember -SID 'S-1-5-32-580'` (the domain group), `gpresult /scope computer /h
$env:TEMP\gp.html`.

### 4.4 Sensor host — the credential

As §3.1 with the domain account (`domain` = the NetBIOS domain name; `username` without `DOMAIN\`):
```bash
read -rs WINPW
```
```bash
printf '\nwindows-domain:\n  type: winrm\n  username: svc-nis2inv\n  domain: "%s"\n  password: "%s"\n' '<NETBIOS DOMAIN>' "$WINPW" | sudo tee -a /opt/nis2inv-sensor/config/credentials.yaml >/dev/null; unset WINPW
sudo chown root:root /opt/nis2inv-sensor/config/credentials.yaml && sudo chmod 600 /opt/nis2inv-sensor/config/credentials.yaml
sudo docker restart nis2inv-sensor
```
Console: the profile's *Software inventory over WinRM* with `ref:windows-domain`. Checks and failures as §3.6; a DC
refusing NTLM shows as "password isn't accepted" with 4776 / 8004 events on the domain controller.

### 4.5 Revoke

Disable or delete `svc-nis2inv` — that alone stops collection on every host. Then unlink the GPO: its firewall rule
goes at the next refresh, and the group membership too (the *Remove this item …* option above); user rights keep the
last applied list unless another GPO sets them (set them back in the baseline GPO); the listener and the RootSDDL entry
stay until a cleanup script reverses the startup script. Console: switch the profile's WinRM collection off or opt
endpoints out.

## 5. Windows — Microsoft Intune (later)

Not built or tested. What has to be settled first, with the Intune mechanism that would carry each part:

| Need | Candidate mechanism | Open question |
|---|---|---|
| The account | a local account created by a remediation script; or a domain account on hybrid-joined devices (§4) | a local account's password must reach every device and stay secret (Windows LAPS manages one admin account, not ours); cloud-only Entra accounts don't log on over NTLM |
| Remote Management Users membership | Endpoint security → Account protection → *Local user group membership* | supports the built-in group for the chosen account type? |
| Certificate | a PKCS or SCEP certificate profile (Server Authentication, subject = device DNS name) | the same per-host pin renewal as §4 |
| Listener + RootSDDL | a remediation (detection + remediation script pair: the §4 startup script as the remediation) | runs as SYSTEM: fine |
| Firewall | Endpoint security → Firewall rules: TCP 5986 from the sensors | — |
| Network logon right | Settings catalog → User Rights → *Access From Network* | replaces the list, as with GPO |
| Reachability | the device must be on a segment with a sensor | roaming devices are out of reach of a segment sensor — the reason the platform reads Intune / an EDR as an inventory source instead (roadmap) |

Decision needed before building: for Intune-managed fleets, collect over WinRM at all, or read Intune's own device
inventory as an inventory source (like Wazuh, step 34) and keep WinRM for unmanaged machines.

## 6. osquery over WinRM (optional, comparison only)

For a customer who runs osqueryd and wants our collector compared with it. osqueryd's pipe `\\.\pipe\osquery.em` allows
SYSTEM and Administrators only, so this method needs a **dedicated administrator account** (`nis2osq`), never the
§3 account (the profile refuses the same credential for both). It doesn't feed findings.

**Windows target** — PowerShell as Administrator, after §3.2 steps 2–5 (the same listener, firewall and certificate):
```powershell
$pw = Read-Host -AsSecureString 'Password for nis2osq'
```
```powershell
New-LocalUser -Name nis2osq -Password $pw -PasswordNeverExpires -AccountNeverExpires -Description 'NIS2 inventory: osquery over WinRM'
Add-LocalGroupMember -SID 'S-1-5-32-544' -Member nis2osq
```
Then deny it local and RDP logon with the §3.2 *Recommended* block, `nis2inv` replaced by `nis2osq`.

- A local administrator logging on over the network gets a filtered token unless LocalAccountTokenFilterPolicy = 1;
  STIG WN11-CC-000037 requires 0, and then the pipe refuses it — there a domain account in the local Administrators
  is the way (with the admin rights that implies).
- **Sensor host**: as §3.1 with `windows-osquery` / `nis2osq`. **Console**: the profile's *osquery over WinRM* card,
  credential `ref:windows-osquery`.
- Revoke: `Remove-LocalUser nis2osq`.
