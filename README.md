# CredHunter

Hardcoded-credential hunter for authorized internal pentesting. Two self-contained scripts — drop, run, collect, delete:

- **`credhunter.sh`** — Linux (Bash 4+)
- **`credhunter.ps1`** — Windows (PowerShell 5.1+, parallel acceleration on PS 7+)

## What it finds

- Hardcoded passwords in config files, scripts, and source (smart regex with confidence scoring)
- SSH/PKI private keys (PEM, OpenSSH, PuTTY .ppk)
- Unix shadow / `crypt(3)` hashes (md5crypt, bcrypt, SHA-256/512, yescrypt, Argon2)
- NTLM hashes (pwdump format), NetNTLMv2 (Responder output), Kerberos AS-REP / TGS-REP roastable hashes
- **Group Policy Preferences `cpassword` — auto-decrypted** with the public Microsoft AES key
- `.netrc`, `.pgpass`, `.my.cnf`, `.htpasswd`, `tomcat-users.xml`, Jenkins `credentials.xml`, Cisco IOS config patterns
- Embedded credentials in URIs (mongodb://, postgres://, mysql://, redis://, ldap://, ssh://, http(s)://user:pass@)
- PowerShell `ConvertTo-SecureString -AsPlainText -Force` anti-pattern
- Docker `config.json` base64 `auth` field (decoded)
- Ansible vault file markers (flagged for offline crack)
- PuTTY, WinSCP, MobaXterm, FileZilla, mRemoteNG, RDCMan saved sessions (path + reversible-cipher decode where possible)
- KeePass `.kdbx` and similar password-manager DBs (flagged for offline crack)
- Unattend.xml / sysprep.xml (Windows answer files with admin passwords)
- Shell / REPL history (`.bash_history`, PSReadLine, `.mysql_history`, `.psql_history`, etc.)
- Backup hives (`SAM`, `SYSTEM`, `SECURITY` under `Repair\` and `RegBack\`)

## What it does NOT find (out of scope by design)

- API keys / OAuth tokens / JWT / cloud bearer tokens — regex is hard and FP rate high. Use trufflehog or gitleaks for those.
- LSASS / memory dumps — different tool category (mimikatz, dumpert).
- DPAPI-encrypted browser passwords / Credential Manager blobs — requires user logon password to decrypt; the tool enumerates paths only and lists offline-decrypt recipes in the report.
- KeePass / Bitwarden / 1Password vault contents — requires master password; the tool flags the file and recommends `keepass2john` etc.

## Quick start

Linux:
```bash
chmod +x credhunter.sh
./credhunter.sh /home /etc /opt
```

Windows:
```powershell
powershell -ExecutionPolicy Bypass -NoProfile -File .\credhunter.ps1 C:\Users C:\inetpub
```

Run with `-h` / `-Help` for the full flag reference. Design spec: [`docs/specs/2026-05-24-credhunter-design.md`](docs/specs/2026-05-24-credhunter-design.md).

## Common flag combos

```bash
# Quick triage — only HIGH-confidence findings, console only
./credhunter.sh --min-confidence HIGH --output console /home /etc

# Maximum coverage — scan every filetype, parallel
./credhunter.sh --all --workers 8 /

# Stealth-ish — minimal CPU spike, single-threaded
./credhunter.sh --serial --output file --quiet /home /etc

# Include archives (slower but catches creds inside .tar.gz backups)
./credhunter.sh --include-archives /var/backups

# Show plaintext secrets in report (use carefully — per engagement RoE)
./credhunter.sh --show-secrets /home > report.txt
```

PowerShell equivalents:
```powershell
.\credhunter.ps1 -MinConfidence HIGH -Output console C:\Users C:\inetpub
.\credhunter.ps1 -All -Workers 8 C:\
.\credhunter.ps1 -Serial -Output file -Quiet C:\Users
```

## Output

A timestamped directory contains:

- `findings.txt` — human-readable, grouped by confidence
- `findings.jsonl` — one JSON record per finding, ready for `jq`
- `recon.json` — host/user/OS/scan-root metadata
- `skipped.log` — paths skipped (permission denied, oversize, binary)
- `loot/` — optional, with `--collect-loot`: copies of Class A files (kdbx, ssh keys, hive backups)

Sensitive output. Clean up post-engagement.

## Authorized use only

This tool is for authorized penetration testing under signed rules of engagement.
