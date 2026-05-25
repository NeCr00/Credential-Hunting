# credshunter

Read-only credential discovery for authorized post-exploitation.
One Bash script for Linux, one PowerShell script for Windows.

Locates passwords, private keys, NTLM and Kerberos hashes, password-manager
databases, cloud tokens, and other reusable authentication material in known
OS locations and within user-supplied paths.

```sh
# Linux
sudo ./credshunter.sh -p / -m 10 -o loot.txt
```

```powershell
# Windows
.\credshunter.ps1 -Path C:\ -MaxFileSizeMB 10 -OutputFile loot.txt
```

---

## Pipeline

Each invocation runs up to five stages, each with progressively wider scope.

| # | Stage | What it does |
|---|---|---|
| 1 | OS-level credential locations | Targeted extraction from registry, GPP, unattend, shadow, RDP/PuTTY/WinSCP sessions, cloud CLIs, browser stores, mail and VPN configs, Wi-Fi profiles. |
| 2 | Confirmed credential containers | Files whose extension *is* the format. `.kdbx`, `.ppk`, `.pfx`, `.keytab`, `.jks`, `.lpdb`, `.opvault`, …. Reported as `[CRITICAL]`. |
| 3 | Auxiliary credential-related files | Strong signal, ambiguous semantics. `.pem`, `.gpg`, `.rdp`, `.ovpn`, `.wallet`. |
| 4 | Suspicious filenames | Tight substring match. `password*`, `vault*`, `htpasswd`, `pwdump`, `sshpass`, `kerberoast`. |
| 5 | File-content scan | Recursive regex over extension-matched candidates inside `-p`. |

Stage 1 is always available. Stages 2–5 require at least one `-p` / `-Path`.

---

## Output

Findings are stratified so an operator knows where to look first.

| Tag | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed credential container — extension is proof. |
| `[HIGH]` | Direct credential assignment, NTLM/Kerberos hash, cloud key, JWT, GPP `cpassword`. |
| `[KEY]` | `BEGIN … PRIVATE KEY` headers, PuTTY private keys, readable SAM hive. |
| `[INTEREST]` | Auxiliary credential-related file. |
| `[NAME]` | Filename strongly suggests credentials. |
| `[LOW]` | Generic token shape — manual review. |
| `[CHECK]` | OS location inspected (existence / readability). |
| `[SKIP]` | File skipped (binary / size / unreadable). |

Exit `1` if any `[CRITICAL]`, `[HIGH]`, or `[KEY]` finding lands.
Exit `130` on interrupt. Exit `0` clean.

---

## Options

| Bash | PowerShell | Effect |
|---|---|---|
| `-p PATH` (repeat) | `-Path PATH[,PATH]` | Scope for stages 2–5. |
| `-a` / `--all` | `-All` | Stage 5 scans every readable text file. |
| `-m N` | `-MaxFileSizeMB N` | Skip files larger than N MB. Default 5. |
| `--no-size-limit` | `-NoSizeLimit` | Disable the size cap entirely. |
| `-j N` | — | Parallel grep workers (Bash only). |
| `-s` / `--skip-system` | `-SkipSystem` | Skip stage 1 (OS-level checks). |
| `-q` / `--quiet` | `-Quiet` | Reduce status noise. Findings still printed. |
| `--no-color` | `-NoColor` | Strip ANSI. |
| `-o FILE` | `-OutputFile FILE` | Append plain-text log. |
| `-h` / `--help` | `Get-Help .\credshunter.ps1` | Full help. |

---

## Examples

```sh
# Full sweep, elevated, write log
sudo ./credshunter.sh -p / -m 10 -o /tmp/findings.txt

# Targeted directories, eight parallel workers
./credshunter.sh -p /var/www -p /home -p /opt -j 8

# Aggressive — every readable file, no size cap
./credshunter.sh -a --no-size-limit -p /srv/customer-app

# Content-scan only, quiet
./credshunter.sh --skip-system -p . -q
```

```powershell
# Full sweep, elevated
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\credshunter.ps1 -Path C:\ -MaxFileSizeMB 10 -OutputFile loot.txt

# User profiles plus IIS
.\credshunter.ps1 -Path C:\Users, C:\inetpub

# All files inside a backup tree
.\credshunter.ps1 -All -Path D:\Backup

# Pipe-safe (e.g. through evil-winrm)
.\credshunter.ps1 -Path C:\Users -NoColor -OutputFile C:\Users\Public\loot.txt
```

---

## What is checked

### Linux

Shell histories · SSH keys & configs · `/etc/environment` and `profile.d` ·
cron · systemd units · MySQL / PostgreSQL / MongoDB / Redis configs · web-app
configs (`wp-config.php`, Joomla `configuration.php`, Drupal `settings.php`,
Laravel `.env`, `web.config`, `.htpasswd`) · Docker & Kubernetes ·
`~/.aws`, `~/.azure`, `~/.gcloud`, `~/.kube`, `~/.docker`, `~/.netrc`,
`~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.s3cfg`, rclone · Firefox
& Chrome credential stores · `/etc/shadow`, `/etc/sudoers`, `/etc/anaconda-ks.cfg`
· NetworkManager and wpa_supplicant · OpenVPN, WireGuard, IPsec, PPP ·
Postfix, Dovecot, Sendmail · Samba, vsftpd, proftpd, rsyncd · Squid, SNMP,
Kerberos keytabs.

### Windows

AutoLogon registry · Group Policy Preferences `cpassword` · `unattend.xml` /
`sysprep` · PowerShell history (`PSReadLine`) for every user profile ·
`cmdkey /list` and Credential / Vault directories · saved RDP / PuTTY /
WinSCP / FileZilla sessions · VNC registry keys · SNMP communities · SAM /
SYSTEM / SECURITY hives (live, `repair\`, `RegBack\`) · IIS `web.config` +
`applicationHost.config` + live `appcmd` apppool dump · scheduled task XML ·
services running under non-system `StartName` · `netsh wlan show profile
key=clear` per profile · McAfee `SiteList.xml` · Chrome / Edge / Brave /
Opera / Firefox credential stores · cloud CLIs (`.aws`, `.azure`, `gcloud`,
`.kube`, `.docker`) · OpenVPN / WireGuard · .NET `machine.config`.

---

## Pattern set

**Confirmed extensions (stage 2)**
`.kdbx` `.kdb` `.psafe3` `.agilekeychain` `.opvault` `.1pif` `.1pux` `.lpdb`
`.enpass` `.enpassdb` `.bitwarden_export` `.ppk` `.pfx` `.p12` `.pvk`
`.jks` `.keystore` `.truststore` `.bek` `.fve` `.keytab` `.dpapimk`

**Auxiliary extensions (stage 3)**
`.pem` `.key` `.priv` `.asc` `.gpg` `.rdp` `.ovpn` `.wallet`

**Suspicious-name fragments (stage 4)**
`password*` · `passwd*` · `pswd` · `credential*` · `creds` · `secret*` ·
`vault*` · `authentication` · `authenticator` · `passphrase` · `dbpass` ·
`database_password` · `masterkey` · `master_password` · `sshpass` ·
`htpasswd` · `pgpass` · `keyring` · `pwdump` · `kerberoast` · `asreproast` ·
`hashdump` · `keepass`

**Content patterns (stage 5)**

- Generic password assignments (`password|passwd|pwd|pass|passphrase`)
- Database / service password keys (`db_password`, `mysql_pwd`, …)
- Connection strings (`Server=…;Password=…`, `Data Source=…;`)
- URL-embedded credentials (`scheme://user:pass@host`)
- GPP `cpassword="…"` blobs
- AWS `AKIA…` + 40-char secret, GCP service-account JSON, GitHub
  `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, Slack `xox*`, webhook URLs
- JWTs (`eyJ…\.eyJ…\.…`), bearer tokens, generic API secrets
- NTLM dumps (`user:rid:lm:nt:::`), Kerberos `$krb5tgs$` / `$krb5asrep$`,
  MS Cache `$DCC2$`
- shadow-format hashes (`$1$` … `$y$`), bcrypt
- Private-key headers (RSA, DSA, EC, OpenSSH, PKCS#8, encrypted, PGP, PuTTY)

---

## False-positive controls

- **Placeholder denylist** — `password`, `changeme`, `your_password`, `null`,
  `none`, `example`, `xxxxx`, `*****`, …
- **Template markers rejected** — `${VAR}`, `$(cmd)`, `{{tpl}}`,
  `<placeholder>`, `%ENVVAR%`, `#{expr}`
- **Suffix heuristic** — `*_PASSWORD`, `YOUR_*`, `INSERT_*`, `REPLACE_*`,
  `EXAMPLE_*` dropped
- **Length / alphabet checks** — values under 4 or over 256 chars, single
  repeating char, pure punctuation → drop
- **Confidence stratification** — LOW patterns are emitted only if no HIGH
  match landed in the same file
- **Per-file match cap** — 20 hits per file maximum
- **Per-path dedup** — every file scanned at most once across all stages
- **Default path pruning** — `.git`, `node_modules`, `.venv`, `__pycache__`,
  `target`, `build`, `dist`, `WinSxS`, `Installer`, `SoftwareDistribution`,
  `/proc`, `/sys`, `/usr/share`, `/usr/lib`, `/var/log`, `/var/cache`,
  `/var/lib/docker/overlay2`, …

---

## Requirements

| Linux | Windows |
|---|---|
| Bash 4+ | PowerShell 5.1 or 7+ |
| `find`, `grep`, `awk`, `sed`, `stat` | Built-in .NET |
| `pkill` (recommended, for clean interrupt) | Elevated session for SAM / Vault / Wi-Fi key access |

Tested on Debian / Ubuntu, RHEL / CentOS / Rocky / Alma, Arch, Alpine, and
Windows 10 / 11 / Server 2016–2022.

---

## Safety

Both scripts are **read-only**. They never modify the host, never write
outside the optional log file, and never transmit data. Run only against
systems you have explicit written authorization to assess.

Ctrl + C aborts cleanly: SIGINT to the foreground process group kills the
running `grep` / `find` and exits with status 130. All temporary files are
removed on exit.

---

## License

For authorized security testing only. No warranty.
