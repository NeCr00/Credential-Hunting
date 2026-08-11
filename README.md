<div align="center">

<img src="assets/credshunter-icon.svg" alt="CredsHunter" width="148" />

# CredsHunter

**Find credentials that can actually be reused for lateral movement or privilege escalation.**

<br>

![read-only](https://img.shields.io/badge/read--only-yes-3fb950?style=flat-square)
![no network](https://img.shields.io/badge/network-none-3fb950?style=flat-square)
![version](https://img.shields.io/badge/version-2.4.0-2dd4bf?style=flat-square)
![bash](https://img.shields.io/badge/bash-4%2B-2b3137?style=flat-square&logo=gnubash&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-2b3137?style=flat-square&logo=powershell&logoColor=white)
![authorized use only](https://img.shields.io/badge/use-authorized%20only-f85149?style=flat-square)

</div>

---

## Overview

`CredsHunter` is a **read-only credential discovery toolkit** for authorized internal penetration testing and post-exploitation.

It searches Linux and Windows hosts for credential material that is realistically useful during an engagement: plaintext passwords, database connection strings, private keys, credential containers, reusable hashes, shell-history credentials, GPP `cpassword` values, unattended-install credentials, and other high-value local artifacts.

The project deliberately **does not target cloud / SaaS access tokens** such as JWTs, AWS access keys, GitHub tokens, Slack tokens, or generic API keys. Those artifacts frequently create noise during internal assessments and are usually less useful for host-to-host lateral movement.


### Design goals

- **Reuse-focused** — prioritize credentials that can support privilege escalation or lateral movement.
- **Read-only** — never modify the target system.
- **Network-silent** — never transmit discovered data.
- **Low-noise** — tuned filters suppress common false positives.
- **Cross-platform** — matching Linux and Windows workflows.
- **Operator-friendly** — live findings, grouped severity tiers, plain-text logging, stage controls, and clean interruption handling.

---

## How it works

CredsHunter uses a five-stage funnel that narrows from known credential locations to recursive content inspection.

| Stage | Focus | Examples |
|:--:|---|---|
| **1** | OS & application credential stores | Registry, GPP, histories, vaults, keys, saved sessions, known credential locations |
| **2** | Confirmed credential containers | `.kdbx`, `.ppk`, `.pfx`, `.p12`, `.keytab`, keystores and similar containers |
| **3** | High-value file types | Private keys, `.env`, backups, databases, captures, archives, configuration files |
| **4** | Suspicious filenames | `*password*`, `*secret*`, `*credential*`, `*login*`, `*account*` |
| **5** | Content scan | 70+ tuned credential regexes with false-positive filtering |

Stages **1** and **5** perform the deepest inspection. Stages **2–4** are intentionally fast filename and extension passes.

Each finding is filtered before it reaches the final results, and findings are surfaced as the scan progresses rather than being hidden until the end.

---

## Quick start

### Linux

```bash
git clone https://github.com/NeCr00/Credential-Hunting.git
cd Credential-Hunting
chmod +x credshunter.sh

sudo ./credshunter.sh -p / -o loot.txt
```

### Windows

```powershell
git clone https://github.com/NeCr00/Credential-Hunting.git
cd Credential-Hunting

.\credshunter.ps1 -Path C:\ -OutputFile loot.txt
```

> Elevated execution is recommended when you want access to protected credential locations such as SAM / SYSTEM hives, vault directories, or other privileged stores.

---

## Usage

### Linux

Full host sweep with findings written to a file:

```bash
sudo ./credshunter.sh -p / -o loot.txt
```

Scan selected locations only:

```bash
./credshunter.sh -p /home -p /var/www -p /opt
```

Targeted scan without the slower recursive content stage:

```bash
./credshunter.sh -p /var/www -p /home --no-stage5
```

Exclude a directory tree:

```bash
./credshunter.sh -p / -x /var/lib/customer-app
```

### Windows

Full `C:\` sweep:

```powershell
.\credshunter.ps1 -Path C:\ -OutputFile loot.txt
```

Scan multiple locations:

```powershell
.\credshunter.ps1 -Path C:\Users,C:\inetpub
```

Web / database host with SQL and CSV-style data scanning enabled:

```powershell
.\credshunter.ps1 -Path D:\ -IncludeData
```

Disable built-in system / vendor exclusions:

```powershell
.\credshunter.ps1 -Path C:\ -NoDefaultExclude
```

CredsHunter is pipe-friendly. Use `--no-color` on Linux or `-NoColor` on Windows when redirecting or filtering output.

---

## Finding tiers

Results are grouped by usefulness and confidence, with the most important findings shown first.

| Tag | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed credential container |
| `[HIGH]` | Reusable password, hash, GPP `cpassword`, or equivalent credential material |
| `[KEY]` | Private key or other key material, including readable SAM / SYSTEM hive findings |
| `[INTEREST]` | High-value file or location worth manual review |
| `[NAME]` | Suspicious filename — useful as a review hint |

A sensitive result in **CRITICAL**, **HIGH**, or **KEY** causes a non-zero sensitive-findings exit status. `INTEREST` and `NAME` findings alone do not.

For example:

```bash
./credshunter.sh -p /etc && echo "No high-confidence credential findings"
```

---

## Scan controls

| Goal | Linux | Windows |
|---|---|---|
| Add scan paths | `-p PATH` / `--path PATH` | `-Path PATH` |
| Exclude paths | `-x PATH` / `--exclude PATH` | `-ExcludePath PATH` |
| Scan every readable text file in Stage 5 | `-a` / `--all` | `-All` |
| Change file-size cap | `-m N` / `--max-size N` | `-MaxFileSizeMB N` |
| Disable size cap | `--no-size-limit` | `-NoSizeLimit` |
| Write findings to file | `-o FILE` / `--output FILE` | `-OutputFile FILE` |
| Skip OS-level checks | `-s` / `--skip-system` / `--no-stage1` | `-SkipSystem` / `-NoStage1` |
| Skip a stage | `--no-stage2` ... `--no-stage5` | `-NoStage2` ... `-NoStage5` |
| Reduce status output | `-q` / `--quiet` | `-Quiet` |
| Disable ANSI colors | `--no-color` | `-NoColor` |
| Include SQL / CSV-style data files | — | `-IncludeData` |
| Disable default vendor/system exclusions | — | `-NoDefaultExclude` |

The default maximum file size is **5 MB**. Increase it when credentials may live in larger logs, dumps, or configuration exports, or disable the cap when appropriate.

---

## Customization

The pattern libraries and file-type lists are intentionally kept in clearly labeled configuration arrays inside each script.

You can extend or trim:

- Stage 2 credential-container extensions
- Stage 3 high-value file types and exact filenames
- Stage 4 suspicious filename tokens
- Stage 5 content-scan extensions
- Credential detection patterns
- False-positive filters

Edit the relevant list in one place; the scanning workflow does not need to be rewritten.

---

## Requirements

| Platform | Requirements |
|---|---|
| **Linux** | Bash 4+, `find`, `grep`, `awk`, `sed`, `stat` |
| **Linux — optional** | `realpath`, `file` |
| **Windows** | PowerShell 5.1+ |
| **Privileges** | Elevated execution is optional, but increases visibility into protected credential locations |

The Linux implementation is designed for common distributions including Debian/Ubuntu, RHEL-family systems, Arch, and Alpine.

---

## FAQ

<details>
<summary><strong>Does CredsHunter change anything on the host?</strong></summary>
<br>

No. The scanner is read-only. It writes only to the output file you explicitly choose, does not transmit findings over the network, and cleans up its temporary working data on exit.

</details>

<details>
<summary><strong>Why are AWS, GitHub, Slack, JWT, and generic API tokens ignored?</strong></summary>
<br>

By design. CredsHunter is optimized for credentials that are useful for local privilege escalation and in-network lateral movement. Cloud and SaaS tokens are a major source of false-positive noise during this type of assessment.

Local cloud-CLI credential **files and locations may still be surfaced for review**; the tool simply avoids treating generic cloud/SaaS token patterns as primary reusable-credential findings.

</details>

<details>
<summary><strong>Stage 5 is slow. How can I speed it up?</strong></summary>
<br>

Narrow the scope with `-p` / `-Path`, exclude noisy trees, keep the default file-size limit, or skip the recursive content scan with `--no-stage5` / `-NoStage5`.

</details>

<details>
<summary><strong>A credential was missed. What should I check?</strong></summary>
<br>

Confirm that the target file:

1. Is inside the selected scan path.
2. Is not inside an excluded path.
3. Is below the configured size limit.
4. Uses an extension included in Stage 5.

For a broader check, use `-a` / `--all` on Linux or `-All` on Windows.

</details>

---

## Wiki

For deeper project documentation, usage notes, and additional information, visit the **[Credential-Hunting Wiki](https://github.com/NeCr00/Credential-Hunting/wiki)**.

---

## Contributing

Contributions are welcome.

If you have a useful credential pattern, a false-positive reduction, a platform-specific credential location, or an improvement to scan performance and output quality, feel free to open an issue or pull request.

---

## Responsible use

CredsHunter is intended for **authorized security testing, internal penetration testing, red-team engagements, labs, and CTF environments**.

Only run it on systems you own or have explicit permission to assess.

<div align="center">
  <sub>Read-only. Network-silent. Built for signal over noise.</sub>
</div>
