# CredsHunter
<div align="center">

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/19a115de-0fc1-4745-ba61-b3a69994d07a" />


<br>

![read-only](https://img.shields.io/badge/read--only-yes-3fb950?style=flat-square)
![no network](https://img.shields.io/badge/network-none-3fb950?style=flat-square)
![bash](https://img.shields.io/badge/bash-4%2B-2b3137?style=flat-square&logo=gnubash&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-2b3137?style=flat-square&logo=powershell&logoColor=white)
![authorized use only](https://img.shields.io/badge/use-authorized%20only-f85149?style=flat-square)

</div>

---

`credshunter` hunts material a pentester can **reuse** to move laterally or escalate on Linux and Windows: plaintext passwords, DB connection strings, GPP `cpassword`, SSH and PuTTY keys, NTLM / Kerberos / shadow hashes, command-line creds in shell history, KeePass / RDP / WinSCP files, and more. It deliberately ignores cloud and SaaS tokens (AWS, GitHub, Slack, JWTs) — the noise that rarely helps inside a network.

One Bash script for Linux, one PowerShell script for Windows. **Read-only · no network · no dependencies.**

## Quickstart

```bash
# Linux — sweep / and write a log
sudo ./credshunter.sh -p / -o loot.txt
```

```powershell
# Windows — elevated sweep of C:\
.\credshunter.ps1 -Path C:\ -OutputFile loot.txt
```

## Pipeline

Five stages. Each streams its findings the moment it finishes.

| # | Stage | Looks for |
|:-:|---|---|
| **1** | OS stores | registry · GPP · histories · vaults · keys |
| **2** | Containers | `.kdbx` `.ppk` `.pfx` `.keytab` … |
| **3** | High-value | keys · `.env` · backups · DBs · captures |
| **4** | Filenames | `*password*` · `*secret*` · `*credential*` |
| **5** | Content | 70+ tuned regexes, one pass per file |

## Output

| Tag | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed credential container |
| `[HIGH]` | Reusable password · hash · GPP cpassword |
| `[KEY]` | Private key or readable SAM / SYSTEM hive |
| `[INTEREST]` | High-value file worth a look |
| `[NAME]` | Suspicious filename — review hint |

```text
======================================================================
  Stage 5 -- Recursive content scan
----------------------------------------------------------------------
  Found: 3 file(s)   (0.07s)

  [HIGH     ]  /var/www/html/wp-config.php
  [HIGH     ]  /mnt/sysvol/Policies/.../Groups.xml
  [KEY      ]  /home/alice/.ssh/id_ed25519
======================================================================
```

## Options

| Bash | PowerShell | Effect |
|---|---|---|
| `-p PATH` | `-Path PATH` | Scope for stages 2–5 (repeatable) |
| `-o FILE` | `-OutputFile FILE` | Append a findings log (owner-only) |
| `-a` | `-All` | Stage 5 scans every readable file |
| `--no-stageN` | `-NoStageN` | Skip stage N (1–5) |
| `-q` | `-Quiet` | Reduce status noise |
| `-h` | `-h` | Help menu |

Full reference: `-h` / `Get-Help .\credshunter.ps1` 


## Wiki
Check out the [Wiki Document](https://github.com/NeCr00/Credential-Hunting/wiki) for more information about the project.

## Contribute
Feel free to contribute on the project !
