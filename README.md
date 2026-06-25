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

`credshunter` is a read-only credential finder for authorized post-exploitation. It walks a host once and surfaces the secrets you can actually **reuse** — passwords, keys, hashes, and credential files — while staying quiet on the cloud / SaaS tokens that only add noise.

Two siblings, one behaviour: `credshunter.sh` for Linux, `credshunter.ps1` for Windows.

## How it works

A five-stage funnel, narrowing from *where credentials live* to *what's inside files*. Each stage prints its findings the moment it finishes.

```
 Stage 1   OS credential stores     registry · GPP · histories · vaults · keys · other
 Stage 2   Confirmed containers     .kdbx · .ppk · .pfx · .keytab · other
 Stage 3   High-value file types    keys · .env · backups · DBs · captures · other
 Stage 4   Suspicious filenames     *password* · *secret* · *credential*
 Stage 5   Content scan             70+ tuned regexes, one pass per file
```

Stages 1 and 5 do the heavy lifting; 2–4 are fast filename / extension passes. Every finding clears a false-positive filter before it reaches you.

## Usage

```bash
# Linux — full sweep, log to file
sudo ./credshunter.sh -p / -o loot.txt

# Targeted, skip the slow content scan
./credshunter.sh -p /var/www -p /home --no-stage5
```

```powershell
# Windows — elevated sweep of C:\
.\credshunter.ps1 -Path C:\ -OutputFile loot.txt

# Web / DB box: also scan SQL & CSV dumps
.\credshunter.ps1 -Path D:\ -IncludeData
```

Pipe-friendly — add `--no-color` / `-NoColor` and grep for a tier.

## Output

Findings are grouped into five tiers, loudest first.

| Tag | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed credential container |
| `[HIGH]` | Reusable password · hash · GPP cpassword |
| `[KEY]` | Private key or readable SAM / SYSTEM hive |
| `[INTEREST]` | High-value file worth a look |
| `[NAME]` | Suspicious filename — review hint |

The exit code is `1` whenever anything lands in CRITICAL / HIGH / KEY — handy for CI:
`./credshunter.sh -p /etc && echo clean`.

## Tuning

| Want to… | Do this |
|---|---|
| Limit scope | `-p` / `-Path` to include, `-x` / `-ExcludePath` to skip |
| Scan every file | `-a` / `-All` |
| Add SQL / CSV dumps | `-IncludeData` *(PowerShell)* |
| Change the size cap | `-m N` / `-MaxFileSizeMB N`, or `--no-size-limit` / `-NoSizeLimit` |
| Skip a stage | `--no-stageN` / `-NoStageN` |

Patterns and file-type lists live in clearly-labelled arrays near the top of each script — edit one place, nothing else needed.

## FAQ

**Does it change anything on the host?**
No. It writes only to the log file you choose, never touches the network, and exits cleanly on Ctrl-C.

**Why ignore AWS / GitHub / Slack tokens?**
By design — they rarely help with in-network movement and are the top source of false positives. Local cloud-CLI credential *files* are still listed.

**Stage 5 feels slow, or a password was missed.**
Verbose logs are the usual cost — they're bounded by the size cap. Narrow with `-p`, skip content scanning with `--no-stage5`, and confirm the target isn't over the size cap, in an excluded path, or an extension outside the Stage 5 set (use `-All` to be sure).



## Wiki
Check out the [Wiki Document](https://github.com/NeCr00/Credential-Hunting/wiki) for more information about the project.

## Contribute
Feel free to contribute on the project !
