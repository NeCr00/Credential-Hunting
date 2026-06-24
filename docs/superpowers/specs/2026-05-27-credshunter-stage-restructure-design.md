# credshunter — Stage Restructure & UX Improvements

**Date:** 2026-05-27
**Scope:** Both `credshunter.sh` (Linux Bash) and `credshunter.ps1` (Windows PowerShell)
**Status:** Approved (Sections A + B confirmed)

---

## 1. Goals

1. Simplify Stages 3 and 4 to a smaller, user-explicit pattern surface — accepting reduced detection in exchange for a cleaner mental model and lower noise.
2. Move all Stage 2–5 pattern data into one clearly delimited block at the top of each script, so adding or removing patterns is a single-location edit.
3. Print stage-scoped findings live, at the end of each stage, so the operator can assess results as the scan progresses rather than waiting for the final report.
4. Allow any stage to be individually disabled via a CLI flag.

Stage 1 (OS-level credential checks) and Stage 5 (recursive content scan) keep their current pattern data unchanged. Their *runner* code changes only to support the new "print live" and "skip" behaviour.

## 2. Non-goals

- No change to OS-level checks in Stage 1.
- No change to credential regex patterns used in Stage 5 content scanning.
- No change to the exclusion data (`EXCLUDE_DIR_NAMES`, `EXCLUDE_PATHS`, `SKIP_DB_BASENAMES`, `ExcludePathPrefixes`, `ExcludePathContains`).
- No change to the read-only, no-network, authorized-testing-only safety constraints.
- No change to the final consolidated report at end of run.

## 3. Stage definitions (after restructure)

### Stage 1 — OS-level credential checks
Unchanged. 12 substages on Linux; 24 substages on Windows (Windows has more, covering Windows-specific OS credential sinks). Continues to bypass user-supplied path exclusions and target hardcoded OS-known credential sinks.

### Stage 2 — confirmed credential containers
Unchanged. Match alone = `[CRITICAL]`.

```
kdbx, kdb, psafe3, agilekeychain, opvault, 1pif, 1pux, lpdb, enpass, enpassdb,
bitwarden_export, ppk, pfx, p12, pvk, jks, keystore, truststore, bek, fve,
keytab, dpapimk
```

`keytab` remains in Stage 2 only. Stage 3 does not re-flag it.

### Stage 3 — high-value file types
**Replaces** the current `HIGH_VALUE_EXTS` list. Match = `[INTEREST]`. Three sub-categories driven from three arrays:

**Extensions (`STAGE3_EXTENSIONS` — matches `*.ext`):**
```
pem, key, priv, crt, cer, csr,
env, envrc, keytab,
sh, bash,
bak, old, orig, backup, swp, save,
db, sqlite, sqlite3,
log,
pcap, pcapng,
tar, tgz, gz, zip, 7z
```

> Note: `keytab` is also in Stage 2 — Stage 3 must dedup against Stage 2 findings before emitting `[INTEREST]`. The intent is "Stage 2 catches it first; Stage 3 has the name for completeness in the customizable list".

**Exact filenames (`STAGE3_EXACT_NAMES` — full-name match):**
```
krb5.conf, .htpasswd, .netrc, .pgpass, .my.cnf, my.cnf, .mysql.cnf
```

**Glob patterns (`STAGE3_GLOB_PATTERNS`):**
```
krb5cc_*
*.tar.gz
```

`*.tar.gz` is handled here, not as a `gz` extension match, so `foo.tar.gz` doesn't double-classify.

### Stage 4 — filename substring search
**Replaces** the current `EXACT_CRED_FILENAMES` (~120 entries) and `SUSPICIOUS_NAMES` (24 entries) lists. Match = `[NAME]`.

**Substring tokens (`STAGE4_NAME_TOKENS` — case-insensitive substring):**
```
credential, secret, pass, password, passwd, account, login
```

Trade-off: any non-standard-path placement of files like `.bash_history`, `id_rsa`, `shadow`, `unattend.xml`, `web.config`, `wp-config.php` is no longer caught by Stage 4. They remain caught by Stage 1 on canonical OS paths.

Binary exclusions and self-script-name exclusion from the prior tuning pass are preserved (DLLs, EXEs, etc. do not enter Stage 4).

### Stage 5 — recursive content scan
Unchanged. Same regex pattern set. Same `SEARCH_EXTS` extension surface (renamed to `STAGE5_EXTENSIONS` for naming consistency).

## 4. Centralized config block

A single block at the **top of each script**, immediately after the header / license comment, before CLI argument parsing. Bash form:

```bash
# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
#  Edit these to add / remove what the tool flags. No other changes required.
# ============================================================================

STAGE2_EXTENSIONS=( ... )

STAGE3_EXTENSIONS=( ... )
STAGE3_EXACT_NAMES=( ... )
STAGE3_GLOB_PATTERNS=( ... )

STAGE4_NAME_TOKENS=( ... )

STAGE5_EXTENSIONS=( ... )
```

PowerShell form (script-scope, same content):

```powershell
# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
# ============================================================================

$script:Stage2Extensions   = @( ... )

$script:Stage3Extensions   = @( ... )
$script:Stage3ExactNames   = @( ... )
$script:Stage3GlobPatterns = @( ... )

$script:Stage4NameTokens   = @( ... )

$script:Stage5Extensions   = @( ... )
```

Old array names (`GUARANTEED_CRED_EXTS`, `HIGH_VALUE_EXTS`, `EXACT_CRED_FILENAMES`, `SUSPICIOUS_NAMES`, `SEARCH_EXTS` and their PS equivalents) are removed; all references migrate to the new `STAGE*` names.

## 5. Per-stage skip flags

### Bash
```
--no-stage1           Skip Stage 1 (OS-level credential checks)
--no-stage2           Skip Stage 2 (confirmed credential containers)
--no-stage3           Skip Stage 3 (high-value file types)
--no-stage4           Skip Stage 4 (filename substring search)
--no-stage5           Skip Stage 5 (recursive content scan)
--skip-system         (alias for --no-stage1, kept for backward compatibility)
```

### PowerShell
```
-NoStage1, -NoStage2, -NoStage3, -NoStage4, -NoStage5
-SkipSystem           (alias for -NoStage1, kept for backward compatibility)
```

Internally each `--no-stageN` flag sets `STAGE_N_SKIP=1` (bash) / `$script:StageNSkip = $true` (PS). The stage runner checks the flag, prints a `Stage N — SKIPPED` block, and returns without doing work.

## 6. Live result printing

At the end of each stage, before the next stage starts, print a single structured block to stderr (so file redirection of stdout doesn't break the live preview).

### Format

```
======================================================================
  Stage 3 — High-value file types
----------------------------------------------------------------------
  Found: 7 file(s)   (0.42s)

  [INTEREST]  /home/user/backups/db.sqlite
  [INTEREST]  /opt/app/.env.production
  [INTEREST]  /home/admin/krb5cc_1001
  [INTEREST]  /tmp/network.pcap
  [INTEREST]  /var/log/auth.log.bak
  [INTEREST]  /home/admin/.netrc
  [INTEREST]  /etc/krb5.conf
======================================================================
```

Color-on rendering uses ANSI; `--no-color` keeps ASCII separators (`===` / `---`) so log files stay clean.

### Behaviour
- **Channel:** Live blocks print to **stdout** — same channel as the final consolidated report. `2>/dev/null` does not suppress them; `> out.txt` captures them. Matches existing report behaviour.
- **Quiet mode (`--quiet` / `-Quiet`):** print only the one-line header (`Stage N — Found: X file(s)`); skip the per-file enumeration.
- **All findings printed** (no truncation) when not in quiet mode.
- **Stage-scoped** — Stage 3's block lists only Stage 3 findings; Stage 5's block lists only Stage 5 findings, not Stage 1's. Achieved via per-stage line-count snapshots on the underlying tier files:
  | Stage | Tracked file(s) |
  |---|---|
  | 1 | `HIGH_FILE`, `KEY_FILE` (delta vs scan-start) |
  | 2 | `GUARANTEED_FILE` |
  | 3 | `INTEREST_FILE` |
  | 4 | `NAME_FILE`, `EXACT_FILE` (combined) |
  | 5 | `HIGH_FILE`, `KEY_FILE` (delta vs end-of-Stage-1) |
- **Per-stage timing** in the header `(0.42s)`.
- **Empty stages still emit a block** with `Found: 0 file(s)` — confirms the stage ran.
- **Skipped stages emit `Stage N — SKIPPED`** with no body.
- **Stage 1 substages**: each substage already prints its own `info` line during execution. The end-of-Stage-1 live block adds a `Found: N file(s)` summary line and (non-quiet) the consolidated finding list. No per-substage regrouping inside the block — the existing substage info lines provide that structure.
- **Stage 5**: groups by tier ([CRITICAL] / [HIGH] / [KEY] / [INTEREST]).

### Final report
Unchanged. The end-of-run consolidated report still prints the full tier-grouped summary. The live blocks supplement, not replace.

## 7. Implementation impact (per-file delta summary)

### `credshunter.sh`
| Change | Location |
|---|---|
| Add `USER-CUSTOMIZABLE PATTERN LISTS` block | Top of script, after header |
| Delete `GUARANTEED_CRED_EXTS`, `HIGH_VALUE_EXTS`, `EXACT_CRED_FILENAMES`, `SUSPICIOUS_NAMES`, `SEARCH_EXTS` | ~lines 1090–1255 |
| Add `STAGE_N_SKIP` flag parsing | CLI arg loop |
| Add `--no-stageN` flags to `--help` | help block |
| Add `stage_begin` / `stage_end` helpers | helper section |
| Rewrite `find_high_value_files` to read new Stage 3 arrays (`STAGE3_EXTENSIONS`, `STAGE3_EXACT_NAMES`, `STAGE3_GLOB_PATTERNS`) and dedup against Stage 2's `GUARANTEED_FILE` (so `keytab` doesn't double-report) | Stage 3 fn |
| Rewrite `find_suspicious_filenames` to drop exact-name pass; substring pass uses `STAGE4_NAME_TOKENS` | Stage 4 fn |
| Wrap each stage call in `stage_begin`/`stage_end` and the skip check | `main()` |

### `credshunter.ps1`
| Change | Location |
|---|---|
| Add `USER-CUSTOMIZABLE PATTERN LISTS` block | Top of script, after `param()` |
| Delete `$script:HighValueExtensions`, etc. | wherever they're defined |
| Add `[switch]$NoStage1..$NoStage5` params | `param()` |
| Add `Begin-Stage` / `End-Stage` helpers | helper section |
| Rewrite `Find-HighValueFiles` to use Stage 3 arrays (`Stage3Extensions`, `Stage3ExactNames`, `Stage3GlobPatterns`) and dedup against Stage 2's guaranteed-container findings (so `keytab` doesn't double-report) | Stage 3 fn |
| Rewrite `Find-SuspiciousNames` to substring-only with new tokens | Stage 4 fn |
| Wrap each stage call in `Begin-Stage`/`End-Stage` and the skip check | `Main` block |

## 8. Verification plan

After implementation:
1. `bash -n credshunter.sh` → must print `BASH_SYNTAX_OK` equivalent.
2. PSParser `ParseFile` on `credshunter.ps1` → 0 errors.
3. Both scripts `--help` outputs include the new `--no-stageN` / `-NoStageN` flags.
4. Run each script with `--no-stage3 --no-stage4` against the docker test environment and confirm Stage 3 and Stage 4 blocks render as `SKIPPED`, other stages still run normally.
5. Confirm a deliberate plant of `secrets.kdbx` shows up in Stage 2's live block only (not duplicated in Stage 3).
6. Confirm a deliberate plant of `id_rsa` in `/tmp/share/` no longer triggers Stage 4 (regression check on the dropped exact-name list).
7. Re-run docker `measure.sh` / `measure.ps1` benchmarks and confirm 0% FP rate is preserved.

## 9. Open questions

None — all four interpretive choices (Section A) and three implementation choices (Section B) confirmed by user.
