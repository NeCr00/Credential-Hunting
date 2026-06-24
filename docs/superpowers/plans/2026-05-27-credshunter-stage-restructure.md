# credshunter — Stage Restructure & UX Improvements: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure both credshunter scripts so Stage 3/4 pattern surfaces become user-spec lists at the top of the file, every stage is individually skippable, and each stage prints its findings live the moment it finishes.

**Architecture:** Surgery on two existing single-file scanners — no new files, no new dependencies. All pattern data moves into a single `USER-CUSTOMIZABLE PATTERN LISTS` block near the top of each script. Stage runners wrap in `stage_begin`/`stage_end` helpers that handle timing, skip-flag gating, and the live-results block. Stage 3 logic gains a dedup pass against Stage 2 outputs (so `keytab` doesn't double-flag).

**Tech Stack:** Bash 4+ (`credshunter.sh`), PowerShell 5.1+ / PS Core (`credshunter.ps1`), Docker test harness (`docker/measure.sh`, `docker/measure.ps1`).

**Context:** No git repository exists in the project root — "Commit" steps are replaced with "Verify" steps that confirm the change took effect. The design spec lives at `docs/superpowers/specs/2026-05-27-credshunter-stage-restructure-design.md`.

**Files modified by this plan:**
- `/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh` (Linux bash, ~1783 lines)
- `/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1` (Windows PS, ~2069 lines)

**Files NOT modified:**
- `docker/populate.sh`, `docker/measure.sh`, `docker/measure.ps1` — read-only consumers; new flags are backward compatible
- `README.md` — separate follow-up task if user asks
- `docker/Dockerfile.*`, `docker-compose.yml`

---

## Phase 1 — Bash (`credshunter.sh`)

### Task 1: Insert `USER-CUSTOMIZABLE PATTERN LISTS` block

**Files:**
- Modify: `credshunter.sh:172-173` (insert directly after the closing `}` of `usage()`)

- [ ] **Step 1: Verify current state**

Run: `grep -n "^usage() {" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: `174:usage() {`

Run: `sed -n '171,174p' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: empty `EOF` marker on 171, closing `}` of `usage()` on 172, blank line on 173, `usage()` on 174 — confirms the insertion point is between the help text and the parse_args function.

Actually wait — re-read the file: the version banner `usage()` is what ends at line 172. We want to add the patterns block BEFORE `parse_args()` but AFTER all the help/usage definitions. Inserting at line 214 (right after `usage()` closes its EOF heredoc on line 213) is the correct spot.

Re-verify with: `sed -n '213,218p' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: `213: EOF` `214: }` `215: # ----------------------------------------------------------------------------` `216: #  Argument parsing` `217: # ----------------------------------------------------------------------------` `218: parse_args() {`

- [ ] **Step 2: Insert the new pattern-lists block**

Use `Edit` tool to anchor on the existing comment block before `parse_args()` and prepend the new patterns block. Old string:

```
}

# ----------------------------------------------------------------------------
#  Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
```

New string:

```
}

# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
#
#  Edit the arrays below to add or remove what each stage flags. NO OTHER
#  changes are required when you tweak these.
#
#  All matching is case-insensitive (Linux `find -iname`).
# ============================================================================

# ── Stage 2 — confirmed credential containers (match alone = [CRITICAL]) ─────
STAGE2_EXTENSIONS=(
    kdbx kdb psafe3 agilekeychain opvault 1pif 1pux lpdb enpass enpassdb
    bitwarden_export ppk pfx p12 pvk jks keystore truststore bek fve keytab
    dpapimk
)

# ── Stage 3 — high-value file types (match = [INTEREST]) ─────────────────────
# Files matching these are surfaced but not auto-classified as credentials.
STAGE3_EXTENSIONS=(
    # SSH / TLS private key formats
    pem key priv crt cer csr
    # App-secret dotfile extensions
    env envrc
    # Kerberos
    keytab
    # Shell scripts
    sh bash
    # Backup / scratch / saved variants
    bak old orig backup swp save
    # SQLite databases (text caches dropped — see SKIP_DB_BASENAMES filter)
    db sqlite sqlite3
    # Log files (admin sometimes pastes pw into custom logs)
    log
    # Packet captures (may contain plaintext auth)
    pcap pcapng
    # Compressed archives (admin backups often contain creds)
    tar tgz gz zip 7z
)

# Exact filename matches for Stage 3 (no extension — dotfiles & config files)
STAGE3_EXACT_NAMES=(
    krb5.conf
    .htpasswd .netrc .pgpass .my.cnf my.cnf .mysql.cnf
)

# Glob patterns for Stage 3 (used as `find -name '<pattern>'`)
STAGE3_GLOB_PATTERNS=(
    'krb5cc_*'
    '*.tar.gz'
)

# ── Stage 4 — filename substring tokens (match = [NAME]) ────────────────────
# Any filename containing one of these tokens (case-insensitive) is flagged.
# Keep this list short: each entry is a substring, so loose entries balloon
# the false-positive rate.
STAGE4_NAME_TOKENS=(
    credential secret pass password passwd account login
)

# ── Stage 5 — content-scan extension allow-list ─────────────────────────────
# Recursive credential-pattern scan runs ONLY on files with one of these
# extensions (unless --all is passed).
STAGE5_EXTENSIONS=(
    # Configuration & structured data
    conf config cfg cnf ini env envrc
    yaml yml toml json jsonc json5 xml plist
    properties prop props settings
    tf tfvars tfstate hcl
    # Shell & scripting
    sh bash zsh ksh csh fish profile bashrc zshrc
    ps1 psm1 psd1 ps1xml bat cmd vbs vbe wsf wsh ahk
    # Source code commonly carrying hardcoded passwords
    py pl rb php phtml php3 php5 lua groovy tcl coffee
    java cs vb go rs c cpp h hpp
    js ts jsx tsx mjs cjs
    # Web app files
    aspx asp ashx asmx asax ascx cshtml vbhtml
    jsp jspx jspf cfm cfc htm html htaccess
    # Database / connection (text)
    sql ddl dump dsn udl ora tns
    # Windows-specific text formats
    reg pol rdp rdg rdcman inf unattend answerfile
    # Remote access tools
    ovpn openvpn vnc rdc tcc ica session kix
    # Plain text / notes
    txt text md markdown rtf nfo log logs readme
    # Backups / temp / cached configs
    bak backup old orig original save saved tmp temp cache
    # Data exports / directory dumps
    csv tsv ldif ldiff
    # systemd / cron
    service unit timer socket crontab cron
    # Variant config suffixes
    local shared template example sample dist
)

# ----------------------------------------------------------------------------
#  Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
```

- [ ] **Step 3: Verify the block was inserted correctly**

Run: `grep -n "^STAGE[2-5]_" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected:
```
<some-line>:STAGE2_EXTENSIONS=(
<some-line>:STAGE3_EXTENSIONS=(
<some-line>:STAGE3_EXACT_NAMES=(
<some-line>:STAGE3_GLOB_PATTERNS=(
<some-line>:STAGE4_NAME_TOKENS=(
<some-line>:STAGE5_EXTENSIONS=(
```

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

---

### Task 2: Add `--no-stageN` skip flags

**Files:**
- Modify: `credshunter.sh:45-46` (state variables) and `credshunter.sh:218-236` (`parse_args` case block)

- [ ] **Step 1: Add `STAGE_N_SKIP` state variables**

Use `Edit` tool. Old string:
```
QUIET=0
SKIP_SYSTEM=0
```

New string:
```
QUIET=0
SKIP_SYSTEM=0
STAGE1_SKIP=0
STAGE2_SKIP=0
STAGE3_SKIP=0
STAGE4_SKIP=0
STAGE5_SKIP=0
```

- [ ] **Step 2: Add the `--no-stageN` cases in `parse_args`**

Use `Edit` tool. Old string:
```
            -s|--skip-system) SKIP_SYSTEM=1; shift ;;
```

New string:
```
            -s|--skip-system) SKIP_SYSTEM=1; STAGE1_SKIP=1; shift ;;
            --no-stage1)      STAGE1_SKIP=1; SKIP_SYSTEM=1; shift ;;
            --no-stage2)      STAGE2_SKIP=1; shift ;;
            --no-stage3)      STAGE3_SKIP=1; shift ;;
            --no-stage4)      STAGE4_SKIP=1; shift ;;
            --no-stage5)      STAGE5_SKIP=1; shift ;;
```

- [ ] **Step 3: Verify the flag parsing**

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

Run: `bash "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" --no-stage1 --no-stage2 --no-stage3 --no-stage4 --no-stage5 2>&1 | head -5`
Expected: a warning about no `-p` supplied (the flags parse without error; the warning is from main()).

---

### Task 3: Add `stage_begin` / `stage_end` helpers + live block printer

**Files:**
- Modify: `credshunter.sh` — insert helpers right after `end_progress()` (around line 620) and before the `Content scanning core` section header

- [ ] **Step 1: Locate the insertion point**

Run: `grep -n "^end_progress\b\|^# ============================================================================$" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" | head -10`
Expected: a line like `615:end_progress() {` and several `# ====` separator lines. Pick the one immediately after `end_progress() { ... }` closes (around line 620-621) and before the next `# ====` section header.

- [ ] **Step 2: Insert stage helpers**

Use `Edit` tool. Old string (the start of the "Content scanning core" comment block at the right location — adjust the actual snapshot the harness reads if line numbers shift):
```
# ============================================================================
#  Content scanning core
```

New string:
```
# ============================================================================
#  Stage lifecycle — per-stage timing, skip-gating, and live-results block
# ============================================================================

declare -A STAGE_BEFORE_GUARANTEED
declare -A STAGE_BEFORE_INTEREST
declare -A STAGE_BEFORE_NAME
declare -A STAGE_BEFORE_EXACT
declare -A STAGE_BEFORE_HIGH
declare -A STAGE_BEFORE_KEY
declare -A STAGE_START_TIME

# Snapshot finding-file line counts BEFORE a stage runs, so the live
# results block can print just the delta.
stage_begin() {
    local n=$1
    STAGE_BEFORE_GUARANTEED[$n]=$(wc -l <"$GUARANTEED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_INTEREST[$n]=$(wc -l <"$INTEREST_FILE"   2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_NAME[$n]=$(wc -l <"$NAME_FILE"           2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_EXACT[$n]=$(wc -l <"$EXACT_FILE"         2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_HIGH[$n]=$(wc -l <"$HIGH_FILE"           2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_KEY[$n]=$(wc -l <"$KEY_FILE"             2>/dev/null | tr -d ' ' || echo 0)
    STAGE_START_TIME[$n]=$(date +%s.%N 2>/dev/null || date +%s)
}

# Print the live results block for stage <n>. <title> is the human-readable
# stage name. The block reads the per-stage tracked tier files and prints
# only the delta since stage_begin.
stage_end() {
    local n=$1 title="$2"
    local end=$(date +%s.%N 2>/dev/null || date +%s)
    local elapsed
    elapsed=$(awk -v a="${STAGE_START_TIME[$n]:-0}" -v b="$end" \
        'BEGIN{ d=b-a; if(d<0)d=0; printf "%.2f", d }')

    # Compute deltas for each tier file
    local now_guar now_int now_name now_ex now_hi now_ky
    now_guar=$(wc -l <"$GUARANTEED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    now_int=$(wc -l <"$INTEREST_FILE"    2>/dev/null | tr -d ' ' || echo 0)
    now_name=$(wc -l <"$NAME_FILE"       2>/dev/null | tr -d ' ' || echo 0)
    now_ex=$(wc -l <"$EXACT_FILE"        2>/dev/null | tr -d ' ' || echo 0)
    now_hi=$(wc -l <"$HIGH_FILE"         2>/dev/null | tr -d ' ' || echo 0)
    now_ky=$(wc -l <"$KEY_FILE"          2>/dev/null | tr -d ' ' || echo 0)

    local d_guar=$(( now_guar - ${STAGE_BEFORE_GUARANTEED[$n]:-0} ))
    local d_int=$((  now_int  - ${STAGE_BEFORE_INTEREST[$n]:-0} ))
    local d_name=$(( now_name - ${STAGE_BEFORE_NAME[$n]:-0} ))
    local d_ex=$((   now_ex   - ${STAGE_BEFORE_EXACT[$n]:-0} ))
    local d_hi=$((   now_hi   - ${STAGE_BEFORE_HIGH[$n]:-0} ))
    local d_ky=$((   now_ky   - ${STAGE_BEFORE_KEY[$n]:-0} ))
    local total=$(( d_guar + d_int + d_name + d_ex + d_hi + d_ky ))

    # Header
    printf '\n%b======================================================================%b\n' "$C" "$NC"
    printf '%b  Stage %s — %s%b\n' "$BOLD" "$n" "$title" "$NC"
    printf '%b----------------------------------------------------------------------%b\n' "$C" "$NC"
    printf '  Found: %b%s%b file(s)   (%ss)\n' "$W$BOLD" "$total" "$NC" "$elapsed"

    # Body — skip in quiet mode
    if [ "$QUIET" -eq 0 ] && [ "$total" -gt 0 ]; then
        printf '\n'
        stage_print_delta CRITICAL "$GUARANTEED_FILE" "${STAGE_BEFORE_GUARANTEED[$n]:-0}" "$d_guar"
        stage_print_delta HIGH     "$HIGH_FILE"       "${STAGE_BEFORE_HIGH[$n]:-0}"      "$d_hi"
        stage_print_delta KEY      "$KEY_FILE"        "${STAGE_BEFORE_KEY[$n]:-0}"       "$d_ky"
        stage_print_delta INTEREST "$INTEREST_FILE"   "${STAGE_BEFORE_INTEREST[$n]:-0}"  "$d_int"
        stage_print_delta CRED_FILE "$EXACT_FILE"     "${STAGE_BEFORE_EXACT[$n]:-0}"     "$d_ex"
        stage_print_delta NAME     "$NAME_FILE"       "${STAGE_BEFORE_NAME[$n]:-0}"      "$d_name"
    fi
    printf '%b======================================================================%b\n' "$C" "$NC"
}

# Print delta lines from a tier file in the form: [TIER]  /path
# Args: tier-label file before-count delta
stage_print_delta() {
    local tier="$1" file="$2" before="$3" delta="$4"
    [ "$delta" -le 0 ] && return
    [ ! -s "$file" ] && return
    local start=$((before + 1))
    # tier files have variable columns; we just print the LAST column (path)
    # for HIGH/KEY (TSV: label\tfile\tline\tpreview) and the only column for
    # name/exact (single path) / interest (TSV: category\tpath).
    case "$tier" in
        HIGH|KEY)
            tail -n "+$start" "$file" | awk -F'\t' -v t="$tier" '{ printf "  [%s]  %s\n", t, $2 }'
            ;;
        INTEREST|CRED_FILE|NAME)
            tail -n "+$start" "$file" | awk -F'\t' -v t="$tier" '{ p=$NF; printf "  [%s]  %s\n", t, p }'
            ;;
        CRITICAL)
            # guaranteed.tsv format: ext<TAB>path
            tail -n "+$start" "$file" | awk -F'\t' '{ printf "  [CRITICAL]  %s\n", $2 }'
            ;;
    esac
}

# Print the SKIPPED variant of a stage block — used when --no-stageN is set
stage_skipped() {
    local n=$1 title="$2"
    printf '\n%b======================================================================%b\n' "$C" "$NC"
    printf '%b  Stage %s — %s  [SKIPPED]%b\n' "$BOLD" "$n" "$title" "$NC"
    printf '%b======================================================================%b\n' "$C" "$NC"
}

# ============================================================================
#  Content scanning core
```

- [ ] **Step 3: Verify the helpers parse and the file is still syntactically valid**

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

Run: `grep -nE "^stage_(begin|end|print_delta|skipped)\(\)" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: four lines, one per helper function.

---

### Task 4: Rewrite Stage 3 (`find_high_value_files`) using new arrays

**Files:**
- Modify: `credshunter.sh` — the existing `find_high_value_files` function (currently uses `HIGH_VALUE_EXTS`)

- [ ] **Step 1: Locate the current Stage 3 function**

Run: `grep -n "^find_high_value_files()" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: a line number around 1368.

Run: `sed -n '1367,1420p' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Note: confirm what the existing function looks like; the replacement below targets the *entire* function body.

- [ ] **Step 2: Replace the function body**

Use `Edit` tool. Locate by the function signature and the existing line `for e in "${HIGH_VALUE_EXTS[@]}"; do` inside it. Old string (capture the full function — adapt to the exact current text in the file):

```
# Stage 3 — auxiliary credential-related files
find_high_value_files() {
```

New string (REPLACE the full function with this — read the current function first, then construct old_string to span the entire body):

```
# Stage 3 — high-value file types (NEW SPEC)
# Three sub-passes driven by the top-of-file arrays:
#   STAGE3_EXTENSIONS    — match by extension (case-insensitive)
#   STAGE3_EXACT_NAMES   — match by full basename
#   STAGE3_GLOB_PATTERNS — match by find -name glob
#
# Files already flagged by Stage 2 (guaranteed credential containers) are
# deduped against `GUARANTEED_FILE` so e.g. `*.keytab` doesn't double-emit.
find_high_value_files() {
    section "Stage 3 — High-value file types"
    local path
    local excludes; excludes=$(build_find_excludes)

    # Build dedup set from Stage 2 outputs (column 2 = path)
    declare -A STAGE2_HITS=()
    if [ -s "$GUARANTEED_FILE" ]; then
        local g
        while IFS=$'\t' read -r _ g; do
            [ -n "$g" ] && STAGE2_HITS["$g"]=1
        done <"$GUARANTEED_FILE"
    fi

    # ---- Pass 1: extensions ----
    local ext_expr="" first=1 e
    for e in "${STAGE3_EXTENSIONS[@]}"; do
        if [ "$first" -eq 1 ]; then
            ext_expr=" \\( -iname '*.${e}'"; first=0
        else
            ext_expr+=" -o -iname '*.${e}'"
        fi
    done
    [ -n "$ext_expr" ] && ext_expr+=" \\)"

    # ---- Pass 2: exact filenames ----
    local name_expr="" first2=1 n
    for n in "${STAGE3_EXACT_NAMES[@]}"; do
        if [ "$first2" -eq 1 ]; then
            name_expr=" \\( -iname '${n}'"; first2=0
        else
            name_expr+=" -o -iname '${n}'"
        fi
    done
    [ -n "$name_expr" ] && name_expr+=" \\)"

    # ---- Pass 3: glob patterns ----
    local glob_expr="" first3=1 g
    for g in "${STAGE3_GLOB_PATTERNS[@]}"; do
        if [ "$first3" -eq 1 ]; then
            glob_expr=" \\( -iname '${g}'"; first3=0
        else
            glob_expr+=" -o -iname '${g}'"
        fi
    done
    [ -n "$glob_expr" ] && glob_expr+=" \\)"

    # Compose: extension OR exact-name OR glob
    local combined=""
    for clause in "$ext_expr" "$name_expr" "$glob_expr"; do
        [ -z "$clause" ] && continue
        if [ -z "$combined" ]; then combined="$clause"
        else combined="\\( $combined -o $clause \\)"
        fi
    done

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            # Stage 2 dedup
            [ -n "${STAGE2_HITS[$f]:-}" ] && continue
            # Per-tier SKIP_DB_BASENAMES filter
            local bn="${f##*/}"
            local skip=0 k
            for k in "${SKIP_DB_BASENAMES[@]}"; do
                if [ "${bn,,}" = "${k,,}" ]; then skip=1; break; fi
            done
            [ "$skip" -eq 1 ] && continue
            record_interest "high_value_file" "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $excludes -type f $combined -print" 2>/dev/null)
    done

    ok "Stage 3 catalogued ${W}${BOLD}${count}${NC} high-value file(s)."
}
```

- [ ] **Step 3: Verify the rewrite parses**

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

---

### Task 5: Rewrite Stage 4 (`find_suspicious_filenames`) — substring only

**Files:**
- Modify: `credshunter.sh` — the existing `find_suspicious_filenames` function

- [ ] **Step 1: Locate the current Stage 4 function**

Run: `grep -n "^find_suspicious_filenames()" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: a line number (was around 1423 before Task 3, now shifted by the helper insertion).

Run: `sed -n '<that_line>,+80p' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"` — confirm function body.

- [ ] **Step 2: Replace the function body**

Use `Edit` tool. Old string spans the entire function from the comment line above it through its closing `}`. New string:

```
# Stage 4 — filename substring search (NEW SPEC)
# Single pass: any file whose basename (case-insensitive) contains one of
# STAGE4_NAME_TOKENS is emitted as a [NAME] finding.
#
# Binary executables, libraries, and the scanner's own file are excluded.
find_suspicious_filenames() {
    section "Stage 4 — Filename substring search"
    local path
    local excludes; excludes=$(build_find_excludes)

    local count=0 self_name
    self_name="${SCRIPT_PATH##*/}"

    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            local bn="${f##*/}"
            local bn_lower="${bn,,}"
            # Skip our own script
            [ "$bn" = "$self_name" ] && continue
            local t
            for t in "${STAGE4_NAME_TOKENS[@]}"; do
                if [[ "$bn_lower" == *"${t,,}"* ]]; then
                    record_name "$f"
                    count=$((count + 1))
                    break
                fi
            done
        done < <(eval "find \"$path\" -mindepth 1 $excludes -type f \
            ! -iname '*.dll' ! -iname '*.exe' ! -iname '*.sys' ! -iname '*.so' \
            ! -iname '*.dylib' ! -iname '*.ocx' ! -iname '*.pdb' ! -iname '*.nupkg' \
            ! -iname '*.mui' ! -iname '*.cpl' ! -iname '*.drv' \
            -print" 2>/dev/null)
    done

    ok "Stage 4 found ${W}${BOLD}${count}${NC} filename(s) matching credential tokens."
}
```

- [ ] **Step 3: Verify the rewrite parses**

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

---

### Task 6: Wire `main()`, delete dead arrays, update `usage()`

**Files:**
- Modify: `credshunter.sh:1738-1781` (`main()` body)
- Modify: `credshunter.sh:186-198` (usage block — add new flags)
- Delete: old `GUARANTEED_CRED_EXTS`, `HIGH_VALUE_EXTS`, `EXACT_CRED_FILENAMES`, `SUSPICIOUS_NAMES`, `SEARCH_EXTS` arrays (lines ~1094-1256 in the original file, may have shifted)

- [ ] **Step 1: Update `usage()` help text**

Use `Edit` tool. Old string:
```
  -s, --skip-system     Skip stage 1 (OS-level credential checks).
  -q, --quiet           Reduce status noise. Findings still printed.
```

New string:
```
  -s, --skip-system     Skip stage 1 (OS-level credential checks).
      --no-stage1       Same as --skip-system (alias).
      --no-stage2       Skip stage 2 (confirmed credential containers).
      --no-stage3       Skip stage 3 (high-value file types).
      --no-stage4       Skip stage 4 (filename substring search).
      --no-stage5       Skip stage 5 (recursive content scan).
  -q, --quiet           Reduce status noise. Findings still printed.
```

- [ ] **Step 2: Rewrite `main()` to wire per-stage skip + live blocks**

Use `Edit` tool. Old string spans the *body* of `main()` from the `if [ "$SKIP_SYSTEM" -eq 0 ]; then` block through the close of the SCAN_PATHS branch. New string:

```
    if [ "$STAGE1_SKIP" -eq 0 ]; then
        stage_begin 1
        run_system_checks
        stage_end 1 "OS-level credential checks"
    else
        stage_skipped 1 "OS-level credential checks"
    fi

    if [ ${#SCAN_PATHS[@]} -eq 0 ]; then
        warn "No paths supplied (-p). Skipping stages 2-5."
        warn "Tip: pass -p / to scan everything under root."
    else
        if [ "$STAGE2_SKIP" -eq 0 ]; then
            stage_begin 2; find_guaranteed_credentials; stage_end 2 "Confirmed credential containers"
        else
            stage_skipped 2 "Confirmed credential containers"
        fi
        if [ "$STAGE3_SKIP" -eq 0 ]; then
            stage_begin 3; find_high_value_files; stage_end 3 "High-value file types"
        else
            stage_skipped 3 "High-value file types"
        fi
        if [ "$STAGE4_SKIP" -eq 0 ]; then
            stage_begin 4; find_suspicious_filenames; stage_end 4 "Filename substring search"
        else
            stage_skipped 4 "Filename substring search"
        fi
        if [ "$STAGE5_SKIP" -eq 0 ]; then
            stage_begin 5; scan_user_paths_contents; stage_end 5 "Recursive content scan"
        else
            stage_skipped 5 "Recursive content scan"
        fi
    fi
```

- [ ] **Step 3: Rename consumer references BEFORE deleting source arrays**

Run: `grep -n "SEARCH_EXTS\|HIGH_VALUE_EXTS\|GUARANTEED_CRED_EXTS\|EXACT_CRED_FILENAMES\|SUSPICIOUS_NAMES" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`

For each remaining reference (outside the array DEFINITION itself), use `Edit` with `replace_all=true` to swap:
- `SEARCH_EXTS`          → `STAGE5_EXTENSIONS`
- `GUARANTEED_CRED_EXTS` → `STAGE2_EXTENSIONS`
- `HIGH_VALUE_EXTS`      → (no callers should remain after Task 4 rewrote `find_high_value_files`; if any remain, remove them)
- `EXACT_CRED_FILENAMES` → (no callers should remain after Task 5 rewrote `find_suspicious_filenames`; if any remain, remove them)
- `SUSPICIOUS_NAMES`     → `STAGE4_NAME_TOKENS`

Important: leave the array DEFINITION lines alone for now (they're deleted in the next step).

- [ ] **Step 4: Delete the obsolete array definitions**

Run: `grep -n "^GUARANTEED_CRED_EXTS=(\|^HIGH_VALUE_EXTS=(\|^EXACT_CRED_FILENAMES=(\|^SUSPICIOUS_NAMES=(\|^SEARCH_EXTS=(" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`

For each of those five arrays, use the `Edit` tool to delete the entire array definition (from the array name down to and including the closing `)` on its own line). After all deletions, the only pattern arrays should be the new `STAGE*` ones at the top.

- [ ] **Step 5: Confirm no stale references remain**

Run: `grep -cE "GUARANTEED_CRED_EXTS|HIGH_VALUE_EXTS|EXACT_CRED_FILENAMES|SUSPICIOUS_NAMES|SEARCH_EXTS" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: `0`

- [ ] **Step 6: Final syntax check**

Run: `bash -n "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" && echo OK`
Expected: `OK`

Run: `grep -cE "GUARANTEED_CRED_EXTS|HIGH_VALUE_EXTS|EXACT_CRED_FILENAMES|SUSPICIOUS_NAMES|SEARCH_EXTS" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh"`
Expected: `0`

---

### Task 7: Bash functional verification

**Files:** none modified — verification only.

- [ ] **Step 1: Build a tiny scratch test directory**

Run:
```bash
T=$(mktemp -d) && \
mkdir -p "$T/sub" && \
printf 'PASSWORD = "real-cred"\n' > "$T/secrets.env" && \
printf 'CONTENT\n' > "$T/db.sqlite" && \
printf 'CONTENT\n' > "$T/sub/passwd_backup.txt" && \
printf 'CONTENT\n' > "$T/keytab" && \
ls "$T"
```

- [ ] **Step 2: Run scanner with no stage skips**

Run: `bash "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" --skip-system -p "$T" --no-color 2>&1 | tee /tmp/credshunter_run1.log`
Expected: live result blocks for Stages 2–5 appear; `secrets.env` shows in Stage 3 (INTEREST), `passwd_backup.txt` in Stage 4 (NAME), `keytab` in Stage 2 (CRITICAL) — and NOT also in Stage 3 (dedup).

- [ ] **Step 3: Run scanner with Stage 3 and Stage 4 skipped**

Run: `bash "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.sh" --skip-system --no-stage3 --no-stage4 -p "$T" --no-color 2>&1 | tee /tmp/credshunter_run2.log`
Expected:
- "Stage 3 — High-value file types  [SKIPPED]" block prints
- "Stage 4 — Filename substring search  [SKIPPED]" block prints
- Stage 5 still runs and surfaces the regex hit on `secrets.env`

- [ ] **Step 4: Verify live block format**

Run: `grep -E "^={50,}|^  Stage [0-9] — " /tmp/credshunter_run1.log | head -20`
Expected: alternating box separators and stage headers in the format `  Stage N — <title>`.

- [ ] **Step 5: Clean up**

Run: `rm -rf "$T" /tmp/credshunter_run1.log /tmp/credshunter_run2.log && echo CLEANED`

---

## Phase 2 — PowerShell (`credshunter.ps1`)

### Task 8: Insert `USER-CUSTOMIZABLE PATTERN LISTS` block

**Files:**
- Modify: `credshunter.ps1` — insert directly before the existing Stage 2 array definition (currently `$script:GuaranteedCredExtensions = @(...)` around line 473)

- [ ] **Step 1: Locate the insertion point**

Run: `grep -n '^\\$script:GuaranteedCredExtensions = @(' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"`
Expected: a line number around 473.

- [ ] **Step 2: Replace the existing pattern arrays (lines ~470-640) with new STAGE* arrays**

Use `Edit` tool. Locate by anchoring on the existing comment block header that introduces the pattern data. Old string (the comment header through `$script:SearchExtensionsSet` definition — read the file first to get the exact spans):

```
# ============================================================================

# Stage 2: confirmed credential containers
$script:GuaranteedCredExtensions = @(
```

New string:

```
# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
#
#  Edit the arrays below to add or remove what each stage flags. NO OTHER
#  changes are required when you tweak these.
# ============================================================================

# ── Stage 2 — confirmed credential containers (match alone = [CRITICAL]) ─────
$script:Stage2Extensions = @(
    '.kdbx','.kdb','.psafe3'
    '.agilekeychain','.opvault','.1pif','.1pux'
    '.lpdb','.enpass','.enpassdb','.bitwarden_export'
    '.ppk','.pfx','.p12','.pvk'
    '.jks','.keystore','.truststore'
    '.bek','.fve','.keytab','.dpapimk'
)

# ── Stage 3 — high-value file types (match = [INTEREST]) ────────────────────
$script:Stage3Extensions = @(
    # SSH / TLS private key formats
    '.pem','.key','.priv','.crt','.cer','.csr'
    # App-secret dotfile extensions
    '.env','.envrc'
    # Kerberos
    '.keytab'
    # Shell scripts
    '.sh','.bash'
    # Backup / scratch / saved variants
    '.bak','.old','.orig','.backup','.swp','.save'
    # SQLite databases (system DB basenames filtered separately)
    '.db','.sqlite','.sqlite3'
    # Logs
    '.log'
    # Packet captures
    '.pcap','.pcapng'
    # Compressed archives
    '.tar','.tgz','.gz','.zip','.7z'
)

# Exact filenames (full-name match) for Stage 3
$script:Stage3ExactNames = @(
    'krb5.conf'
    '.htpasswd','.netrc','.pgpass','.my.cnf','my.cnf','.mysql.cnf'
)
$script:Stage3ExactNamesSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage3ExactNames, [System.StringComparer]::OrdinalIgnoreCase)

# Glob patterns for Stage 3 (PowerShell `-like` syntax)
$script:Stage3GlobPatterns = @(
    'krb5cc_*'
    '*.tar.gz'
)

# Known SQL Server SYSTEM / TEMPLATE database basenames — every Windows host
# with SQL Server ships these; not user data. Filter at Stage 3.
$script:SkipDbFilenames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'master.mdf','mastlog.ldf'
        'model.mdf','modellog.ldf'
        'msdb.mdf','msdbdata.mdf','msdblog.ldf'
        'tempdb.mdf','templog.ldf'
        'mssqlsystemresource.mdf','mssqlsystemresource.ldf'
        'model_msdbdata.mdf','model_msdblog.ldf'
        'model_replicatedmaster.mdf','model_replicatedmaster.ldf'
    ),
    [System.StringComparer]::OrdinalIgnoreCase)

# ── Stage 4 — filename substring tokens (match = [NAME]) ────────────────────
# Any filename containing one of these tokens (case-insensitive) is flagged.
$script:Stage4NameTokens = @(
    'credential','secret','pass','password','passwd','account','login'
)

# ── Stage 5 — content-scan extension allow-list ────────────────────────────
$script:Stage5Extensions = @(
```

(continue with the existing `.conf .config ...` content of the old `$script:SearchExtensions` array — copy it verbatim through to the closing `)`)

Then immediately after the closing `)`:

```
$script:Stage5ExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage5Extensions, [System.StringComparer]::OrdinalIgnoreCase)
```

- [ ] **Step 3: Delete the old `$script:CredFileNames`, `$script:CredFileNamesSet`, and `$script:SuspiciousNamePatterns` arrays**

Run: `grep -n '^\\$script:CredFileNames\b\|^\\$script:CredFileNamesSet\b\|^\\$script:SuspiciousNamePatterns\b' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"`

For each, use `Edit` to delete the entire definition (from the variable line through the closing `)` on its own line).

- [ ] **Step 4: Verify the script still parses**

Run:
```
pwsh -NoProfile -Command "
\$errors = \$null; \$tokens = \$null
[System.Management.Automation.Language.Parser]::ParseFile('/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1', [ref]\$tokens, [ref]\$errors) | Out-Null
if (\$errors.Count -eq 0) { 'PWSH_SYNTAX_OK' } else { \$errors | ForEach-Object { \$_.ToString() } }
"
```
Expected: `PWSH_SYNTAX_OK`

---

### Task 9: Add `-NoStageN` switch params

**Files:**
- Modify: `credshunter.ps1:65-88` (param block)

- [ ] **Step 1: Add the switches**

Use `Edit` tool. Old string:
```
    [switch] $SkipSystem,

    [switch] $Quiet,
```

New string:
```
    [switch] $SkipSystem,
    [switch] $NoStage1,
    [switch] $NoStage2,
    [switch] $NoStage3,
    [switch] $NoStage4,
    [switch] $NoStage5,

    [switch] $Quiet,
```

- [ ] **Step 2: Compute effective skip booleans after the param block**

Use `Edit` tool. Find a stable anchor (e.g., the `$script:Version = '2.0.0'` line) and insert immediately after the existing `$script:Version` assignment.

Old string:
```
$script:Version        = '2.0.0'
```

New string:
```
$script:Version        = '2.0.0'

# Stage-skip booleans: -SkipSystem is the legacy alias for -NoStage1
$script:Stage1Skip = $SkipSystem.IsPresent -or $NoStage1.IsPresent
$script:Stage2Skip = $NoStage2.IsPresent
$script:Stage3Skip = $NoStage3.IsPresent
$script:Stage4Skip = $NoStage4.IsPresent
$script:Stage5Skip = $NoStage5.IsPresent
```

- [ ] **Step 3: Verify**

Run: the same pwsh ParseFile command from Task 8 Step 4. Expected: `PWSH_SYNTAX_OK`

---

### Task 10: Add `Begin-Stage` / `End-Stage` / `Stage-Skipped` helpers

**Files:**
- Modify: `credshunter.ps1` — insert helpers near the other output helpers (e.g., right after `Write-Banner` / `Write-Section` / `Write-Info` definitions, around line ~780-800).

- [ ] **Step 1: Locate the insertion point**

Run: `grep -n '^function Write-Banner\|^function Write-Section\|^function Write-LogLine' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"`
Expected: function definitions for the existing output helpers.

- [ ] **Step 2: Insert the stage lifecycle helpers**

Find the closing `}` of `Write-LogLine` (one of the last output helpers) and insert after it. Use `Edit` tool. Old string:
```
function Write-LogLine { param([string]$Line)
    if ([string]::IsNullOrEmpty($script:LogPath)) { return }
    $clean = $Line -replace "`e\[[0-9;]*m", ''
    Add-Content -Path $script:LogPath -Value $clean -Encoding UTF8
}
```

New string:
```
function Write-LogLine { param([string]$Line)
    if ([string]::IsNullOrEmpty($script:LogPath)) { return }
    $clean = $Line -replace "`e\[[0-9;]*m", ''
    Add-Content -Path $script:LogPath -Value $clean -Encoding UTF8
}

# ============================================================================
#  Stage lifecycle — per-stage timing, skip-gating, and live-results block
# ============================================================================

$script:StageBeforeCounts = @{}
$script:StageStartTime    = @{}

function Begin-Stage { param([int]$N)
    $script:StageBeforeCounts[$N] = @{
        Guaranteed = $script:Guaranteed.Count
        High       = $script:HighFindings.Count
        Key        = $script:KeyFindings.Count
        Interest   = $script:Interesting.Count
        Cred       = $script:CredFiles.Count
        Name       = $script:SuspiciousNamesFound.Count
    }
    $script:StageStartTime[$N] = [DateTime]::UtcNow
}

function End-Stage { param([int]$N, [string]$Title)
    $before = $script:StageBeforeCounts[$N]
    $elapsed = ([DateTime]::UtcNow - $script:StageStartTime[$N]).TotalSeconds
    $dGuar = $script:Guaranteed.Count           - $before.Guaranteed
    $dHigh = $script:HighFindings.Count         - $before.High
    $dKey  = $script:KeyFindings.Count          - $before.Key
    $dInt  = $script:Interesting.Count          - $before.Interest
    $dCred = $script:CredFiles.Count            - $before.Cred
    $dName = $script:SuspiciousNamesFound.Count - $before.Name
    $total = $dGuar + $dHigh + $dKey + $dInt + $dCred + $dName

    Write-Host ""
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
    Write-Host "$($script:CBold)  Stage $N - $Title$($script:CNC)"
    Write-Host "$($script:CC)----------------------------------------------------------------------$($script:CNC)"
    Write-Host ("  Found: $($script:CW)$($script:CBold){0}$($script:CNC) file(s)   ({1:N2}s)" -f $total, $elapsed)

    if (-not $Quiet -and $total -gt 0) {
        Write-Host ""
        # CRITICAL
        if ($dGuar -gt 0) {
            $script:Guaranteed | Select-Object -Last $dGuar | ForEach-Object {
                Write-Host ("  [CRITICAL]  {0}" -f $_.Path)
            }
        }
        # HIGH
        if ($dHigh -gt 0) {
            $script:HighFindings | Select-Object -Last $dHigh | ForEach-Object {
                Write-Host ("  [HIGH]      {0}" -f $_.Path)
            }
        }
        # KEY
        if ($dKey -gt 0) {
            $script:KeyFindings | Select-Object -Last $dKey | ForEach-Object {
                Write-Host ("  [KEY]       {0}" -f $_.Path)
            }
        }
        # INTEREST
        if ($dInt -gt 0) {
            $script:Interesting | Select-Object -Last $dInt | ForEach-Object {
                Write-Host ("  [INTEREST]  {0}" -f $_.Path)
            }
        }
        # CRED_FILE
        if ($dCred -gt 0) {
            $script:CredFiles | Select-Object -Last $dCred | ForEach-Object {
                Write-Host ("  [CRED_FILE] {0}" -f $_)
            }
        }
        # NAME
        if ($dName -gt 0) {
            $script:SuspiciousNamesFound | Select-Object -Last $dName | ForEach-Object {
                Write-Host ("  [NAME]      {0}" -f $_)
            }
        }
    }
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
}

function Stage-Skipped { param([int]$N, [string]$Title)
    Write-Host ""
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
    Write-Host "$($script:CBold)  Stage $N - $Title  [SKIPPED]$($script:CNC)"
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
}
```

- [ ] **Step 3: Verify**

Run: the pwsh ParseFile command. Expected: `PWSH_SYNTAX_OK`

Run: `grep -nE "^function (Begin-Stage|End-Stage|Stage-Skipped)\b" "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"`
Expected: three lines.

---

### Task 11: Rewrite `Find-HighValueFiles` (Stage 3) — three-pass + Stage 2 dedup

**Files:**
- Modify: `credshunter.ps1:1742-1770` (`Find-HighValueFiles` function body)

- [ ] **Step 1: Replace the function**

Use `Edit` tool. Old string (the entire function from signature through closing `}`):

```
# Stage 3 - auxiliary credential-related files
function Find-HighValueFiles { param([string[]]$Paths)
```

(... replace through end of function — match the existing body exactly)

New string:

```
# Stage 3 - high-value file types (NEW SPEC)
# Three passes driven by top-of-file arrays:
#   $script:Stage3Extensions    — extension match
#   $script:Stage3ExactNames    — exact-basename match
#   $script:Stage3GlobPatterns  — wildcard match (PowerShell -like)
# Files already flagged by Stage 2 are deduped via $script:GuaranteedHashes.
function Find-HighValueFiles { param([string[]]$Paths)
    Write-Section "Stage 3 - High-value file types"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                # Stage 2 dedup (Add-Interesting won't double-record, but skip
                # early for performance)
                if ($script:GuaranteedHashes.Contains($f)) { continue }

                $name = [System.IO.Path]::GetFileName($f)
                $nameLc = $name.ToLowerInvariant()
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()

                # SQL Server system-DB filter (always skip)
                if ($script:SkipDbFilenames.Contains($name)) { continue }

                $matched = $false

                # Pass 1: extension
                if ($script:Stage3Extensions -contains $ext) { $matched = $true }

                # Pass 2: exact filename
                if (-not $matched -and $script:Stage3ExactNamesSet.Contains($name)) {
                    $matched = $true
                }

                # Pass 3: glob (e.g. krb5cc_*, *.tar.gz)
                if (-not $matched) {
                    foreach ($g in $script:Stage3GlobPatterns) {
                        if ($nameLc -like $g.ToLowerInvariant()) { $matched = $true; break }
                    }
                }

                if ($matched) {
                    Add-Interesting -Category 'high_value_file' -Path $f
                    $count++
                }
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
    Write-Ok "Stage 3 catalogued $($script:CW)$count$($script:CNC) high-value file(s)."
}
```

- [ ] **Step 2: Verify**

Run: pwsh ParseFile command. Expected: `PWSH_SYNTAX_OK`

---

### Task 12: Rewrite `Find-SuspiciousNames` (Stage 4) — tokens only, no exact list

**Files:**
- Modify: `credshunter.ps1:1773-1827` (`Find-SuspiciousNames` function body)

- [ ] **Step 1: Replace the function**

Use `Edit` tool. Old string spans the entire function from signature through closing `}`.

New string:

```
# Stage 4 - filename substring search (NEW SPEC)
# Single pass: any file whose basename contains a token from
# $script:Stage4NameTokens (case-insensitive) is emitted as a [NAME] finding.
# Binary executables, libraries, and the scanner's own script are excluded.
function Find-SuspiciousNames { param([string[]]$Paths)
    Write-Section "Stage 4 - Filename substring search"

    $binaryExts = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('.dll','.exe','.sys','.ocx','.com','.scr','.drv','.cpl',
                    '.ax','.efi','.mui','.so','.dylib','.lib','.bin',
                    '.tlb','.olb','.tlh','.pdb','.ilk','.nupkg'),
        [System.StringComparer]::OrdinalIgnoreCase)
    $selfName = if ($script:SelfPath) { [System.IO.Path]::GetFileName($script:SelfPath).ToLowerInvariant() } else { '' }

    $tokens = @($script:Stage4NameTokens | ForEach-Object { $_.ToLowerInvariant() })

    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($e in [System.IO.Directory]::EnumerateFiles($current)) {
                $name = [System.IO.Path]::GetFileName($e).ToLowerInvariant()
                if ($selfName -and $name -eq $selfName) { continue }
                $ext = [System.IO.Path]::GetExtension($e).ToLowerInvariant()
                if ($binaryExts.Contains($ext)) { continue }

                foreach ($t in $tokens) {
                    if ($name.Contains($t)) {
                        Add-SuspiciousName -Path $e
                        $count++
                        break
                    }
                }
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
    Write-Ok "Stage 4 found $($script:CW)$count$($script:CNC) filename(s) matching credential tokens."
}
```

- [ ] **Step 2: Verify**

Run: pwsh ParseFile command. Expected: `PWSH_SYNTAX_OK`

---

### Task 13: Wire `Invoke-Main`, rename array references, update help

**Files:**
- Modify: `credshunter.ps1:2024-2038` (the stage orchestration block in `Invoke-Main`)
- Modify: any remaining references to `$script:GuaranteedCredExtensions`, `$script:HighValueExtensions`, `$script:SearchExtensions`, `$script:SearchExtensionsSet`, `$script:CredFileNamesSet`, `$script:SuspiciousNamePatterns`
- Modify: `credshunter.ps1` help text / synopsis (if exists at top with `<# ... #>` block)

- [ ] **Step 1: Find any remaining stale references**

Run:
```
grep -nE '\\$script:(GuaranteedCredExtensions|HighValueExtensions|SearchExtensions|SearchExtensionsSet|CredFileNamesSet|SuspiciousNamePatterns|CredFileNames)\b' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"
```

For each hit, use `Edit` with `replace_all=true` to rename:
- `$script:GuaranteedCredExtensions` → `$script:Stage2Extensions`
- `$script:HighValueExtensions`      → (no longer used; logic is in `Find-HighValueFiles` rewrite — if any callers remain, remove them)
- `$script:SearchExtensions`         → `$script:Stage5Extensions`
- `$script:SearchExtensionsSet`      → `$script:Stage5ExtensionsSet`
- `$script:CredFileNamesSet`         → (deleted; remove any caller — Stage 4 no longer uses exact-name matching)
- `$script:SuspiciousNamePatterns`   → `$script:Stage4NameTokens` (already used by new Find-SuspiciousNames)
- `$script:CredFileNames`            → (deleted; remove)

- [ ] **Step 2: Find and update `Find-GuaranteedCredentials` to use `$script:Stage2Extensions`**

Run: `grep -n '^function Find-GuaranteedCredentials' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"`

Inside that function, find the line that references the old array name and replace with `$script:Stage2Extensions`.

- [ ] **Step 3: Wire stages in `Invoke-Main`**

Use `Edit` tool. Old string:
```
    if (-not $SkipSystem) {
        Invoke-SystemChecks
    } else {
        Write-Warn "Skipping OS-level checks (per -SkipSystem)."
    }

    if ($Path.Count -eq 0) {
        Write-Warn "No -Path supplied. Skipping stages 2-5."
        Write-Warn "Tip: pass -Path C:\ to scan everywhere."
    } else {
        Find-GuaranteedCredentials -Paths $Path
        Find-HighValueFiles -Paths $Path
        Find-SuspiciousNames -Paths $Path
        Invoke-UserPathScan -Paths $Path
    }
```

New string:
```
    if (-not $script:Stage1Skip) {
        Begin-Stage 1
        Invoke-SystemChecks
        End-Stage 1 "OS-level credential checks"
    } else {
        Stage-Skipped 1 "OS-level credential checks"
    }

    if ($Path.Count -eq 0) {
        Write-Warn "No -Path supplied. Skipping stages 2-5."
        Write-Warn "Tip: pass -Path C:\ to scan everywhere."
    } else {
        if (-not $script:Stage2Skip) {
            Begin-Stage 2; Find-GuaranteedCredentials -Paths $Path; End-Stage 2 "Confirmed credential containers"
        } else {
            Stage-Skipped 2 "Confirmed credential containers"
        }
        if (-not $script:Stage3Skip) {
            Begin-Stage 3; Find-HighValueFiles -Paths $Path; End-Stage 3 "High-value file types"
        } else {
            Stage-Skipped 3 "High-value file types"
        }
        if (-not $script:Stage4Skip) {
            Begin-Stage 4; Find-SuspiciousNames -Paths $Path; End-Stage 4 "Filename substring search"
        } else {
            Stage-Skipped 4 "Filename substring search"
        }
        if (-not $script:Stage5Skip) {
            Begin-Stage 5; Invoke-UserPathScan -Paths $Path; End-Stage 5 "Recursive content scan"
        } else {
            Stage-Skipped 5 "Recursive content scan"
        }
    }
```

- [ ] **Step 4: Update the `<# .DESCRIPTION ... #>` help block at the top of the script to document the new flags**

Run: `grep -n '^\.PARAMETER' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"` — find the existing `.PARAMETER` entries.

Use `Edit` tool. Find the `.PARAMETER SkipSystem` entry and append five new `.PARAMETER` blocks after it:

Old string:
```
.PARAMETER SkipSystem
    Skip stage 1 (OS-level credential checks).
```

New string:
```
.PARAMETER SkipSystem
    Skip stage 1 (OS-level credential checks). Alias for -NoStage1.

.PARAMETER NoStage1
    Skip stage 1 (OS-level credential checks).

.PARAMETER NoStage2
    Skip stage 2 (confirmed credential containers).

.PARAMETER NoStage3
    Skip stage 3 (high-value file types).

.PARAMETER NoStage4
    Skip stage 4 (filename substring search).

.PARAMETER NoStage5
    Skip stage 5 (recursive content scan).
```

(If no `.PARAMETER SkipSystem` block exists, skip this step — the `-Help` output will use defaults from the param block.)

- [ ] **Step 5: Verify**

Run: pwsh ParseFile command. Expected: `PWSH_SYNTAX_OK`

Run:
```
grep -cE '\\$script:(GuaranteedCredExtensions|HighValueExtensions|SearchExtensions|SearchExtensionsSet|CredFileNamesSet|SuspiciousNamePatterns|CredFileNames)\b' "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1"
```
Expected: `0`

---

### Task 14: PowerShell functional verification

**Files:** none modified — verification only.

- [ ] **Step 1: Build a tiny scratch test directory**

Run:
```
T=$(mktemp -d) && \
mkdir -p "$T/sub" && \
printf 'PASSWORD = "real-cred"\n' > "$T/secrets.env" && \
printf 'CONTENT\n' > "$T/db.sqlite" && \
printf 'CONTENT\n' > "$T/sub/passwd_backup.txt" && \
printf 'CONTENT\n' > "$T/host.keytab" && \
ls "$T"
```

- [ ] **Step 2: Run scanner with all stages**

Run: `pwsh -NoProfile -File "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1" -SkipSystem -Path "$T" -NoColor 2>&1 | tee /tmp/credshunter_ps_run1.log`
Expected:
- Stage 2 live block contains `[CRITICAL] <T>/host.keytab`
- Stage 3 live block contains `[INTEREST] <T>/secrets.env` and `[INTEREST] <T>/db.sqlite` but NOT `host.keytab` (deduped)
- Stage 4 live block contains `[NAME] <T>/sub/passwd_backup.txt`
- Stage 5 live block contains a HIGH/KEY finding on `secrets.env`

- [ ] **Step 3: Run with `-NoStage3 -NoStage4`**

Run: `pwsh -NoProfile -File "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/credshunter.ps1" -SkipSystem -NoStage3 -NoStage4 -Path "$T" -NoColor 2>&1 | tee /tmp/credshunter_ps_run2.log`
Expected: Stage 3 and Stage 4 print `[SKIPPED]` blocks.

- [ ] **Step 4: Verify**

Run: `grep -E "Stage [0-9] - .*\[SKIPPED\]|Stage [0-9] - " /tmp/credshunter_ps_run2.log`
Expected: SKIPPED lines for stages 3 and 4; non-SKIPPED for stages 1, 2, 5.

- [ ] **Step 5: Clean up**

Run: `rm -rf "$T" /tmp/credshunter_ps_run1.log /tmp/credshunter_ps_run2.log && echo CLEANED`

---

## Phase 3 — End-to-end verification

### Task 15: Docker benchmark + regression check

**Files:** none modified — verification only.

- [ ] **Step 1: Inspect docker harness availability**

Run: `ls "/Users/pentester/Desktop/Tools/Personal Tools/credshunter/docker/" | sort`
Expected: `Dockerfile.linux`, `Dockerfile.pwsh`, `docker-compose.yml`, `measure.ps1`, `measure.sh`, `populate.sh`

- [ ] **Step 2: Build and run linux benchmark**

Run:
```
cd "/Users/pentester/Desktop/Tools/Personal Tools/credshunter" && \
docker compose -f docker/docker-compose.yml run --rm linux 2>&1 | tail -60
```
Expected:
- `Detection rate: ~100%` (catches all planted TPs)
- `Noise rate: 0%` (no FPs)
- New live-results blocks visible in output for each stage

- [ ] **Step 3: Build and run powershell benchmark**

Run:
```
cd "/Users/pentester/Desktop/Tools/Personal Tools/credshunter" && \
docker compose -f docker/docker-compose.yml run --rm pwsh 2>&1 | tail -60
```
Expected: same as Step 2.

- [ ] **Step 4: Skip-flag smoke test in docker**

Run:
```
docker compose -f docker/docker-compose.yml run --rm linux \
    bash /credshunter.sh --skip-system --no-stage3 --no-stage4 -p /testenv --no-color 2>&1 | grep -E "Stage [0-9] —|SKIPPED" | head -20
```
Expected: Stage 3 and 4 lines contain `[SKIPPED]`; other stages run normally.

- [ ] **Step 5: Final sign-off**

If all three docker runs report `0%` noise rate and detection rate stays at or near the previous baseline, the restructure is complete. If the detection rate dropped, the regression is almost certainly from dropping the EXACT_CRED_FILENAMES list in Stage 4 (expected per spec — confirm the missed TPs are exactly the ones predicted by the spec's "trade-off" note).

---

## Spec → Plan coverage check (self-review)

| Spec requirement | Implementing task(s) |
|---|---|
| Stage 1 unchanged | Tasks 6, 13 (only orchestration wrapped; no logic touched) |
| Stage 2 unchanged | Task 6 step 4, Task 13 step 2 (array renamed, function untouched) |
| Stage 3 = new list (extensions + exact + glob), dedup vs Stage 2 | Tasks 4, 11 |
| Stage 4 = 7-token substring only | Tasks 5, 12 |
| Stage 5 unchanged (renamed array) | Tasks 6 step 5, Task 13 step 1 |
| Centralized config block at top | Tasks 1, 8 |
| `--no-stageN` / `-NoStageN` flags | Tasks 2, 9 |
| `--skip-system` / `-SkipSystem` aliases `--no-stage1` / `-NoStage1` | Tasks 2 step 2, Task 9 step 2 |
| Live results block at end of each stage | Tasks 3, 10 |
| Quiet mode suppresses per-file enumeration | Tasks 3, 10 (gated by `$QUIET` / `$Quiet`) |
| Stage-scoped delta printing | Tasks 3, 10 (snapshot-on-begin pattern) |
| Skipped stage still emits a block | Tasks 3, 10 (`stage_skipped` / `Stage-Skipped`) |
| Empty stage still emits a block | Tasks 3, 10 (block always prints; only body is suppressed if zero in quiet mode) |
| Stage 5 grouped by tier | Tasks 3 step 2, Task 10 step 2 (`stage_print_delta` / `End-Stage` iterate tiers) |
| Final report unchanged | No task touches `print_summary` / `Write-FullSummary` |
| Verification via docker harness | Task 15 |

No gaps identified.
