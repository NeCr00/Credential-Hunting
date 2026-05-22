#requires -Version 5.1

<#
.SYNOPSIS
    Windows hardcoded-credential hunter for authorized penetration testing.

.DESCRIPTION
    Recursively scans a target path for files commonly containing hardcoded
    credentials on Windows hosts: passwords, API tokens, connection strings,
    GPP cpasswords, unattend.xml secrets, ConvertTo-SecureString plaintext
    usage, WinSCP / PuTTY material, RDP files, private keys, cloud creds,
    and password hashes.

    Designed for authorized lab / CTF / OSCP / red-team triage on Windows
    only.  Pure PowerShell, no external dependencies.  Works on Windows
    PowerShell 5.1 (shipped with Windows 10 / 11 / Server 2016+) and on
    PowerShell 7+.

.PARAMETER Path
    Target directory or file to scan.  Positional argument.

.PARAMETER All
    Scan every readable file under <Path>.  Default mode targets only the
    file types that realistically hold credentials.

.PARAMETER MaxSizeMB
    Skip files larger than this many megabytes.  Default: 10.

.PARAMETER Context
    Print one line of surrounding context per hit.

.PARAMETER Quiet
    Hide banner / progress; only show findings and the summary.

.EXAMPLE
    .\CredHunter.ps1 C:\inetpub

.EXAMPLE
    .\CredHunter.ps1 -All -Context C:\Users

.EXAMPLE
    .\CredHunter.ps1 -MaxSizeMB 5 -Quiet C:\

.NOTES
    Authorized testing only.
    Microsoft Defender / EDRs may flag this script as suspicious because
    it performs broad credential discovery.  Add an exclusion on the lab
    host, or sign / pin it as appropriate before running in scope.

    Execution policy bypass for a one-shot run:
        powershell -ExecutionPolicy Bypass -File .\CredHunter.ps1 C:\target
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Path,

    [Alias('a')]
    [switch] $All,

    [Alias('s')]
    [int]    $MaxSizeMB = 10,

    [Alias('c')]
    [switch] $Context,

    [Alias('q')]
    [switch] $Quiet,

    [Alias('h')]
    [switch] $Help
)

# ----------------------------------------------------------------------------
#  Help / argument validation
# ----------------------------------------------------------------------------

if ($Help -or [string]::IsNullOrWhiteSpace($Path)) {
    @"
CredHunter.ps1  -  Windows hardcoded credential hunter

Usage:
  .\CredHunter.ps1 [options] <Path>

Options:
  -Path <string>        Target directory or file (positional).
  -All        (-a)      Scan every readable file under <Path>. Default mode
                        targets only file types that realistically hold
                        credentials.
  -MaxSizeMB <int>(-s)  Skip files larger than this many MB. Default: 10.
  -Context    (-c)      Print one line of surrounding context per hit.
  -Quiet      (-q)      Hide banner / progress; only show findings + summary.
  -Help       (-h)      Show this help.

Examples:
  .\CredHunter.ps1 C:\inetpub
  .\CredHunter.ps1 -All -Context C:\Users
  .\CredHunter.ps1 -MaxSizeMB 5 -Quiet C:\

If execution policy blocks the script:
  powershell -ExecutionPolicy Bypass -File .\CredHunter.ps1 C:\target

Authorized testing only.
"@ | Write-Host
    return
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "Path '$Path' does not exist."
    exit 1
}

# Resolve to a full path for clean output and to harden -LiteralPath usage.
$ResolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath

# ----------------------------------------------------------------------------
#  Globals / counters
# ----------------------------------------------------------------------------

$script:Hits         = 0
$script:FilesScanned = 0
$script:CatCounts    = @{}

# ----------------------------------------------------------------------------
#  File enumeration policy
# ----------------------------------------------------------------------------

# Exact (lower-cased) basenames to always scan in smart mode.
$SmartNames = @(
    # IIS / .NET application configuration
    'web.config','app.config','machine.config','applicationhost.config',
    'connectionstrings.config','aspnet.config',

    # Sysprep / unattended install
    'unattend.xml','unattended.xml','autounattend.xml','sysprep.xml',
    'sysprep.inf',

    # Group Policy Preferences (GPP) - SYSVOL goldmine
    'groups.xml','services.xml','scheduledtasks.xml','datasources.xml',
    'printers.xml','drives.xml',

    # WordPress / common CMS configs
    'wp-config.php','wp-config-sample.php','configuration.php',

    # Python / Django / Flask
    'settings.py','local_settings.py','config.py','secret.py','secrets.py',

    # Ruby / Rails
    'database.yml','database.yaml','secrets.yml','secrets.yaml',
    'application.yml','application.yaml','application.properties',
    'bootstrap.yml','bootstrap.properties',

    # PHP DB / generic
    'config.php','connect.php','db.php','database.php',

    # Java EE
    'standalone.xml','server.xml','context.xml','tomcat-users.xml',
    'hibernate.cfg.xml','persistence.xml',

    # PowerShell history (per-user)
    'consolehost_history.txt',

    # SSH client material (lives under %USERPROFILE%\.ssh on Windows too)
    'id_rsa','id_dsa','id_ecdsa','id_ed25519','id_xmss',
    'authorized_keys','known_hosts',

    # Credential / auth stores
    '.netrc','_netrc','.pgpass','.my.cnf','.htpasswd','.htdigest',
    'credentials','credentials.csv','credentials.json','authinfo',
    'passwords','passwords.txt','master.passwd',

    # Cloud CLIs (commonly on dev / admin boxes)
    'credentials.json','config.json','token.json',

    # GUI tools that store creds in plaintext / reversible form
    'winscp.ini','filezilla.xml','recentservers.xml','sitemanager.xml',
    'firezilla.xml',

    # SQL Server / Office DB connection metadata
    'master.publishsettings',

    # CI / IaC
    'dockerfile','jenkinsfile','vagrantfile',
    'terraform.tfstate','terraform.tfstate.backup'
)

# Lower-cased extensions to always scan in smart mode.
$SmartExtensions = @(
    # Configuration
    '.config','.cfg','.cnf','.ini','.conf','.properties',
    '.yaml','.yml','.json','.toml','.xml','.plist',

    # PowerShell / batch / VBScript
    '.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.wsf',

    # .NET / web
    '.cs','.vb','.fs','.aspx','.ashx','.asmx','.cshtml','.vbhtml','.razor',
    '.sln','.csproj','.vbproj','.fsproj','.props','.targets',
    '.user','.pubxml','.publishsettings',

    # Front-end / generic source
    '.js','.ts','.jsx','.tsx','.mjs','.cjs',
    '.py','.rb','.pl','.php','.go','.java','.kt','.scala','.groovy',
    '.rs','.c','.cpp','.cc','.h','.hpp','.swift','.lua','.r',
    '.sh','.bash','.zsh','.tcl',

    # Database connection files
    '.udl','.dsn','.dbml',

    # Backups / drafts / templates
    '.bak','.backup','.old','.orig','.save','.tmp',
    '.sample','.example','.template','.dist','.copy',

    # SQL dumps
    '.sql','.dump','.dacpac',

    # Remote-access stored sessions
    '.rdp','.rdg','.ppk',

    # IaC
    '.tf','.tfvars',

    # Logs
    '.log',

    # Notes / plaintext
    '.txt','.md','.csv','.tsv','.rtf','.note','.notes',

    # Env files
    '.env'
)

# Wildcard patterns matched against the filename (-like).
$SmartGlobs = @(
    '.env*','*.env','env.*',
    'docker-compose*.yml','docker-compose*.yaml',
    'dockerfile*','dockerfile.*',
    '*.tfstate*','*.log.*'
)

# Directory names pruned anywhere in the path (build/cache/vendor noise +
# Windows system noise that explodes scan time with zero credential value).
$ExcludeDirs = @(
    # VCS
    '.git','.svn','.hg','.bzr',
    # Package / dependency caches
    'node_modules','bower_components','packages',
    '__pycache__','.pytest_cache','.mypy_cache','.ruff_cache',
    'venv','.venv','.tox','virtualenv',
    'vendor','site-packages','eggs','.eggs',
    # Build outputs
    'dist','build','target','out','.next','.nuxt',
    'bin','obj',
    # Tool caches
    '.cache','.npm','.yarn','.gradle','.m2','.ivy2',
    # IDE
    '.idea','.vscode','.vs','.terraform',
    # Windows system / runtime noise
    'WinSxS','SoftwareDistribution','Servicing','assembly',
    'DriverStore','LiveKernelReports',
    'WindowsApps','Installer',
    '$Recycle.Bin','System Volume Information',
    'CrashDumps','Temporary Internet Files'
)

# Build a single regex that matches any excluded dir as a path segment.
# Path comparison is case-insensitive on Windows; we rely on the regex flag.
$ExcludePathRegex = '(?i)\\(?:' + (
    ($ExcludeDirs | ForEach-Object { [regex]::Escape($_) }) -join '|'
) + ')\\'

# ----------------------------------------------------------------------------
#  Regex patterns (PowerShell uses .NET regex - PCRE-equivalent for our needs).
#  Single-quoted strings preserve every char literally - we use \x27 for the
#  ASCII apostrophe inside character classes to avoid shell-quoting hassles.
# ----------------------------------------------------------------------------

# ---- PRIVATE KEYS ----------------------------------------------------------
$PAT_PRIVKEY = '-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|DH) )?PRIVATE KEY(?: BLOCK)?-----'
$PAT_PUTTY   = '^PuTTY-User-Key-File-[0-9]+:'

# ---- PASSWORDS -------------------------------------------------------------
# Key=value, optional snake-case prefix, optional quoted key, value of 2+ chars
$PAT_PASSWORD         = '(?i)(?<![A-Za-z])(?:[a-z][a-z0-9_]*_)?(?:password|passwd|passphrase|pwd)(?![A-Za-z])["\x27]?\s*(?:=>|[:=])\s*["\x27]?[^"\x27\s\r\n#;,]{2,200}'
# PHP define('KEY','value') and similar
$PAT_PASSWORD_DEFINE  = '(?i)\bdefine\s*\(\s*["\x27][a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*["\x27]\s*,\s*["\x27][^"\x27\r\n]{1,200}["\x27]'
# .netrc style "password <value>"
$PAT_PASSWORD_NETRC   = '(?i)(?:^|[^A-Za-z_])password\s+\S{3,}'
# Note: a separate user/login pattern was intentionally omitted - the password
# line itself is the high-signal indicator and is already caught by
# PAT_PASSWORD; a bare "user=foo" line would generate excessive false positives.

# ---- WINDOWS CONNECTION STRINGS (Server=...;Password=...;) -----------------
# Anchored on the leading "Server=" / "Data Source=" / "Initial Catalog="
# token so we don't double-count generic password= lines (those are PASSWORD).
$PAT_CONN_STRING = '(?i)(?:Server|Data\s*Source|Initial\s*Catalog|Database|Host)\s*=\s*[^;"\x27\r\n]+\s*;[^"\x27\r\n]{0,300}?(?:Password|Pwd)\s*=\s*[^;"\x27\r\n]{1,}'
# JDBC URLs with explicit credentials
$PAT_JDBC        = '(?i)jdbc:[a-z0-9]+:[^"\x27\s]+[?&;](?:user|password|pwd)=[^"\x27\s&;]+'
# Standard service URLs with embedded user:pass
$PAT_URL_CREDS   = '(?i)\b(?:https?|ftp|ftps|sftp|ssh|scp|rsync|ldap|ldaps|mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|smtp|smtps|imap|imaps|pop3|pop3s)://[^:/\s@"\x27]+:[^/\s@"\x27<>]{1,}@[^\s"\x27<>]+'

# ---- GROUP POLICY PREFERENCES CPASSWORD (high-signal: AES, key is public) --
$PAT_GPP_CPASSWORD = '(?i)\bcpassword\s*=\s*"[A-Za-z0-9+/=]{8,}"'

# ---- UNATTEND / SYSPREP PASSWORD ELEMENT -----------------------------------
# Multi-line in real files; we flag the opening tag so the analyst can pivot.
$PAT_UNATTEND      = '(?i)<(?:AdministratorPassword|DomainPassword|LocalAccountPassword|AutoLogon)\b'
# In the same family - inline plain-text password attributes
$PAT_UNATTEND_INL  = '(?i)<(?:Password|UserPassword)>[^<\r\n]{1,}</(?:Password|UserPassword)>'

# ---- POWERSHELL ANTI-PATTERNS ---------------------------------------------
# ConvertTo-SecureString applied to a hard-coded plaintext.
$PAT_SECURESTRING   = '(?i)ConvertTo-SecureString\s+["\x27][^"\x27\r\n]{1,}["\x27][^\r\n]*?-AsPlainText'
$PAT_SECURESTRING2  = '(?i)ConvertTo-SecureString\s+-AsPlainText[^"\x27\r\n]*?["\x27][^"\x27\r\n]{1,}["\x27]'
$PAT_SECURESTRING3  = '(?i)ConvertTo-SecureString\s+-String\s+["\x27][^"\x27\r\n]{1,}["\x27]'
# PSCredential constructions whose password came from above
$PAT_PSCRED_PLAIN   = '(?i)New-Object\s+(?:System\.Management\.Automation\.)?PSCredential\s*\(\s*["\x27][^"\x27]+["\x27]\s*,'
# Export-CliXml output marker (encrypted but worth flagging during triage)
$PAT_CLIXML_PSCRED  = 'System\.Management\.Automation\.PSCredential'
# Encoded payloads typically used to hide secrets
$PAT_ENCODED_PS     = '(?i)powershell(?:\.exe)?(?:[\s/-][a-z]+)*\s+-(?:enc(?:odedcommand)?|ec)\s+[A-Za-z0-9+/=]{40,}'

# ---- REMOTE-ACCESS FILES ---------------------------------------------------
# RDP stored credential
$PAT_RDP_PASSWORD   = '(?im)^password\s+51:b:[A-Fa-f0-9]{2,}'
# WinSCP.ini stored password (AES with hard-coded key - reversible)
$PAT_WINSCP         = '(?i)\bPassword\s*=\s*A35C[A-Fa-f0-9]{6,}'
# net use commands embedding plaintext credentials in batch / scripts
$PAT_NET_USE        = '(?i)\bnet\s+use\s+\\\\[^\s]+\s+\S+\s+/user:\S+'
# runas /savecred sentinel (saved creds in Credential Manager)
$PAT_RUNAS_SAVECRED = '(?i)\brunas\s+(?:[/-][a-z:]+\s+){0,4}/savecred\b'

# ---- WLAN PROFILE STORED KEY ----------------------------------------------
$PAT_WLAN_KEY       = '(?i)<keyMaterial>[^<\r\n]{1,}</keyMaterial>'

# ---- AWS -------------------------------------------------------------------
$PAT_AWS_AKID   = '\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|ABIA|ACCA)[0-9A-Z]{16}\b'
$PAT_AWS_SECRET = '(?i)\baws[_\-]?(?:secret[_\-]?)?(?:access[_\-]?)?key(?:[_\-]?id)?\b\s*(?:=>|[:=])\s*["\x27]?[A-Za-z0-9/+=]{16,}["\x27]?'

# ---- HIGH-CONFIDENCE TOKEN FORMATS ----------------------------------------
$PAT_TOKEN = '\b(?:ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghr_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,}|glpat-[0-9A-Za-z_\-]{20}|hf_[A-Za-z0-9]{30,}|EAAA[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{36}|dckr_pat_[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b'

# ---- JWT -------------------------------------------------------------------
$PAT_JWT = '\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'

# ---- GENERIC API KEY ASSIGNMENTS ------------------------------------------
$PAT_API_KEY = '(?i)\b(?:api[_\-]?key|apikey|x[_\-]?api[_\-]?key|client[_\-]?secret|consumer[_\-]?(?:key|secret)|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|refresh[_\-]?token|app[_\-]?key|app[_\-]?id|private[_\-]?token|subscription[_\-]?key)\b["\x27]?\s*(?:=>|[:=])\s*["\x27]?[A-Za-z0-9_\-\.=/+]{12,}["\x27]?'

# ---- AUTHORIZATION HEADERS ------------------------------------------------
$PAT_AUTH = '(?i)\bauthorization\s*[:=]\s*["\x27]?(?:Bearer|Basic|Digest|Token)\s+[A-Za-z0-9_\-\.=/+]{8,}'

# ---- AZURE / GCP ----------------------------------------------------------
$PAT_AZURE = '(?i)(?:DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}|AccountKey=[A-Za-z0-9+/=]{60,}|SharedAccessSignature=sv=[A-Za-z0-9%&=_\-]+)'
$PAT_GCP   = '"type"\s*:\s*"service_account"'

# ---- NETRC FULL BLOCK -----------------------------------------------------
$PAT_NETRC_BLOCK = '(?i)^\s*machine\s+\S+\s+login\s+\S+\s+password\s+\S+'

# ---- GENERIC SECRETS ------------------------------------------------------
$PAT_SECRET = '(?i)\b(?:secret[_\-]?key|signing[_\-]?key|encryption[_\-]?key|app[_\-]?secret|session[_\-]?secret|csrf[_\-]?secret|jwt[_\-]?secret|django[_\-]?secret|flask[_\-]?secret|rails[_\-]?secret|cookie[_\-]?secret|webhook[_\-]?secret|master[_\-]?key|machine[_\-]?key|validation[_\-]?key|decryption[_\-]?key)\b["\x27]?\s*(?:=>|[:=])\s*["\x27]?[^"\x27\s\r\n#;,]{6,}'
# .NET machineKey element (validationKey / decryptionKey live in web.config)
$PAT_MACHINEKEY = '(?i)<machineKey\b[^>]*?(?:validation|decryption)Key\s*=\s*"[A-Fa-f0-9]{32,}"'

# ---- PASSWORD HASHES (shadow / htpasswd / NTLM / Kerberos) ----------------
$PAT_HASH = '\$(?:1|2[abxy]?|5|6|y|7)\$[A-Za-z0-9./]{1,}\$[A-Za-z0-9./]{8,}|\$apr1\$[A-Za-z0-9./]{1,}\$[A-Za-z0-9./]{8,}|:\$NT\$[a-fA-F0-9]{32}|\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b|\$krb5(?:tgs|asrep)\$[^\s]{8,}'

# ============================================================================
#  Helpers
# ============================================================================

function Test-IsBinaryFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $LiteralPath)

    try {
        $stream = [System.IO.File]::OpenRead($LiteralPath)
    }
    catch {
        return $true   # cannot open -> skip safely
    }
    try {
        $buffer = New-Object byte[] 4096
        $read   = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -lt 1) { return $false }   # empty -> treat as text

        # BOM-based text detection (important on Windows: many .ps1 / .xml
        # files are saved as UTF-16 LE, which is full of alternating NUL
        # bytes and would otherwise be misclassified as binary).
        if ($read -ge 3 -and $buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF) { return $false }   # UTF-8  BOM
        if ($read -ge 2 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE)                          { return $false }   # UTF-16 LE
        if ($read -ge 2 -and $buffer[0] -eq 0xFE -and $buffer[1] -eq 0xFF)                          { return $false }   # UTF-16 BE
        if ($read -ge 4 -and $buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE -and $buffer[2] -eq 0    -and $buffer[3] -eq 0) { return $false } # UTF-32 LE

        # No BOM: any NUL in the first 4KB strongly suggests binary.
        for ($i = 0; $i -lt $read; $i++) {
            if ($buffer[$i] -eq 0) { return $true }
        }
        return $false
    }
    finally {
        $stream.Dispose()
    }
}

# Write-Host -ForegroundColor is safe everywhere: it writes to the host UI
# (not the pipeline) so redirection / Out-File never receives colour codes.

function Write-Color {
    param(
        [string] $Text,
        [ConsoleColor] $Color = [ConsoleColor]::Gray,
        [switch] $NoNewline
    )
    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
}

function Get-CandidateFiles {
    [CmdletBinding()]
    param([string] $Root)

    $maxBytes = $MaxSizeMB * 1MB
    $extSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $SmartExtensions) { [void]$extSet.Add($e) }
    $nameSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $SmartNames) { [void]$nameSet.Add($n) }

    # If $Root is a single file, return it directly (subject to size cap).
    if (Test-Path -LiteralPath $Root -PathType Leaf) {
        $fi = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
        if ($fi -and $fi.Length -le $maxBytes) { $fi }
        return
    }

    Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $f = $_
            if ($f.Length -gt $maxBytes)            { return $false }
            if ($f.FullName -match $ExcludePathRegex) { return $false }
            if ($All)                                { return $true  }
            if ($extSet.Contains($f.Extension))      { return $true  }
            if ($nameSet.Contains($f.Name))          { return $true  }
            foreach ($g in $SmartGlobs) {
                if ($f.Name -like $g) { return $true }
            }
            return $false
        }
}

function Write-Hit {
    param(
        [string]      $Category,
        [ConsoleColor]$Color,
        [string]      $FilePath,
        [int]         $LineNumber,
        [string]      $Line
    )

    # Trim leading whitespace and truncate very long lines.
    $clean = $Line -replace '^[\s\t]+', ''
    if ($clean.Length -gt 240) { $clean = $clean.Substring(0, 240) + '…' }

    $catPadded = $Category.PadRight(13)

    Write-Color "[$catPadded] " -Color $Color -NoNewline
    Write-Color $FilePath        -Color Cyan  -NoNewline
    Write-Color ':'              -Color Gray  -NoNewline
    Write-Color $LineNumber      -Color Yellow -NoNewline
    Write-Color "  $clean"       -Color Gray

    if ($Context) {
        Write-FileContext -FilePath $FilePath -LineNumber $LineNumber
    }
}

function Write-FileContext {
    param([string] $FilePath, [int] $LineNumber)

    try {
        $start = [Math]::Max(1, $LineNumber - 1)
        $end   = $LineNumber + 1
        $i     = 0
        # Get-Content is fine for context display; we already know the file is text.
        Get-Content -LiteralPath $FilePath -TotalCount $end -ErrorAction Stop |
            ForEach-Object {
                $i++
                if ($i -ge $start -and $i -le $end -and $i -ne $LineNumber) {
                    $ctx = $_
                    if ($ctx.Length -gt 200) { $ctx = $ctx.Substring(0,200) + '…' }
                    Write-Color "  | $ctx" -Color DarkGray
                }
            }
    } catch { }
}

function Invoke-Category {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]       $Category,
        [Parameter(Mandatory)][ConsoleColor] $Color,
        [Parameter(Mandatory)][string[]]     $Patterns
    )

    # Select-String accepts an array of patterns natively (no PCRE single-pattern
    # limitation like grep -P).  One MatchInfo is emitted per line that hit any
    # pattern, so we get clean per-line dedup within a category for free.
    $script:CandidateFiles |
        Select-String -Pattern $Patterns -AllMatches -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Hit -Category $Category -Color $Color `
                      -FilePath $_.Path -LineNumber $_.LineNumber -Line $_.Line
            $script:Hits++
            if ($script:CatCounts.ContainsKey($Category)) {
                $script:CatCounts[$Category]++
            } else {
                $script:CatCounts[$Category] = 1
            }
        }
}

function Show-Banner {
    Write-Color ('+' + ('-' * 50) + '+') -Color White
    Write-Color '|  ' -Color White -NoNewline
    Write-Color 'CredHunter' -Color Green -NoNewline
    Write-Color '  -  Windows credential discovery        |' -Color White
    Write-Color ('+' + ('-' * 50) + '+') -Color White
    Write-Color ("target:    {0}" -f $ResolvedPath) -Color DarkGray
    $mode = if ($All) { 'all' } else { 'smart' }
    $ctx  = if ($Context) { 'on' } else { 'off' }
    Write-Color ("mode:      {0}    max-size: {1}MB    context: {2}`n" -f $mode, $MaxSizeMB, $ctx) -Color DarkGray
}

function Show-Summary {
    Write-Host ''
    Write-Color ('-' * 14 + '  summary  ' + '-' * 14) -Color White

    if ($script:Hits -eq 0) {
        Write-Color 'No credential indicators found.' -Color DarkGray
        Write-Color ("Files scanned: {0}" -f $script:FilesScanned) -Color DarkGray
        return
    }

    Write-Color ("Total hits: {0}   Files scanned: {1}`n" -f $script:Hits, $script:FilesScanned) -Color White

    $script:CatCounts.GetEnumerator() |
        Sort-Object Value -Descending |
        ForEach-Object {
            $name  = $_.Key.PadRight(13)
            $count = $_.Value
            Write-Color "  $name $count" -Color White
        }
}

# ============================================================================
#  Main
# ============================================================================

if (-not $Quiet) { Show-Banner }

# Enumerate candidate files once and reuse for every category.
if (-not $Quiet) { Write-Color '[i] enumerating files...' -Color Blue }
$script:CandidateFiles = @( Get-CandidateFiles -Root $ResolvedPath |
                            Where-Object { -not (Test-IsBinaryFile -LiteralPath $_.FullName) } )
$script:FilesScanned   = $script:CandidateFiles.Count

if ($script:FilesScanned -eq 0) {
    if (-not $Quiet) {
        Write-Color "[!] No matching files under '$ResolvedPath'." -Color Yellow
    }
    Show-Summary
    return
}

if (-not $Quiet) {
    Write-Color ("[i] scanning {0} file(s)...`n" -f $script:FilesScanned) -Color Blue
}

# Order by signal: highest-confidence findings stream first.
Invoke-Category -Category 'PRIVATE_KEY'  -Color Red     -Patterns @($PAT_PRIVKEY, $PAT_PUTTY)
Invoke-Category -Category 'GPP_CPASSWD'  -Color Red     -Patterns @($PAT_GPP_CPASSWORD)
Invoke-Category -Category 'UNATTEND'     -Color Red     -Patterns @($PAT_UNATTEND, $PAT_UNATTEND_INL)
Invoke-Category -Category 'CONN_STRING'  -Color Red     -Patterns @($PAT_CONN_STRING, $PAT_JDBC)
Invoke-Category -Category 'PASSWORD'     -Color Red     -Patterns @(
    $PAT_PASSWORD, $PAT_PASSWORD_DEFINE, $PAT_PASSWORD_NETRC
)
Invoke-Category -Category 'SECURESTRING' -Color Red     -Patterns @(
    $PAT_SECURESTRING, $PAT_SECURESTRING2, $PAT_SECURESTRING3, $PAT_PSCRED_PLAIN
)
Invoke-Category -Category 'URL_CREDS'    -Color Red     -Patterns @($PAT_URL_CREDS)
Invoke-Category -Category 'AWS'          -Color Red     -Patterns @($PAT_AWS_AKID, $PAT_AWS_SECRET)
Invoke-Category -Category 'TOKEN'        -Color Magenta -Patterns @($PAT_TOKEN)
Invoke-Category -Category 'JWT'          -Color Magenta -Patterns @($PAT_JWT)
Invoke-Category -Category 'API_KEY'      -Color Yellow  -Patterns @($PAT_API_KEY)
Invoke-Category -Category 'AUTH_HEADER'  -Color Yellow  -Patterns @($PAT_AUTH)
Invoke-Category -Category 'AZURE'        -Color Yellow  -Patterns @($PAT_AZURE)
Invoke-Category -Category 'GCP'          -Color Yellow  -Patterns @($PAT_GCP)
Invoke-Category -Category 'NETRC'        -Color Yellow  -Patterns @($PAT_NETRC_BLOCK)
Invoke-Category -Category 'SECRET'       -Color Yellow  -Patterns @($PAT_SECRET, $PAT_MACHINEKEY)
Invoke-Category -Category 'WINSCP'       -Color Yellow  -Patterns @($PAT_WINSCP)
Invoke-Category -Category 'RDP'          -Color Yellow  -Patterns @($PAT_RDP_PASSWORD)
Invoke-Category -Category 'WLAN_KEY'     -Color Yellow  -Patterns @($PAT_WLAN_KEY)
Invoke-Category -Category 'NET_USE'      -Color Yellow  -Patterns @($PAT_NET_USE, $PAT_RUNAS_SAVECRED)
Invoke-Category -Category 'PS_CLIXML'    -Color Yellow  -Patterns @($PAT_CLIXML_PSCRED)
Invoke-Category -Category 'PS_ENCODED'   -Color Yellow  -Patterns @($PAT_ENCODED_PS)
Invoke-Category -Category 'HASH'         -Color Blue    -Patterns @($PAT_HASH)

Show-Summary
