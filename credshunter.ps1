<#
.SYNOPSIS
    credshunter — Windows credential discovery for authorized post-exploitation.

.DESCRIPTION
    Hunts hard-coded passwords, private keys, NTLM hashes, database creds,
    cloud secrets, GPP cpassword, registry AutoLogon, RDP/PuTTY/WinSCP
    sessions, IIS web.config, unattend files, browser credential stores and
    other reusable authentication material on Windows hosts.

    Read-only. Never modifies the system. Never transmits data.
    Built for authorized internal pentests, red team engagements, CTFs, and
    privilege escalation labs.

.PARAMETER Path
    One or more directories to scan recursively. File-content scanning is
    limited to these paths. Common OS checks run regardless.

.PARAMETER All
    Scan every readable text file in -Path, not just credential-related
    extensions. Binary files are still skipped.

.PARAMETER MaxFileSizeMB
    Skip files larger than this many megabytes. Applies to both the OS-level
    extraction and the stage-4 content scan. Default: 5.

.PARAMETER NoSizeLimit
    Disable the file-size cap entirely (scan files of any size). Use with
    caution — large logs and archives are slow and full of binary data.

.PARAMETER OutputFile
    Append a plaintext log of all findings to this file.

.PARAMETER SkipSystem
    Skip the OS-level credential checks (registry, GPP, unattend, …).

.PARAMETER Quiet
    Less verbose output. Findings still printed.

.PARAMETER NoColor
    Disable ANSI colors in the console output.

.EXAMPLE
    .\credshunter.ps1 -Path C:\Users,C:\inetpub -OutputFile loot.txt

.EXAMPLE
    .\credshunter.ps1 -Path C:\ -All -MaxFileSizeMB 10

.EXAMPLE
    .\credshunter.ps1 -SkipSystem -Path .\app -Quiet

.NOTES
    Requires PowerShell 5.1 or later. Some checks (SAM hive, system shadow,
    full credential vault) require an elevated session.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]] $Path = @(),

    [switch] $All,

    [ValidateRange(1, 10240)]
    [int] $MaxFileSizeMB = 5,

    [switch] $NoSizeLimit,

    [string] $OutputFile,

    [switch] $SkipSystem,

    [switch] $Quiet,

    [switch] $NoColor
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'Continue'
$script:Version        = '1.0.0'

# ----------------------------------------------------------------------------
#  Configuration
# ----------------------------------------------------------------------------
$script:MaxFileSizeBytes  = $MaxFileSizeMB * 1MB
$script:SkipLarge         = -not $NoSizeLimit.IsPresent
$script:MaxMatchesPerFile = 20
$script:MaxPreviewLen     = 140

# ----------------------------------------------------------------------------
#  Color support (ANSI escape sequences, honors NO_COLOR / -NoColor)
# ----------------------------------------------------------------------------
$script:UseColor = -not $NoColor `
    -and -not $env:NO_COLOR `
    -and ($Host.Name -ne 'Default Host') `
    -and ($Host.UI.SupportsVirtualTerminal -or $true)

if ($script:UseColor) {
    $ESC = [char]27
    $script:CR    = "$ESC[1;31m"; $script:CG = "$ESC[1;32m"
    $script:CY    = "$ESC[1;33m"; $script:CB = "$ESC[1;34m"
    $script:CM    = "$ESC[1;35m"; $script:CC = "$ESC[1;36m"
    $script:CW    = "$ESC[1;37m"; $script:CD = "$ESC[2m"
    $script:CBold = "$ESC[1m";    $script:CNC = "$ESC[0m"
} else {
    $script:CR=''; $script:CG=''; $script:CY=''; $script:CB=''
    $script:CM=''; $script:CC=''; $script:CW=''; $script:CD=''
    $script:CBold=''; $script:CNC=''
}

# ----------------------------------------------------------------------------
#  Finding storage
# ----------------------------------------------------------------------------
$script:HighFindings    = [System.Collections.Generic.List[object]]::new()
$script:LowFindings     = [System.Collections.Generic.List[object]]::new()
$script:KeyFindings     = [System.Collections.Generic.List[object]]::new()
$script:Interesting     = [System.Collections.Generic.List[object]]::new()
$script:Guaranteed      = [System.Collections.Generic.List[object]]::new()
$script:GuaranteedHashes = [System.Collections.Generic.HashSet[string]]::new()
$script:SuspiciousNamesFound = [System.Collections.Generic.List[string]]::new()
$script:LocationsChecked     = [System.Collections.Generic.List[object]]::new()
$script:SkippedFiles         = [System.Collections.Generic.List[object]]::new()
$script:FindingHashes        = [System.Collections.Generic.HashSet[string]]::new()
$script:InterestingHashes    = [System.Collections.Generic.HashSet[string]]::new()
$script:NameHashes           = [System.Collections.Generic.HashSet[string]]::new()
$script:CheckedHashes        = [System.Collections.Generic.HashSet[string]]::new()
# Per-path dedup so a file is processed at most once across stages 1 + 4
$script:ScannedPaths         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# ============================================================================
#  Pattern data
# ============================================================================

# Focused pattern set used ONLY by OS-level checks (stage 1). A precise
# subset of the generic stage-4 patterns, tuned for the formats commonly
# found in OS-known credential locations (GPP XML, unattend XML, .env,
# .bashrc, .htpasswd, shadow, netrc, wp-config, registry dumps, etc.).
# Stage 4 uses HighPatterns below — they overlap, but kept separate so OS
# checks stay independent of the recursive content-scan pipeline.
$script:OsPatterns = @(
    @{ Label = 'password';
       Regex = '(?im)(?:^|[^A-Za-z_])(password|passwd|pwd|pass|passphrase)\s*[:=]\s*[^\s#].{2,}' }
    @{ Label = 'db_password';
       Regex = '(?im)(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smb|smtp|ftp|sftp|admin|user|service)[_-]?(password|passwd|pwd|pass)\s*[:=]' }
    @{ Label = 'url_credentials';
       Regex = '(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|ftp|ftps|sftp|ssh|smb|cifs|https?|amqp|rabbitmq)://[^\s/:@]+:[^\s/@]+@' }
    @{ Label = 'connection_string';
       Regex = '(?im)(server|host|data\s*source)\s*=.*?(password|pwd)\s*=' }
    @{ Label = 'gpp_cpassword';
       Regex = '(?i)cpassword\s*=\s*"?([A-Za-z0-9+/=]{20,})"?' }
    @{ Label = 'unattend_password';
       Regex = '(?is)<(?:Administrator)?Password>\s*<Value>([^<]+)</Value>' }
    @{ Label = 'aws_access_key';
       Regex = 'AKIA[0-9A-Z]{16}' }
    @{ Label = 'github_token';
       Regex = '\bgh[pousr]_[A-Za-z0-9]{30,}\b' }
    @{ Label = 'slack_token';
       Regex = '\bxox[abprs]-[A-Za-z0-9-]{10,}\b' }
    @{ Label = 'env_credential';
       Regex = '(?m)^\s*[A-Z][A-Z0-9_]*(PASSWORD|PASS|PWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*\s*=' }
    @{ Label = 'wp_db_define';
       Regex = "define\(\s*['""](DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT)['""]" }
    @{ Label = 'htpasswd_entry';
       Regex = '(?m)^[^:\s#]+:\$(apr1|2[aby]?|5|6|y)\$' }
    @{ Label = 'shadow_hash';
       Regex = '(?m)^[^:]+:\$(1|2[aby]?|5|6|y)\$[A-Za-z0-9./$]+' }
    @{ Label = 'ntlm_dump';
       Regex = '(?m)^[^:\r\n]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' }
    @{ Label = 'sudoers_nopasswd';
       Regex = '(?i)NOPASSWD\s*[:=]' }
    @{ Label = 'netrc_pass';
       Regex = '(?im)^\s*(machine\s+\S+\s+)?(login|user|username)\s+\S+\s+password\s+' }
    @{ Label = 'jwt';
       Regex = '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b' }
)

# High-confidence content patterns. Each entry: @{ Label = ...; Regex = ... }
$script:HighPatterns = @(
    @{ Label = 'password';
       Regex = '(?im)(?:^|[^A-Za-z_])(password|passwd|pwd|pass|passphrase)\s*[:=]\s*[^\s#].{2,}' }

    @{ Label = 'db_password';
       Regex = '(?im)(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smb|smtp|ftp|sftp|admin|user|service)[_-]?(password|passwd|pwd|pass)\s*[:=]' }

    @{ Label = 'connection_string';
       Regex = '(?im)(server|host|data\s*source)\s*=.*?(password|pwd)\s*=' }

    @{ Label = 'url_credentials';
       Regex = '(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|ftp|ftps|sftp|ssh|smb|cifs|https?|amqp|rabbitmq)://[^\s/:@]+:[^\s/@]+@' }

    @{ Label = 'gpp_cpassword';
       Regex = '(?i)cpassword\s*=\s*"?([A-Za-z0-9+/=]{20,})"?' }

    @{ Label = 'aws_access_key';
       Regex = 'AKIA[0-9A-Z]{16}' }

    @{ Label = 'aws_secret';
       Regex = '(?i)aws_secret_access_key\s*[:=]\s*["'']?([A-Za-z0-9/+=]{40})' }

    @{ Label = 'github_token';
       Regex = '\bgh[pousr]_[A-Za-z0-9]{30,}\b' }

    @{ Label = 'slack_token';
       Regex = '\bxox[abprs]-[A-Za-z0-9-]{10,}\b' }

    @{ Label = 'slack_webhook';
       Regex = 'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+' }

    @{ Label = 'bearer_token';
       Regex = '(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})' }

    @{ Label = 'api_secret';
       Regex = '(?i)(api|auth|access|refresh|client|app)[_-]?(secret|token|key)\s*[:=]\s*["'']?([A-Za-z0-9._/+=~-]{16,})' }

    @{ Label = 'jwt';
       Regex = '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b' }

    # Unattend / autounattend
    @{ Label = 'unattend_password';
       Regex = '(?is)<(?:Administrator)?Password>\s*<Value>([^<]+)</Value>' }
)

# Private key markers
$script:KeyPatterns = @(
    @{ Label = 'rsa_private';        Regex = '-----BEGIN RSA PRIVATE KEY-----' }
    @{ Label = 'dsa_private';        Regex = '-----BEGIN DSA PRIVATE KEY-----' }
    @{ Label = 'ec_private';         Regex = '-----BEGIN EC PRIVATE KEY-----' }
    @{ Label = 'openssh_private';    Regex = '-----BEGIN OPENSSH PRIVATE KEY-----' }
    @{ Label = 'pkcs8_private';      Regex = '-----BEGIN PRIVATE KEY-----' }
    @{ Label = 'encrypted_private';  Regex = '-----BEGIN ENCRYPTED PRIVATE KEY-----' }
    @{ Label = 'pgp_private';        Regex = '-----BEGIN PGP PRIVATE KEY BLOCK-----' }
    @{ Label = 'putty_private';      Regex = 'PuTTY-User-Key-File-' }
)

# Hash / ticket patterns
$script:HashPatterns = @(
    @{ Label = 'ntlm_dump';      Regex = '(?m)^[^:\r\n]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' }
    @{ Label = 'ntlm_pair';      Regex = '\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b' }
    @{ Label = 'krb5_tgs';       Regex = '\$krb5tgs\$' }
    @{ Label = 'krb5_asrep';     Regex = '\$krb5asrep\$' }
    @{ Label = 'mscash';         Regex = '\$DCC2\$' }
    @{ Label = 'shadow_sha512';  Regex = '\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}' }
    @{ Label = 'bcrypt';         Regex = '\$2[aby]?\$[0-9]{2}\$[A-Za-z0-9./]{53}' }
)

# Low-confidence (only emit when no high-conf hit in file)
$script:LowPatterns = @(
    @{ Label = 'generic_token';
       Regex = '(?i)(token|secret|key)\s*[:=]\s*["'']?([A-Za-z0-9._/+=~-]{12,})' }
    @{ Label = 'generic_md5';
       Regex = '(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])' }
)

# Placeholder values (lowercased) that are almost never real credentials
$script:FalsePositives = @(
    '','password','passwd','pwd','pass','passphrase','secret','token',
    'null','none','nil','undefined','empty','void',
    'example','sample','demo','placeholder','dummy','fake',
    'test','tester','testing','testpassword','testpass','test123',
    'foo','bar','baz','qux','foobar',
    'changeme','change_me','change-me','changethis','change-this','changeit','change-it',
    'todo','fixme','tbd','n/a','na',
    'your_password','yourpassword','your-password','yourpasswordhere',
    'insert_password','replace_me','replace-me','replace_this','insert_here',
    '<password>','<pass>','<secret>','<token>','<key>','<value>','<your-password>',
    '...','....','.....','********','*****','***','xxxxxxxx','xxxxx','xxx'
)

# Default content-search extensions
$script:SearchExtensions = @(
    '.conf','.config','.cfg','.ini','.env','.envrc'
    '.yaml','.yml','.toml','.json','.xml','.properties'
    '.txt','.log','.md','.csv'
    '.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.vbe','.wsh','.wsf'
    '.aspx','.asp','.ashx','.ascx','.cshtml','.vbhtml','.master','.svc'
    '.cs','.vb','.java','.py','.pl','.rb','.php','.js','.ts','.jsx','.tsx','.mjs','.cjs'
    '.sql','.udl'
    '.sh','.bash','.zsh','.ksh'
    '.tf','.tfvars','.hcl'
    '.htm','.html','.htaccess'
    '.reg','.pol','.rdp','.ovpn'
    '.service','.unit','.timer'
)

# Extensions whose presence ALONE confirms credential material. These are
# dedicated credential / password-database / keystore formats — finding one
# means you've found credentials, full stop. Reported in their own
# "Confirmed credential containers" section ahead of the auxiliary list.
$script:GuaranteedCredExtensions = @(
    # Password manager databases
    '.kdbx','.kdb'                          # KeePass 2.x / 1.x
    '.psafe3'                               # Password Safe v3
    '.agilekeychain'                        # 1Password legacy
    '.opvault'                              # 1Password vault
    '.1pif','.1pux'                         # 1Password exports
    '.lpdb'                                 # LastPass local DB
    '.enpass','.enpassdb'                   # Enpass
    '.bitwarden_export'                     # Bitwarden export

    # Private-key / cert+key bundles — never public
    '.ppk'                                  # PuTTY private key
    '.pfx','.p12'                           # PKCS#12 (cert + private key)
    '.pvk'                                  # Microsoft private key file

    # Server keystores (alias + private key inside)
    '.jks','.keystore','.truststore'

    # Disk-encryption key files
    '.bek','.fve'                           # BitLocker recovery / FVE

    # Kerberos keytabs
    '.keytab'

    # Windows DPAPI master keys
    '.dpapimk'
)

# Auxiliary credential-related extensions. STRONG signal but not 100% — a
# .pem may be a public cert, a .gpg may be encrypted data rather than a
# private key, a .rdp may not have the password saved, etc. Reported under
# "Interesting credential-related files" — worth inspecting, not assumed.
$script:HighValueExtensions = @(
    '.pem','.key','.priv'                   # PEM-encoded data (key OR cert)
    '.asc','.gpg'                           # PGP material (sig, key, or encrypted)
    '.rdp'                                  # Saved RDP — may carry creds
    '.ovpn'                                 # OpenVPN profile
    '.wallet'                               # Oracle wallet / various
)

# Suspicious filename fragments — case-insensitive substring match against
# the basename. Kept INTENTIONALLY TIGHT: every term here must be a strong
# credential indicator on its own. Generic words ('config', 'key', 'conn',
# 'backup', 'account', 'login', 'auth') are excluded because:
#   1. They produce massive false-positive noise on real hosts (every .conf
#      file, every keyboard.txt, every login log line, etc.)
#   2. Any text file with credentials in it will already be picked up by
#      the stage-4 content scanner via its extension.
# The OS-level checks separately handle well-known credential files such as
# SAM/SYSTEM hives, GPP XML, unattend, .htpasswd, .pgpass, ~/.netrc, etc.,
# so we don't need name-based detection for those either.
$script:SuspiciousNamePatterns = @(
    # Direct, high-signal credential terms
    'password','passwords','passwd','pswd'
    'credential','credentials','creds'
    'secret','secrets'
    'vault','vaults'
    'authentication','authenticator'
    'passphrase'

    # DB / master / SSH password specifics
    'dbpass','db_pass','database_password'
    'masterkey','master_password','masterpass'
    'sshpass'

    # Credential dump tool outputs
    'pwdump','kerberoast','asreproast','hashdump'

    # KeePass / password-manager artefacts that may show up without
    # the typical .kdbx extension (renamed, base-named, etc.)
    'keepass'
)

# Directory *names* never to descend into (matched anywhere in the tree).
# Tuned to skip places that almost never contain meaningful credentials.
$script:ExcludeDirNames = @(
    # Version control internals
    '.git','.hg','.svn','.bzr','CVS','_darcs'
    # Package manager caches / language ecosystems
    'node_modules','.npm','.pnpm-store','.yarn','.yarn-cache','.bun'
    '.venv','venv','env','.pyenv','.virtualenvs','__pycache__'
    '.mypy_cache','.pytest_cache','.tox','.nox','.ruff_cache'
    'site-packages','dist-packages'
    'vendor','bower_components'
    '.terraform','.terragrunt-cache'
    '.gradle','.m2','.ivy2','.sbt'
    # Build outputs
    'target','dist','build','out','coverage','.next','.nuxt','obj'
    # IDE metadata
    '.idea','.vscode','.vs','.history'
    # Windows system noise
    'WinSxS','Installer','SoftwareDistribution','CrashDumps'
    'LiveKernelReports','servicing','AppPatch','assembly'
    'Fonts','Help','IME','Media','PolicyDefinitions'
    # OS junk
    '.Trash','.Spotlight-V100','.fseventsd'
)

# Absolute-path prefixes never to descend into (Windows-side). Compared
# case-insensitively against the file's full path.
$script:ExcludePathPrefixes = @(
    (Join-Path $env:SystemRoot 'WinSxS')
    (Join-Path $env:SystemRoot 'Installer')
    (Join-Path $env:SystemRoot 'SoftwareDistribution')
    (Join-Path $env:SystemRoot 'Logs')
    (Join-Path $env:SystemRoot 'LiveKernelReports')
    (Join-Path $env:SystemRoot 'servicing')
    (Join-Path $env:SystemRoot 'assembly')
    (Join-Path $env:SystemRoot 'Microsoft.NET\assembly')
    (Join-Path $env:SystemRoot 'Fonts')
    (Join-Path $env:SystemRoot 'Help')
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v2.0.50727')
    (Join-Path $env:SystemRoot 'PolicyDefinitions')
    (Join-Path ${env:ProgramFiles} 'WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Packages')
    "$env:SystemDrive\`$Recycle.Bin"
    "$env:SystemDrive\System Volume Information"
) | Where-Object { $_ -and $_.Trim() -ne '' }

# ============================================================================
#  Output helpers
# ============================================================================

function Write-Banner {
    if ($Quiet) { return }
    Write-Host ""
    Write-Host "$($script:CC)$($script:CBold)  ┌─────────────────────────────────────────────────────────────┐$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  │  credshunter  ·  Windows credential discovery for pentesters │$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  │  v$($script:Version)  ·  $($script:CD)authorized testing only · read-only$($script:CNC)$($script:CC)$($script:CBold)              │$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  └─────────────────────────────────────────────────────────────┘$($script:CNC)"
    Write-Host ""
}

function Write-Section { param([string]$Title)
    Write-Host ""
    Write-Host "$($script:CBold)$($script:CC)═══ $Title ═══$($script:CNC)"
}

function Write-Info { param([string]$Msg) if (-not $Quiet) { Write-Host "$($script:CB)[*]$($script:CNC) $Msg" } }
function Write-Ok   { param([string]$Msg) if (-not $Quiet) { Write-Host "$($script:CG)[+]$($script:CNC) $Msg" } }
function Write-Warn { param([string]$Msg) Write-Host "$($script:CY)[!]$($script:CNC) $Msg" }
function Write-Err  { param([string]$Msg) Write-Host "$($script:CR)[x]$($script:CNC) $Msg" }

function Write-LogLine {
    param([string]$Line)
    if (-not [string]::IsNullOrEmpty($script:LogPath)) {
        # Strip ANSI codes before writing to file
        $clean = $Line -replace "`e\[[0-9;]*m", ''
        Add-Content -Path $script:LogPath -Value $clean -Encoding UTF8
    }
}

# ============================================================================
#  Predicates / helpers
# ============================================================================

function Get-FileSizeSafe { param([string]$FullPath)
    try { return (New-Object System.IO.FileInfo $FullPath).Length } catch { return -1 }
}

# Check whether a directory should be skipped during recursive traversal.
# Honors both ExcludeDirNames (basename match) and ExcludePathPrefixes
# (absolute path prefix match, case-insensitive).
function Test-DirectoryExcluded { param([string]$DirectoryPath)
    try {
        $dname = [System.IO.Path]::GetFileName($DirectoryPath)
        if ($script:ExcludeDirNames -contains $dname) { return $true }
        $full = $DirectoryPath
        foreach ($prefix in $script:ExcludePathPrefixes) {
            if (-not $prefix) { continue }
            if ($full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    } catch {}
    return $false
}

# Binary heuristic: first 1024 bytes contain a NUL byte (or read fails / empty)
function Test-IsBinary { param([string]$FullPath)
    try {
        $fs = [System.IO.File]::OpenRead($FullPath)
        try {
            $buf = New-Object byte[] 1024
            $read = $fs.Read($buf, 0, $buf.Length)
            if ($read -le 0) { return $true }
            for ($i = 0; $i -lt $read; $i++) {
                if ($buf[$i] -eq 0) { return $true }
            }
            return $false
        } finally { $fs.Dispose() }
    } catch { return $true }
}

function Test-FalsePositive { param([string]$Value)
    if ($null -eq $Value) { return $true }
    $v = $Value.Trim()
    # Strip surrounding quotes
    $v = $v -replace '^["'']|["'']$', ''
    $v = $v.Trim()
    if ($v.Length -lt 4 -or $v.Length -gt 256) { return $true }

    $lower = $v.ToLowerInvariant()
    if ($script:FalsePositives -contains $lower) { return $true }

    # Suffix-based placeholders
    if ($lower -match '_(password|secret|token|key|pass|pwd)$') { return $true }
    if ($lower -match '^(your|insert|replace|example|sample|test)_') { return $true }

    # Variable interpolation / templates
    if ($v -match '\$\{[^}]+\}')            { return $true }
    if ($v -match '\$\([^)]+\)')            { return $true }
    if ($v -match '\{\{[^}]+\}\}')          { return $true }
    if ($v -match '<%.*?%>')                { return $true }
    if ($v -match '#\{[^}]+\}')             { return $true }
    if ($v -match '<[A-Za-z_][^>]*>')       { return $true }
    if ($v -match '%[A-Z_]+%')              { return $true }
    if ($v -match '\$\d+|\$\$')             { return $true }

    # Single repeating character
    if ($v.Length -ge 3 -and $v -match "^(.)\1+$") { return $true }

    # Only punctuation
    if ($v -match '^[^A-Za-z0-9]+$') { return $true }

    return $false
}

function Format-Preview { param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text -replace '[\r\n]+', ' '
    $t = $t -replace '\s+', ' '
    $t = $t.Trim()
    if ($t.Length -gt $script:MaxPreviewLen) {
        $t = $t.Substring(0, $script:MaxPreviewLen) + '…'
    }
    return $t
}

function Get-LineNumber { param([string]$Content, [int]$Index)
    if ($Index -lt 0) { return 1 }
    # Count newlines up to Index
    $sub = $Content.Substring(0, [Math]::Min($Index, $Content.Length))
    return ($sub.Split("`n").Length)
}

function Add-Finding {
    param(
        [ValidateSet('High','Low','Key')] [string]$Bucket,
        [string]$Label,
        [string]$Path,
        [int]   $LineNumber,
        [string]$Preview
    )
    $key = "$Bucket|$Label|$Path|$LineNumber"
    if (-not $script:FindingHashes.Add($key)) { return }
    $obj = [PSCustomObject]@{
        Label      = $Label
        Path       = $Path
        LineNumber = $LineNumber
        Preview    = $Preview
    }
    switch ($Bucket) {
        'High' { $script:HighFindings.Add($obj) }
        'Low'  { $script:LowFindings.Add($obj)  }
        'Key'  { $script:KeyFindings.Add($obj)  }
    }
}

function Add-Interesting { param([string]$Category, [string]$Path)
    $k = "$Category|$Path"
    if ($script:InterestingHashes.Add($k)) {
        $script:Interesting.Add([PSCustomObject]@{ Category = $Category; Path = $Path })
    }
}

function Add-Guaranteed { param([string]$Extension, [string]$Path)
    if ($script:GuaranteedHashes.Add($Path)) {
        $script:Guaranteed.Add([PSCustomObject]@{ Extension = $Extension; Path = $Path })
    }
}

function Add-SuspiciousName { param([string]$Path)
    if ($script:NameHashes.Add($Path)) {
        $script:SuspiciousNamesFound.Add($Path) | Out-Null
    }
}

function Add-Checked { param([string]$Label, [string]$Path)
    $k = "$Label|$Path"
    if ($script:CheckedHashes.Add($k)) {
        $script:LocationsChecked.Add([PSCustomObject]@{ Label = $Label; Path = $Path })
    }
}

function Add-Skipped { param([string]$Path, [string]$Reason)
    $script:SkippedFiles.Add([PSCustomObject]@{ Path = $Path; Reason = $Reason })
}

# ============================================================================
#  Content scanning core
# ============================================================================

# OS-level credential extraction. Applies the focused $script:OsPatterns
# set plus private-key markers to a known credential-bearing file.
#
# Used by stage-1 OS checks ONLY. Stage-4 file-content scanning calls
# Invoke-FileContentScan below — the two are intentionally separate so
# that the recursive content-scan pipeline processes only extension-matched
# candidates from the user-supplied paths.
function Invoke-OSExtract { param([string]$FullPath, [string]$Label)
    # Dedup: each path processed at most once across stages 1 + 4
    if (-not $script:ScannedPaths.Add($FullPath)) { return }

    $size = Get-FileSizeSafe -FullPath $FullPath
    if ($size -lt 0) { Add-Skipped -Path $FullPath -Reason 'unreadable'; return }
    if ($size -eq 0) { return }
    if ($script:SkipLarge -and $size -gt $script:MaxFileSizeBytes) {
        Add-Skipped -Path $FullPath -Reason ("size>{0}MB" -f $MaxFileSizeMB); return
    }
    if (Test-IsBinary -FullPath $FullPath) {
        Add-Skipped -Path $FullPath -Reason 'binary'; return
    }
    try {
        $content = [System.IO.File]::ReadAllText($FullPath)
    } catch {
        Add-Skipped -Path $FullPath -Reason 'read_error'; return
    }
    if ([string]::IsNullOrEmpty($content)) { return }

    # Private-key markers first
    foreach ($p in $script:KeyPatterns) {
        $m = [regex]::Match($content, $p.Regex)
        if ($m.Success) {
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket Key -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview $m.Value
        }
    }

    # Focused OS patterns
    $matchesFound = 0
    foreach ($p in $script:OsPatterns) {
        $rx = [regex]::new($p.Regex)
        foreach ($m in $rx.Matches($content)) {
            if ($matchesFound -ge $script:MaxMatchesPerFile) { return }
            $line  = $m.Value
            $value = $line
            $eq = $line.IndexOfAny(@(':','='))
            if ($eq -ge 0 -and $eq -lt $line.Length-1) {
                $value = $line.Substring($eq+1).Trim().Trim('"',"'",' ',';')
                $value = ($value -split '[#;]')[0]
            }
            if (Test-FalsePositive -Value $value) { continue }
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket High -Label ("{0}/{1}" -f $Label, $p.Label) -Path $FullPath -LineNumber $lineNo -Preview (Format-Preview $line)
            $matchesFound++
        }
    }
}

function Invoke-FileContentScan { param([string]$FullPath)
    # Dedup: each path processed at most once across stages 1 + 4
    if (-not $script:ScannedPaths.Add($FullPath)) { return }

    $size = Get-FileSizeSafe -FullPath $FullPath
    if ($size -lt 0) {
        Add-Skipped -Path $FullPath -Reason 'unreadable'
        return
    }
    if ($size -eq 0) { return }
    if ($script:SkipLarge -and $size -gt $script:MaxFileSizeBytes) {
        Add-Skipped -Path $FullPath -Reason ("size>{0}MB" -f $MaxFileSizeMB)
        return
    }
    if (Test-IsBinary -FullPath $FullPath) {
        Add-Skipped -Path $FullPath -Reason 'binary'
        return
    }

    try {
        $content = [System.IO.File]::ReadAllText($FullPath)
    } catch {
        Add-Skipped -Path $FullPath -Reason 'read_error'
        return
    }
    if ([string]::IsNullOrEmpty($content)) { return }

    $matchesFound = 0

    # High-confidence patterns
    foreach ($p in $script:HighPatterns) {
        $regex = [regex]::new($p.Regex)
        $mtchs = $regex.Matches($content)
        foreach ($m in $mtchs) {
            if ($matchesFound -ge $script:MaxMatchesPerFile) { return }
            $line  = $m.Value
            # Best-effort: pull right-hand value
            $value = $line
            $eq = $line.IndexOfAny(@(':','='))
            if ($eq -ge 0 -and $eq -lt $line.Length-1) {
                $value = $line.Substring($eq+1).Trim().Trim('"',"'",' ',';')
                $value = ($value -split '[#;]')[0]
            }
            if (Test-FalsePositive -Value $value) { continue }
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket High -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview (Format-Preview $line)
            $matchesFound++
        }
    }

    # Private key markers
    foreach ($p in $script:KeyPatterns) {
        $idx = $content.IndexOf($p.Regex.Substring(0, [Math]::Min(40, $p.Regex.Length)))
        # Use full regex (in case header has variations like OPENSSH)
        $m = [regex]::Match($content, $p.Regex)
        if ($m.Success) {
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket Key -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview $m.Value
        }
    }

    # Hash / ticket patterns
    foreach ($p in $script:HashPatterns) {
        $regex = [regex]::new($p.Regex)
        $mtchs = $regex.Matches($content)
        foreach ($m in $mtchs) {
            if ($matchesFound -ge $script:MaxMatchesPerFile) { return }
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket High -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview (Format-Preview $m.Value)
            $matchesFound++
        }
    }

    # Low-confidence (only if no high-conf hit)
    if ($matchesFound -eq 0) {
        foreach ($p in $script:LowPatterns) {
            $regex = [regex]::new($p.Regex)
            $mtchs = $regex.Matches($content)
            foreach ($m in $mtchs) {
                if ($matchesFound -ge $script:MaxMatchesPerFile) { return }
                $value = $m.Value
                $eq = $value.IndexOfAny(@(':','='))
                if ($eq -ge 0 -and $eq -lt $value.Length-1) {
                    $value = $value.Substring($eq+1).Trim().Trim('"',"'",' ')
                }
                if (Test-FalsePositive -Value $value) { continue }
                $lineNo = Get-LineNumber -Content $content -Index $m.Index
                Add-Finding -Bucket Low -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview (Format-Preview $m.Value)
                $matchesFound++
            }
        }
    }
}

# Quick helper for known-file checks. Records "checked" + runs the focused
# OS extraction (NOT the generic stage-4 content scanner).
function Test-KnownFile { param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Add-Checked -Label $Label -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Invoke-OSExtract -FullPath $Path -Label $Label
}

# ============================================================================
#  OS-level credential checks (Windows)
# ============================================================================

function Test-RegistryAutoLogon {
    Write-Info "Checking AutoLogon registry…"
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogon'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        Add-Checked -Label 'autologon_registry' -Path $k
        try {
            $p = Get-ItemProperty -Path $k -ErrorAction Stop
            $hasPassword = $false
            foreach ($prop in 'DefaultPassword','AltDefaultPassword','AutoAdminLogon') {
                if ($p.PSObject.Properties.Match($prop).Count -gt 0) {
                    $v = $p.$prop
                    if ($prop -eq 'AutoAdminLogon' -and ("$v" -ne '1' -and "$v" -ne 'true')) { continue }
                    if (-not [string]::IsNullOrEmpty($v) -and -not (Test-FalsePositive -Value $v)) {
                        Add-Finding -Bucket High -Label "autologon_$($prop.ToLower())" -Path $k -LineNumber 0 -Preview ("{0} = {1}" -f $prop, $v)
                        $hasPassword = $true
                    }
                }
            }
        } catch {}
    }
}

function Test-GPPCPassword {
    Write-Info "Checking Group Policy Preferences (cpassword)…"
    $roots = @(
        Join-Path $env:SystemRoot 'SYSVOL'
        Join-Path $env:ProgramData 'Microsoft\Group Policy\History'
        Join-Path $env:SystemRoot 'System32\GroupPolicy'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Add-Checked -Label 'gpp_root' -Path $root
        try {
            $xmls = Get-ChildItem -LiteralPath $root -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Drives.xml','Printers.xml' -ErrorAction SilentlyContinue
            foreach ($x in $xmls) {
                try {
                    $c = [System.IO.File]::ReadAllText($x.FullName)
                    if ($c -match 'cpassword\s*=\s*"([A-Za-z0-9+/=]{16,})"') {
                        Add-Finding -Bucket High -Label 'gpp_cpassword' -Path $x.FullName -LineNumber 0 -Preview "cpassword=$($Matches[1])"
                    }
                } catch {}
            }
        } catch {}
    }
}

function Test-UnattendedInstall {
    Write-Info "Checking unattended install files…"
    $files = @(
        Join-Path $env:SystemRoot 'Panther\Unattend.xml'
        Join-Path $env:SystemRoot 'Panther\Unattended.xml'
        Join-Path $env:SystemRoot 'Panther\Unattend\Unattend.xml'
        Join-Path $env:SystemRoot 'Panther\Unattend\Unattended.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\unattend.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\sysprep.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\Panther\unattend.xml'
        Join-Path $env:SystemDrive '\unattend.xml'
        Join-Path $env:SystemDrive '\autounattend.xml'
        Join-Path $env:SystemDrive '\sysprep.inf'
        Join-Path $env:SystemDrive '\sysprep\sysprep.xml'
        Join-Path $env:SystemRoot 'debug\NetSetup.log'
    )
    foreach ($f in $files) { Test-KnownFile -Path $f -Label 'unattend' }
}

function Test-PowerShellHistory {
    Write-Info "Checking PowerShell history…"
    $hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    Test-KnownFile -Path $hist -Label 'powershell_history'
    # All users
    try {
        $userDirs = Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue
        foreach ($u in $userDirs) {
            $p = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (Test-Path -LiteralPath $p) { Test-KnownFile -Path $p -Label 'powershell_history' }
        }
    } catch {}
    # cmd.exe doskey buffer doesn't persist; skip.
}

function Test-CmdkeyVault {
    Write-Info "Checking Windows credential vault references…"
    try {
        $out = & cmdkey.exe /list 2>$null
        if ($out) {
            $joined = ($out -join "`n")
            Add-Checked -Label 'cmdkey_list' -Path 'cmdkey /list'
            # Each block typically: "Target: ..."  "Type: ..."  "User: ..."
            $blocks = ($joined -split '(?m)^\s*Target:' )
            foreach ($b in $blocks) {
                if ($b -match 'User:\s*(.+)' -or $b -match 'Target:\s*(.+)') {
                    $tgt = ($b -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | '
                    if ($tgt) {
                        Add-Finding -Bucket High -Label 'saved_credential' -Path 'cmdkey:list' -LineNumber 0 -Preview (Format-Preview $tgt)
                    }
                }
            }
        }
    } catch {}

    # Vault credential files (encrypted, just flag)
    $vaultPaths = @(
        Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Credentials'
        Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Credentials'
        Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Vault'
        Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Vault'
    )
    foreach ($p in $vaultPaths) {
        if (Test-Path -LiteralPath $p) {
            Add-Checked -Label 'vault_dir' -Path $p
            try {
                Get-ChildItem -LiteralPath $p -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Add-Interesting -Category 'windows_vault_file' -Path $_.FullName
                }
            } catch {}
        }
    }
}

function Test-RDPSavedSessions {
    Write-Info "Checking saved RDP sessions and .rdp files…"
    $keys = @(
        'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
        'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Add-Checked -Label 'rdp_registry' -Path $k
            try {
                Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p.UsernameHint) {
                        Add-Finding -Bucket Low -Label 'rdp_userhint' -Path $_.PSPath -LineNumber 0 -Preview ("UsernameHint = {0}" -f $p.UsernameHint)
                    }
                }
            } catch {}
        }
    }
    # .rdp files in common locations
    foreach ($d in @($env:USERPROFILE, $env:PUBLIC, "$env:SystemDrive\Users")) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        try {
            Get-ChildItem -LiteralPath $d -Recurse -Force -Include '*.rdp' -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object {
                    Add-Interesting -Category 'saved_rdp_file' -Path $_.FullName
                    Invoke-OSExtract -FullPath $_.FullName -Label 'rdp_file'
                }
        } catch {}
    }
}

function Test-PuTTYSessions {
    Write-Info "Checking PuTTY saved sessions…"
    $root = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (Test-Path $root) {
        Add-Checked -Label 'putty_sessions' -Path $root
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                $entries = @()
                foreach ($prop in 'HostName','UserName','PortForwardings','ProxyHost','ProxyUsername','ProxyPassword','PublicKeyFile') {
                    if ($p.$prop) { $entries += "$prop=$($p.$prop)" }
                }
                if ($entries) {
                    Add-Finding -Bucket Low -Label 'putty_session' -Path $_.PSPath -LineNumber 0 -Preview (Format-Preview ($entries -join ' | '))
                }
                if ($p.ProxyPassword -and -not (Test-FalsePositive -Value $p.ProxyPassword)) {
                    Add-Finding -Bucket High -Label 'putty_proxy_password' -Path $_.PSPath -LineNumber 0 -Preview "ProxyPassword=$($p.ProxyPassword)"
                }
            }
        } catch {}
    }
}

function Test-WinSCPSessions {
    Write-Info "Checking WinSCP saved sessions…"
    $root = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
    if (Test-Path $root) {
        Add-Checked -Label 'winscp_sessions' -Path $root
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                $entries = @()
                foreach ($prop in 'HostName','UserName','Password','PortNumber','PublicKeyFile') {
                    if ($p.$prop) { $entries += "$prop=$($p.$prop)" }
                }
                if ($p.Password) {
                    Add-Finding -Bucket High -Label 'winscp_password' -Path $_.PSPath -LineNumber 0 -Preview ("WinSCP saved password ({0})" -f ($entries -join ' | '))
                } elseif ($entries) {
                    Add-Finding -Bucket Low -Label 'winscp_session' -Path $_.PSPath -LineNumber 0 -Preview (Format-Preview ($entries -join ' | '))
                }
            }
        } catch {}
    }
    # WinSCP.ini files
    foreach ($d in @($env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE)) {
        if (-not $d) { continue }
        try {
            Get-ChildItem -LiteralPath $d -Recurse -Force -Filter 'WinSCP.ini' -ErrorAction SilentlyContinue |
                Select-Object -First 5 |
                ForEach-Object {
                    Add-Interesting -Category 'winscp_ini' -Path $_.FullName
                    Invoke-OSExtract -FullPath $_.FullName -Label 'winscp_ini'
                }
        } catch {}
    }
}

function Test-FileZilla {
    Write-Info "Checking FileZilla configuration…"
    $files = @(
        Join-Path $env:APPDATA 'FileZilla\sitemanager.xml'
        Join-Path $env:APPDATA 'FileZilla\recentservers.xml'
        Join-Path $env:APPDATA 'FileZilla\filezilla.xml'
        Join-Path $env:APPDATA 'FileZilla Server\FileZilla Server.xml'
    )
    foreach ($f in $files) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'filezilla_config' -Path $f
            Test-KnownFile -Path $f -Label 'filezilla'
        }
    }
}

function Test-VNCRegistry {
    Write-Info "Checking VNC registry keys…"
    $keys = @(
        'HKLM:\SOFTWARE\TightVNC\Server'
        'HKLM:\SOFTWARE\WOW6432Node\TightVNC\Server'
        'HKLM:\SOFTWARE\RealVNC\WinVNC4'
        'HKLM:\SOFTWARE\WOW6432Node\RealVNC\WinVNC4'
        'HKCU:\Software\TightVNC\Server'
        'HKCU:\Software\ORL\WinVNC3'
        'HKCU:\Software\RealVNC\WinVNC4'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Add-Checked -Label 'vnc_registry' -Path $k
            try {
                $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
                foreach ($prop in 'Password','PasswordViewOnly','ControlPassword','MSLogonRequired') {
                    if ($p.$prop) {
                        $val = if ($p.$prop -is [byte[]]) { [BitConverter]::ToString($p.$prop) } else { "$($p.$prop)" }
                        Add-Finding -Bucket High -Label 'vnc_password' -Path $k -LineNumber 0 -Preview ("{0} = {1}" -f $prop, $val)
                    }
                }
            } catch {}
        }
    }
}

function Test-SNMPRegistry {
    Write-Info "Checking SNMP community strings…"
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if (Test-Path $key) {
        Add-Checked -Label 'snmp_communities' -Path $key
        try {
            $p = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
            foreach ($name in $p.GetValueNames()) {
                if ($name) {
                    Add-Finding -Bucket High -Label 'snmp_community' -Path $key -LineNumber 0 -Preview ("community = {0}" -f $name)
                }
            }
        } catch {}
    }
}

function Test-SAMHives {
    Write-Info "Checking SAM/SYSTEM/SECURITY hive files…"
    $hives = @(
        (Join-Path $env:SystemRoot 'System32\config\SAM')
        (Join-Path $env:SystemRoot 'System32\config\SYSTEM')
        (Join-Path $env:SystemRoot 'System32\config\SECURITY')
        (Join-Path $env:SystemRoot 'repair\SAM')
        (Join-Path $env:SystemRoot 'repair\SYSTEM')
        (Join-Path $env:SystemRoot 'repair\SECURITY')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SAM')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SYSTEM')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SECURITY')
    )
    foreach ($h in $hives) {
        if (Test-Path -LiteralPath $h) {
            Add-Checked -Label 'sam_hive' -Path $h
            try {
                # Test readability
                $fs = [System.IO.File]::OpenRead($h)
                $fs.Close()
                Add-Interesting -Category 'readable_hive' -Path $h
                Add-Finding -Bucket Key -Label 'readable_sam_hive' -Path $h -LineNumber 0 -Preview "Hive readable — extract with secretsdump.py / impacket-secretsdump"
            } catch {
                # locked, expected on running system
            }
        }
    }
}

function Test-IISConfigs {
    Write-Info "Checking IIS web.config and applicationHost.config…"
    $files = @(
        Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
        Join-Path $env:SystemRoot 'System32\inetsrv\config\administration.config'
    )
    foreach ($f in $files) { Test-KnownFile -Path $f -Label 'iis_config' }
    # Recursively scan inetpub for web.config files
    $inetpub = Join-Path $env:SystemDrive '\inetpub'
    if (Test-Path -LiteralPath $inetpub) {
        try {
            Get-ChildItem -LiteralPath $inetpub -Recurse -Force -Filter 'web.config' -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object { Test-KnownFile -Path $_.FullName -Label 'iis_webconfig' }
        } catch {}
    }
    # appcmd (live config dump) if elevated
    try {
        $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
        if (Test-Path -LiteralPath $appcmd) {
            $out = & $appcmd list apppool /text:* 2>$null
            if ($out) {
                $blob = ($out -join "`n")
                if ($blob -match '(?i)password\s*[:=]\s*"?([^"\s]+)"?') {
                    if (-not (Test-FalsePositive -Value $Matches[1])) {
                        Add-Finding -Bucket High -Label 'iis_apppool_password' -Path 'appcmd:apppool' -LineNumber 0 -Preview (Format-Preview $blob.Substring([Math]::Max(0,$blob.IndexOf('password',0,[StringComparison]::OrdinalIgnoreCase)-20), 200))
                    }
                }
            }
        }
    } catch {}
}

function Test-ScheduledTasks {
    Write-Info "Checking scheduled task XML definitions…"
    $tasks = Join-Path $env:SystemRoot 'System32\Tasks'
    if (-not (Test-Path -LiteralPath $tasks)) { return }
    try {
        Get-ChildItem -LiteralPath $tasks -Recurse -Force -File -ErrorAction SilentlyContinue |
            Select-Object -First 500 |
            ForEach-Object {
                try {
                    $c = [System.IO.File]::ReadAllText($_.FullName)
                    if ($c -match '(?i)<RunLevel>HighestAvailable</RunLevel>' -or
                        $c -match '(?i)<UserId>([^<]+)</UserId>' -or
                        $c -match '(?i)<LogonType>Password</LogonType>') {
                        Invoke-OSExtract -FullPath $_.FullName -Label 'scheduled_task'
                    }
                } catch {}
            }
    } catch {}
}

function Test-ServiceCredentials {
    Write-Info "Checking service accounts running as non-system users…"
    try {
        $svcs = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $svcs) {
            if ($s.StartName -and
                $s.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService)|NT SERVICE\\)') {
                Add-Finding -Bucket Low -Label 'service_runas' -Path ('service:' + $s.Name) -LineNumber 0 -Preview ("{0} runs as {1} (path: {2})" -f $s.Name, $s.StartName, $s.PathName)
            }
        }
    } catch {}
}

function Test-WiFiProfiles {
    Write-Info "Checking saved Wi-Fi profile keys (requires admin for clear text)…"
    try {
        $profilesOut = & netsh.exe wlan show profiles 2>$null
        if ($profilesOut) {
            $names = @()
            foreach ($l in $profilesOut) {
                if ($l -match 'All User Profile\s*:\s*(.+)$' -or $l -match 'Profile\s+\(.*\)\s*:\s*(.+)$') {
                    $names += $Matches[1].Trim()
                }
            }
            foreach ($n in $names) {
                Add-Checked -Label 'wifi_profile' -Path $n
                try {
                    $detail = & netsh.exe wlan show profile name="$n" key=clear 2>$null
                    $blob = ($detail -join "`n")
                    if ($blob -match '(?i)Key Content\s*:\s*(.+)') {
                        $key = $Matches[1].Trim()
                        if (-not (Test-FalsePositive -Value $key)) {
                            Add-Finding -Bucket High -Label 'wifi_key' -Path ('wifi:' + $n) -LineNumber 0 -Preview ("SSID `"{0}`": {1}" -f $n, $key)
                        }
                    }
                } catch {}
            }
        }
    } catch {}
}

function Test-McAfeeSiteList {
    Write-Info "Checking McAfee SiteList (legacy ePO)…"
    $candidates = @(
        Join-Path ${env:ProgramFiles} 'McAfee\Common Framework\SiteList.xml'
        Join-Path ${env:ProgramFiles(x86)} 'McAfee\Common Framework\SiteList.xml'
        Join-Path $env:ALLUSERSPROFILE 'McAfee\Common Framework\SiteList.xml'
        Join-Path $env:ALLUSERSPROFILE 'McAfee\Common Framework\SiteMgr.xml'
    )
    foreach ($f in $candidates) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'mcafee_sitelist' -Path $f
            Test-KnownFile -Path $f -Label 'mcafee_sitelist'
        }
    }
}

function Test-BrowserCredentialFiles {
    Write-Info "Checking browser credential databases…"
    $users = Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $candidates = @(
            "$($u.FullName)\AppData\Local\Google\Chrome\User Data\Default\Login Data"
            "$($u.FullName)\AppData\Local\Google\Chrome\User Data\Default\Cookies"
            "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
            "$($u.FullName)\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
            "$($u.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
            "$($u.FullName)\AppData\Roaming\Opera Software\Opera Stable\Login Data"
            "$($u.FullName)\AppData\Local\Google\Chrome\User Data\Local State"
            "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data\Local State"
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) {
                Add-Interesting -Category 'browser_credentials' -Path $c
            }
        }
    }
}

function Test-CloudCliCredentials {
    Write-Info "Checking cloud CLI credential stores…"
    $users = Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $candidates = @(
            "$($u.FullName)\.aws\credentials"
            "$($u.FullName)\.aws\config"
            "$($u.FullName)\.azure\accessTokens.json"
            "$($u.FullName)\.azure\azureProfile.json"
            "$($u.FullName)\AppData\Roaming\gcloud\credentials.db"
            "$($u.FullName)\AppData\Roaming\gcloud\access_tokens.db"
            "$($u.FullName)\.kube\config"
            "$($u.FullName)\.docker\config.json"
            "$($u.FullName)\.netrc"
            "$($u.FullName)\_netrc"
            "$($u.FullName)\.git-credentials"
            "$($u.FullName)\.npmrc"
            "$($u.FullName)\.pypirc"
            "$($u.FullName)\.s3cfg"
            "$($u.FullName)\AppData\Roaming\rclone\rclone.conf"
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) {
                Add-Interesting -Category 'cloud_credential_file' -Path $c
                Test-KnownFile -Path $c -Label 'cloud_cli'
            }
        }
    }
}

function Test-SSHKeysWindows {
    Write-Info "Checking SSH keys in user profiles…"
    $users = Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $ssh = Join-Path $u.FullName '.ssh'
        if (-not (Test-Path -LiteralPath $ssh)) { continue }
        Add-Checked -Label 'ssh_dir' -Path $ssh
        try {
            Get-ChildItem -LiteralPath $ssh -Force -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $name = $_.Name
                    if ($name -match '^id_[a-z0-9]+$' -or $name -match '\.(pem|key|priv)$' -or $name -eq 'identity') {
                        Invoke-OSExtract -FullPath $_.FullName -Label 'ssh_key'
                    } elseif ($name -in 'config','authorized_keys','known_hosts') {
                        Invoke-OSExtract -FullPath $_.FullName -Label 'ssh_config'
                    }
                }
        } catch {}
    }
}

function Test-MiscWindowsLocations {
    Write-Info "Checking misc Windows locations (OpenVPN, SQL, etc.)…"
    $extras = @(
        Join-Path ${env:ProgramFiles} 'OpenVPN\config'
        Join-Path ${env:ProgramFiles(x86)} 'OpenVPN\config'
        Join-Path $env:ProgramData 'OpenVPN\config'
        Join-Path ${env:ProgramFiles} 'WireGuard\Data'
        Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\Config\machine.config'
        Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config'
    )
    foreach ($p in $extras) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if ((Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).PSIsContainer) {
            try {
                Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Select-Object -First 100 |
                    ForEach-Object { Test-KnownFile -Path $_.FullName -Label 'misc_credstore' }
            } catch {}
        } else {
            Test-KnownFile -Path $p -Label 'misc_credstore'
        }
    }
}

function Invoke-SystemChecks {
    Write-Section "Stage 1 — OS-level credential locations"
    Test-RegistryAutoLogon
    Test-GPPCPassword
    Test-UnattendedInstall
    Test-PowerShellHistory
    Test-CmdkeyVault
    Test-RDPSavedSessions
    Test-PuTTYSessions
    Test-WinSCPSessions
    Test-FileZilla
    Test-VNCRegistry
    Test-SNMPRegistry
    Test-SAMHives
    Test-IISConfigs
    Test-ScheduledTasks
    Test-ServiceCredentials
    Test-WiFiProfiles
    Test-McAfeeSiteList
    Test-BrowserCredentialFiles
    Test-CloudCliCredentials
    Test-SSHKeysWindows
    Test-MiscWindowsLocations
    Write-Ok "System checks complete."
}

# ============================================================================
#  Recursive scanning of user-supplied paths
# ============================================================================

function Get-CandidateFiles {
    param([string[]]$Paths, [bool]$AllMode)

    $result = [System.Collections.Generic.List[string]]::new()
    $stack  = [System.Collections.Generic.Stack[string]]::new()

    foreach ($root in $Paths) {
        try {
            $abs = [System.IO.Path]::GetFullPath($root)
        } catch { Write-Warn "Invalid path: $root"; continue }
        if (-not (Test-Path -LiteralPath $abs)) { Write-Warn "Path does not exist: $abs"; continue }
        if (-not (Get-Item -LiteralPath $abs -ErrorAction SilentlyContinue).PSIsContainer) {
            $result.Add($abs); continue
        }
        $stack.Push($abs)
    }

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        # Files in current dir
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                try {
                    $ext  = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                    $name = [System.IO.Path]::GetFileName($f).ToLowerInvariant()
                    $include = $false
                    if ($AllMode) {
                        $include = $true
                    } elseif ($script:SearchExtensions -contains $ext) {
                        $include = $true
                    } elseif ($name -in 'dockerfile','vagrantfile','makefile','authorized_keys','known_hosts','config','identity','sitemanager.xml','recentservers.xml','winscp.ini') {
                        $include = $true
                    } elseif ($name -like 'id_*' -and $name -notlike '*.pub') {
                        $include = $true
                    } elseif ($name -like '*rc' -and $ext -eq '') {
                        $include = $true
                    }
                    if (-not $include) { continue }
                    # Size cap at enumeration time (cheaper than discarding later)
                    if ($script:SkipLarge) {
                        try {
                            $fi = New-Object System.IO.FileInfo $f
                            if ($fi.Length -gt $script:MaxFileSizeBytes) { continue }
                        } catch { continue }
                    }
                    $result.Add($f)
                } catch {}
            }
        } catch {}
        # Subdirectories
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }

    return $result
}

# Stage 2a — confirmed credential containers (extension alone is proof).
function Find-GuaranteedCredentials {
    param([string[]]$Paths)
    Write-Section "Stage 2 — Confirmed credential containers"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) {
        if (Test-Path -LiteralPath $r) { $stack.Push($r) }
    }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($script:GuaranteedCredExtensions -contains $ext) {
                    Add-Guaranteed -Extension $ext.TrimStart('.') -Path $f
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
    if ($count -gt 0) {
        Write-Ok "Found $($script:CR)$($script:CBold)$count$($script:CNC) $($script:CR)confirmed credential container(s)$($script:CNC)."
    } else {
        Write-Ok "Found $($script:CW)0$($script:CNC) confirmed credential container(s)."
    }
}

# Stage 2b — auxiliary credential-related files (high value but ambiguous).
function Find-HighValueFiles {
    param([string[]]$Paths)
    Write-Section "Stage 3 — Auxiliary credential-related files"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) {
        if (Test-Path -LiteralPath $r) { $stack.Push($r) }
    }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($script:HighValueExtensions -contains $ext) {
                    Add-Interesting -Category 'credential_related' -Path $f
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
    Write-Ok "Found $($script:CW)$count$($script:CNC) auxiliary credential-related file(s)."
}

function Find-SuspiciousNames {
    param([string[]]$Paths)
    Write-Section "Stage 4 — Suspicious filenames"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) {
        if (Test-Path -LiteralPath $r) { $stack.Push($r) }
    }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($e in [System.IO.Directory]::EnumerateFileSystemEntries($current)) {
                $name = [System.IO.Path]::GetFileName($e).ToLowerInvariant()
                foreach ($pat in $script:SuspiciousNamePatterns) {
                    if ($name.Contains($pat)) {
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
    Write-Ok "Found $($script:CW)$($script:SuspiciousNamesFound.Count)$($script:CNC) suspiciously-named file(s)."
}

function Invoke-UserPathScan {
    param([string[]]$Paths)
    Write-Section "Stage 5 — File-content scan"
    if (-not $Paths -or $Paths.Count -eq 0) {
        Write-Warn "No paths provided; skipping content scan."
        return
    }
    Write-Info "Enumerating candidate files…"
    $files = Get-CandidateFiles -Paths $Paths -AllMode $All.IsPresent
    $total = $files.Count
    if ($total -eq 0) {
        Write-Warn "No candidate files found in the supplied paths."
        return
    }
    $mode = if ($All) { 'all' } else { 'extensions' }
    Write-Ok "Candidate files: $($script:CW)$total$($script:CNC)  (mode: $mode)"

    $i = 0
    foreach ($f in $files) {
        $i++
        if (($i % 20) -eq 0 -or $i -eq $total) {
            Write-Progress -Activity "Scanning files for credentials" `
                           -Status ("{0} / {1}" -f $i, $total) `
                           -CurrentOperation $f `
                           -PercentComplete ([Math]::Min(100, ($i * 100 / $total)))
        }
        Invoke-FileContentScan -FullPath $f
    }
    Write-Progress -Activity "Scanning files for credentials" -Completed
    Write-Ok "Scanned $($script:CW)$total$($script:CNC) files."
}

# ============================================================================
#  Output / summary
# ============================================================================

function Write-FindingsSection {
    param([string]$Title, [System.Collections.Generic.List[object]]$List, [string]$Tag, [string]$Color)
    if ($List.Count -eq 0) { return }
    Write-Host ""
    Write-Host "$($script:CBold)$($script:CW)▸ $Title$($script:CNC)"
    Write-LogLine ""
    Write-LogLine "=== $Title ==="
    foreach ($f in $List | Sort-Object Label, Path, LineNumber) {
        Write-Host ("  $Color[$Tag]$($script:CNC) $($script:CD)$($f.Label)$($script:CNC)  $($script:CY)$($f.Path):$($f.LineNumber)$($script:CNC)")
        Write-Host ("       $($script:CD)$($f.Preview)$($script:CNC)")
        Write-LogLine ("[$Tag] $($f.Label) $($f.Path):$($f.LineNumber)  $($f.Preview)")
    }
}

function Write-FullSummary {
    Write-Section "Findings"

    # CRITICAL: confirmed credential containers (extension == proof)
    if ($script:Guaranteed.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)▸ Confirmed credential containers  ⚠$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Confirmed credential containers ==="
        foreach ($g in $script:Guaranteed | Sort-Object Extension, Path) {
            Write-Host ("  $($script:CBold)$($script:CR)[CRITICAL]$($script:CNC) $($script:CD)$($g.Extension.PadRight(8))$($script:CNC)  $($script:CW)$($g.Path)$($script:CNC)")
            Write-LogLine ("[CRITICAL] $($g.Extension)  $($g.Path)")
        }
    }

    Write-FindingsSection -Title "High-confidence credentials" -List $script:HighFindings -Tag "HIGH" -Color $script:CR
    Write-FindingsSection -Title "Private keys & authentication material" -List $script:KeyFindings -Tag "KEY" -Color $script:CM

    if ($script:Interesting.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)▸ Interesting credential-related files$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Interesting credential-related files ==="
        foreach ($i in $script:Interesting | Sort-Object Category, Path) {
            Write-Host ("  $($script:CC)[INTEREST]$($script:CNC) $($script:CD)$($i.Category)$($script:CNC)  $($i.Path)")
            Write-LogLine ("[INTEREST] $($i.Category)  $($i.Path)")
        }
    }

    if ($script:SuspiciousNamesFound.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)▸ Suspicious filenames$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Suspicious filenames ==="
        foreach ($n in $script:SuspiciousNamesFound | Sort-Object -Unique) {
            Write-Host ("  $($script:CY)[NAME]$($script:CNC) $n")
            Write-LogLine ("[NAME] $n")
        }
    }

    Write-FindingsSection -Title "Low-confidence (manual review)" -List $script:LowFindings -Tag "LOW" -Color $script:CD

    if ($script:LocationsChecked.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)▸ OS locations checked$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== OS locations checked ==="
        foreach ($c in $script:LocationsChecked | Sort-Object Label, Path) {
            Write-Host ("  $($script:CB)[CHECK]$($script:CNC) $($script:CD)$($c.Label)$($script:CNC)  $($c.Path)")
            Write-LogLine ("[CHECK] $($c.Label)  $($c.Path)")
        }
    }

    if ($script:SkippedFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)▸ Skipped files$($script:CNC)"
        Write-Host ("  $($script:CD)[SKIP]$($script:CNC) {0} file(s) skipped (binary / size / unreadable). See log." -f $script:SkippedFiles.Count)
        Write-LogLine ""
        Write-LogLine "=== Skipped files ==="
        foreach ($s in $script:SkippedFiles) {
            Write-LogLine ("[SKIP] $($s.Reason)  $($s.Path)")
        }
    }

    # Summary table
    Write-Section "Summary"
    $nGuar  = $script:Guaranteed.Count
    $nHigh  = $script:HighFindings.Count
    $nKey   = $script:KeyFindings.Count
    $nInt   = $script:Interesting.Count
    $nName  = $script:SuspiciousNamesFound.Count
    $nLow   = $script:LowFindings.Count
    $nCheck = $script:LocationsChecked.Count
    $nSkip  = $script:SkippedFiles.Count
    $fmt = "  {0,-44} {1,5}"
    Write-Host ("$($script:CBold)" + ($fmt -f 'Category','Count') + "$($script:CNC)")
    Write-Host ('  ' + ('─' * 44) + '  ' + ('─' * 5))
    Write-Host ("$($script:CBold)$($script:CR)" + ($fmt -f 'Confirmed credential containers ⚠',    $nGuar)  + "$($script:CNC)")
    Write-Host ("$($script:CR)" + ($fmt -f 'High-confidence credentials',           $nHigh)  + "$($script:CNC)")
    Write-Host ("$($script:CM)" + ($fmt -f 'Private keys / auth material',          $nKey)   + "$($script:CNC)")
    Write-Host ("$($script:CC)" + ($fmt -f 'Auxiliary credential-related files',    $nInt)   + "$($script:CNC)")
    Write-Host ("$($script:CY)" + ($fmt -f 'Suspicious filenames',                  $nName)  + "$($script:CNC)")
    Write-Host ("$($script:CD)" + ($fmt -f 'Low-confidence (review)',               $nLow)   + "$($script:CNC)")
    Write-Host ("$($script:CB)" + ($fmt -f 'OS locations checked',                  $nCheck) + "$($script:CNC)")
    Write-Host ("$($script:CD)" + ($fmt -f 'Files skipped (size/binary/perm)',      $nSkip)  + "$($script:CNC)")
    Write-Host ('  ' + ('─' * 44) + '  ' + ('─' * 5))

    Write-LogLine ""
    Write-LogLine "Summary:"
    Write-LogLine "  Confirmed credential containers: $nGuar"
    Write-LogLine "  High-confidence credentials:     $nHigh"
    Write-LogLine "  Private keys / material:         $nKey"
    Write-LogLine "  Auxiliary credential-related:    $nInt"
    Write-LogLine "  Suspicious filenames:            $nName"
    Write-LogLine "  Low-confidence:                  $nLow"
    Write-LogLine "  OS locations checked:            $nCheck"
    Write-LogLine "  Files skipped:                   $nSkip"

    if ($script:LogPath) {
        Write-Host ""
        Write-Host "$($script:CB)[*]$($script:CNC) Full log written to $($script:CW)$($script:LogPath)$($script:CNC)"
    }
}

# ============================================================================
#  Entry point
# ============================================================================

function Invoke-Main {
    $script:LogPath = $null
    if ($OutputFile) {
        try {
            New-Item -ItemType File -Path $OutputFile -Force | Out-Null
            $script:LogPath = (Resolve-Path -LiteralPath $OutputFile).Path
        } catch {
            Write-Err "Cannot write to $OutputFile : $_"
            exit 2
        }
    }

    Write-Banner

    if ($script:SkipLarge) {
        Write-Info ("Size cap: skipping files larger than $($script:CW){0} MB$($script:CNC)  (use -MaxFileSizeMB N to change, -NoSizeLimit to disable)" -f $MaxFileSizeMB)
    } else {
        Write-Warn "Size cap disabled (-NoSizeLimit) — every readable file will be inspected."
    }

    if (-not $SkipSystem) {
        Invoke-SystemChecks
    } else {
        Write-Warn "Skipping OS-level checks (per -SkipSystem)."
    }

    if ($Path.Count -eq 0) {
        Write-Warn "No -Path supplied. Skipping recursive scanning."
        Write-Warn "Tip: pass -Path C:\ to recursively scan everywhere."
    } else {
        Find-GuaranteedCredentials -Paths $Path
        Find-HighValueFiles -Paths $Path
        Find-SuspiciousNames -Paths $Path
        Invoke-UserPathScan -Paths $Path
    }

    Write-FullSummary

    if ($script:Guaranteed.Count -gt 0 -or
        $script:HighFindings.Count -gt 0 -or
        $script:KeyFindings.Count -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

# Ctrl+C / pipeline stop should exit immediately. PowerShell raises
# PipelineStoppedException when the user hits Ctrl+C; we catch it, clear
# any in-flight progress bar, print a brief notice, and return 130.
try {
    Invoke-Main
} catch [System.Management.Automation.PipelineStoppedException] {
    try { Write-Progress -Activity '*' -Completed } catch {}
    Write-Host ""
    Write-Warn "Interrupted by user. Exiting."
    exit 130
} catch {
    try { Write-Progress -Activity '*' -Completed } catch {}
    if ($_.Exception.GetType().FullName -match 'Stopped|Cancel|Interrupt') {
        Write-Host ""
        Write-Warn "Interrupted by user. Exiting."
        exit 130
    }
    Write-Err ("Fatal: " + $_.Exception.Message)
    exit 2
}
