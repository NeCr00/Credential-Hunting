<#
.SYNOPSIS
  credhunter.ps1 - internal-pentest credential hunter (Windows)
.DESCRIPTION
  Hardcoded-credential hunter for authorized internal pentesting.
  Spec: docs/specs/2026-05-24-credhunter-design.md
  Authorized use only.

  Secrets are emitted plaintext in console output, findings.txt, and
  findings.jsonl (match_redacted equals match_text). The -ShowSecrets
  switch is accepted for backward compatibility but is a no-op. Clean
  up the output directory after the engagement.
.PARAMETER Output
  console | file | both (default: both). 'console' suppresses all file
  output (findings.txt / findings.jsonl); 'file' suppresses console
  rendering; 'both' writes everywhere.
.PARAMETER ShowSecrets
  Deprecated. Always-on. Findings are unredacted by design.
#>
[CmdletBinding(PositionalBinding=$false)]
param(
    [Alias('o')]
    [ValidateSet('console','file','both')]
    [string]$Output = 'both',

    [string]$OutDir = '',

    [switch]$All,
    [switch]$IncludeArchives,
    [switch]$IncludeOffice,
    [switch]$IncludeCompressed,
    [switch]$IncludeTemp,
    [switch]$ScanSqlite,

    [string]$MaxSize = '10M',

    [ValidateSet('HIGH','MEDIUM','LOW')]
    [string]$MinConfidence = 'LOW',

    [switch]$ShowSecrets,
    [switch]$CollectLoot,
    [switch]$Serial,
    [int]$Workers = 0,
    [switch]$FollowSymlinks,
    [switch]$CrossMounts,

    [string[]]$Exclude = @(),
    [string[]]$IncludeExt = @(),

    [switch]$SkipKnownLocations,
    [switch]$SkipContentScan,

    [Alias('q')]
    [switch]$Quiet,

    [switch]$NoColor,

    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$ScanRoots = @()
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:VERSION = '1.0.0'
$script:TS = (Get-Date).ToString('yyyyMMdd-HHmmss')
try { $script:HOSTN = [System.Net.Dns]::GetHostName() } catch { $script:HOSTN = $env:COMPUTERNAME }
if (-not $script:HOSTN) { $script:HOSTN = 'unknown' }

$script:IsWindowsHost = $true
if ($PSVersionTable.PSEdition -eq 'Core') {
    try { $script:IsWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows) } catch { $script:IsWindowsHost = $false }
}

$script:DefaultRoots = @(
    'C:\Users','C:\inetpub','C:\Windows\Panther',
    'C:\Windows\System32\config\RegBack','C:\Windows\Sysprep',
    'C:\Windows\debug','C:\ProgramData','C:\Temp',
    'C:\Backup','C:\Install'
)

if (-not $ScanRoots -or $ScanRoots.Count -eq 0) {
    $ScanRoots = @($script:DefaultRoots | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue })
} else {
    $normalized = New-Object System.Collections.Generic.List[string]
    foreach ($r in $ScanRoots) {
        if ([string]::IsNullOrWhiteSpace($r)) { continue }
        $cand = $r
        if (-not $script:IsWindowsHost) { $cand = $r -replace '\\','/' }
        if (Test-Path -LiteralPath $cand -ErrorAction SilentlyContinue) {
            try { $normalized.Add((Resolve-Path -LiteralPath $cand -ErrorAction Stop).ProviderPath) }
            catch { $normalized.Add($cand) }
        } elseif (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue) {
            try { $normalized.Add((Resolve-Path -LiteralPath $r -ErrorAction Stop).ProviderPath) }
            catch { $normalized.Add($r) }
        }
    }
    $ScanRoots = @($normalized)
}

if (-not $OutDir) { $OutDir = ".{0}credhunter-loot-{1}-{2}" -f [IO.Path]::DirectorySeparatorChar, $script:HOSTN, $script:TS }
if ($Workers -le 0) { $Workers = [Environment]::ProcessorCount }
if ($Serial) { $Workers = 1 }

try { New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop | Out-Null }
catch { [Console]::Error.WriteLine("cannot create $OutDir : $($_.Exception.Message)"); exit 2 }

$script:FindJsonl  = Join-Path $OutDir 'findings.jsonl'
$script:FindTxt    = Join-Path $OutDir 'findings.txt'
$script:SkippedLog = Join-Path $OutDir 'skipped.log'
$script:ReconJson  = Join-Path $OutDir 'recon.json'
$script:LootDir    = Join-Path $OutDir 'loot'

foreach ($p in @($script:FindJsonl, $script:FindTxt, $script:SkippedLog)) {
    Set-Content -LiteralPath $p -Value '' -NoNewline -Force
}

# Write-Progress wrappers, suppressed under -Quiet.
$script:ProgressEnabled = -not $Quiet
function Write-PhaseProgress {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Status,
        [int]$Current = 0,
        [int]$Total = 0
    )
    if (-not $script:ProgressEnabled) { return }
    $pct = -1
    if ($Total -gt 0) {
        $pct = [int](100 * $Current / $Total)
        if ($pct -lt 0) { $pct = 0 } elseif ($pct -gt 100) { $pct = 100 }
    }
    $opp = $ProgressPreference
    $ProgressPreference = 'Continue'
    Write-Progress -Id 1 -Activity ("Phase {0}" -f $Phase) -Status $Status -PercentComplete $pct
    $ProgressPreference = $opp
}
function Complete-PhaseProgress {
    param([string]$Phase = '')
    if (-not $script:ProgressEnabled) { return }
    $opp = $ProgressPreference
    $ProgressPreference = 'Continue'
    Write-Progress -Id 1 -Activity ("Phase {0}" -f $Phase) -Completed
    $ProgressPreference = $opp
}

$script:Findings = New-Object System.Collections.Generic.List[hashtable]
$script:SeenDedup = [System.Collections.Generic.HashSet[string]]::new()
$script:SeenInodes = New-Object System.Collections.Generic.HashSet[string]
$script:SkippedCounts = @{ size=0; binary=0; perm=0; excluded=0 }
$script:ScannedCount = 0
$script:DupSuppressed = 0

# Output buffers: appended once per phase to avoid mutex-per-write hot path.
$script:JsonlBuf   = New-Object System.Collections.Generic.List[string]
$script:TxtBuf     = New-Object System.Collections.Generic.List[string]
$script:SkippedBuf = New-Object System.Collections.Generic.List[string]

# Compiled-regex cache: every call site uses Get-Rx to avoid recompiling.
$script:RxCache = @{}
function Get-Rx {
    param([string]$Pattern, [System.Text.RegularExpressions.RegexOptions]$Options = 'None')
    $k = "$Pattern|$($Options.value__)"
    $rx = $script:RxCache[$k]
    if ($rx) { return $rx }
    $rx = [regex]::new($Pattern, ($Options -bor [System.Text.RegularExpressions.RegexOptions]::Compiled))
    $script:RxCache[$k] = $rx
    return $rx
}

if ($script:IsWindowsHost) {
    try {
        $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wpr = [Security.Principal.WindowsPrincipal]::new($wid)
        $script:CurrentUser = $wid.Name
        $script:CurrentSid  = $wid.User.Value
        if ($wpr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $script:Priv = 'admin'
        } else {
            $script:Priv = 'user'
        }
    } catch {
        $script:CurrentUser = $env:USERNAME
        $script:CurrentSid  = ''
        $script:Priv = 'user'
    }
} else {
    $script:CurrentUser = $env:USER
    if (-not $script:CurrentUser) { $script:CurrentUser = 'unknown' }
    $script:CurrentSid = ''
    $script:Priv = 'user'
}

$script:OsCaption = ''
if ($script:IsWindowsHost) {
    try { $script:OsCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } catch { $script:OsCaption = '' }
}
if (-not $script:OsCaption) {
    try {
        if ($PSVersionTable.OS) { $script:OsCaption = $PSVersionTable.OS } else { $script:OsCaption = [System.Environment]::OSVersion.VersionString }
    } catch { $script:OsCaption = 'unknown' }
}

$reconObj = [ordered]@{
    version    = $script:VERSION
    host       = $script:HOSTN
    user       = $script:CurrentUser
    sid        = $script:CurrentSid
    priv       = $script:Priv
    os         = $script:OsCaption
    ts         = $script:TS
    scan_roots = @($ScanRoots)
    workers    = $Workers
    max_size   = $MaxSize
}
$reconObj | ConvertTo-Json -Compress -Depth 4 | Set-Content -LiteralPath $script:ReconJson -Force

$script:UseColor = (-not $NoColor) -and (-not $Quiet)
function Write-Phase {
    param([string]$Tag, [string]$Msg)
    if ($Quiet) { return }
    if ($script:UseColor) {
        Write-Host ("[ {0} ] " -f $Tag) -ForegroundColor DarkGray -NoNewline
        Write-Host $Msg
    } else {
        Write-Host ("[ {0} ] {1}" -f $Tag, $Msg)
    }
}
function Write-Info { param([string]$Msg) if (-not $Quiet) { Write-Host $Msg } }
function Write-Warn { param([string]$Msg) [Console]::Error.WriteLine("[ warn ] $Msg") }

if (-not $Quiet) {
    Write-Host ""
    if ($script:UseColor) {
        Write-Host "credhunter v$($script:VERSION)" -ForegroundColor White -NoNewline
        Write-Host " - internal pentest credential hunter"
    } else {
        Write-Host "credhunter v$($script:VERSION) - internal pentest credential hunter"
    }
    Write-Host "-----------------------------------------------------"
    Write-Phase 'recon' ("host={0} user={1} priv={2} os={3}" -f $script:HOSTN, $script:CurrentUser, $script:Priv, $script:OsCaption)
    Write-Phase 'recon' ("scan roots: {0}" -f ($ScanRoots -join ' '))
    Write-Phase 'recon' ("workers={0} max-size={1} output={2}" -f $Workers, $MaxSize, $OutDir)
    Write-Host ""
}

function Convert-SizeToBytes {
    param([string]$Spec)
    if (-not $Spec) { return 10485760 }
    $n = 0
    if ($Spec -match '^([0-9]+)([KMGkmg])?$') {
        $n = [int64]$Matches[1]
        switch -regex ($Matches[2]) {
            '^[Kk]$' { return $n * 1024 }
            '^[Mm]$' { return $n * 1024 * 1024 }
            '^[Gg]$' { return $n * 1024 * 1024 * 1024 }
            default  { return $n }
        }
    }
    return 10485760
}
$script:MaxBytes = Convert-SizeToBytes $MaxSize

$script:WinDir = if ($env:WINDIR) { $env:WINDIR } else { 'C:\Windows' }
$script:ProgData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }

$script:ExcludePrefixes = @(
    "$($script:WinDir)\WinSxS",
    "$($script:WinDir)\Installer",
    "$($script:WinDir)\Servicing",
    "$($script:WinDir)\assembly",
    "$($script:WinDir)\SchCache",
    "$($script:WinDir)\Fonts",
    "$($script:WinDir)\IME",
    "$($script:WinDir)\Globalization",
    "$($script:WinDir)\Help",
    "$($script:WinDir)\Resources",
    "$($script:WinDir)\schemas",
    "$($script:WinDir)\PolicyDefinitions",
    "$($script:WinDir)\diagnostics",
    "$($script:WinDir)\WinStore",
    "$($script:WinDir)\SystemApps",
    "$($script:WinDir)\ShellExperiences",
    "$($script:WinDir)\ShellComponents",
    "$($script:WinDir)\Boot",
    "$($script:WinDir)\PrintDialog",
    "$($script:WinDir)\InfusedApps",
    "$($script:WinDir)\SoftwareDistribution\Download",
    "$($script:WinDir)\System32\DriverStore\FileRepository",
    "$($script:WinDir)\System32\spool\drivers",
    "$($script:WinDir)\System32\catroot",
    "$($script:WinDir)\System32\catroot2",
    "$($script:WinDir)\System32\winevt\Logs",
    "$($script:WinDir)\System32\WDI",
    "$($script:WinDir)\System32\Migration",
    "$($script:WinDir)\System32\Tasks\Microsoft",
    "$($script:WinDir)\System32\config\TxR",
    "$($script:WinDir)\System32\config\Journal",
    "$($script:WinDir)\Microsoft.NET\assembly",
    "$($script:WinDir)\Logs\CBS",
    "$($script:WinDir)\Logs\DISM",
    "$($script:WinDir)\Logs\WindowsUpdate",
    "$($script:WinDir)\Logs\waasmedic",
    'C:\$Recycle.Bin',
    'C:\System Volume Information',
    'C:\Recovery',
    'C:\$WINDOWS.~BT',
    'C:\$WINDOWS.~WS',
    'C:\Boot',
    "$($script:ProgData)\Microsoft\Windows Defender",
    "$($script:ProgData)\Microsoft\Search\Data",
    "$($script:ProgData)\Microsoft\Diagnosis",
    "$($script:ProgData)\Microsoft\Crypto",
    "$($script:ProgData)\Microsoft\Windows\WER",
    "$($script:ProgData)\Microsoft\NetFramework\BreadcrumbStore",
    "$($script:ProgData)\Package Cache"
)

$script:ExcludeGlobs = @(
    '*\AppData\Local\Microsoft\Windows\WebCache\*',
    '*\AppData\Local\Microsoft\Windows\INetCache\*',
    '*\AppData\Local\Microsoft\Windows\INetCookies\*',
    '*\AppData\Local\Microsoft\Windows\Explorer\*',
    '*\AppData\Local\Microsoft\Windows\Notifications\*',
    '*\AppData\Local\Microsoft\Windows\FontCache\*',
    '*\AppData\Local\Microsoft\Windows\Caches\*',
    '*\AppData\Local\Microsoft\WindowsApps\*',
    '*\AppData\Local\Microsoft\Internet Explorer\Recovery\*',
    '*\AppData\Local\Microsoft\Edge\User Data\*\Cache\*',
    '*\AppData\Local\Microsoft\Edge\User Data\*\Code Cache\*',
    '*\AppData\Local\Microsoft\Edge\User Data\*\GPUCache\*',
    '*\AppData\Local\Microsoft\Edge\User Data\*\Service Worker\*',
    '*\AppData\Local\Microsoft\Edge\User Data\*\ShaderCache\*',
    '*\AppData\Local\Google\Chrome\User Data\*\Cache\*',
    '*\AppData\Local\Google\Chrome\User Data\*\Code Cache\*',
    '*\AppData\Local\Google\Chrome\User Data\*\GPUCache\*',
    '*\AppData\Local\Google\Chrome\User Data\*\Service Worker\*',
    '*\AppData\Local\Google\Chrome\User Data\*\ShaderCache\*',
    '*\AppData\Local\BraveSoftware\*\User Data\*\Cache\*',
    '*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*',
    '*\AppData\Local\Mozilla\Firefox\Profiles\*\startupCache\*',
    '*\AppData\Local\Mozilla\Firefox\Profiles\*\shader-cache\*',
    '*\AppData\Local\Mozilla\Firefox\Profiles\*\offlineCache\*',
    '*\AppData\Local\ConnectedDevicesPlatform\*',
    '*\AppData\Local\D3DSCache\*',
    '*\AppData\Local\Packages\*\AC\*',
    '*\AppData\Local\Microsoft\Office\*\WefCache\*',
    '*\AppData\Local\Microsoft\Office\*\OfficeFileCache\*',
    '*\AppData\Local\Microsoft\Office\*\UnsavedFiles\*',
    '*\AppData\Local\Adobe\ARM\*',
    '*\AppData\Local\Adobe\OOBE\*',
    '*\AppData\Local\Adobe\Color\*',
    '*\node_modules\*',
    '*\.nuget\packages\*',
    '*\packages\*\lib\*',
    '*\.vs\*',
    '*\bin\Debug\*',
    '*\bin\Release\*',
    '*\obj\Debug\*',
    '*\obj\Release\*',
    '*\Pods\*',
    '*\.gradle\caches\*',
    '*\hiberfil.sys',
    '*\pagefile.sys',
    '*\swapfile.sys',
    '*\DumpStack.log*'
)

if (-not $IncludeTemp) {
    $script:ExcludeGlobs += '*\AppData\Local\Temp\*'
    $script:ExcludeGlobs += "$($script:WinDir)\Temp\*"
}

$script:SkipExtRegex = '\.(jpg|jpeg|png|gif|bmp|tiff|tif|ico|webp|heic|heif|raw|cr2|nef|psd|ai|eps|mp3|mp4|mov|avi|mkv|wmv|flv|wav|flac|ogg|opus|webm|m4a|m4v|aac|svg|ttf|otf|woff|woff2|eot|fon|exe|dll|dylib|class|pyc|pyo|pyd|wasm|iso|img|dmg|msi|msu|cab|deb|rpm|snap|appx|appxbundle|efi|sys|mdb|accdb|dbf|frm|ibd|myd|myi|aof|rdb|epub|mobi|azw|azw3|djvu|vsd|vsdx|po|pot|mo|xliff)$'

if (-not $IncludeOffice) {
    $script:SkipExtRegex = $script:SkipExtRegex -replace '\)\$$',')$|\.(pdf|doc|xls|ppt|odt|ods|odp)$'
}
if (-not $ScanSqlite) {
    $script:SkipExtRegex = $script:SkipExtRegex -replace '\)\$$',')$|\.(db|sqlite|sqlite3|sqlite-journal)$'
}
if (-not $IncludeArchives) {
    $script:SkipExtRegex = $script:SkipExtRegex -replace '\)\$$',')$|\.(zip|gz|bz2|xz|lz|lzma|7z|rar|tar|tgz|tbz2|txz|jar|war|ear|apk|aab|ipa|nupkg)$'
}

$script:SkipNameRegex = '(^package-lock\.json$|^yarn\.lock$|^pnpm-lock\.yaml$|^Pipfile\.lock$|^poetry\.lock$|^uv\.lock$|^Cargo\.lock$|^Gemfile\.lock$|^composer\.lock$|^go\.sum$|^mix\.lock$|^flake\.lock$|^pubspec\.lock$|\.min\.js$|\.min\.css$|\.map$)'

$script:DefaultExtRegex = '\.(conf|cnf|cfg|config|ini|properties|toml|yaml|yml|json|xml|plist|env|reg|inf|sh|bash|zsh|ksh|fish|ps1|psm1|psd1|bat|cmd|vbs|vbe|wsf|wsc|py|rb|pl|pm|php|phtml|js|mjs|cjs|ts|tsx|jsx|vue|svelte|java|scala|kt|kts|groovy|go|rs|swift|m|mm|cs|vb|fs|fsx|c|cpp|cc|cxx|h|hpp|lua|r|dart|ex|exs|erl|hs|clj|cljs|htm|html|jsp|jspx|asp|aspx|cshtml|razor|ejs|pug|twig|erb|haml|mustache|hbs|ipynb|rmd|qmd|sql|ddl|dml|psql|mysql|pgsql|tf|tfvars|bicep|log|out|err|trace|bak|backup|old|orig|save|swp|swo|tmp|copy|original|dist|sample|example)$'

$script:DefaultExtNames = @(
    'dockerfile','containerfile','jenkinsfile','makefile','gnumakefile',
    '.gitlab-ci.yml','docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml'
)

function Test-Excluded {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($p in $script:ExcludePrefixes) {
        if ($Path.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($g in $script:ExcludeGlobs) {
        if ($Path -like $g) { return $true }
    }
    foreach ($g in $Exclude) {
        if ($Path -like $g) { return $true }
    }
    return $false
}

function Test-Binary {
    # Treat OneDrive placeholders / reparse points as binary so the content
    # path skips them — this is the defensive belt to Get-CandidateFiles's
    # braces. Avoids triggering a network download on Open().
    param([string]$Path)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.Exists) {
            $attrInt = [int]$fi.Attributes
            if (($attrInt -band 0x441400) -ne 0) { return $true }
            if ((-not $FollowSymlinks) -and (($attrInt -band 0x400) -ne 0)) { return $true }
        }
    } catch {}
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    } catch { return $true }
    try {
        $buf = New-Object byte[] 8192
        $n = $fs.Read($buf, 0, 8192)
        if ($n -le 0) { return $false }
        if ($n -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { return $false }
        if ($n -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { return $false }
        if ($n -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { return $false }
        for ($i = 0; $i -lt $n; $i++) {
            if ($buf[$i] -eq 0) { return $true }
        }
        return $false
    } finally {
        $fs.Dispose()
    }
}

function Read-TextFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    } catch { return $null }
    try {
        $len = $fs.Length
        if ($len -gt $script:MaxBytes) { return $null }
        $head = New-Object byte[] ([Math]::Min(4, $len))
        $null = $fs.Read($head, 0, $head.Length)
        $fs.Position = 0
        $enc = [System.Text.Encoding]::UTF8
        if ($head.Length -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) {
            $enc = [System.Text.Encoding]::UTF8
        } elseif ($head.Length -ge 2 -and $head[0] -eq 0xFF -and $head[1] -eq 0xFE) {
            $enc = [System.Text.Encoding]::Unicode
        } elseif ($head.Length -ge 2 -and $head[0] -eq 0xFE -and $head[1] -eq 0xFF) {
            $enc = [System.Text.Encoding]::BigEndianUnicode
        }
        $sr = New-Object System.IO.StreamReader($fs, $enc, $true)
        $text = $sr.ReadToEnd()
        $sr.Dispose()
        return $text
    } catch {
        return $null
    } finally {
        if ($fs) { $fs.Dispose() }
    }
}

function Get-LineStarts {
    # Build (and cache) the array of byte offsets where each line begins:
    # arr[0]=0, arr[i] = offset just after the i'th '\n'. Cached on the
    # string identity (HashCode + Length) so repeat callers for the same
    # file body skip the O(n) build. Per-match line lookup is then an
    # O(log n) binary search.
    param([string]$Content)
    if ($null -eq $script:LineStartsCache) { $script:LineStartsCache = @{} }
    if (-not $Content) { return @(0) }
    $key = "{0}:{1}" -f $Content.Length, [System.String]::Intern($Content).GetHashCode()
    $cached = $script:LineStartsCache[$key]
    if ($cached) { return $cached }
    $starts = New-Object System.Collections.Generic.List[int]
    $starts.Add(0)
    $i = 0
    while (($i = $Content.IndexOf("`n", $i)) -ge 0) {
        $starts.Add($i + 1)
        $i++
    }
    $arr = $starts.ToArray()
    $script:LineStartsCache[$key] = $arr
    return $arr
}

function Get-LineNumber {
    # O(log n) via binary search over the cached line-starts index.
    # The naive per-match newline count was the dominant cost on big
    # log files (462 KB / 15k lines → 100 ms PER call).
    param([string]$Content, [int]$Offset)
    if ($Offset -le 0 -or -not $Content) { return 1 }
    if ($Offset -gt $Content.Length) { $Offset = $Content.Length }
    $arr = Get-LineStarts $Content
    $idx = [Array]::BinarySearch($arr, [int]$Offset)
    if ($idx -lt 0) { $idx = -($idx + 1) - 1 }
    if ($idx -lt 0) { $idx = 0 }
    return $idx + 1
}

function Get-LineText {
    param([string]$Content, [int]$Offset)
    if ($Offset -lt 0 -or -not $Content -or $Offset -ge $Content.Length) { return '' }
    $start = $Offset
    while ($start -gt 0 -and $Content[$start - 1] -ne "`n" -and $Content[$start - 1] -ne "`r") { $start-- }
    $end = $Offset
    while ($end -lt $Content.Length -and $Content[$end] -ne "`n" -and $Content[$end] -ne "`r") { $end++ }
    $line = $Content.Substring($start, $end - $start)
    if ($line.Length -gt 4096) { $line = $line.Substring(0, 4096) }
    return $line
}

$script:Placeholders = @(
    'password','passw0rd','p@ssw0rd','p@ssword','pass','passwd','pwd','secret','test','testing',
    'changeme','change-me','change_me','changeit','default','defaultpassword',
    'your_password','yourpassword','yoursecret','your-secret-here',
    'example','examplepassword','sample','samplepassword','dummy','placeholder',
    'redacted','xxx','xxxx','xxxxx','xxxxxx','xxxxxxxx','***','****','********',
    '<password>','[password]','{password}','{{password}}','${password}','<%= password %>',
    '%password%','$password','$passwd',
    'null','none','nil','n/a','na','tbd','todo','fixme','???','!!!',
    'foo','bar','foobar','hello','world','helloworld',
    'insert_password','enter_password','type_password_here','secret_here','password_here',
    'my_password','mypassword','admin','administrator','root','user','guest','anonymous',
    '123456','12345678','qwerty','abc123','letmein','monkey','dragon'
)
$script:PlaceholderSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($p in $script:Placeholders) { [void]$script:PlaceholderSet.Add($p.ToLower()) }

function Test-Placeholder {
    param([string]$V)
    if ($null -eq $V) { return $false }
    $clean = $V.Trim().Trim('"',"'",[char]0x60).ToLower()
    return $script:PlaceholderSet.Contains($clean)
}

function Get-Entropy {
    param([string]$S)
    if ([string]::IsNullOrEmpty($S)) { return 0.0 }
    $tally = @{}
    foreach ($c in $S.ToCharArray()) {
        if ($tally.ContainsKey($c)) { $tally[$c]++ } else { $tally[$c] = 1 }
    }
    $H = 0.0
    $n = [double]$S.Length
    foreach ($v in $tally.Values) {
        $p = $v / $n
        $H -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($H, 2)
}

function Test-TestPath {
    param([string]$P)
    if (-not $P) { return $false }
    $norm = $P -replace '\\','/'
    if ($norm -match '(?i)/(test|tests|spec|specs|fixture|fixtures|sample|samples|example|examples|demo|demos|mock|mocks|__tests__|__mocks__|e2e|testdata|test-data|testresources)/') { return $true }
    if ($norm -match '(?i)(_test\.|\.test\.|\.spec\.|_spec\.|\.example\.|\.sample\.|\.demo\.)') { return $true }
    return $false
}

function Test-Comment {
    param([string]$Line)
    if (-not $Line) { return $false }
    $t = $Line.TrimStart()
    if ($t.StartsWith('#'))   { return $true }
    if ($t.StartsWith('//'))  { return $true }
    if ($t.StartsWith('--'))  { return $true }
    if ($t.StartsWith(';'))   { return $true }
    if ($t.StartsWith('%'))   { return $true }
    if ($t.StartsWith('<!--')){ return $true }
    if ($t.StartsWith('/*'))  { return $true }
    if ($t.StartsWith('"""')) { return $true }
    if ($t.StartsWith("'''")) { return $true }
    if ($t.StartsWith('<#'))  { return $true }
    return $false
}

function Test-EnvReference {
    param([string]$V)
    if (-not $V) { return $false }
    if ($V -match '^\s*\$\{[^}]+\}\s*$') { return $true }
    if ($V -match '^\s*\$[A-Z_][A-Z0-9_]*\s*$') { return $true }
    if ($V -match '^\s*%[A-Z_][A-Z0-9_]*%\s*$') { return $true }
    if ($V -match '(?i)\b(os\.environ|process\.env|System\.getenv|getenv|ENV\[)') { return $true }
    if ($V -match '\{\{[^}]+\}\}') { return $true }
    if ($V -match '<%[^%]+%>') { return $true }
    return $false
}

function Test-IdentifierShape {
    param([string]$V)
    if (-not $V) { return $false }
    return ($V -match '^[A-Za-z_\$][A-Za-z0-9_.\$]*$')
}

function Convert-EntropyDemotion {
    param([string]$Val, [string]$Conf)
    $H = Get-Entropy $Val
    $len = $Val.Length
    $demote = $false
    if ($len -ge 4 -and $len -le 7) {
        if ($H -lt 3.0) { $demote = $true }
    } elseif ($len -ge 8 -and $len -le 15) {
        if ($H -lt 2.0) { $demote = $true }
    } elseif ($len -ge 16 -and $len -le 31) {
        if ($H -lt 2.5) { $demote = $true }
    } elseif ($len -ge 32) {
        if ($H -lt 3.0) { $demote = $true }
    }
    if (-not $demote) { return @{ conf = $Conf; demoted = $false; entropy = $H } }
    $new = switch ($Conf) { 'HIGH' { 'MEDIUM' } 'MEDIUM' { 'LOW' } default { 'LOW' } }
    return @{ conf = $new; demoted = $true; entropy = $H }
}

function Format-Redacted {
    # Redaction intentionally disabled in this build; -ShowSecrets is a no-op
    # kept for backward-compat. All findings emit plaintext in findings.txt
    # and findings.jsonl (match_redacted is always equal to match_text).
    param([string]$S)
    if ($null -eq $S) { return '' }
    return $S
}

function Get-DedupKey {
    param([string]$RuleId, [string]$Path, [int]$LineNo, [string]$Match)
    $raw = "$RuleId|$Path|$LineNo|$Match"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
        $hash  = $sha.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    } finally { $sha.Dispose() }
}

$script:FileMetaCache = @{}
function Get-FileMetadata {
    # Cached per abs_path. Phase 5 records many findings per file; the
    # uncached version called Get-Item + Get-Acl per finding (3-4 IO ops
    # each) which dominated walltime when finding density was high.
    param([string]$Path)
    if (-not $Path) { return @{ mtime=''; size=0; mode=''; owner='' } }
    $cached = $script:FileMetaCache[$Path]
    if ($cached) { return $cached }
    $meta = @{ mtime=''; size=0; mode=''; owner='' }
    try {
        $it = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($it) {
            $meta.mtime = $it.LastWriteTimeUtc.ToString('o')
            if ($it -is [System.IO.FileInfo]) { $meta.size = $it.Length }
            $meta.mode = $it.Mode
            # ACL owner lookup is the most expensive piece — skip on
            # macOS/Linux where Get-Acl errors anyway, and skip altogether
            # when we don't have a Windows file path (e.g. registry pseudo
            # paths like "HKLM:\...::ValueName").
            if ($script:IsWindowsHost -and $Path -notmatch '::') {
                try {
                    $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
                    if ($acl) { $meta.owner = $acl.Owner }
                } catch {}
            }
        }
    } catch {}
    $script:FileMetaCache[$Path] = $meta
    return $meta
}

function Add-Finding {
    param([hashtable]$F)
    if (-not $F.rule_id)         { return }
    if (-not $F.confidence)      { $F.confidence = 'MEDIUM' }
    if (-not $F.base_confidence) { $F.base_confidence = $F.confidence }
    if (-not $F.category)        { $F.category = 'PASSWORD' }
    if (-not $F.demotions)       { $F.demotions = @() }
    if ($null -eq $F.line_no)    { $F.line_no = 0 }
    if (-not $F.match_text)      { $F.match_text = '' }
    if (-not $F.line_text)       { $F.line_text = '' }
    if ($null -eq $F.entropy)    { $F.entropy = 0 }

    $minRank = @{ 'LOW'=0; 'MEDIUM'=1; 'HIGH'=2 }
    if ($minRank[$F.confidence] -lt $minRank[$MinConfidence]) { return }

    # Cross-phase dedup: compute key early; suppress duplicates so the
    # in-memory buffer never contains two records with the same dedup_key.
    $dedup = Get-DedupKey -RuleId $F.rule_id -Path $F.abs_path -LineNo $F.line_no -Match $F.match_text
    if ($script:SeenDedup.Contains($dedup)) { $script:DupSuppressed++; return }
    [void]$script:SeenDedup.Add($dedup)

    $F.dedup_key      = $dedup
    $F.host           = $script:HOSTN
    $F.scan_user      = $script:CurrentUser
    $F.scan_user_priv = $script:Priv
    # Secrets are emitted plaintext; match_redacted retained as alias of
    # match_text for schema compatibility with the spec finding record.
    $F.match_redacted = $F.match_text

    $meta = Get-FileMetadata $F.abs_path
    $F.file_mtime = $meta.mtime
    $F.file_size  = $meta.size
    $F.file_mode  = $meta.mode
    $F.file_owner = $meta.owner

    $script:Findings.Add($F)
}

function Convert-JsonString {
    # Hand-rolled JSON string escape (RFC 8259 minimum set). PowerShell's
    # ConvertTo-Json invokes a reflective serializer (~50 ms/call) so the
    # per-finding path uses this instead and assembles JSON object text
    # by hand. Returns a quoted JSON string literal.
    param([AllowNull()][string]$S)
    if ([string]::IsNullOrEmpty($S)) { return '""' }
    $sb = New-Object System.Text.StringBuilder ($S.Length + 2)
    [void]$sb.Append('"')
    foreach ($c in $S.ToCharArray()) {
        $i = [int]$c
        switch ($i) {
            0x22 { [void]$sb.Append('\"') ; continue }
            0x5C { [void]$sb.Append('\\') ; continue }
            0x08 { [void]$sb.Append('\b') ; continue }
            0x09 { [void]$sb.Append('\t') ; continue }
            0x0A { [void]$sb.Append('\n') ; continue }
            0x0C { [void]$sb.Append('\f') ; continue }
            0x0D { [void]$sb.Append('\r') ; continue }
            default {
                if ($i -lt 0x20) {
                    [void]$sb.AppendFormat('\u{0:x4}', $i)
                } else {
                    [void]$sb.Append($c)
                }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

$script:JsonStringFields = @(
    'rule_id','category','confidence','base_confidence',
    'host','scan_user','scan_user_priv','abs_path','rel_path',
    'line_text','pre_context','post_context','match_text','match_redacted',
    'key_name','file_mtime','file_mode','file_owner','dedup_key',
    'decoder_applied','fp_reason','notes'
)
$script:JsonNumberFields = @('line_no','col_start','col_end','file_size','entropy')

function ConvertTo-FindingJson {
    # Hand-rolled JSON object writer for the finding record schema. Faster
    # than ConvertTo-Json by ~2 orders of magnitude in PS5/PS7. Field order
    # mirrors the spec (§4.6); demotions is JSON-array, scalar fields are
    # strings or numbers, nulls emit explicit null literals.
    param([hashtable]$F)
    $sb = New-Object System.Text.StringBuilder 512
    [void]$sb.Append('{')
    $first = $true
    foreach ($k in $script:JsonStringFields) {
        $v = $F[$k]
        if (-not $first) { [void]$sb.Append(',') }
        [void]$sb.Append('"').Append($k).Append('":')
        if ($null -eq $v) {
            [void]$sb.Append('null')
        } else {
            [void]$sb.Append((Convert-JsonString ([string]$v)))
        }
        $first = $false
    }
    if (-not $first) { [void]$sb.Append(',') }
    [void]$sb.Append('"demotions":[')
    $dem = $F['demotions']
    if ($dem -and $dem.Count -gt 0) {
        $sep = ''
        foreach ($d in $dem) {
            [void]$sb.Append($sep).Append((Convert-JsonString ([string]$d)))
            $sep = ','
        }
    }
    [void]$sb.Append(']')
    foreach ($k in $script:JsonNumberFields) {
        $v = $F[$k]
        [void]$sb.Append(',"').Append($k).Append('":')
        if ($null -eq $v) {
            [void]$sb.Append('null')
        } elseif ($v -is [double] -or $v -is [single] -or $v -is [decimal]) {
            [void]$sb.Append(([string]$v))
        } else {
            try { [void]$sb.Append(([string][int64]$v)) }
            catch { [void]$sb.Append('0') }
        }
    }
    [void]$sb.Append('}')
    return $sb.ToString()
}

function Save-Finding {
    # Buffer: real file writes happen once per phase via Flush-Buffers below.
    # Mutex/handle churn was the dominant cost at scale.
    param([hashtable]$F)
    if ($Output -eq 'console') { return }
    $script:JsonlBuf.Add((ConvertTo-FindingJson $F))

    $loc = ''
    if ($F.line_no -and $F.line_no -gt 0) { $loc = ":$($F.line_no)" }
    $script:TxtBuf.Add(("[{0}] {1,-26} {2}{3}" -f $F.confidence, $F.rule_id, $F.abs_path, $loc))
    if ($F.match_text) {
        $script:TxtBuf.Add("       $($F.match_text)")
    }
    if ($F.fp_reason) {
        $script:TxtBuf.Add("       fp_reason=$($F.fp_reason)")
    }
    if ($F.key_name) {
        $script:TxtBuf.Add("       key=$($F.key_name)")
    }
}

function Flush-Buffers {
    # Single append per file at phase end. UTF-8 without BOM; matches
    # what Add-Content -Encoding utf8 used to write.
    if ($script:JsonlBuf.Count -gt 0) {
        try { [System.IO.File]::AppendAllLines($script:FindJsonl, $script:JsonlBuf) } catch {}
        $script:JsonlBuf.Clear()
    }
    if ($script:TxtBuf.Count -gt 0) {
        try { [System.IO.File]::AppendAllLines($script:FindTxt, $script:TxtBuf) } catch {}
        $script:TxtBuf.Clear()
    }
    if ($script:SkippedBuf.Count -gt 0) {
        try { [System.IO.File]::AppendAllLines($script:SkippedLog, $script:SkippedBuf) } catch {}
        $script:SkippedBuf.Clear()
    }
}

function Add-Skipped {
    param([string]$Path, [string]$Reason)
    $script:SkippedBuf.Add("$Path`t$Reason")
    if ($script:SkippedCounts.ContainsKey($Reason)) { $script:SkippedCounts[$Reason]++ }
}

$script:GppKey = [byte[]](
    0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
    0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
    0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
)

function Invoke-GppDecrypt {
    param([string]$B64)
    if ([string]::IsNullOrWhiteSpace($B64)) { return $null }
    try {
        $pad = (4 - ($B64.Length % 4)) % 4
        $padded = $B64 + ('=' * $pad)
        $ct = [Convert]::FromBase64String($padded)
        if ($ct.Length -eq 0) { return $null }
        # Real GPP ciphertexts are AES-256-CBC block-aligned (multiple of 16);
        # the base64 trailing padding is stripped on disk so the decoded
        # bytes may land a few short of an AES block. Zero-pad up to the
        # next block; the printable-ascii guard at the end will reject
        # mojibake that comes from non-GPP input padded this way.
        if ($ct.Length % 16 -ne 0) {
            $pad2 = 16 - ($ct.Length % 16)
            $tmp = New-Object byte[] ($ct.Length + $pad2)
            [Array]::Copy($ct, $tmp, $ct.Length)
            $ct = $tmp
        }
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
            $aes.KeySize = 256
            $aes.Key     = $script:GppKey
            $aes.IV      = New-Object byte[] 16
            $dec = $aes.CreateDecryptor()
            try {
                $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)
            } finally { $dec.Dispose() }
            # Decode UTF-16LE first, then trim trailing non-printable
            # characters. The GPP encrypt path PKCS7-pads the AES blob,
            # which after UTF-16LE decode lands as either trailing NUL
            # characters or a single non-ASCII codepoint (e.g. \x02\x02
            # decodes to U+0202). Trim those off rather than decoded
            # ASCII characters mid-string.
            $text = [System.Text.Encoding]::Unicode.GetString($pt)
            $end = $text.Length
            while ($end -gt 0) {
                $code = [int]$text[$end - 1]
                if ($code -ge 0x20 -and $code -le 0x7E) { break }
                $end--
            }
            if ($end -le 0) { return $null }
            $text = $text.Substring(0, $end)
            # Reject mojibake: GPP plaintexts are ASCII printable passwords.
            foreach ($ch in $text.ToCharArray()) {
                $code = [int]$ch
                if ($code -lt 0x20 -or $code -gt 0x7E) { return $null }
            }
            return $text
        } finally { $aes.Dispose() }
    } catch { return $null }
}

function Convert-DockerAuth {
    param([string]$B64)
    if ([string]::IsNullOrWhiteSpace($B64)) { return $null }
    try {
        $pad = (4 - ($B64.Length % 4)) % 4
        $padded = $B64 + ('=' * $pad)
        $bytes = [Convert]::FromBase64String($padded)
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($text -match '^([^:]+):(.+)$') {
            return @{ user = $Matches[1]; password = $Matches[2] }
        }
    } catch {}
    return $null
}

function Convert-CiscoType7 {
    param([string]$Hex)
    if (-not $Hex -or $Hex.Length -lt 4) { return $null }
    try {
        $key = 'dsfd;kfoA,.iyewrkldJKDHSUB'
        $seedStr = $Hex.Substring(0, 2)
        $seed = [int]::Parse($seedStr)
        $body = $Hex.Substring(2)
        $out = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $body.Length; $i += 2) {
            if ($i + 1 -ge $body.Length) { break }
            $hexByte = $body.Substring($i, 2)
            $val = [Convert]::ToInt32($hexByte, 16)
            # PowerShell `/` returns Double; force integer division.
            $idx = ($seed + [int]($i / 2)) % $key.Length
            $k = $key[$idx]
            $c = [char]($val -bxor [int]$k)
            [void]$out.Append($c)
        }
        return $out.ToString()
    } catch { return $null }
}

function Convert-PercentDecode {
    param([string]$S)
    if (-not $S) { return $S }
    try { return [System.Uri]::UnescapeDataString($S) } catch { return $S }
}

function Convert-HtmlDecode {
    param([string]$S)
    if (-not $S) { return $S }
    try { return [System.Net.WebUtility]::HtmlDecode($S) } catch { return $S }
}

function Get-MatchContext {
    param([System.Text.RegularExpressions.Match]$M, [string]$Content)
    $offset = $M.Index
    return @{
        line_no   = Get-LineNumber -Content $Content -Offset $offset
        line_text = Get-LineText -Content $Content -Offset $offset
        col_start = $offset
        col_end   = $offset + $M.Length
    }
}

function Scan-PrivateKey {
    param([string]$Path, [string]$Content)
    $rx = Get-Rx '-----BEGIN (?<t>(RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP |SSH2 ENCRYPTED )?)PRIVATE KEY[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----' 'Multiline'
    foreach ($m in $rx.Matches($Content)) {
        $enc = 'no'
        if ($Content -match '(?m)^(Proc-Type: 4,ENCRYPTED|DEK-Info:)') { $enc = 'yes' }
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'pem.private_key'
            category   = 'PRIVATE_KEY'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = "-----BEGIN $($m.Groups['t'].Value)PRIVATE KEY-----"
            match_text = "-----BEGIN $($m.Groups['t'].Value)PRIVATE KEY-----"
            key_name   = "encrypted=$enc"
        }
    }
}

function Scan-Ppk {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '(?m)^PuTTY-User-Key-File-[23]:\s*(?<algo>\S+)').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'putty.ppk'
            category   = 'PRIVATE_KEY'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = "PuTTY PPK $($m.Groups['algo'].Value)"
        }
    }
}

function Scan-Wireguard {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '(?m)^\s*PrivateKey\s*=\s*(?<k>[A-Za-z0-9+/]{43}=)').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'wireguard.privkey'
            category   = 'PRIVATE_KEY'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Groups['k'].Value
            key_name   = 'PrivateKey'
        }
    }
}

function Scan-GppCpassword {
    param([string]$Path, [string]$Content)
    $patterns = @(
        '\bcpassword\s*=\s*"(?<b>[A-Za-z0-9+/]{8,}={0,2})"',
        "\bcpassword\s*=\s*'(?<b>[A-Za-z0-9+/]{8,}={0,2})'"
    )
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($pat in $patterns) {
        foreach ($m in (Get-Rx $pat).Matches($Content)) {
            $b64 = $m.Groups['b'].Value
            if (-not $seen.Add($b64)) { continue }
            $ctx = Get-MatchContext -M $m -Content $Content
            Add-Finding @{
                rule_id    = 'gpp.cpassword'
                category   = 'PASSWORD'
                confidence = 'HIGH'
                base_confidence = 'HIGH'
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = $b64
                key_name   = 'cpassword'
                decoder_applied = 'gpp'
            }
            $plain = Invoke-GppDecrypt $b64
            if ($plain) {
                Add-Finding @{
                    rule_id    = 'gpp.cpassword.plaintext'
                    category   = 'PASSWORD'
                    confidence = 'HIGH'
                    base_confidence = 'HIGH'
                    abs_path   = $Path
                    line_no    = $ctx.line_no
                    line_text  = $ctx.line_text
                    match_text = $plain
                    key_name   = 'cpassword(decrypted)'
                    decoder_applied = 'gpp.aes256'
                }
            }
        }
    }
}

function Scan-ShadowHash {
    param([string]$Path, [string]$Content)
    $pat = '(?m)^(?<u>[A-Za-z_][A-Za-z0-9_.-]{0,31}):(?<h>\$(1|2[abxy]?|5|6|7|y|argon2(i|d|id))\$[A-Za-z0-9./$,=+\-]{10,}):'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $hash = $m.Groups['h'].Value
        $user = $m.Groups['u'].Value
        $algo = 'unknown'
        if ($hash -like '$1$*')  { $algo = 'md5crypt' }
        elseif ($hash -like '$5$*') { $algo = 'sha256crypt' }
        elseif ($hash -like '$6$*') { $algo = 'sha512crypt' }
        elseif ($hash -like '$y$*') { $algo = 'yescrypt' }
        elseif ($hash -like '$7$*') { $algo = 'scrypt' }
        elseif ($hash -like '$2*')  { $algo = 'bcrypt' }
        elseif ($hash -like '$argon2*') { $algo = 'argon2' }
        Add-Finding @{
            rule_id    = 'shadow.hash'
            category   = "HASH:$algo"
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $hash
            key_name   = "user=$user algo=$algo"
        }
    }
}

function Scan-Htpasswd {
    param([string]$Path, [string]$Content)
    $pat = '(?m)^(?<u>[A-Za-z0-9._-]+):(?<h>(\$(apr1|2[axyb]?|5|6)\$\S+|\{SHA\}[A-Za-z0-9+/=]{27,28}|[A-Za-z0-9./]{13}))\s*$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'htpasswd.line'
            category   = 'HASH:htpasswd'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Groups['h'].Value
            key_name   = "user=$($m.Groups['u'].Value)"
        }
    }
}

function Scan-NetNTLMv2 {
    param([string]$Path, [string]$Content)
    $pat = '(?m)^(?<line>[^:\s]{1,64}::[^:\s]{1,64}:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32,})$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'netntlmv2'
            category   = 'HASH:netntlmv2'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Groups['line'].Value
            key_name   = 'hashcat -m 5600'
        }
    }
}

function Scan-PwdumpNtlm {
    param([string]$Path, [string]$Content)
    $pat = '(?m)^(?<u>[^:\s]{1,256}):(?<rid>\d+):(?<lm>[A-Fa-f0-9]{32}):(?<nt>[A-Fa-f0-9]{32}):::'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'pwdump.ntlm'
            category   = 'HASH:ntlm'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = "user=$($m.Groups['u'].Value) rid=$($m.Groups['rid'].Value) hashcat -m 1000"
        }
    }
}

function Scan-Krb5Asrep {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '\$krb5asrep\$(?<et>17|18|23)\$[^:\s]{1,256}:[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'krb5.asrep'
            category   = 'HASH:krb5asrep'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = "etype=$($m.Groups['et'].Value) hashcat -m 18200"
        }
    }
}

function Scan-Krb5Tgs {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '\$krb5tgs\$(?<et>17|18|23)\$\*[^*\s]{1,256}\*\$[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'krb5.tgs'
            category   = 'HASH:krb5tgs'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = "etype=$($m.Groups['et'].Value) hashcat -m 13100"
        }
    }
}

function Scan-UriBasicCreds {
    param([string]$Path, [string]$Content)
    $pat = '\b(?<scheme>mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis(s)?|amqps?|ldaps?|ftps?|sftp|ssh|mssql|jdbc:[a-z0-9]+|https?)://(?<user>[^/\s:@"''<>]{1,128}):(?<pw>[^/\s@"''<>]{1,256})@(?<host>[^\s"''<>]{1,256})'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $decUser = Convert-PercentDecode $m.Groups['user'].Value
        $decPw   = Convert-PercentDecode $m.Groups['pw'].Value
        if (Test-Placeholder $decPw) { continue }
        Add-Finding @{
            rule_id    = 'uri.basic_creds'
            category   = 'URI_CREDS'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = "scheme=$($m.Groups['scheme'].Value) user=$decUser"
        }
    }
}

function Scan-Netrc {
    param([string]$Path, [string]$Content)
    $pat = '(?im)^\s*machine\s+(?<m>\S+)\s+login\s+(?<l>\S+)\s+password\s+(?<p>\S{1,256})'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'netrc.cred'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Groups['p'].Value
            key_name   = "machine=$($m.Groups['m'].Value) login=$($m.Groups['l'].Value)"
        }
    }
}

function Scan-Pgpass {
    param([string]$Path, [string]$Content)
    $pat = '(?m)^(?<host>[*A-Za-z0-9.\-]+):(?<port>\*|\d{1,5}):(?<db>\*|[^:\r\n]+):(?<user>[^:\r\n]+):(?<pw>(\\:|[^:\r\n])+)$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $pw = $m.Groups['pw'].Value
        if (Test-Placeholder $pw) { continue }
        Add-Finding @{
            rule_id    = 'pgpass.cred'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $pw
            key_name   = "host=$($m.Groups['host'].Value) user=$($m.Groups['user'].Value)"
        }
    }
}

function Scan-MyCnf {
    param([string]$Path, [string]$Content)
    $pat = '(?ims)^\s*\[(?<sec>client|mysql|mysqldump)\][\s\S]{0,2048}?^\s*password\s*=\s*(?<q>["'']?)(?<v>.{4,256}?)\k<q>\s*$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $pw = $m.Groups['v'].Value
        if (Test-Placeholder $pw) { continue }
        Add-Finding @{
            rule_id    = 'mycnf.password'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $pw
            key_name   = "section=$($m.Groups['sec'].Value)"
        }
    }
}

function Scan-TomcatUser {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '(?i)<user\b[^>]*\bpassword\s*=\s*"(?<v>[^"]{1,256})"').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $pw = Convert-HtmlDecode $m.Groups['v'].Value
        if (Test-Placeholder $pw) { continue }
        Add-Finding @{
            rule_id    = 'tomcat.user'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $pw
            key_name   = 'tomcat-users.xml'
        }
    }
}

function Scan-CiscoSecret {
    param([string]$Path, [string]$Content)
    $pat = '(?im)^\s*(?<en>enable\s+)?(?<typ>secret|password)\s+(?<lev>0|5|7|8|9)\s+(?<v>\S{4,256})\s*$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $val = $m.Groups['v'].Value
        $level = $m.Groups['lev'].Value
        if (Test-Placeholder $val) { continue }
        $decoded = ''
        if ($level -eq '7') {
            $d = Convert-CiscoType7 $val
            if ($d) { $decoded = $d }
        }
        Add-Finding @{
            rule_id    = 'cisco.secret'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $val
            key_name   = "type=$($m.Groups['typ'].Value) level=$level"
        }
        if ($decoded) {
            Add-Finding @{
                rule_id    = 'cisco.type7.plaintext'
                category   = 'PASSWORD'
                confidence = 'HIGH'
                base_confidence = 'HIGH'
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = $decoded
                key_name   = 'cisco-type-7-decoded'
                decoder_applied = 'cisco.type7.xor'
            }
        }
    }
}

function Scan-DotnetConnstr {
    param([string]$Path, [string]$Content)
    $pat = '(?i)(Server|Data Source)\s*=\s*[^;]+;[^"\r\n]*?(User\s*ID|UID)\s*=\s*[^;]+;[^"\r\n]*?(Password|Pwd)\s*=\s*(?<pw>[^;"\r\n]{1,256})'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $pw = $m.Groups['pw'].Value
        if (Test-Placeholder $pw) { continue }
        Add-Finding @{
            rule_id    = 'dotnet.connstr'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $pw
            key_name   = 'connectionString'
        }
    }
}

function Scan-JdbcPassword {
    param([string]$Path, [string]$Content)
    $pat = '(?i)\bjdbc:[a-z0-9]+://[^?\s"'']+\?[^"''\r\n]*?(password|pwd)=(?<pw>[^&"''\r\n]{1,256})'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $pw = $m.Groups['pw'].Value
        if (Test-Placeholder $pw) { continue }
        Add-Finding @{
            rule_id    = 'jdbc.password'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $pw
            key_name   = 'jdbc-url'
        }
    }
}

function Scan-PsSecureString {
    param([string]$Path, [string]$Content)
    $pat = '(?i)ConvertTo-SecureString\s+(-String\s+)?(?<q>["''])(?<v>[^"''\r\n]{4,512})\k<q>\s+(-AsPlainText\s+-Force|-Force\s+-AsPlainText)'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $val = $m.Groups['v'].Value
        if (Test-Placeholder $val) { continue }
        Add-Finding @{
            rule_id    = 'ps.securestring_plain'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $val
            key_name   = 'ConvertTo-SecureString'
        }
    }
}

function Scan-DockerAuth {
    param([string]$Path, [string]$Content)
    $pat = '"auths"\s*:\s*\{[\s\S]*?"auth"\s*:\s*"(?<b>[A-Za-z0-9+/=]{8,})"'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $b64 = $m.Groups['b'].Value
        Add-Finding @{
            rule_id    = 'docker.auth_b64'
            category   = 'STORED_CRED:docker'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $b64
            key_name   = 'docker.config.json auth'
            decoder_applied = 'docker.b64'
        }
        $dec = Convert-DockerAuth $b64
        if ($dec) {
            Add-Finding @{
                rule_id    = 'docker.auth.plaintext'
                category   = 'URI_CREDS:docker'
                confidence = 'HIGH'
                base_confidence = 'HIGH'
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = "$($dec.user):$($dec.password)"
                key_name   = "user=$($dec.user)"
                decoder_applied = 'docker.b64'
            }
        }
    }
}

function Scan-AnsibleVaultHeader {
    param([string]$Path, [string]$Content)
    foreach ($m in (Get-Rx '(?m)^\$ANSIBLE_VAULT;\d+\.\d+;AES256').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'ansible.vault_header'
            category   = 'REFERENCE'
            confidence = 'MEDIUM'
            base_confidence = 'HIGH'
            demotions  = @('reference_not_extractable')
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = 'ansible-vault'
            notes      = 'encrypted; request vault password from engagement team. offline: ansible-vault decrypt'
        }
    }
}

function Scan-WinscpSession {
    param([string]$Path, [string]$Content)
    $pat = '(?im)^\s*Password\s*=\s*(?<v>[A-Za-z0-9+/=]{8,})\s*$'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $val = $m.Groups['v'].Value
        Add-Finding @{
            rule_id    = 'winscp.password'
            category   = 'STORED_CRED:winscp'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $val
            key_name   = 'WinSCP saved session (obfuscated)'
            notes      = 'WinSCP XOR-deobfuscate offline with WinSCPPasswdExtractor or winscp.com /command'
        }
    }
}

function Scan-WinUnattendPassword {
    param([string]$Path, [string]$Content)
    if ($Path -notmatch '(?i)(unattend|sysprep)') { return }
    $pat = '(?is)<(?<tag>Password|AdministratorPassword|DomainPassword|LocalAccountPassword)>\s*<Value>(?<v>[^<]+)</Value>'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $val = $m.Groups['v'].Value.Trim()
        if (Test-Placeholder $val) { continue }
        $tag = $m.Groups['tag'].Value
        $plain = ''
        $decoder = $null
        if ($val -match '^[A-Za-z0-9+/]+={0,2}$' -and ($val.Length % 4 -eq 0) -and $val.Length -ge 4) {
            try {
                $bytes = [Convert]::FromBase64String($val)
                foreach ($enc in @([System.Text.Encoding]::Unicode, [System.Text.Encoding]::UTF8)) {
                    try {
                        $candidate = $enc.GetString($bytes).TrimEnd([char]0)
                        if (-not $candidate) { continue }
                        $suffix = $tag
                        if ($candidate.EndsWith($suffix)) { $candidate = $candidate.Substring(0, $candidate.Length - $suffix.Length) }
                        if ($candidate -and $candidate -match '^[\x20-\x7E]+$') {
                            $plain = $candidate
                            $decoder = if ($enc -eq [System.Text.Encoding]::Unicode) { 'unattend.b64.utf16' } else { 'unattend.b64.utf8' }
                            break
                        }
                    } catch {}
                }
            } catch {}
        }
        Add-Finding @{
            rule_id    = 'unattend.password'
            category   = 'PASSWORD'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $val
            key_name   = "tag=$tag"
            decoder_applied = $decoder
        }
        if ($plain) {
            Add-Finding @{
                rule_id    = 'unattend.password.plaintext'
                category   = 'PASSWORD'
                confidence = 'HIGH'
                base_confidence = 'HIGH'
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = $plain
                key_name   = "tag=$tag (decoded)"
                decoder_applied = $decoder
            }
        }
    }
}

function Scan-WinScriptHelpers {
    param([string]$Path, [string]$Content)
    $patterns = @(
        @{ id='win.net_user';   pat='(?i)\bnet\s+user\s+\S+\s+(?<v>\S{4,256})\s+/add';        key='net user' }
        @{ id='win.psexec';     pat='(?i)\bpsexec(\.exe)?\b[^\r\n]*-p\s+(?<v>\S{1,256})';      key='psexec -p' }
        @{ id='win.sqlcmd';     pat='(?i)\bsqlcmd\b[^\r\n]*-P\s+(?<v>\S{1,256})';              key='sqlcmd -P' }
        @{ id='win.curl_basic'; pat='(?i)\bcurl\b[^\r\n]*-u\s+[^\s:]+:(?<v>\S{1,256})';        key='curl -u' }
        @{ id='win.sshpass';    pat='(?i)\bsshpass\s+-p\s+(?<v>\S{1,256})';                    key='sshpass -p' }
        @{ id='win.defaultpassword'; pat='(?i)\bDefault(User)?Password\s*[:=]\s*"?(?<v>[^"\r\n]{1,256})"?'; key='DefaultPassword' }
    )
    foreach ($p in $patterns) {
        foreach ($m in (Get-Rx $p.pat).Matches($Content)) {
            $ctx = Get-MatchContext -M $m -Content $Content
            $val = $m.Groups['v'].Value
            if (Test-Placeholder $val) { continue }
            $demotions = @()
            $fp = $null
            if (Test-IdentifierShape $val) {
                Add-Finding @{
                    rule_id    = $p.id
                    category   = 'PASSWORD'
                    confidence = 'LOW'
                    base_confidence = 'MEDIUM'
                    demotions  = @('variable_reference')
                    fp_reason  = 'variable_reference'
                    abs_path   = $Path
                    line_no    = $ctx.line_no
                    line_text  = $ctx.line_text
                    match_text = $val
                    key_name   = $p.key
                }
                continue
            }
            $conf = 'MEDIUM'
            if (Test-Comment $ctx.line_text) { $conf = 'LOW'; $demotions += 'comment' }
            if (Test-TestPath $Path)         { $conf = 'LOW'; $demotions += 'test_path' }
            Add-Finding @{
                rule_id    = $p.id
                category   = 'PASSWORD'
                confidence = $conf
                base_confidence = 'MEDIUM'
                demotions  = $demotions
                fp_reason  = $fp
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = $val
                key_name   = $p.key
            }
        }
    }
    foreach ($m in (Get-Rx '(?i)\bAutoAdminLogon\s*=\s*"?1"?').Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        Add-Finding @{
            rule_id    = 'win.autoadminlogon'
            category   = 'REFERENCE'
            confidence = 'MEDIUM'
            base_confidence = 'MEDIUM'
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $m.Value
            key_name   = 'AutoAdminLogon=1 - check DefaultPassword'
        }
    }
}

function Scan-GenericAssign {
    param([string]$Path, [string]$Content)
    $pat = '(?im)(?<key>\b(password|passwd|pwd|pass|passphrase|secret|cred(ential)?s?|requirepass|bindpw|db[_-]?pass(word)?|smtp[_-]?pass(word)?|ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?))\s*(?:[:=]{1,2}|:=|=>)\s*(?<q>["''`]?)(?<val>(?!\s*$)[^\r\n"''`]{4,512})\k<q>'
    foreach ($m in (Get-Rx $pat).Matches($Content)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $key = $m.Groups['key'].Value
        $val = $m.Groups['val'].Value.Trim()
        if (-not $val) { continue }
        $conf      = 'HIGH'
        $baseConf  = 'HIGH'
        $demotions = @()
        $fp        = $null
        $entropy   = $null

        if (Test-Placeholder $val) {
            $conf = 'LOW'; $fp = 'placeholder'; $demotions += 'placeholder'
        } elseif (Test-EnvReference $val) {
            $conf = 'MEDIUM'; $fp = 'env_reference'; $demotions += 'env_reference'
        } elseif (Test-IdentifierShape $val -and ($m.Groups['q'].Value -eq '')) {
            $conf = 'LOW'; $fp = 'variable_reference'; $demotions += 'variable_reference'
        } elseif ($val.Length -lt 4) {
            $conf = 'LOW'; $fp = 'too_short'; $demotions += 'too_short'
        } elseif ($val.Length -gt 512) {
            $conf = 'LOW'; $fp = 'too_long_likely_blob'; $demotions += 'too_long'
        } else {
            if (Test-Comment $ctx.line_text) {
                $conf = switch ($conf) { 'HIGH' { 'MEDIUM' } default { 'LOW' } }
                $demotions += 'comment'
            }
            if (Test-TestPath $Path) {
                $conf = switch ($conf) { 'HIGH' { 'MEDIUM' } default { 'LOW' } }
                $demotions += 'test_path'
            }
            $ent = Convert-EntropyDemotion -Val $val -Conf $conf
            $conf = $ent.conf
            if ($ent.demoted) { $demotions += 'entropy' }
            $entropy = $ent.entropy
        }
        if ($null -eq $entropy) { $entropy = Get-Entropy $val }
        $cat = if ($demotions -contains 'env_reference') { 'REFERENCE' } else { 'PASSWORD' }
        Add-Finding @{
            rule_id    = 'pw.assign.generic'
            category   = $cat
            confidence = $conf
            base_confidence = $baseConf
            demotions  = $demotions
            abs_path   = $Path
            line_no    = $ctx.line_no
            line_text  = $ctx.line_text
            match_text = $val
            key_name   = $key
            fp_reason  = $fp
            entropy    = $entropy
        }
    }
}

function Scan-FileContent {
    param([string]$Path)
    if (-not $Path) { return }
    if (Test-Excluded $Path) { return }
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        Add-Skipped $Path 'perm'
        return
    }
    if (-not ($fi -is [System.IO.FileInfo])) { return }
    if ($fi.Length -gt $script:MaxBytes) {
        Add-Skipped $Path 'size'
        return
    }
    $key = "{0}:{1}" -f $fi.Length, $fi.LastWriteTimeUtc.Ticks
    $key = "{0}|{1}" -f $Path.ToLower(), $key
    if (-not $script:SeenInodes.Add($key)) { return }

    if (Test-Binary $Path) {
        Add-Skipped $Path 'binary'
        return
    }
    $content = Read-TextFile $Path
    if ($null -eq $content) {
        Add-Skipped $Path 'perm'
        return
    }
    $script:ScannedCount++

    Scan-PrivateKey         $Path $content
    Scan-Ppk                $Path $content
    Scan-Wireguard          $Path $content
    Scan-GppCpassword       $Path $content
    Scan-ShadowHash         $Path $content
    Scan-Htpasswd           $Path $content
    Scan-NetNTLMv2          $Path $content
    Scan-PwdumpNtlm         $Path $content
    Scan-Krb5Asrep          $Path $content
    Scan-Krb5Tgs            $Path $content
    Scan-UriBasicCreds      $Path $content
    Scan-Netrc              $Path $content
    Scan-Pgpass             $Path $content
    Scan-MyCnf              $Path $content
    Scan-TomcatUser         $Path $content
    Scan-CiscoSecret        $Path $content
    Scan-DotnetConnstr      $Path $content
    Scan-JdbcPassword       $Path $content
    Scan-PsSecureString     $Path $content
    Scan-DockerAuth         $Path $content
    Scan-AnsibleVaultHeader $Path $content
    Scan-WinUnattendPassword $Path $content
    Scan-WinScriptHelpers   $Path $content
    if ($Path -match '(?i)(winscp\.ini|WinSCP 2\\Sessions)') {
        Scan-WinscpSession $Path $content
    }
    Scan-GenericAssign      $Path $content
    # Drop the per-file line-starts cache so we don't grow unbounded
    # across the candidate list.
    if ($script:LineStartsCache) { $script:LineStartsCache.Clear() }
}

$script:ClassANameRegex = '^(id_rsa|id_dsa|id_ecdsa|id_ed25519|id_xmss|id_ecdsa_sk|id_ed25519_sk|authorized_keys|known_hosts|.htpasswd|.netrc|_netrc|.pgpass|.my\.cnf|.mylogin\.cnf|.smbcredentials|.cifs-credentials|.credentials|.git-credentials|.npmrc|.yarnrc|.yarnrc\.yml|kubeconfig|wg0\.conf|krb5\.keytab|azureProfile\.json|accessTokens\.json|application_default_credentials\.json|Groups\.xml|Services\.xml|ScheduledTasks\.xml|Drives\.xml|Printers\.xml|DataSources\.xml|unattend\.xml|autounattend\.xml|sysprep\.inf|sysprep\.xml|shadow\.bak|shadow\.old|shadow-|passwd\.bak|passwd-|gshadow\.bak|SAM|SYSTEM|SECURITY|ntds\.dit|WinSCP\.ini|sitemanager\.xml|recentservers\.xml|filezilla\.xml|confCons\.xml|MobaXterm\.ini|RDCMan\.settings|credentials\.xml|master\.key|hudson\.util\.Secret|initialAdminPassword|\.env|wp-config\.php|wp-config-sample\.php|configuration\.php|LocalSettings\.php|local\.xml|database\.yml|web\.config|app\.config|machine\.config|connectionStrings\.config|tnsnames\.ora|sqlnet\.ora|wallet\.sso|cwallet\.sso)$'

$script:ClassAExtRegex = '\.(kdbx|kdb|psafe3|agilekeychain|opvault|1pif|pem|key|priv|pk8|pkcs8|rsa|dsa|ec|ppk|openssh|pfx|p12|jks|keystore|bks|uber|pkcs12|kubeconfig|ovpn|keytab|rdg|rdp|ica|tds|rtsz|rtsx)$'

# Pre-compiled instances of the file-name classifiers. Called per candidate
# file in Phase 3/4; precompile saves the regex re-parse per call.
# IgnoreCase matches PowerShell's default -match behavior — load-bearing
# for Windows fixtures (e.g. Unattend.xml vs unattend\.xml).
$script:RxIgnore      = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$script:RxClassAName  = Get-Rx $script:ClassANameRegex $script:RxIgnore
$script:RxClassAExt   = Get-Rx $script:ClassAExtRegex  $script:RxIgnore
$script:RxSkipExt     = Get-Rx $script:SkipExtRegex    $script:RxIgnore
$script:RxSkipName    = Get-Rx $script:SkipNameRegex   $script:RxIgnore
$script:RxDefaultExt  = Get-Rx $script:DefaultExtRegex $script:RxIgnore

function Test-ClassAFile {
    param([string]$Name)
    if (-not $Name) { return $false }
    if ($script:RxClassAName.IsMatch($Name)) { return $true }
    if ($script:RxClassAExt.IsMatch($Name)) { return $true }
    if ($Name -like '.env.*') { return $true }
    if ($Name -like 'bw_export_*.csv') { return $true }
    if ($Name -like 'lastpass_export*.csv') { return $true }
    if ($Name -like 'LastPassExport*.csv') { return $true }
    if ($Name -like 'Dashlane Export*.csv') { return $true }
    if ($Name -like 'enpass*.json') { return $true }
    if ($Name -like 'ssh_host_*_key') { return $true }
    if ($Name -like 'krb5cc_*') { return $true }
    if ($Name -in @('Login Data','Login Data For Account','Cookies','Web Data','Local State','key3.db','key4.db','logins.json','signons.sqlite','cert9.db')) { return $true }
    if ($Name -like '*.bitwarden_export.json') { return $true }
    if ($Name -like 'application*.properties') { return $true }
    if ($Name -like 'application*.yml') { return $true }
    if ($Name -in @('application.properties','application.yml','bootstrap.yml','settings.xml')) { return $true }
    return $false
}

function Test-KeywordFile {
    param([string]$Name)
    if (-not $Name) { return $false }
    $lower = $Name.ToLower()
    if ($lower -like '*password*') { return $true }
    if ($lower -like '*pass*.txt') { return $true }
    if ($lower -like '*cred*') { return $true }
    if ($lower -like '*credential*') { return $true }
    if ($lower -like '*secret*') { return $true }
    if ($lower -eq 'pw.txt') { return $true }
    if ($lower -eq 'pwd.txt') { return $true }
    if ($lower -like '*.passwd') { return $true }
    if ($lower -like '*.pass') { return $true }
    if ($lower -like '*.creds') { return $true }
    return $false
}

function Test-ExtensionAllowed {
    param([string]$Name)
    if (-not $Name) { return $false }
    $lower = $Name.ToLower()
    if ($script:RxSkipExt.IsMatch($lower)) { return $false }
    if ($script:RxSkipName.IsMatch($lower)) { return $false }
    if ($All) { return $true }
    if ($script:RxDefaultExt.IsMatch($lower)) { return $true }
    if ($lower -in $script:DefaultExtNames) { return $true }
    if ($lower -like '*.dockerfile') { return $true }
    if ($lower -like 'docker-compose.y*ml') { return $true }
    if ($lower -like 'compose.y*ml') { return $true }
    if ($lower -like '*.jenkinsfile') { return $true }
    if ($lower -like '*.gradle' -or $lower -like '*.gradle.kts') { return $true }
    if ($lower -in @('pom.xml','package.json','jenkinsfile','dockerfile','containerfile','makefile','gnumakefile')) { return $true }
    if ($lower -like '*.tf' -or $lower -like '*.tfvars') { return $true }
    if ($lower -like 'azure-pipelines*.yml') { return $true }
    if ($lower -like 'cloudbuild*.yaml') { return $true }
    if ($lower -like 'buildspec*.yml') { return $true }
    foreach ($e in $IncludeExt) {
        $ePat = $e.TrimStart('.')
        if ($lower.EndsWith(".$ePat")) { return $true }
    }
    return $false
}

function Get-CandidateFiles {
    # Walker:
    # - Prunes excluded subtrees BEFORE recursing (key perf win).
    # - Skips reparse points (junctions, symlinks) unless -FollowSymlinks
    #   is set. Classic Windows hang source: C:\Documents and Settings
    #   junction loops back into C:\Users.
    # - Skips OneDrive/cloud placeholder files (FILE_ATTRIBUTE_OFFLINE
    #   0x1000, FILE_ATTRIBUTE_RECALL_ON_OPEN 0x40000, RECALL_ON_DATA_ACCESS
    #   0x400000) — reading them would trigger network download.
    # - Honors -CrossMounts by tracking the original root's volume serial.
    param([string]$Root, [scriptblock]$OnProgress = $null)
    $result = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $rootVolume = $null
    if (-not $CrossMounts) {
        try {
            $rootInfo = [System.IO.DirectoryInfo]::new($Root)
            if ($rootInfo.Root) { $rootVolume = $rootInfo.Root.FullName.ToLower() }
        } catch {}
    }
    # Bitmask: ReparsePoint (0x400) | Offline (0x1000) | RecallOnOpen (0x40000)
    # | RecallOnDataAccess (0x400000). Test with -band any.
    $offlineFlags = 0x441400
    $reparseFlag  = [int][System.IO.FileAttributes]::ReparsePoint
    $dirSeen = 0
    try {
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($Root)
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop()
            $dirSeen++
            if ($OnProgress -and ($dirSeen % 50 -eq 0)) { & $OnProgress $cur $dirSeen }
            try {
                $di = [System.IO.DirectoryInfo]::new($cur)
                if (-not $di.Exists) { continue }
                # Don't cross mount boundaries unless asked.
                if ($rootVolume -and $di.Root -and $di.Root.FullName.ToLower() -ne $rootVolume) { continue }
                $entries = $null
                try { $entries = $di.GetFileSystemInfos() } catch { Add-Skipped $cur 'perm'; continue }
                foreach ($e in $entries) {
                    $full = $e.FullName
                    if (Test-Excluded $full) {
                        Add-Skipped $full 'excluded'
                        continue
                    }
                    $attrInt = [int]$e.Attributes
                    if ((-not $FollowSymlinks) -and (($attrInt -band $reparseFlag) -ne 0)) { continue }
                    if (($attrInt -band $offlineFlags) -ne 0) {
                        # OneDrive/iCloud placeholder; skip without opening.
                        Add-Skipped $full 'excluded'
                        continue
                    }
                    if ($e -is [System.IO.DirectoryInfo]) {
                        $stack.Push($full)
                    } else {
                        $result.Add($e)
                    }
                }
            } catch {
                Add-Skipped $cur 'perm'
            }
        }
    } catch {}
    return $result
}

$script:KnownPaths = @(
    "$($script:WinDir)\Panther\Unattend.xml",
    "$($script:WinDir)\Panther\Unattend\Unattend.xml",
    "$($script:WinDir)\Panther\autounattend.xml",
    "$($script:WinDir)\Panther\setupact.log",
    "$($script:WinDir)\Panther\setuperr.log",
    "$($script:WinDir)\System32\Sysprep\Unattend.xml",
    "$($script:WinDir)\System32\Sysprep\Panther\Unattend.xml",
    "$($script:WinDir)\System32\sysprep\sysprep.xml",
    "$($script:WinDir)\System32\sysprep\sysprep.inf",
    'C:\unattend.xml','C:\unattend.txt','C:\unattend.inf',
    'C:\autounattend.xml','A:\Unattend.xml',
    "$($script:WinDir)\Debug\NetSetup.log",
    "$($script:WinDir)\Debug\PASSWD.LOG",
    "$($script:WinDir)\Debug\mrt.log",
    "$($script:WinDir)\WindowsUpdate.log",
    "$($script:WinDir)\Repair\SAM",
    "$($script:WinDir)\Repair\SYSTEM",
    "$($script:WinDir)\Repair\SECURITY",
    "$($script:WinDir)\System32\config\RegBack\SAM",
    "$($script:WinDir)\System32\config\RegBack\SYSTEM",
    "$($script:WinDir)\System32\config\RegBack\SECURITY",
    "$($script:WinDir)\System32\config\SAM",
    "$($script:WinDir)\System32\config\SYSTEM",
    "$($script:WinDir)\System32\config\SECURITY",
    "$($script:WinDir)\NTDS\ntds.dit",
    "$($script:WinDir)\System32\inetsrv\Config\applicationHost.config",
    "$($script:WinDir)\System32\inetsrv\Config\administration.config",
    "$($script:WinDir)\Apache24\conf\httpd.conf"
)

$script:KnownGlobs = @(
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\Services\Services.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\Drives\Drives.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\Printers\Printers.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\Machine\Preferences\DataSources\DataSources.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\User\Preferences\Groups\Groups.xml",
    "$($script:ProgData)\Microsoft\Group Policy\History\*\User\Preferences\Drives\Drives.xml",
    "C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history\*\Machine\Preferences\Groups\Groups.xml",
    'C:\inetpub\wwwroot\web.config',
    'C:\inetpub\wwwroot\*\web.config',
    'C:\inetpub\*\web.config',
    "$($script:WinDir)\Panther\*.log",
    "$($script:WinDir)\Panther\*.xml",
    "$($script:WinDir)\Panther\Unattend\*.xml",
    "$($script:WinDir)\System32\Sysprep\*.xml",
    "$($script:WinDir)\System32\Sysprep\Panther\*.xml",
    "$($script:WinDir)\ccmcache\*",
    "$($script:WinDir)\CCM\Logs\*.log",
    "$($script:WinDir)\CCMSetup\Logs\*.log",
    'C:\ProgramData\MySQL\MySQL Server *\my.ini',
    'C:\Program Files\MySQL\*\my.ini',
    'C:\Program Files\Redis\redis.windows.conf',
    'C:\Program Files\OpenVPN\config\*.ovpn',
    "$($script:ProgData)\OpenVPN\config\*.ovpn",
    'C:\Program Files\WireGuard\Data\Configurations\*.conf*',
    "$($script:ProgData)\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\*.xml"
)

function Get-UserBasedKnownPaths {
    $result = New-Object System.Collections.Generic.List[string]
    $usersRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $usersRoot)) { return $result }
    try {
        $userDirs = Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue
    } catch { return $result }
    foreach ($u in $userDirs) {
        $base = $u.FullName
        $candidates = @(
            "$base\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
            "$base\Documents\PowerShell_transcript.*.txt",
            "$base\.aws\credentials","$base\.aws\config",
            "$base\.azure",
            "$base\.docker\config.json",
            "$base\.kube\config",
            "$base\.netrc","$base\_netrc","$base\.pgpass","$base\.my.cnf",
            "$base\.git-credentials","$base\.npmrc","$base\.ssh\id_rsa","$base\.ssh\id_ed25519",
            "$base\.ssh\authorized_keys","$base\.ssh\config",
            "$base\AppData\Roaming\WinSCP.ini",
            "$base\AppData\Roaming\FileZilla\sitemanager.xml",
            "$base\AppData\Roaming\FileZilla\recentservers.xml",
            "$base\AppData\Roaming\MobaXterm\MobaXterm.ini",
            "$base\AppData\Roaming\mRemoteNG\confCons.xml",
            "$base\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings",
            "$base\Documents\*.rdg",
            "$base\.m2\settings.xml",
            "$base\OpenVPN\config\*.ovpn",
            "$base\.config\gcloud\credentials.db"
        )
        foreach ($c in $candidates) { $result.Add($c) }
    }
    return $result
}

$script:RegistryProbes = @(
    @{ Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
       Values=@('AutoAdminLogon','DefaultUserName','DefaultDomainName','DefaultPassword','AltDefaultPassword');
       Enumerate=$false; Label='winlogon' },
    @{ Key='HKCU:\Software\SimonTatham\PuTTY\Sessions';
       Values=@('HostName','UserName','ProxyPassword','PublicKeyFile');
       Enumerate=$true; Label='putty' },
    @{ Key='HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions';
       Values=@('HostName','UserName','Password','PublicKeyFile');
       Enumerate=$true; Label='winscp' },
    @{ Key='HKLM:\SOFTWARE\TightVNC\Server';
       Values=@('Password','ControlPassword','PasswordViewOnly');
       Enumerate=$false; Label='tightvnc' },
    @{ Key='HKCU:\Software\TightVNC\Server';
       Values=@('Password','ControlPassword');
       Enumerate=$false; Label='tightvnc.user' },
    @{ Key='HKLM:\SOFTWARE\RealVNC\vncserver';
       Values=@('Password');
       Enumerate=$false; Label='realvnc' },
    @{ Key='HKLM:\SOFTWARE\RealVNC\WinVNC4';
       Values=@('Password');
       Enumerate=$false; Label='winvnc4' },
    @{ Key='HKCU:\Software\Mobatek\MobaXterm';
       Values=@('M','C','P');
       Enumerate=$true; Label='mobaxterm' }
)

function Invoke-RegistryProbes {
    if (-not $script:IsWindowsHost) { return }
    foreach ($p in $script:RegistryProbes) {
        try {
            if (-not (Test-Path -LiteralPath $p.Key -ErrorAction SilentlyContinue)) { continue }
        } catch { continue }
        try {
            $targets = @()
            if ($p.Enumerate) {
                $children = Get-ChildItem -LiteralPath $p.Key -ErrorAction SilentlyContinue
                if ($children) { $targets = $children }
            }
            if (-not $targets -or $targets.Count -eq 0) {
                $targets = @(Get-Item -LiteralPath $p.Key -ErrorAction SilentlyContinue)
            }
            foreach ($t in $targets) {
                if (-not $t) { continue }
                foreach ($vn in $p.Values) {
                    try {
                        $val = (Get-ItemProperty -LiteralPath $t.PSPath -Name $vn -ErrorAction SilentlyContinue).$vn
                    } catch { continue }
                    if ($null -eq $val) { continue }
                    $sval = "$val"
                    if (-not $sval) { continue }
                    if (Test-Placeholder $sval) { continue }
                    $sub = if ($t.PSChildName) { ".$($t.PSChildName)" } else { '' }
                    Add-Finding @{
                        rule_id    = "reg.$($p.Label)$sub.$vn"
                        category   = 'PASSWORD'
                        confidence = 'HIGH'
                        base_confidence = 'HIGH'
                        abs_path   = "$($t.PSPath)::$vn"
                        line_no    = 0
                        match_text = $sval
                        key_name   = $vn
                    }
                }
            }
        } catch {}
    }
}

function Invoke-CmdkeyList {
    if (-not $script:IsWindowsHost) { return }
    try {
        $out = & cmd /c 'cmdkey /list' 2>$null
        if ($out) {
            $joined = ($out -join "`n")
            if ($joined.Length -gt 4000) { $joined = $joined.Substring(0, 4000) }
            Add-Finding @{
                rule_id    = 'wincred.cmdkey'
                category   = 'STORED_CRED:cmdkey'
                confidence = 'MEDIUM'
                base_confidence = 'MEDIUM'
                abs_path   = 'cmdkey /list'
                line_no    = 0
                match_text = $joined
                key_name   = 'enumerated credential targets'
                notes      = 'See SharpDPAPI/Mimikatz dpapi::cred for offline decryption'
            }
        }
    } catch {}
}

function Invoke-VaultCmd {
    if (-not $script:IsWindowsHost) { return }
    try {
        $out = & cmd /c 'vaultcmd /list' 2>$null
        if ($out) {
            $joined = ($out -join "`n")
            if ($joined.Length -gt 4000) { $joined = $joined.Substring(0, 4000) }
            Add-Finding @{
                rule_id    = 'wincred.vaultcmd'
                category   = 'STORED_CRED:vault'
                confidence = 'MEDIUM'
                base_confidence = 'MEDIUM'
                abs_path   = 'vaultcmd /list'
                line_no    = 0
                match_text = $joined
                key_name   = 'Windows Vault'
            }
        }
    } catch {}
}

function Invoke-ClassAFileFinding {
    param([string]$Path)
    $base = Split-Path $Path -Leaf
    if (Test-ClassAFile $base) {
        Add-Finding @{
            rule_id    = 'class_a.filename'
            category   = 'PRIVATE_KEY'
            confidence = 'HIGH'
            base_confidence = 'HIGH'
            abs_path   = $Path
            line_no    = 0
            match_text = $base
            key_name   = 'Class A filename'
        }
        return $true
    }
    return $false
}

function Invoke-Phase2 {
    if ($SkipKnownLocations) { return }
    Write-Phase 'phase 2/5' 'known-locations sweep'
    $pre = $script:Findings.Count
    $seen = 0

    foreach ($p in $script:KnownPaths) {
        $seen++
        Write-PhaseProgress -Phase '2/5: known locations' -Status $p
        try {
            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
                $it = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
                if ($it -is [System.IO.FileInfo]) {
                    [void](Invoke-ClassAFileFinding $it.FullName)
                    if (-not (Test-Binary $it.FullName)) { Scan-FileContent $it.FullName }
                } elseif ($it -is [System.IO.DirectoryInfo]) {
                    Get-ChildItem -LiteralPath $it.FullName -Recurse -File -Force -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            [void](Invoke-ClassAFileFinding $_.FullName)
                            if (-not (Test-Binary $_.FullName)) { Scan-FileContent $_.FullName }
                        }
                }
            }
        } catch {}
    }
    foreach ($g in $script:KnownGlobs) {
        $seen++
        Write-PhaseProgress -Phase '2/5: known locations' -Status $g
        try {
            $items = Get-ChildItem -Path $g -Force -ErrorAction SilentlyContinue
            foreach ($it in $items) {
                if ($it -is [System.IO.FileInfo]) {
                    [void](Invoke-ClassAFileFinding $it.FullName)
                    if (-not (Test-Binary $it.FullName)) { Scan-FileContent $it.FullName }
                }
            }
        } catch {}
    }
    foreach ($up in Get-UserBasedKnownPaths) {
        $seen++
        Write-PhaseProgress -Phase '2/5: known locations' -Status $up
        try {
            if ($up -like '*\**' -or $up -like '*?*' -or $up -like '*\[*') {
                $items = Get-ChildItem -Path $up -Force -ErrorAction SilentlyContinue
                foreach ($it in $items) {
                    if ($it -is [System.IO.FileInfo]) {
                        [void](Invoke-ClassAFileFinding $it.FullName)
                        if (-not (Test-Binary $it.FullName)) { Scan-FileContent $it.FullName }
                    }
                }
            } elseif (Test-Path -LiteralPath $up -ErrorAction SilentlyContinue) {
                [void](Invoke-ClassAFileFinding $up)
                if (-not (Test-Binary $up)) { Scan-FileContent $up }
            }
        } catch {}
    }

    Write-PhaseProgress -Phase '2/5: known locations' -Status 'registry/credentials enumeration'
    Invoke-RegistryProbes
    Invoke-CmdkeyList
    Invoke-VaultCmd

    Complete-PhaseProgress -Phase '2/5: known locations'
    Flush-Buffers
    $post = $script:Findings.Count
    Write-Info ("  {0} findings" -f ($post - $pre))
}

function Invoke-Phase3 {
    Write-Phase 'phase 3/5' 'filename-pattern hunt'
    $pre = $script:Findings.Count
    $rootIdx = 0
    foreach ($r in $ScanRoots) {
        $rootIdx++
        Write-PhaseProgress -Phase '3/5: filename hunt' -Status $r -Current $rootIdx -Total $ScanRoots.Count
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        try {
            $rootInfo = Get-Item -LiteralPath $r -Force -ErrorAction SilentlyContinue
            if ($rootInfo -is [System.IO.FileInfo]) {
                $name = $rootInfo.Name
                if (Test-ClassAFile $name) {
                    Add-Finding @{
                        rule_id    = 'class_a.filename'
                        category   = 'PRIVATE_KEY'
                        confidence = 'HIGH'
                        base_confidence = 'HIGH'
                        abs_path   = $rootInfo.FullName
                        line_no    = 0
                        match_text = $name
                    }
                }
                continue
            }
        } catch {}
        $progressCb = {
            param($cur, $seen)
            Write-PhaseProgress -Phase '3/5: filename hunt' -Status ("{0}  (dirs scanned: {1})" -f $cur, $seen)
        }
        $files = Get-CandidateFiles -Root $r -OnProgress $progressCb
        foreach ($fi in $files) {
            $name = $fi.Name
            if (Test-ClassAFile $name) {
                Add-Finding @{
                    rule_id    = 'class_a.filename'
                    category   = 'PRIVATE_KEY'
                    confidence = 'HIGH'
                    base_confidence = 'HIGH'
                    abs_path   = $fi.FullName
                    line_no    = 0
                    match_text = $name
                }
            } elseif (Test-KeywordFile $name) {
                Add-Finding @{
                    rule_id    = 'keyword.filename'
                    category   = 'PASSWORD'
                    confidence = 'MEDIUM'
                    base_confidence = 'MEDIUM'
                    abs_path   = $fi.FullName
                    line_no    = 0
                    match_text = $name
                }
            }
        }
    }
    Complete-PhaseProgress -Phase '3/5: filename hunt'
    Flush-Buffers
    $post = $script:Findings.Count
    Write-Info ("  {0} findings" -f ($post - $pre))
}

function Invoke-Phase4 {
    if ($SkipContentScan) { return }
    Write-Phase 'phase 4/5' 'content scan'
    $pre = $script:Findings.Count
    $candidates = New-Object System.Collections.Generic.List[string]
    $rootIdx = 0
    foreach ($r in $ScanRoots) {
        $rootIdx++
        Write-PhaseProgress -Phase '4/5: build candidate list' -Status $r -Current $rootIdx -Total $ScanRoots.Count
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        try {
            $rootInfo = Get-Item -LiteralPath $r -Force -ErrorAction SilentlyContinue
            if ($rootInfo -is [System.IO.FileInfo]) {
                if (Test-ExtensionAllowed $rootInfo.Name) { $candidates.Add($rootInfo.FullName) }
                continue
            }
        } catch {}
        $progressCb = {
            param($cur, $seen)
            Write-PhaseProgress -Phase '4/5: build candidate list' -Status ("{0}  (dirs scanned: {1})" -f $cur, $seen)
        }
        $files = Get-CandidateFiles -Root $r -OnProgress $progressCb
        foreach ($fi in $files) {
            if (Test-ExtensionAllowed $fi.Name) { $candidates.Add($fi.FullName) }
        }
    }
    Write-Info ("  ({0} candidate files)" -f $candidates.Count)

    # Content scan with per-50-file progress update + ETA. Parallel paths
    # (ForEach-Object -Parallel on PS7) are out of scope for this pass —
    # they need separate per-worker buffers + merge, the serial loop is
    # already much faster after the regex/buffer optimizations.
    $total = $candidates.Count
    if ($total -gt 0) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0
        foreach ($f in $candidates) {
            $i++
            if (($i % 50) -eq 0 -or $i -eq $total) {
                $elapsed = $sw.Elapsed.TotalSeconds
                $rate = if ($elapsed -gt 0) { $i / $elapsed } else { 0 }
                $remaining = $total - $i
                $eta = if ($rate -gt 0) { [int]($remaining / $rate) } else { -1 }
                $status = "{0}/{1} files ({2} findings, ETA {3}s)" -f $i, $total, $script:Findings.Count, $eta
                Write-PhaseProgress -Phase '4/5: content scan' -Status $status -Current $i -Total $total
            }
            Scan-FileContent $f
        }
    }
    Complete-PhaseProgress -Phase '4/5: content scan'
    Flush-Buffers
    $post = $script:Findings.Count
    Write-Info ("  {0} findings" -f ($post - $pre))
}

function Get-ConfidenceColor {
    param([string]$Conf)
    switch ($Conf) {
        'HIGH'   { return 'Red' }
        'MEDIUM' { return 'Yellow' }
        default  { return 'Cyan' }
    }
}

function Invoke-Phase5 {
    Write-Phase 'phase 5/5' 'rendering report'
    $total = $script:Findings.Count
    $idx = 0
    foreach ($f in $script:Findings) {
        $idx++
        if (($idx % 100) -eq 0 -or $idx -eq $total) {
            Write-PhaseProgress -Phase '5/5: render' -Status ("serializing {0}/{1}" -f $idx, $total) -Current $idx -Total $total
        }
        Save-Finding $f
    }
    Flush-Buffers
    Complete-PhaseProgress -Phase '5/5: render'

    $high = @($script:Findings | Where-Object { $_.confidence -eq 'HIGH' }).Count
    $med  = @($script:Findings | Where-Object { $_.confidence -eq 'MEDIUM' }).Count
    $low  = @($script:Findings | Where-Object { $_.confidence -eq 'LOW' }).Count
    $total = $script:Findings.Count

    if ($Output -eq 'console' -or $Output -eq 'both') {
        Write-Host ""
        Write-Host "====================================================="
        if ($script:UseColor) {
            Write-Host "  " -NoNewline; Write-Host "HIGH" -ForegroundColor Red -NoNewline; Write-Host "-confidence findings ($high)"
        } else {
            Write-Host "  HIGH-confidence findings ($high)"
        }
        Write-Host "-----------------------------------------------------"
        foreach ($f in ($script:Findings | Where-Object { $_.confidence -eq 'HIGH' })) {
            $loc = if ($f.line_no -and $f.line_no -gt 0) { ":$($f.line_no)" } else { '' }
            $line = "  [HIGH] {0,-26} {1}{2}" -f $f.rule_id, $f.abs_path, $loc
            if ($script:UseColor) { Write-Host $line -ForegroundColor Red } else { Write-Host $line }
            if ($f.match_text) {
                if ($script:UseColor) { Write-Host "         $($f.match_text)" -ForegroundColor DarkGray } else { Write-Host "         $($f.match_text)" }
            }
            if ($f.key_name) {
                if ($script:UseColor) { Write-Host "         key=$($f.key_name)" -ForegroundColor DarkGray } else { Write-Host "         key=$($f.key_name)" }
            }
        }
        if ($med -gt 0) {
            Write-Host ""
            Write-Host "-----------------------------------------------------"
            if ($script:UseColor) {
                Write-Host "  " -NoNewline; Write-Host "MEDIUM" -ForegroundColor Yellow -NoNewline; Write-Host "-confidence findings ($med)"
            } else {
                Write-Host "  MEDIUM-confidence findings ($med)"
            }
            Write-Host "-----------------------------------------------------"
            foreach ($f in ($script:Findings | Where-Object { $_.confidence -eq 'MEDIUM' } | Select-Object -First 25)) {
                $loc = if ($f.line_no -and $f.line_no -gt 0) { ":$($f.line_no)" } else { '' }
                $line = "  [MED]  {0,-26} {1}{2}" -f $f.rule_id, $f.abs_path, $loc
                if ($script:UseColor) { Write-Host $line -ForegroundColor Yellow } else { Write-Host $line }
                if ($f.match_text) {
                    if ($script:UseColor) { Write-Host "         $($f.match_text)" -ForegroundColor DarkGray } else { Write-Host "         $($f.match_text)" }
                }
            }
            if ($med -gt 25) { Write-Host "  ... and $($med - 25) more (see findings.txt)" }
        }
        if ($low -gt 0 -and $MinConfidence -eq 'LOW') {
            Write-Host ""
            Write-Host "-----------------------------------------------------"
            if ($script:UseColor) {
                Write-Host "  " -NoNewline; Write-Host "LOW" -ForegroundColor Cyan -NoNewline; Write-Host "-confidence findings ($low) (truncated)"
            } else {
                Write-Host "  LOW-confidence findings ($low) (truncated)"
            }
            Write-Host "-----------------------------------------------------"
            foreach ($f in ($script:Findings | Where-Object { $_.confidence -eq 'LOW' } | Select-Object -First 10)) {
                $loc = if ($f.line_no -and $f.line_no -gt 0) { ":$($f.line_no)" } else { '' }
                $line = "  [LOW]  {0,-26} {1}{2}" -f $f.rule_id, $f.abs_path, $loc
                if ($script:UseColor) { Write-Host $line -ForegroundColor Cyan } else { Write-Host $line }
                if ($f.fp_reason) { Write-Host "         fp_reason=$($f.fp_reason)" -ForegroundColor DarkGray }
            }
            if ($low -gt 10) { Write-Host "  ... and $($low - 10) more (see findings.txt)" }
        }
        Write-Host ""
        Write-Host "====================================================="
        Write-Host "  Summary"
        Write-Host "-----------------------------------------------------"
        Write-Host ("   Total findings:     {0,5}   (HIGH: {1}, MEDIUM: {2}, LOW: {3})" -f $total, $high, $med, $low)
        Write-Host ("   Scanned files:      {0,5}" -f $script:ScannedCount)
        Write-Host ("   Skipped (size):     {0,5}" -f $script:SkippedCounts['size'])
        Write-Host ("   Skipped (binary):   {0,5}" -f $script:SkippedCounts['binary'])
        Write-Host ("   Skipped (perm):     {0,5}" -f $script:SkippedCounts['perm'])
        Write-Host ("   Skipped (excluded): {0,5}" -f $script:SkippedCounts['excluded'])
        Write-Host ("   Dedup suppressed:   {0,5}" -f $script:DupSuppressed)
        if ($Output -ne 'console') {
            Write-Host ("   Report:    {0}" -f $script:FindTxt)
            Write-Host ("              {0}" -f $script:FindJsonl)
            Write-Host ("              {0}" -f $script:SkippedLog)
        }
        Write-Host ""
        Write-Host "   !! findings contain plaintext credentials; delete $OutDir post-engagement"
        Write-Host "====================================================="
    }

    if ($CollectLoot) {
        try {
            New-Item -ItemType Directory -Path $script:LootDir -Force | Out-Null
            foreach ($f in ($script:Findings | Where-Object { $_.rule_id -in @('class_a.filename','class_a.file_present','pem.private_key') })) {
                try {
                    $dest = Join-Path $script:LootDir (Split-Path $f.abs_path -Leaf)
                    Copy-Item -LiteralPath $f.abs_path -Destination $dest -Force -ErrorAction SilentlyContinue
                } catch {}
            }
        } catch {}
    }

    if ($total -gt 0) { $script:ExitCode = 1 } else { $script:ExitCode = 0 }
}

$script:ExitCode = 0
Invoke-Phase2
Invoke-Phase3
Invoke-Phase4
Invoke-Phase5
exit $script:ExitCode
