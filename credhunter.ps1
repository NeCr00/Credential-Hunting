<#
.SYNOPSIS
  credhunter.ps1 - internal-pentest credential hunter (Windows)
.DESCRIPTION
  Hardcoded-credential hunter for authorized internal pentesting.
  Spec: docs/specs/2026-05-24-credhunter-design.md
  Authorized use only.
.PARAMETER Output
  console | file | both (default: both)
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

$script:Findings = New-Object System.Collections.Generic.List[hashtable]
$script:DedupSet = New-Object System.Collections.Generic.HashSet[string]
$script:SeenInodes = New-Object System.Collections.Generic.HashSet[string]
$script:SkippedCounts = @{ size=0; binary=0; perm=0; excluded=0 }
$script:ScannedCount = 0

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
    param([string]$Path)
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

function Get-LineNumber {
    param([string]$Content, [int]$Offset)
    if ($Offset -le 0 -or -not $Content) { return 1 }
    $slice = $Content.Substring(0, [Math]::Min($Offset, $Content.Length))
    $count = 1
    for ($i = 0; $i -lt $slice.Length; $i++) {
        if ($slice[$i] -eq "`n") { $count++ }
    }
    return $count
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
    param([string]$S)
    if ($ShowSecrets) { return $S }
    if ([string]::IsNullOrEmpty($S)) { return '' }
    if ($S.Length -le 4) { return '****' }
    $stars = '*' * ($S.Length - 4)
    return ($S.Substring(0, 2) + $stars + $S.Substring($S.Length - 2, 2))
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

function Get-FileMetadata {
    param([string]$Path)
    $meta = @{ mtime=''; size=0; mode=''; owner='' }
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            $it = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            if ($it) {
                $meta.mtime = $it.LastWriteTimeUtc.ToString('o')
                if ($it -is [System.IO.FileInfo]) { $meta.size = $it.Length }
                $meta.mode = $it.Mode
                if ($script:IsWindowsHost) {
                    try {
                        $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
                        if ($acl) { $meta.owner = $acl.Owner }
                    } catch {}
                }
            }
        }
    } catch {}
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

    $dedup = Get-DedupKey -RuleId $F.rule_id -Path $F.abs_path -LineNo $F.line_no -Match $F.match_text
    if (-not $script:DedupSet.Add($dedup)) { return }

    $F.dedup_key      = $dedup
    $F.host           = $script:HOSTN
    $F.scan_user      = $script:CurrentUser
    $F.scan_user_priv = $script:Priv
    $F.match_redacted = Format-Redacted $F.match_text

    $meta = Get-FileMetadata $F.abs_path
    $F.file_mtime = $meta.mtime
    $F.file_size  = $meta.size
    $F.file_mode  = $meta.mode
    $F.file_owner = $meta.owner

    $script:Findings.Add($F)
}

function Save-Finding {
    param([hashtable]$F)
    $json = $F | ConvertTo-Json -Compress -Depth 6
    Add-Content -LiteralPath $script:FindJsonl -Value $json -Encoding utf8

    $loc = ''
    if ($F.line_no -and $F.line_no -gt 0) { $loc = ":$($F.line_no)" }
    $hdr = "[{0}] {1,-26} {2}{3}" -f $F.confidence, $F.rule_id, $F.abs_path, $loc
    Add-Content -LiteralPath $script:FindTxt -Value $hdr -Encoding utf8
    if ($F.match_text) {
        if ($ShowSecrets) {
            Add-Content -LiteralPath $script:FindTxt -Value ("       $($F.match_text)") -Encoding utf8
        } else {
            Add-Content -LiteralPath $script:FindTxt -Value ("       $($F.match_redacted)") -Encoding utf8
        }
    }
    if ($F.fp_reason) {
        Add-Content -LiteralPath $script:FindTxt -Value ("       fp_reason=$($F.fp_reason)") -Encoding utf8
    }
    if ($F.key_name) {
        Add-Content -LiteralPath $script:FindTxt -Value ("       key=$($F.key_name)") -Encoding utf8
    }
}

function Add-Skipped {
    param([string]$Path, [string]$Reason)
    try { Add-Content -LiteralPath $script:SkippedLog -Value "$Path`t$Reason" -Encoding utf8 } catch {}
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
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $aes.KeySize = 256
            $aes.Key     = $script:GppKey
            $aes.IV      = New-Object byte[] 16
            $dec = $aes.CreateDecryptor()
            try {
                $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)
            } finally { $dec.Dispose() }
            $text = [System.Text.Encoding]::Unicode.GetString($pt)
            return $text.TrimEnd([char]0)
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
            $k = $key[($seed + $i / 2) % $key.Length]
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
    $pat = '-----BEGIN (?<t>(RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP |SSH2 ENCRYPTED )?)PRIVATE KEY[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----'
    $rx = [regex]::new($pat, 'Multiline')
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
    foreach ($m in [regex]::Matches($Content, '(?m)^PuTTY-User-Key-File-[23]:\s*(?<algo>\S+)')) {
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
    foreach ($m in [regex]::Matches($Content, '(?m)^\s*PrivateKey\s*=\s*(?<k>[A-Za-z0-9+/]{43}=)')) {
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
        foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, '\$krb5asrep\$(?<et>17|18|23)\$[^:\s]{1,256}:[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}')) {
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
    foreach ($m in [regex]::Matches($Content, '\$krb5tgs\$(?<et>17|18|23)\$\*[^*\s]{1,256}\*\$[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}')) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, '(?i)<user\b[^>]*\bpassword\s*=\s*"(?<v>[^"]{1,256})"')) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, '(?m)^\$ANSIBLE_VAULT;\d+\.\d+;AES256')) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
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
        foreach ($m in [regex]::Matches($Content, $p.pat)) {
            $ctx = Get-MatchContext -M $m -Content $Content
            $val = $m.Groups['v'].Value
            if (Test-Placeholder $val) { continue }
            $conf = 'MEDIUM'
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
            Add-Finding @{
                rule_id    = $p.id
                category   = 'PASSWORD'
                confidence = $conf
                base_confidence = 'MEDIUM'
                abs_path   = $Path
                line_no    = $ctx.line_no
                line_text  = $ctx.line_text
                match_text = $val
                key_name   = $p.key
            }
        }
    }
    foreach ($m in [regex]::Matches($Content, '(?i)\bAutoAdminLogon\s*=\s*"?1"?')) {
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
    foreach ($m in [regex]::Matches($Content, $pat)) {
        $ctx = Get-MatchContext -M $m -Content $Content
        $key = $m.Groups['key'].Value
        $val = $m.Groups['val'].Value.Trim()
        if (-not $val) { continue }
        $conf = 'HIGH'
        $baseConf = 'HIGH'
        $demotions = @()
        $fp = $null

        if (Test-Placeholder $val) {
            $conf = 'LOW'; $fp = 'placeholder'; $demotions += 'placeholder'
        } elseif (Test-EnvReference $val) {
            $conf = 'MEDIUM'; $fp = 'env_reference'; $demotions += 'env_reference'
            $cat = 'REFERENCE'
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
        if (-not $entropy) { $entropy = Get-Entropy $val }
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
}

$script:ClassANameRegex = '^(id_rsa|id_dsa|id_ecdsa|id_ed25519|id_xmss|id_ecdsa_sk|id_ed25519_sk|authorized_keys|known_hosts|.htpasswd|.netrc|_netrc|.pgpass|.my\.cnf|.mylogin\.cnf|.smbcredentials|.cifs-credentials|.credentials|.git-credentials|.npmrc|.yarnrc|.yarnrc\.yml|kubeconfig|wg0\.conf|krb5\.keytab|azureProfile\.json|accessTokens\.json|application_default_credentials\.json|Groups\.xml|Services\.xml|ScheduledTasks\.xml|Drives\.xml|Printers\.xml|DataSources\.xml|unattend\.xml|autounattend\.xml|sysprep\.inf|sysprep\.xml|shadow\.bak|shadow\.old|shadow-|passwd\.bak|passwd-|gshadow\.bak|SAM|SYSTEM|SECURITY|ntds\.dit|WinSCP\.ini|sitemanager\.xml|recentservers\.xml|filezilla\.xml|confCons\.xml|MobaXterm\.ini|RDCMan\.settings|credentials\.xml|master\.key|hudson\.util\.Secret|initialAdminPassword|\.env|wp-config\.php|wp-config-sample\.php|configuration\.php|LocalSettings\.php|local\.xml|database\.yml|web\.config|app\.config|machine\.config|connectionStrings\.config|tnsnames\.ora|sqlnet\.ora|wallet\.sso|cwallet\.sso)$'

$script:ClassAExtRegex = '\.(kdbx|kdb|psafe3|agilekeychain|opvault|1pif|pem|key|priv|pk8|pkcs8|rsa|dsa|ec|ppk|openssh|pfx|p12|jks|keystore|bks|uber|pkcs12|kubeconfig|ovpn|keytab|rdg|rdp|ica|tds|rtsz|rtsx)$'

function Test-ClassAFile {
    param([string]$Name)
    if (-not $Name) { return $false }
    if ($Name -match $script:ClassANameRegex) { return $true }
    if ($Name -match $script:ClassAExtRegex) { return $true }
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
    if ($lower -match $script:SkipExtRegex) { return $false }
    if ($lower -match $script:SkipNameRegex) { return $false }
    if ($All) { return $true }
    if ($lower -match $script:DefaultExtRegex) { return $true }
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
    param([string]$Root)
    $result = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    try {
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($Root)
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop()
            try {
                $di = [System.IO.DirectoryInfo]::new($cur)
                if (-not $di.Exists) { continue }
                $entries = $null
                try { $entries = $di.GetFileSystemInfos() } catch { Add-Skipped $cur 'perm'; continue }
                foreach ($e in $entries) {
                    $full = $e.FullName
                    if (Test-Excluded $full) { continue }
                    if ($e -is [System.IO.DirectoryInfo]) {
                        if ((-not $FollowSymlinks) -and ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { continue }
                        $stack.Push($full)
                    } else {
                        if ((-not $FollowSymlinks) -and ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { continue }
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

    foreach ($p in $script:KnownPaths) {
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

    Invoke-RegistryProbes
    Invoke-CmdkeyList
    Invoke-VaultCmd

    $post = $script:Findings.Count
    Write-Info ("  {0} findings" -f ($post - $pre))
}

function Invoke-Phase3 {
    Write-Phase 'phase 3/5' 'filename-pattern hunt'
    $pre = $script:Findings.Count
    foreach ($r in $ScanRoots) {
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
        $files = Get-CandidateFiles $r
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
    $post = $script:Findings.Count
    Write-Info ("  {0} findings" -f ($post - $pre))
}

function Invoke-Phase4 {
    if ($SkipContentScan) { return }
    Write-Phase 'phase 4/5' 'content scan'
    $pre = $script:Findings.Count
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($r in $ScanRoots) {
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        try {
            $rootInfo = Get-Item -LiteralPath $r -Force -ErrorAction SilentlyContinue
            if ($rootInfo -is [System.IO.FileInfo]) {
                if (Test-ExtensionAllowed $rootInfo.Name) { $candidates.Add($rootInfo.FullName) }
                continue
            }
        } catch {}
        $files = Get-CandidateFiles $r
        foreach ($fi in $files) {
            if (Test-ExtensionAllowed $fi.Name) { $candidates.Add($fi.FullName) }
        }
    }
    Write-Info ("  ({0} candidate files)" -f $candidates.Count)
    if ($Workers -le 1 -or $candidates.Count -lt 4 -or $PSVersionTable.PSVersion.Major -lt 7) {
        foreach ($f in $candidates) { Scan-FileContent $f }
    } else {
        foreach ($f in $candidates) { Scan-FileContent $f }
    }
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
    foreach ($f in $script:Findings) { Save-Finding $f }

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
                $shown = if ($ShowSecrets) { $f.match_text } else { $f.match_redacted }
                if ($script:UseColor) { Write-Host "         $shown" -ForegroundColor DarkGray } else { Write-Host "         $shown" }
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
                    $shown = if ($ShowSecrets) { $f.match_text } else { $f.match_redacted }
                    if ($script:UseColor) { Write-Host "         $shown" -ForegroundColor DarkGray } else { Write-Host "         $shown" }
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
        Write-Host ("   Report:    {0}" -f $script:FindTxt)
        Write-Host ("              {0}" -f $script:FindJsonl)
        Write-Host ("              {0}" -f $script:SkippedLog)
        if ($ShowSecrets) {
            Write-Host ""
            Write-Host "   !! --show-secrets emitted plaintext to disk; delete $OutDir post-engagement"
        }
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
