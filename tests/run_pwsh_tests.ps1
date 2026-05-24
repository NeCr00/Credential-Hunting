# Smoke test for credhunter.ps1
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')
Get-ChildItem -Filter 'credhunter-loot-*' -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
$out = & $pwsh -NoProfile -ExecutionPolicy Bypass -File .\credhunter.ps1 -Output console -NoColor -SkipKnownLocations tests\fixtures\windows 2>&1 | Out-String

Write-Host "----- captured output -----"
Write-Host $out
Write-Host "----- end output -----"

$fail = $false
function Assert-Find($pat) {
  if ($out -notmatch [regex]::Escape($pat)) {
    Write-Host "FAIL: $pat"
    $script:fail = $true
  } else {
    Write-Host "PASS: $pat"
  }
}

Assert-Find 'dotnet.connstr'
Assert-Find 'gpp.cpassword'
Assert-Find 'unattend'

if (-not $fail) {
  Write-Host "ALL TESTS PASSED"
  exit 0
} else {
  Write-Host "SOME TESTS FAILED"
  exit 1
}
