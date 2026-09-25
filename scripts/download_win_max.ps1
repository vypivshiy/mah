# download_win_max.ps1
# Downloads Windows client MSI installer for MAX

param(
    [Parameter(Position = 0)]
    [Alias("OutFile", "Output")]
    [string]$Out
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$RepoRoot = Split-Path -Parent $ScriptDir

if (-not $Out) {
    $Out = Join-Path $RepoRoot "MAX.msi"
} elseif ((Test-Path $Out -PathType Container) -or $Out.EndsWith("\") -or $Out.EndsWith("/")) {
    $Out = Join-Path $Out "MAX.msi"
    if (-not [System.IO.Path]::IsPathRooted($Out)) {
        $Out = Join-Path (Get-Location).Path $Out
    }
} else {
    if (-not [System.IO.Path]::IsPathRooted($Out)) {
        $Out = Join-Path (Get-Location).Path $Out
    }
}

$parentDir = Split-Path -Parent $Out
if ($parentDir -and !(Test-Path $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

$config = Invoke-RestMethod -Uri 'https://max.ru/_api_/config' `
  -Headers @{
    'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
    'Accept'          = '*/*'
    'Accept-Language'  = 'en-US,en;q=0.9'
    'Referer'         = 'https://download.max.ru/'
    'Origin'          = 'https://download.max.ru'
  }

$url = $config.windowsDesktop
if (-not $url) { throw "Key 'windowsDesktop' not found in config" }

Write-Host "Downloading: $url"
Invoke-WebRequest -Uri $url -OutFile $Out -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
Write-Host "Saved to $Out"
