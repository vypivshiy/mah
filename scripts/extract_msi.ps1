# extract_msi.ps1
# Extracts MSI via 7z, locates *.core.dll and *.config.dll,
# copies them to the destination directory (defaults to repository root),
# and cleans up the temporary extraction directory.

param(
    [Parameter(Position = 0)]
    [Alias("MsiPath", "InputPath")]
    [string]$Msi,

    [Parameter(Position = 1)]
    [Alias("Destination", "Dest", "OutputDir")]
    [string]$Out
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$RepoRoot = Split-Path -Parent $ScriptDir

if (-not $Msi) {
    $Msi = Join-Path $RepoRoot "MAX.msi"
} elseif (-not [System.IO.Path]::IsPathRooted($Msi)) {
    $Msi = Join-Path (Get-Location).Path $Msi
}

if (-not $Out) {
    $Out = $RepoRoot
} elseif (-not [System.IO.Path]::IsPathRooted($Out)) {
    $Out = Join-Path (Get-Location).Path $Out
}

if (!(Test-Path $Msi)) {
    Write-Host "MSI not found: $Msi"
    exit 1
}

if (!(Test-Path $Out)) {
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
}

$tempExtractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("max_msi_extract_" + [System.Guid]::NewGuid().ToString("N"))

try {
    New-Item -ItemType Directory -Path $tempExtractDir -Force | Out-Null

    Write-Host "Target MSI: $Msi"
    Write-Host "Destination: $Out"
    Write-Host "Extracting MSI to temporary directory..."

    & 7z x $Msi "-o$tempExtractDir" -y | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "7z extraction failed with exit code $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "Searching for *.core.dll and *.config.dll ..."
    Write-Host ""

    # Real file name in research: CM_FP_Unspecified.core.dll
    $dlls = Get-ChildItem $tempExtractDir -Recurse -Include *.core.dll,*.config.dll -ErrorAction SilentlyContinue

    if ($dlls) {
        $dlls | Select-Object FullName, Length | Format-Table -AutoSize

        foreach ($dll in $dlls) {
            Copy-Item $dll.FullName -Destination $Out -Force
        }

        Write-Host ""
        Write-Host "DLL files copied to: $Out"
    }
    else {
        Write-Host "No matching DLL files found."
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $_"
    exit 1
}
finally {
    if (Test-Path $tempExtractDir) {
        Remove-Item $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "Temporary extraction folder removed."
    }
}
