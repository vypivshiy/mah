# extract_msi.ps1
# Извлекает MSI через 7z, ищет *core*.dll
# и удаляет временную папку после успешного завершения

param(
    [string]$Msi = ".\MAX.msi",
    [string]$Out = ".\extract"
)

if (!(Test-Path $Msi)) {
    Write-Host "MSI not found: $Msi"
    exit 1
}

try {
    # удалить старую папку
    if (Test-Path $Out) {
        Remove-Item $Out -Recurse -Force
    }

    New-Item -ItemType Directory -Path $Out | Out-Null

    Write-Host "Extracting MSI..."
    & 7z x $Msi "-o$Out" -y | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "7z extraction failed"
    }

    Write-Host ""
    Write-Host "Searching for *.core.dll and *.config.dll ..."
    Write-Host ""
    # real file name in researches: CM_FP_Unspecified.core.dll
    $dlls = Get-ChildItem $Out -Recurse -Include *.core.dll,*.config.dll -ErrorAction SilentlyContinue

    if ($dlls) {
        $dlls | Select-Object FullName, Length | Format-Table -AutoSize

        # копируем найденные dll рядом со скриптом
        foreach ($dll in $dlls) {
            Copy-Item $dll.FullName -Destination ".\" -Force
        }

        Write-Host ""
        Write-Host "DLL files copied to current directory."
    }
    else {
        Write-Host "No matching DLL files found."
    }

    # удалить временную папку
    Remove-Item $Out -Recurse -Force

    Write-Host ""
    Write-Host "Temporary extraction folder removed."

}
catch {
    Write-Host ""
    Write-Host "ERROR: $_"

    # попытка cleanup при ошибке
    if (Test-Path $Out) {
        Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
    }

    exit 1
}