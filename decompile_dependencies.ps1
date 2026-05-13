#!/usr/bin/env pwsh
# Decompiles all non-Microsoft dependency DLLs from the Release build output
# into tmp/<assembly-name>/ using ilspycmd (invoked via `dnx ilspycmd`).
# Run from the repo root after building the project in Release configuration.

$ErrorActionPreference = "Stop"

$binDir = Join-Path $PSScriptRoot "AuthenticatorChooser\bin\Release\net8.0-windows"
$outRoot = Join-Path $PSScriptRoot "tmp"

$assemblies = @(
    "Unfucked.Windows",
    "Unfucked",
    "ThrottleDebounce",
    "mwinapi",
    "Workshell.PE",
    "Workshell.PE.Resources",
    "ManagedWinapiNativeHelper"
)

foreach ($name in $assemblies) {
    $dll    = Join-Path $binDir "$name.dll"
    $outDir = Join-Path $outRoot $name
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Write-Host "Decompiling $name ..."
    dnx ilspycmd $dll -p -o $outDir
}

# Resources satellite assemblies — one subfolder per locale
$resourceDlls = Get-ChildItem -Path $binDir -Recurse -Filter "AuthenticatorChooser.resources.dll"
foreach ($dll in $resourceDlls) {
    $locale = $dll.Directory.Name
    $outDir = Join-Path $outRoot "AuthenticatorChooser.resources\$locale"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Write-Host "Decompiling AuthenticatorChooser.resources ($locale) ..."
    dnx ilspycmd $dll.FullName -p -o $outDir
}

Write-Host "Done. Output written to: $outRoot"
