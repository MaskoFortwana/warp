#Requires -Version 7.0
#
# Builds, stages and zips the portable Warp (OSS channel, x64).
#
# Mirrors `bundle.ps1 -CHANNEL oss` without editing it. The list of runtime
# files is read from the [Files] section of windows-installer.iss so a new
# upstream runtime file is picked up, or fails the build, instead of being
# silently missed.
#
# Run from the repository root:
#   pwsh script\windows\bundle_portable.ps1 -Version 2026.11.11-portable.12 -Stage
#   pwsh script\windows\bundle_portable.ps1 -Version 2026.11.11-portable.12 -Zip
#   pwsh script\windows\bundle_portable.ps1 -Version x -ListFiles   # any OS

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    # Upstream commit this branch is based on. The script cannot compute it on
    # the runner (no upstream remote), so it is a pinned constant.
    [string]$BaseCommit = '2b2ed236f087b47b463f1cd55598485dd7965338',

    [switch]$Stage,
    [switch]$Zip,
    [switch]$ListFiles,
    [switch]$SkipBuild,

    [string]$OutDir = 'dist\portable'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Constants mirroring `bundle.ps1 -CHANNEL oss` for x64.
$script:PlatformTarget = 'x86_64-pc-windows-msvc'
$script:CargoProfile = 'rlto'
$script:WarpBin = 'warp-oss'
$script:ExeName = 'warp-oss.exe'
$script:AppName = 'WarpOss'
$script:Channel = 'oss'
$script:Arch = 'x64'
$script:Features = 'release_bundle,gui,nld_classifier_v3,nld_heuristic_v2,portable'
$script:ForkUrl = 'https://github.com/MaskoFortwana/warp'
$script:StagingName = 'WarpPortable'

function ConvertTo-NativePath {
    # The .iss and our defaults use backslashes; convert so the same logic
    # runs on Linux (tests) and Windows.
    param([Parameter(Mandatory = $true)][string]$Path)
    return $Path.Replace('\', [System.IO.Path]::DirectorySeparatorChar)
}

function Join-NativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Base,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Relative
    )
    if ($Relative -eq '') { return $Base }
    return [System.IO.Path]::GetFullPath((Join-Path -Path $Base -ChildPath (ConvertTo-NativePath -Path $Relative)))
}

function Get-InstallerFileList {
    # Why parse instead of hard-coding: see header. Anything we do not
    # understand throws, because a silently skipped line is a missing file.
    param(
        [Parameter(Mandatory = $true)][string]$IssPath,
        [Parameter(Mandatory = $true)][string]$TargetProfileDir
    )

    $issDir = [System.IO.Path]::GetDirectoryName($IssPath)
    $lines = Get-Content -LiteralPath $IssPath

    $assetsDir = $null
    foreach ($line in $lines) {
        if ($line -match '^\s*#define\s+AssetsDir\s+"([^"]+)"') {
            $assetsDir = $Matches[1]
            break
        }
    }
    if ($null -eq $assetsDir) {
        throw "No '#define AssetsDir' found in $IssPath"
    }

    $map = @{
        '{#TargetProfileDir}' = $TargetProfileDir
        '{#MyAppExeName}'     = $script:ExeName
        '{#AssetsDir}'        = $assetsDir
        '{#Arch}'             = $script:Arch
        '{#ReleaseChannel}'   = $script:Channel
    }
    $allowedFlags = @('ignoreversion', 'recursesubdirs', 'createallsubdirs', 'overwritereadonly')

    $inFiles = $false
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $lines) {
        $line = $raw.Trim()
        if ($line -match '^\[(.+)\]$') {
            $inFiles = ($Matches[1] -eq 'Files')
            continue
        }
        if (-not $inFiles) { continue }
        if ($line -eq '' -or $line.StartsWith(';')) { continue }
        if (-not $line.StartsWith('Source:')) {
            throw "Unrecognised line in [Files]: $line"
        }
        if ($line -notmatch '^Source:\s*"([^"]+)"\s*;\s*DestDir:\s*"([^"]+)"\s*(?:;\s*Flags:\s*(.*?))?\s*$') {
            throw "Cannot parse [Files] entry: $line"
        }
        $source = $Matches[1]
        $destDir = $Matches[2]
        $flagText = if ($Matches.ContainsKey(3)) { $Matches[3] } else { '' }

        foreach ($key in $map.Keys) {
            $source = $source.Replace($key, $map[$key])
            $destDir = $destDir.Replace($key, $map[$key])
        }
        $destDir = $destDir.Replace('{app}', '')
        if ($source -match '\{' -or $destDir -match '\{') {
            throw "Unknown placeholder in [Files] entry: $line"
        }

        $flags = @($flagText -split '\s+' | Where-Object { $_ -ne '' })
        foreach ($flag in $flags) {
            if ($allowedFlags -notcontains $flag) {
                throw "Unsupported flag '$flag' in [Files] entry: $line"
            }
        }
        $recurse = $flags -contains 'recursesubdirs'

        if ($source.EndsWith('\*')) {
            if (-not $recurse) {
                throw "Wildcard source without recursesubdirs is not supported: $line"
            }
            $source = $source.Substring(0, $source.Length - 2)
        } elseif ($source.Contains('*') -or $source.Contains('?')) {
            throw "Unsupported wildcard in source: $line"
        } elseif ($recurse) {
            throw "recursesubdirs on a non-wildcard source is not supported: $line"
        }

        # Absolute sources (the profile dir) stay as they are; the rest is
        # relative to the .iss directory, like Inno Setup resolves it.
        $nativeSource = ConvertTo-NativePath -Path $source
        if ([System.IO.Path]::IsPathRooted($nativeSource)) {
            $fullSource = [System.IO.Path]::GetFullPath($nativeSource)
        } else {
            $fullSource = [System.IO.Path]::GetFullPath((Join-Path -Path $issDir -ChildPath $nativeSource))
        }

        $entries.Add([pscustomobject]@{
                Source          = $fullSource
                DestRelativeDir = $destDir.Trim('\')
                Recurse         = $recurse
            })
    }

    if ($entries.Count -eq 0) {
        throw "No Source entries found in the [Files] section of $IssPath"
    }
    return , $entries.ToArray()
}

function Invoke-PortableBuild {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ProfileDir,
        [Parameter(Mandatory = $true)][string]$Version
    )

    # app/build.rs reads CARGO_FULL_PROFILE to place conpty.dll; the others
    # select the channel and version exactly as bundle.ps1 does.
    $env:CARGO_FULL_PROFILE = $script:CargoProfile
    $env:CARGO_BIN_NAME = $script:Channel
    $env:WARP_APP_NAME = $script:AppName
    $env:GIT_RELEASE_TAG = $Version

    Write-Host "Building $($script:WarpBin) ($($script:CargoProfile), features: $($script:Features))"
    & cargo build --locked -p warp --profile $script:CargoProfile --bin $script:WarpBin --features $script:Features --target $script:PlatformTarget
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }

    $exePath = Join-Path -Path $ProfileDir -ChildPath $script:ExeName
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "Build finished but $exePath does not exist"
    }

    # The schema dump runs the just-built exe once, so this only works on a
    # host that can execute x64 binaries.
    if (-not $env:SETTINGS_SCHEMA_EXECUTABLE) {
        $env:SETTINGS_SCHEMA_EXECUTABLE = $exePath
    }

    $resourcesDir = Join-Path -Path $ProfileDir -ChildPath 'resources'
    $prepare = Join-Path -Path $RepoRoot -ChildPath 'script\windows\prepare_bundled_resources.ps1'
    $global:LASTEXITCODE = 0
    & $prepare -DestinationDir $resourcesDir -Channel $script:Channel
    if ($LASTEXITCODE -ne 0) {
        throw "prepare_bundled_resources.ps1 failed with exit code $LASTEXITCODE"
    }
}

function Copy-FileList {
    param(
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [Parameter(Mandatory = $true)][string]$StagingDir
    )

    foreach ($entry in $Entries) {
        $destDir = Join-NativePath -Base $StagingDir -Relative $entry.DestRelativeDir
        if ($entry.Recurse) {
            if (-not (Test-Path -LiteralPath $entry.Source -PathType Container)) {
                throw "Missing source directory: $($entry.Source)"
            }
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            # Copy children rather than the directory itself so an existing
            # destination does not get a nested duplicate.
            foreach ($child in Get-ChildItem -LiteralPath $entry.Source -Force) {
                Copy-Item -LiteralPath $child.FullName -Destination $destDir -Recurse -Force
            }
        } else {
            if (-not (Test-Path -LiteralPath $entry.Source -PathType Leaf)) {
                throw "Missing source file: $($entry.Source)"
            }
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Copy-Item -LiteralPath $entry.Source -Destination $destDir -Force
        }
    }
}

function New-PortableReadme {
    param(
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][hashtable]$Values
    )

    $text = [System.IO.File]::ReadAllText($TemplatePath)
    foreach ($key in $Values.Keys) {
        $text = $text.Replace($key, $Values[$key])
    }
    if ($text -match '@[A-Z_]+@') {
        throw "Unreplaced placeholder in readme: $($Matches[0])"
    }
    # CRLF so the file looks right in Notepad. Normalise first to avoid CRCRLF.
    $text = $text.Replace("`r`n", "`n").Replace("`n", "`r`n")
    [System.IO.File]::WriteAllText($DestinationPath, $text, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-Staging {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][object[]]$Entries,
        [Parameter(Mandatory = $true)][string]$StagingDir,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$BaseCommit
    )

    if (Test-Path -LiteralPath $StagingDir) {
        Remove-Item -LiteralPath $StagingDir -Recurse -Force
        if (Test-Path -LiteralPath $StagingDir) {
            throw "Could not delete existing staging folder: $StagingDir"
        }
    }
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

    Copy-FileList -Entries $Entries -StagingDir $StagingDir

    foreach ($licence in @('LICENSE-AGPL', 'LICENSE-MIT')) {
        $src = Join-Path -Path $RepoRoot -ChildPath $licence
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
            throw "Missing licence file: $src"
        }
        Copy-Item -LiteralPath $src -Destination $StagingDir -Force
    }

    $buildCommit = (& git -C $RepoRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or -not $buildCommit) {
        throw 'git rev-parse HEAD failed'
    }
    $template = Join-Path -Path $RepoRoot -ChildPath 'script\windows\portable\PORTABLE-README.txt.in'
    New-PortableReadme -TemplatePath $template -DestinationPath (Join-Path -Path $StagingDir -ChildPath 'PORTABLE-README.txt') -Values @{
        '@VERSION@'      = $Version
        '@FORK_URL@'     = $script:ForkUrl
        '@BUILD_COMMIT@' = $buildCommit.Trim()
        '@BASE_COMMIT@'  = $BaseCommit
        '@BUILD_DATE@'   = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
    }

    # The zip must not carry state or debug symbols: a stray data\ folder
    # would silently seed every user's portable copy.
    if (Test-Path -LiteralPath (Join-Path -Path $StagingDir -ChildPath 'data')) {
        throw "Staging folder contains a data folder: $StagingDir"
    }
    $pdbs = @(Get-ChildItem -LiteralPath $StagingDir -Recurse -Force -Filter '*.pdb')
    if ($pdbs.Count -gt 0) {
        throw "Staging folder contains .pdb files: $($pdbs.FullName -join ', ')"
    }
}

function New-PortableZip {
    param(
        [Parameter(Mandatory = $true)][string]$StagingDir,
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$SumsPath
    )

    if (-not (Test-Path -LiteralPath $StagingDir -PathType Container)) {
        throw "Staging folder not found (run with -Stage first): $StagingDir"
    }
    if (Test-Path -LiteralPath $ZipPath) {
        throw "Zip already exists, refusing to overwrite: $ZipPath"
    }

    # Passing the folder itself (not its children) keeps WarpPortable\ as the
    # top-level entry inside the zip.
    Compress-Archive -LiteralPath $StagingDir -DestinationPath $ZipPath

    $hash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = [System.IO.Path]::GetFileName($ZipPath)
    # LF and no BOM so `sha256sum -c` accepts it on any OS.
    [System.IO.File]::WriteAllText($SumsPath, "$hash  $name`n", [System.Text.UTF8Encoding]::new($false))
}

function Write-GitHubOutput {
    param([Parameter(Mandatory = $true)][hashtable]$Values)
    if (-not $env:GITHUB_OUTPUT) { return }
    foreach ($key in $Values.Keys) {
        Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$key=$($Values[$key])"
    }
}

function Invoke-Main {
    $repoRoot = (Get-Location).ProviderPath
    $issPath = Join-Path -Path $repoRoot -ChildPath (ConvertTo-NativePath -Path 'script\windows\windows-installer.iss')
    if (-not (Test-Path -LiteralPath (Join-Path -Path $repoRoot -ChildPath 'Cargo.toml') -PathType Leaf) -or
        -not (Test-Path -LiteralPath $issPath -PathType Leaf)) {
        throw 'Run this script from the repository root (Cargo.toml and script\windows\windows-installer.iss must exist).'
    }
    if (-not ($Stage -or $Zip -or $ListFiles)) {
        throw 'Nothing to do: pass -Stage, -Zip and/or -ListFiles.'
    }

    $profileDir = Join-NativePath -Base $repoRoot -Relative "target\$($script:PlatformTarget)\$($script:CargoProfile)"
    $outDirNative = ConvertTo-NativePath -Path $OutDir
    if (-not [System.IO.Path]::IsPathRooted($outDirNative)) {
        $outDirNative = Join-Path -Path $repoRoot -ChildPath $outDirNative
    }
    $outDirFull = [System.IO.Path]::GetFullPath($outDirNative)
    $stagingDir = Join-Path -Path $outDirFull -ChildPath $script:StagingName
    $zipPath = Join-Path -Path $outDirFull -ChildPath "warp-portable-$($script:Arch)-$Version.zip"
    $sumsPath = Join-Path -Path $outDirFull -ChildPath 'SHA256SUMS'

    # Parse first so an unknown installer entry fails before a long build.
    $entries = Get-InstallerFileList -IssPath $issPath -TargetProfileDir $profileDir

    if ($ListFiles) {
        $entries |
            Select-Object -Property Source, DestRelativeDir, Recurse, @{ Name = 'Exists'; Expression = { Test-Path -LiteralPath $_.Source } } |
            Format-List |
            Out-String -Width 300 |
            Write-Host
        return
    }

    if ($Stage) {
        if (-not $SkipBuild) {
            Invoke-PortableBuild -RepoRoot $repoRoot -ProfileDir $profileDir -Version $Version
        }
        Invoke-Staging -RepoRoot $repoRoot -Entries $entries -StagingDir $stagingDir -Version $Version -BaseCommit $BaseCommit
        Write-Host "Staged: $stagingDir"
    }

    # ---------------------------------------------------------------------
    # Signing slot
    #
    # A future step inserts here: sign WarpPortable\*.exe and
    # WarpPortable\*.dll (including x64\OpenConsole.exe) in place, between
    # "binaries built and staged" and "zip created". See GitHub issue #26.
    # Nothing is signed in v1; deliberately no code here.
    # ---------------------------------------------------------------------

    if ($Zip) {
        New-PortableZip -StagingDir $stagingDir -ZipPath $zipPath -SumsPath $sumsPath
        Write-Host "Zip: $zipPath"
        Write-Host "SHA256SUMS: $sumsPath"
    }

    Write-GitHubOutput -Values @{
        staging_dir     = $stagingDir
        zip_path        = $zipPath
        sha256sums_path = $sumsPath
    }
}

try {
    Invoke-Main
} catch {
    [Console]::Error.WriteLine("bundle_portable.ps1 failed: $($_.Exception.Message)")
    exit 1
}
exit 0
