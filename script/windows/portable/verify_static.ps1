#
# Static verification of the staged portable folder.
#
# Checks (all of them run; the script reports everything, then exits):
#   1. Every DLL imported by any exe/dll in the folder is shipped next to the
#      importer or is a Windows 10 system DLL (allow-list).
#   2. warp-oss.exe embeds a manifest requesting asInvoker.
#   3. PORTABLE-README.txt exists and contains the expected strings.
#
# Imports and manifests need dumpbin.exe / mt.exe and therefore Windows.
# `-SelfTest` exercises the pure logic on any OS.

[CmdletBinding()]
param(
    [string]$Folder,
    [string]$AllowListPath = (Join-Path -Path $PSScriptRoot -ChildPath 'windows10-system-dlls.txt'),
    [string[]]$ExpectedStrings = @(),
    [string]$ReportPath,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-AllowList {
    # Lines ending in '*' are prefixes (api-ms-win-*), everything else is an
    # exact DLL name.
    param([Parameter(Mandatory = $true)][string]$Path)

    $names = [System.Collections.Generic.List[string]]::new()
    $prefixes = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        if ($line.EndsWith('*')) {
            $prefixes.Add($line.Substring(0, $line.Length - 1).ToLowerInvariant())
        } else {
            $names.Add($line.ToLowerInvariant())
        }
    }
    return [pscustomobject]@{ Names = $names.ToArray(); Prefixes = $prefixes.ToArray() }
}

function Test-ImportClosure {
    # Pure: no file system access, so it can be tested anywhere.
    param(
        [Parameter(Mandatory = $true)][hashtable]$Imports,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ShippedNames,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$AllowList,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$AllowPrefixes
    )

    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $shipped = [System.Collections.Generic.HashSet[string]]::new($ShippedNames, $comparer)
    $system = [System.Collections.Generic.HashSet[string]]::new($AllowList, $comparer)

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($file in ($Imports.Keys | Sort-Object)) {
        foreach ($dll in ($Imports[$file] | Sort-Object -Unique)) {
            $status = 'Missing'
            if ($shipped.Contains($dll)) {
                $status = 'Shipped'
            } elseif ($system.Contains($dll)) {
                $status = 'System'
            } else {
                foreach ($prefix in $AllowPrefixes) {
                    if ($dll.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $status = 'System'
                        break
                    }
                }
            }
            $results.Add([pscustomobject]@{ File = $file; Dll = $dll; Status = $status })
        }
    }
    return , $results.ToArray()
}

function Get-DllNamesFromDumpbin {
    # dumpbin prints each imported DLL on its own line indented by exactly
    # four spaces, in both the normal and the delay-load import sections.
    # Function names are indented further and start with a hex address.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Lines)

    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $Lines) {
        if ($line -match '^ {4}(\S+\.dll)\s*$') {
            [void]$names.Add($Matches[1])
        }
    }
    return , @($names)
}

function Get-ExecutionLevel {
    # Namespace-agnostic: the manifest nests it under asmv3 elements.
    param([Parameter(Mandatory = $true)][string]$ManifestXml)

    $xml = [xml]$ManifestXml
    $node = $xml.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
    if ($null -eq $node) { return $null }
    return $node.GetAttribute('level')
}

function Find-DumpBin {
    $vswhere = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "vswhere.exe not found at $vswhere"
    }
    $found = @(& $vswhere -latest -products '*' -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' -find '**\Hostx64\x64\dumpbin.exe')
    if ($found.Count -eq 0 -or -not $found[0]) {
        throw 'dumpbin.exe not found via vswhere'
    }
    return $found[0]
}

function Find-MtExe {
    $pattern = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Windows Kits\10\bin\*\x64\mt.exe'
    # Directory names are versions like 10.0.22621.0; sort as versions, not text.
    $candidates = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
            Sort-Object -Property { try { [version](Split-Path -Path (Split-Path -Path (Split-Path -Path $_.FullName -Parent) -Parent) -Leaf) } catch { [version]'0.0' } } -Descending)
    if ($candidates.Count -eq 0) {
        throw 'mt.exe not found under the Windows SDK'
    }
    return $candidates[0].FullName
}

function Get-RelativePath {
    param([string]$Root, [string]$Path)
    return [System.IO.Path]::GetRelativePath($Root, $Path)
}

function Invoke-ImportCheck {
    param([string]$Root, [string[]]$AllowNames, [string[]]$AllowPrefixes)

    $dumpbin = Find-DumpBin
    $files = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        $lines = @(& $dumpbin /nologo /imports $file.FullName)
        if ($LASTEXITCODE -ne 0) {
            throw "dumpbin failed on $($file.FullName)"
        }
        $imports = @{ (Get-RelativePath -Root $Root -Path $file.FullName) = (Get-DllNamesFromDumpbin -Lines $lines) }
        # The loader looks next to the importing file first, so only DLLs in
        # that same directory count as shipped for it.
        $sameDir = @(Get-ChildItem -LiteralPath $file.DirectoryName -File -Filter '*.dll' | ForEach-Object { $_.Name })
        $all.AddRange([object[]](Test-ImportClosure -Imports $imports -ShippedNames $sameDir -AllowList $AllowNames -AllowPrefixes $AllowPrefixes))
    }
    return , $all.ToArray()
}

function Invoke-ManifestCheck {
    param([string]$Root)

    $mt = Find-MtExe
    $rows = [System.Collections.Generic.List[object]]::new()
    $exes = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.exe')
    foreach ($exe in $exes) {
        $rel = Get-RelativePath -Root $Root -Path $exe.FullName
        $isMain = ($rel -eq 'warp-oss.exe')
        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            & $mt -nologo "-inputresource:$($exe.FullName);#1" "-out:$tmp" | Out-Null
            if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $tmp).Length -eq 0) {
                $level = $null
                $detail = 'no embedded manifest'
            } else {
                $level = Get-ExecutionLevel -ManifestXml ([System.IO.File]::ReadAllText($tmp))
                $detail = if ($null -eq $level) { 'manifest has no requestedExecutionLevel' } else { $level }
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
        $status = if ($isMain) { if ($level -eq 'asInvoker') { 'Pass' } else { 'Fail' } } else { 'Info' }
        $rows.Add([pscustomobject]@{ File = $rel; Level = $detail; Status = $status })
    }
    if (-not ($rows | Where-Object { $_.File -eq 'warp-oss.exe' })) {
        $rows.Add([pscustomobject]@{ File = 'warp-oss.exe'; Level = 'file not found'; Status = 'Fail' })
    }
    return , $rows.ToArray()
}

function Invoke-ReadmeCheck {
    param([string]$Root, [string[]]$Expected)

    $rows = [System.Collections.Generic.List[object]]::new()
    $path = Join-Path -Path $Root -ChildPath 'PORTABLE-README.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $rows.Add([pscustomobject]@{ Check = 'PORTABLE-README.txt exists'; Status = 'Fail' })
        return , $rows.ToArray()
    }
    $rows.Add([pscustomobject]@{ Check = 'PORTABLE-README.txt exists'; Status = 'Pass' })
    $text = [System.IO.File]::ReadAllText($path)
    foreach ($s in $Expected) {
        $ok = $text.Contains($s)
        $rows.Add([pscustomobject]@{ Check = "contains '$s'"; Status = $(if ($ok) { 'Pass' } else { 'Fail' }) })
    }
    return , $rows.ToArray()
}

function Invoke-SelfTest {
    $failures = [System.Collections.Generic.List[string]]::new()
    function Assert-Equal {
        param($Actual, $Expected, [string]$What)
        if ($Actual -ne $Expected) { $failures.Add("$What : expected '$Expected', got '$Actual'") }
    }

    $imports = @{
        'warp-oss.exe' = @('VCRUNTIME140.dll', 'KERNEL32.dll', 'api-ms-win-core-synch-l1-2-0.dll', 'evil-missing.dll')
    }
    $r = Test-ImportClosure -Imports $imports -ShippedNames @('vcruntime140.dll') -AllowList @('kernel32.dll') -AllowPrefixes @('api-ms-win-')
    $byDll = @{}
    foreach ($row in $r) { $byDll[$row.Dll] = $row.Status }
    Assert-Equal $r.Count 4 'row count'
    Assert-Equal $byDll['VCRUNTIME140.dll'] 'Shipped' 'shipped (case-insensitive)'
    Assert-Equal $byDll['KERNEL32.dll'] 'System' 'system (case-insensitive)'
    Assert-Equal $byDll['api-ms-win-core-synch-l1-2-0.dll'] 'System' 'api-set prefix'
    Assert-Equal $byDll['evil-missing.dll'] 'Missing' 'missing'

    $sample = @('Dump of file x.exe', '  Section contains the following imports:', '', '    KERNEL32.dll', '             140000000 Import Address Table', '                    1A5 GetLastError',
        '  Section contains the following delay load imports:', '', '    SHELL32.dll', '    Ordinal 3')
    $names = Get-DllNamesFromDumpbin -Lines $sample
    Assert-Equal ($names -join ',') 'KERNEL32.dll,SHELL32.dll' 'dumpbin parsing incl. delay load'

    $manifest = '<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>'
    Assert-Equal (Get-ExecutionLevel -ManifestXml $manifest) 'asInvoker' 'manifest level'
    Assert-Equal ($null -eq (Get-ExecutionLevel -ManifestXml '<assembly/>')) $true 'manifest without level'

    if (Test-Path -LiteralPath $AllowListPath -PathType Leaf) {
        $allow = Read-AllowList -Path $AllowListPath
        Assert-Equal ($allow.Prefixes -contains 'api-ms-win-') $true 'allow-list prefix parsed'
        Assert-Equal ($allow.Names -contains 'kernel32.dll') $true 'allow-list name parsed'
        Assert-Equal ($allow.Names -contains 'vcruntime140.dll') $false 'allow-list must not contain vcruntime140'
    } else {
        $failures.Add("allow-list not found: $AllowListPath")
    }

    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { [Console]::Error.WriteLine("SELFTEST FAIL: $_") }
        return $false
    }
    Write-Host 'SelfTest passed.'
    return $true
}

function ConvertTo-MarkdownTable {
    param([object[]]$Rows, [string[]]$Columns)
    if ($Rows.Count -eq 0) { return "_none_`n" }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('| ' + ($Columns -join ' | ') + ' |')
    [void]$sb.AppendLine('|' + (($Columns | ForEach-Object { '---' }) -join '|') + '|')
    foreach ($row in $Rows) {
        $cells = foreach ($c in $Columns) { "$($row.$c)".Replace('|', '\|') }
        [void]$sb.AppendLine('| ' + ($cells -join ' | ') + ' |')
    }
    return $sb.ToString()
}

function Invoke-Main {
    if ($SelfTest) {
        if (Invoke-SelfTest) { return 0 } else { return 1 }
    }
    if (-not $Folder) { throw '-Folder is required.' }
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { throw "Folder not found: $Folder" }
    $root = (Resolve-Path -LiteralPath $Folder).ProviderPath

    # Every section runs even if an earlier one failed, so one run shows all problems.
    $problems = [System.Collections.Generic.List[string]]::new()

    $imports = @()
    try {
        $allow = Read-AllowList -Path $AllowListPath
        $imports = Invoke-ImportCheck -Root $root -AllowNames $allow.Names -AllowPrefixes $allow.Prefixes
        foreach ($m in ($imports | Where-Object { $_.Status -eq 'Missing' })) {
            $problems.Add("Import not shipped and not a Windows 10 system DLL: $($m.File) -> $($m.Dll)")
        }
    } catch {
        $problems.Add("Import check could not run: $($_.Exception.Message)")
    }

    $manifests = @()
    try {
        $manifests = Invoke-ManifestCheck -Root $root
        foreach ($m in ($manifests | Where-Object { $_.Status -eq 'Fail' })) {
            $problems.Add("Manifest check failed for $($m.File): $($m.Level)")
        }
    } catch {
        $problems.Add("Manifest check could not run: $($_.Exception.Message)")
    }

    $readme = @()
    try {
        $readme = Invoke-ReadmeCheck -Root $root -Expected $ExpectedStrings
        foreach ($m in ($readme | Where-Object { $_.Status -eq 'Fail' })) {
            $problems.Add("Readme check failed: $($m.Check)")
        }
    } catch {
        $problems.Add("Readme check could not run: $($_.Exception.Message)")
    }

    Write-Host '== Imports =='
    Write-Host ($imports | Format-Table -AutoSize -Property File, Dll, Status | Out-String -Width 300)
    Write-Host '== Manifest =='
    Write-Host ($manifests | Format-Table -AutoSize -Property File, Level, Status | Out-String -Width 300)
    Write-Host '== Readme =='
    Write-Host ($readme | Format-Table -AutoSize -Property Check, Status | Out-String -Width 300)
    $result = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' }
    Write-Host "== Result: $result =="
    foreach ($p in $problems) { Write-Host "  - $p" }

    if ($ReportPath) {
        $md = [System.Text.StringBuilder]::new()
        [void]$md.AppendLine('# Static verification')
        [void]$md.AppendLine()
        [void]$md.AppendLine('## Imports')
        [void]$md.AppendLine()
        [void]$md.Append((ConvertTo-MarkdownTable -Rows $imports -Columns @('File', 'Dll', 'Status')))
        [void]$md.AppendLine()
        [void]$md.AppendLine('## Manifest')
        [void]$md.AppendLine()
        [void]$md.Append((ConvertTo-MarkdownTable -Rows $manifests -Columns @('File', 'Level', 'Status')))
        [void]$md.AppendLine()
        [void]$md.AppendLine('## Readme')
        [void]$md.AppendLine()
        [void]$md.Append((ConvertTo-MarkdownTable -Rows $readme -Columns @('Check', 'Status')))
        [void]$md.AppendLine()
        [void]$md.AppendLine('## Result')
        [void]$md.AppendLine()
        [void]$md.AppendLine("**$result**")
        foreach ($p in $problems) { [void]$md.AppendLine("- $p") }
        [System.IO.File]::WriteAllText($ReportPath, $md.ToString(), [System.Text.UTF8Encoding]::new($false))
    }

    if ($problems.Count -eq 0) { return 0 } else { return 1 }
}

try {
    $code = Invoke-Main
} catch {
    [Console]::Error.WriteLine("verify_static.ps1 failed: $($_.Exception.Message)")
    exit 1
}
exit $code
