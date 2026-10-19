# R4C: local, nonauthoritative test-package preparation. Never installs a service.
[CmdletBinding()]
param([switch]$LibraryOnly, [string]$TaskRoot, [switch]$FixedIpc)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:R4CScriptPath = $PSCommandPath
$script:R4CCrate = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:R4CRepo = [IO.Path]::GetFullPath((Join-Path $script:R4CCrate '..\..\..'))
$script:R4CApprovedSources = @'
[
  {
    "path": "MemoryCore/scripts/build-gateway-candidate.mjs",
    "sha256": "43bd58e0ded2a8240c389e0c9519e9389ed9353e4fd62a97943434fb171342a3"
  },
  {
    "path": "MemoryCore/scripts/build-gateway-candidate.test.mjs",
    "sha256": "9c2af3b5fa9a33f9256d0111cee7f40600aaeaf87a0aded4c72004cc03b235eb"
  },
  {
    "path": "MemoryCore/scripts/generate-gateway-manifest-v2.mjs",
    "sha256": "e9836da8c7d9bab53f8af521ee851c5f09cc94128a1a217fb528bfa65fa2a14d"
  },
  {
    "path": "MemoryCore/scripts/generate-gateway-manifest-v2.test.mjs",
    "sha256": "b81bf0223a5f0b40692aa14d1e08985209885563207c4a4eddad8343b12be7f5"
  },
  {
    "path": "MemoryCore/scripts/package-protected-gateway.mjs",
    "sha256": "ddd255c0e37f4f5e6620b27c03c5546a28136bc568da7790a9af88e31c5599fd"
  },
  {
    "path": "MemoryCore/scripts/package-protected-gateway.test.mjs",
    "sha256": "8644d09145fd8360e24dfd83f3051e2690967a99c95b2029d0c872f9965e048b"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/Cargo.lock",
    "sha256": "c62b425901d72b9355bcc5d41894c45ea8c546cebbb8168435aaedb611e1cde1"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/Cargo.toml",
    "sha256": "908974a2a45578abd1304be9ce5d327c528236aad7141312c0a09c7993355294"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/launch.rs",
    "sha256": "5854a7f150a4ad1b04d9ab56ba1777f2d56c02dcb7356a244d4ed2754916dc02"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/lib.rs",
    "sha256": "6fd96bdb76384a82097042ad59e14cc9c5da5ab8ee494abdcae27e868559ac7a"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/main.rs",
    "sha256": "aa9daa1188fc3c8d567baccb6cab2ba4beb20ed28b51833bec26d654f75d8257"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/peer.rs",
    "sha256": "37cd4c1d4129921d1f5df0a2f1c5397f9ea25e30f055d3858dfffd11c51db40a"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/release.rs",
    "sha256": "d02298e6c6df8ecd3d399caa24fe42d1ce9fc46c862e00f07e345285814b02a9"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/release_v2.rs",
    "sha256": "1c0018a3a7e114bc0f95b26721df8700c57c0a2854c52eef788d25a152279743"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/src/service.rs",
    "sha256": "18dbc4afc3bd5df17d9f67aa849249ef48e15feed06e3253e4be72ff566ea696"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/tests/launch_contract.rs",
    "sha256": "42e9aaba4b8085b25988152a262919f4748c710c4120d247d735c6f6ca238312"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/tests/peer_contract.rs",
    "sha256": "6358e4184388a7aadf479574777137d0f25dc369312d0c6b68e0949ae9e23ce7"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/tests/release_contract.rs",
    "sha256": "a2dd98e92634a8ee944cd31b065eefaba3eb5c9cb2e060948f32d08fdb434d3a"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/tests/release_v2_contract.rs",
    "sha256": "2d82a544c901f5a160d4c959826325d52b8e27b82db002204875b6e97fec66d1"
  },
  {
    "path": "MemoryCore/tools/windows-runtime-boundary/tests/service_contract.rs",
    "sha256": "ce08d0e3fd65aa656412241865c432f9210552d6e011885dea854354be6edb34"
  }
]
'@ | ConvertFrom-Json

function Assert-R4CPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('/') -or $Path.Substring(2).Contains(':')) { throw 'path_rejected' }
    $parts = $Path.Substring(3).Split('\')
    if ($parts.Count -eq 0) { throw 'path_rejected' }
    foreach ($part in $parts) {
        if ([string]::IsNullOrEmpty($part) -or $part -in @('.','..') -or $part -match '[. ]$|[<>:"/\\|?*\x00-\x1f]' -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)') { throw 'path_rejected' }
    }
    $current = $Path.Substring(0,3)
    foreach ($part in $parts) {
        $current = Join-Path $current $part
        # Do not treat I/O/ACL errors as a nonexistent path.
        try { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { continue }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_rejected' }
        if (-not [string]::Equals($item.Name, $part, [StringComparison]::OrdinalIgnoreCase)) { throw 'path_alias_rejected' }
    }
    return [IO.Path]::GetFullPath($Path)
}
function Get-R4CFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $safe = Assert-R4CPath $Path
    $item = Get-Item -LiteralPath $safe -Force
    if ($item.PSIsContainer -or $item.Length -gt 67108864) { throw 'file_type_or_size_rejected' }
    return [ordered]@{name=$item.Name;sha256=(Get-FileHash -LiteralPath $safe -Algorithm SHA256).Hash.ToLowerInvariant();size=$item.Length}
}
function Assert-R4CBinary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSHA256, [Parameter(Mandatory)][long]$ExpectedSize)
    if ([IO.Path]::GetFileName($Path) -cne 'cmg-runtime-boundary-test-service.exe') { throw 'binary_name_rejected' }
    if ($ExpectedSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedSize -lt 64 -or $ExpectedSize -gt 67108864) { throw 'binary_identity_mismatch' }
    $id = Get-R4CFileIdentity $Path
    if ($id.sha256 -cne $ExpectedSHA256 -or $id.size -ne $ExpectedSize) { throw 'binary_identity_mismatch' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'pe_identity_rejected' }
        $stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -gt $stream.Length - 26) { throw 'pe_identity_rejected' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'pe_identity_rejected' }
        $stream.Position = $offset + 22
        if (($reader.ReadUInt16() -band 0x2000) -ne 0) { throw 'pe_identity_rejected' }
        if ($reader.ReadUInt16() -ne 0x20b) { throw 'pe_identity_rejected' }
    } catch [IO.EndOfStreamException] { throw 'pe_identity_rejected' }
    finally { $stream.Dispose() }
    return $id
}
function Copy-R4CBinary {
    [CmdletBinding()]
    param([string]$Source, [string]$Destination, [string]$ExpectedSHA256, [long]$ExpectedSize)
    $null = Assert-R4CBinary $Source $ExpectedSHA256 $ExpectedSize
    $null = Assert-R4CPath $Destination
    if (Test-Path -LiteralPath $Destination) { throw 'output_collision' }
    $parent = Split-Path -Parent $Destination
    [void][IO.Directory]::CreateDirectory($parent)
    $null = Assert-R4CPath $parent
    $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) }
        finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    $null = Assert-R4CBinary $Source $ExpectedSHA256 $ExpectedSize
    return Assert-R4CBinary $Destination $ExpectedSHA256 $ExpectedSize
}
function New-R4CInstallationContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SHA256, [Parameter(Mandatory)][long]$Size, [string]$ServiceName='CmgRuntimeBoundaryR4ATest')
    if ($ServiceName -cne 'CmgRuntimeBoundaryR4ATest') { throw 'service_name_rejected' }
    if ($SHA256 -cnotmatch '^[0-9a-f]{64}$' -or $Size -lt 64) { throw 'binary_identity_mismatch' }
    $artifact = 'r4c-' + $SHA256
    $target = 'C:\Program Files\TencentDBAgentMemory-L4Test\releases\' + $artifact
    return [ordered]@{
        schema='cmg-r4c-test-installation-v1';serviceName='CmgRuntimeBoundaryR4ATest'
        displayName='CMG Runtime Boundary R4A Test'
        account='NT SERVICE\CmgRuntimeBoundaryR4ATest';serviceSidType='unrestricted'
        artifactId=$artifact;targetDirectory=$target
        binaryPath=$target+'\cmg-runtime-boundary-test-service.exe';binarySHA256=$SHA256;binarySize=$Size
        startMode='demand';serviceType='own';arguments=@();recoveryActions=@()
        expectedSCMSequence=@('START_PENDING','RUNNING','STOP_PENDING','STOPPED')
        serviceControlPolicy='SYSTEM_AND_ADMINISTRATORS_ONLY';serviceDacl='D:P(A;;GA;;;SY)(A;;GA;;;BA)'
        directoryPolicy='Verified ancestors; SYSTEM and Administrators write; service SID read/execute only; no developer write'
        collisionPolicy='ABSENT_SERVICE_AND_ABSENT_TARGET_REQUIRED'
        productionEligible=$false;installationApproved=$false;installationPerformed=$false
        protectedAclAcceptance='NOT_EXECUTED';serviceSidAttestation='NOT_EXECUTED'
        runtimeIntegration='NOT_IMPLEMENTED';trustedRuntimeIssuer='NOT_PROVEN'
        l4TrustedRuntimeBinding='BLOCKED';f01HostProvenance='NOT_PROVEN'
        limitation='Local content identity only; no protected provenance, code-load attestation, or TOCTOU guarantee'
    }
}
function Get-R4CCollisionState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Contract)
    if ($Contract.serviceName -cne 'CmgRuntimeBoundaryR4ATest') { throw 'service_name_rejected' }
    $services = [System.ServiceProcess.ServiceController]::GetServices()
    $found = $false
    try { foreach ($service in $services) { if ($service.ServiceName -ieq $Contract.serviceName) { $found = $true } } }
    finally { foreach ($service in $services) { $service.Dispose() } }
    $null = Assert-R4CPath $Contract.targetDirectory
    $exists = Test-Path -LiteralPath $Contract.targetDirectory -ErrorAction Stop
    if ($found -or $exists) { throw 'installation_collision' }
    return [ordered]@{checkedUTC=[DateTime]::UtcNow.ToString('o');serviceAbsent=$true;targetAbsent=$true;recheckBeforeInstallationRequired=$true}
}
function Write-R4CText {
    param([string]$Path, [string]$Text)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text.Replace("§", [char]96).TrimEnd() + [Environment]::NewLine)
        $stream.Write($bytes,0,$bytes.Length)
    } finally { $stream.Dispose() }
}
function Get-R4CSourceIdentities {
    $head = & 'F:\Software\Git\cmd\git.exe' --no-optional-locks -C $script:R4CRepo rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -cne '558ea6a6fcecab7dccd32d7d74618e5abf28003c') { throw 'source_head_mismatch' }
    $identities = @()
    foreach ($entry in $script:R4CApprovedSources) {
        $path = Join-Path $script:R4CRepo $entry.path
        $id = Get-R4CFileIdentity $path
        if ($id.sha256 -cne $entry.sha256) { throw "source_identity_changed:$($entry.path)" }
        $identities += [ordered]@{path=$entry.path;sha256=$id.sha256;size=$id.size}
    }
    # Cargo must not discover additional code/build scripts or local overrides.
    $allowedRust = @($script:R4CApprovedSources | Where-Object path -like '*.rs' | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $script:R4CRepo $_.path)) })
    foreach ($file in Get-ChildItem -LiteralPath $script:R4CCrate -Recurse -Force -File) {
        if (($file.Extension -eq '.rs' -and $allowedRust -notcontains $file.FullName) -or $file.Name -in @('config','config.toml','rust-toolchain','rust-toolchain.toml')) { throw 'cargo_source_or_configuration_unapproved' }
    }
    return $identities
}
function Assert-R4CCandidate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)
    $null = Assert-R4CPath $Directory
    if (Test-Path -LiteralPath (Join-Path $Directory '.incomplete')) { throw 'candidate_incomplete' }
    $expected = @('ACCEPTANCE.md','build-info.json','candidate-manifest.json','cmg-runtime-boundary-test-service.exe','INSTALLATION.md','installation-contract.json','ROLLBACK.md','source-identities.json')
    $actual = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($actual.Count -ne $expected.Count -or @($actual | Where-Object { $_.PSIsContainer -or $expected -cnotcontains $_.Name }).Count) { throw 'candidate_contents_rejected' }
    foreach ($item in $actual) { $null = Assert-R4CPath $item.FullName }
    $manifest = Get-Content -LiteralPath (Join-Path $Directory 'candidate-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.schema -cne 'cmg-r4c-candidate-v1' -or $manifest.productionEligible -ne $false -or $manifest.files.Count -ne 7) { throw 'candidate_contents_rejected' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        if ($expected -cnotcontains $file.name -or $file.name -ceq 'candidate-manifest.json' -or -not $seen.Add($file.name)) { throw 'candidate_contents_rejected' }
        $id = Get-R4CFileIdentity (Join-Path $Directory $file.name)
        if ($id.sha256 -cne $file.sha256 -or $id.size -ne $file.size) { throw 'candidate_identity_mismatch' }
    }
    $contract = Get-Content -LiteralPath (Join-Path $Directory 'installation-contract.json') -Raw | ConvertFrom-Json
    $fixed = New-R4CInstallationContract $contract.binarySHA256 $contract.binarySize
    if (($contract | ConvertTo-Json -Depth 10 -Compress) -cne ($fixed | ConvertTo-Json -Depth 10 -Compress)) { throw 'candidate_contract_mismatch' }
    $null = Assert-R4CBinary (Join-Path $Directory 'cmg-runtime-boundary-test-service.exe') $contract.binarySHA256 $contract.binarySize
    return $manifest
}
function Assert-R4CArchive {
    [CmdletBinding()]
    param([string]$Archive, [string]$Directory)
    $null = Assert-R4CCandidate $Directory
    $expected = @(Get-ChildItem -LiteralPath $Directory -File | ForEach-Object Name)
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -ne $expected.Count) { throw 'archive_contents_rejected' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $zip.Entries) {
            if ($expected -cnotcontains $entry.FullName -or -not $seen.Add($entry.FullName)) { throw 'archive_contents_rejected' }
            $id = Get-R4CFileIdentity (Join-Path $Directory $entry.FullName)
            if ($entry.Length -ne $id.size) { throw 'archive_identity_mismatch' }
            $stream = $entry.Open()
            try {
                $sha = [Security.Cryptography.SHA256]::Create()
                try { $hash = [Convert]::ToHexString($sha.ComputeHash($stream)).ToLowerInvariant() }
                finally { $sha.Dispose() }
            } finally { $stream.Dispose() }
            if ($hash -cne $id.sha256) { throw 'archive_identity_mismatch' }
        }
    } finally { $zip.Dispose() }
}
function Assert-R4CImports {
    [CmdletBinding()]
    param([string[]]$Imports)
    $allowed = @('advapi32.dll','kernel32.dll','api-ms-win-core-synch-l1-2-0.dll','ntdll.dll','VCRUNTIME140.dll','api-ms-win-crt-runtime-l1-1-0.dll','api-ms-win-crt-math-l1-1-0.dll','api-ms-win-crt-stdio-l1-1-0.dll','api-ms-win-crt-locale-l1-1-0.dll','api-ms-win-crt-heap-l1-1-0.dll')
    if (@($Imports | Sort-Object -Unique).Count -ne $allowed.Count -or @($Imports | Where-Object { $allowed -notcontains $_ }).Count) { throw 'pe_dependency_requires_review' }
}
function Invoke-R4CPreparation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TaskRoot)
    if (-not $IsWindows -or [Environment]::Is64BitProcess -ne $true) { throw 'windows_x64_host_required' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'nonadministrator_required' }
    $root = Assert-R4CPath $TaskRoot
    # Fixed user temporary area: do not accept caller-controlled TEMP as a policy.
    $tempBase = Assert-R4CPath (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp')
    if (-not $root.StartsWith($tempBase + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'output_outside_temporary_area' }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'task_directory_missing' }
    $candidate = Join-Path $root 'candidate'
    $target = Join-Path $root 'cargo-target'
    foreach ($path in @($candidate,$target,(Join-Path $root 'candidate.zip'),(Join-Path $root 'preparation-receipt.json'))) {
        if (Test-Path -LiteralPath $path) { throw 'output_collision' }
    }
    foreach ($variable in [Environment]::GetEnvironmentVariables().Keys) {
        if ($variable -match '^(CARGO_|RUSTUP_|RUSTC|RUSTFLAGS$|CC$|CXX$|CL$|_CL_$|LINK$|_LINK_$|LIB$|LIBPATH$)') { throw "build_override_rejected:$variable" }
    }
    foreach ($directory in @($script:R4CCrate,(Split-Path $script:R4CCrate),(Split-Path (Split-Path $script:R4CCrate)),$script:R4CRepo,'F:\AI','F:\', (Join-Path $env:USERPROFILE '.cargo'))) {
        foreach ($name in @('.cargo\config','.cargo\config.toml','config','config.toml')) {
            if (Test-Path -LiteralPath (Join-Path $directory $name)) { throw 'cargo_configuration_requires_review' }
        }
    }
    $sources = @(Get-R4CSourceIdentities)
    $cargo = 'C:\Users\DeanX\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe'
    $rustc = 'C:\Users\DeanX\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\rustc.exe'
    $linker = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
    $toolHashes = @{
        $cargo='ddfbad20b31b918d3439d070945ec59bbfe037a6ec0ab5b584459e69c8b37d1b'
        $rustc='cf79cfd77b0a144c56a0a6af6bf10bcdf095a73718cd4bf2b9d4fe2d2cbded55'
        $linker='ca11e6c45debd34bf652dfe984c5360a531a005ed78bf72852330c9c2590cf0d'
        (Join-Path (Split-Path $linker) 'dumpbin.exe')='12a1cd87238bd66dfdb788b4fcdcb91ce4b3f81236aab12a7a29e5ae1d85af50'
    }
    foreach ($tool in $toolHashes.Keys) { if ((Get-R4CFileIdentity $tool).sha256 -cne $toolHashes[$tool]) { throw 'tool_identity_requires_review' } }
    $null = Assert-R4CPath $cargo
    $null = Assert-R4CPath $rustc
    $null = Assert-R4CPath $linker
    $libraries = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\lib\x64','C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64','C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64')
    foreach ($library in $libraries) { $null = Assert-R4CPath $library; if (-not (Test-Path -LiteralPath $library -PathType Container)) { throw 'sdk_library_missing' } }
    $cargoVersion = & $cargo --version --verbose
    if ($LASTEXITCODE -ne 0) { throw 'cargo_version_failed' }
    $rustcVersion = & $rustc --version --verbose
    if ($LASTEXITCODE -ne 0) { throw 'rustc_version_failed' }
    $started = [DateTime]::UtcNow.ToString('o')
    $arguments = @('build','--offline','--locked','--release','--manifest-path',(Join-Path $script:R4CCrate 'Cargo.toml'),'--target-dir',$target,'--bin','cmg-runtime-boundary-test-service')
    $scratch = Join-Path $root 'build-tmp'
    if (Test-Path -LiteralPath $scratch) { throw 'output_collision' }
    [void][IO.Directory]::CreateDirectory($scratch)
    $oldTemp = $env:TEMP
    $oldTmp = $env:TMP
    $process = [Diagnostics.Process]::new()
    try {
        $info = [Diagnostics.ProcessStartInfo]::new($cargo)
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.WorkingDirectory = $script:R4CCrate
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.Environment.Clear()
        foreach ($name in @('SystemRoot','WINDIR','USERPROFILE','LOCALAPPDATA','APPDATA')) { $info.Environment[$name] = [Environment]::GetEnvironmentVariable($name) }
        $info.Environment['TEMP'] = $scratch
        $info.Environment['TMP'] = $scratch
        $info.Environment['PATH'] = (Split-Path $cargo) + ';' + (Split-Path $linker) + ';C:\Windows\System32;C:\Windows'
        $info.Environment['LIB'] = $libraries -join ';'
        foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'cargo_process_not_started' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        Write-R4CText (Join-Path $root 'cargo-build.stdout.log') $stdout.GetAwaiter().GetResult()
        Write-R4CText (Join-Path $root 'cargo-build.stderr.log') $stderr.GetAwaiter().GetResult()
    } finally {
        $process.Dispose()
        $env:TEMP = $oldTemp
        $env:TMP = $oldTmp
    }
    Write-R4CText (Join-Path $root 'cargo-build.receipt.json') ([ordered]@{executable=$cargo;arguments=$arguments;exitCode=$exitCode;startedUTC=$started;endedUTC=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 8)
    if ($exitCode -ne 0) { throw "offline_build_failed:$exitCode" }
    $null = Get-R4CSourceIdentities
    $binaryPath = Join-Path $target 'release\cmg-runtime-boundary-test-service.exe'
    $binary = Get-R4CFileIdentity $binaryPath
    $null = Assert-R4CBinary $binaryPath $binary.sha256 $binary.size
    $dumpbin = Join-Path (Split-Path $linker) 'dumpbin.exe'
    $null = Assert-R4CPath $dumpbin
    $dependents = & $dumpbin /DEPENDENTS $binaryPath 2> (Join-Path $root 'pe-dependencies.stderr.log')
    if ($LASTEXITCODE -ne 0) { throw 'pe_dependency_inspection_failed' }
    Write-R4CText (Join-Path $root 'pe-dependencies.stdout.log') ($dependents -join [Environment]::NewLine)
    $importNames = @($dependents | ForEach-Object { if ($_ -match '^\s+([a-zA-Z0-9_.-]+\.dll)\s*$') { $Matches[1] } } | Sort-Object -Unique)
    Assert-R4CImports $importNames
    # MSVC CRT is an external machine prerequisite, not an inbox DLL or bundled file.
    $vcRuntime = Get-R4CFileIdentity 'C:\Windows\System32\vcruntime140.dll'
    $contract = New-R4CInstallationContract $binary.sha256 $binary.size
    $collision = Get-R4CCollisionState $contract
    [void][IO.Directory]::CreateDirectory($candidate)
    Write-R4CText (Join-Path $candidate '.incomplete') 'Not a completed candidate'
    $null = Copy-R4CBinary $binaryPath (Join-Path $candidate $binary.name) $binary.sha256 $binary.size
    Write-R4CText (Join-Path $candidate 'source-identities.json') ($sources | ConvertTo-Json -Depth 8)
    $build = [ordered]@{
        cargoVersion=$cargoVersion;rustcVersion=$rustcVersion
        cargo=(Get-R4CFileIdentity $cargo);rustc=(Get-R4CFileIdentity $rustc)
        linkerPath=$linker;linker=(Get-R4CFileIdentity $linker)
        linkerVersion=(Get-Item -LiteralPath $linker).VersionInfo.FileVersion
        peImports=$importNames;peInspector=(Get-R4CFileIdentity $dumpbin)
        externalRuntimePrerequisite=@{path='C:\Windows\System32\vcruntime140.dll';identity=$vcRuntime;version=(Get-Item -LiteralPath 'C:\Windows\System32\vcruntime140.dll').VersionInfo.FileVersion;protectedLoadingVerified=$false}
        sourceHead='558ea6a6fcecab7dccd32d7d74618e5abf28003c'
        cargoLockSHA256=($sources | Where-Object path -like '*/Cargo.lock').sha256
        preparationScript=(Get-R4CFileIdentity $script:R4CScriptPath)
        buildExitCode=$exitCode;offline=$true;locked=$true;configurationOverridesRejected=$true
        buildWorkingDirectory=$script:R4CCrate;buildEnvironment='EMPTY_PLUS_FIXED_WINDOWS_TOOLCHAIN_ALLOWLIST'
        sdkVersion='10.0.26100.0';libraryDirectories=$libraries
        collisionCheck=$collision;binary=$binary
        provenance='UNPROTECTED_LOCAL_BUILD_NOT_A_TRUSTED_ISSUER'
        realGatewayIncluded=$false;userConfigurationIncluded=$false;secretsIncluded=$false
        toctouLimitation='REMAINS'
    }
    Write-R4CText (Join-Path $candidate 'build-info.json') ($build | ConvertTo-Json -Depth 12)
    Write-R4CText (Join-Path $candidate 'installation-contract.json') ($contract | ConvertTo-Json -Depth 10)
    $checks = @'
function Assert-NoReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_rejected' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}
function Assert-R4CRequiredRights($Rules, [string]$ServiceSid) {
    $full = [int64][Security.AccessControl.FileSystemRights]::FullControl
    $required = @{'S-1-5-18'=$full;'S-1-5-32-544'=$full;$ServiceSid=[int64][Security.AccessControl.FileSystemRights]::ReadAndExecute}
    $granted = @{}
    foreach ($rule in $Rules) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -ne 'Allow') { throw 'deny_ace_requires_review' }
        $sid = $rule.IdentityReference.Value
        $mask = [int64]$rule.FileSystemRights
        if ($mask -band 0x10000000) { $mask = $mask -bor $full }
        if ($required.ContainsKey($sid)) {
            if (-not $granted.ContainsKey($sid)) { $granted[$sid] = [int64]0 }
            $granted[$sid] = $granted[$sid] -bor $mask
        }
    }
    foreach ($sid in $required.Keys) {
        if (-not $granted.ContainsKey($sid) -or ($granted[$sid] -band $required[$sid]) -ne $required[$sid]) { throw 'required_directory_rights_missing' }
    }
}
function Get-R4CServiceSid {
    $output = @(Invoke-FixedSc -Words @('showsid','CmgRuntimeBoundaryR4ATest')) -join [Environment]::NewLine
    $sids = @([regex]::Matches($output,'S-1-5-80(?:-\d+){5}') | ForEach-Object Value | Select-Object -Unique)
    if ($sids.Count -ne 1) { throw 'service_sid_derivation_failed' }
    return $sids[0]
}
function Assert-R4CServicePresence([bool]$RegistryPresent, [bool]$ScmPresent) {
    if ($RegistryPresent -ne $ScmPresent) { throw 'service_presence_inconsistent_preserve' }
    return $RegistryPresent
}
function Assert-WriteBoundary([string]$Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544')
    # Windows servicing owns Program Files; it is not an interactive developer principal.
    if ($Path -ceq 'C:\Program Files') { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw "owner_requires_independent_review:$Path" }
    $writes = [int64]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership) -bor 0x10000000 -bor 0x40000000
    $rules = $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq 'Allow' -and ([int64]$rule.FileSystemRights -band $writes) -ne 0 -and
            $trusted -notcontains $rule.IdentityReference.Value) {
            throw "untrusted_write_ace_requires_review:$Path"
        }
    }
    if ($Path -cne 'C:\Program Files') { Assert-R4CRequiredRights $rules (Get-R4CServiceSid) }
}
function Invoke-FixedSc([string[]]$Words) {
    $output = @(& 'C:\Windows\System32\sc.exe' @Words)
    if ($LASTEXITCODE -ne 0) { throw "sc_failed:$LASTEXITCODE" }
    return $output
}
function Assert-DeployedBinary {
    Assert-NoReparse $exe
    if ((Get-Item -LiteralPath $exe).Length -ne @@SIZE@@ -or
        (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -cne '@@HASH@@') { throw 'binary_identity_mismatch' }
    foreach ($p in @('C:\Program Files',$base,$releases,$target,$exe)) { Assert-WriteBoundary $p }
    $contents = @(Get-ChildItem -LiteralPath $target -Force)
    if ($contents.Count -ne 1 -or $contents[0].Name -cne 'cmg-runtime-boundary-test-service.exe' -or $contents[0].PSIsContainer) { throw 'unexpected_deployment_contents' }
}
function Assert-ServiceConfiguration {
    $r = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CmgRuntimeBoundaryR4ATest'
    if ($r.ImagePath -cne ('"' + $exe + '"') -or $r.ObjectName -ine 'NT SERVICE\CmgRuntimeBoundaryR4ATest' -or
        $r.Start -ne 3 -or $r.Type -ne 16 -or $r.ServiceSidType -ne 1 -or $r.DisplayName -cne 'CMG Runtime Boundary R4A Test') { throw 'service_configuration_mismatch' }
    foreach ($property in @('FailureActions','FailureCommand','FailureActionsOnNonCrashFailures')) {
        if ($r.PSObject.Properties.Name -contains $property) { throw 'recovery_configuration_requires_review' }
    }
    $output = @(Invoke-FixedSc -Words @('sdshow',$name))
    $lines = @($output | Where-Object { $_.Trim().StartsWith('D:') })
    if ($lines.Count -ne 1) { throw 'service_security_unavailable' }
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($lines[0].Trim())
    $seen = @{}
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.AceQualifier -ne 'AccessAllowed' -or
            $ace.SecurityIdentifier.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'service_dacl_rejected' }
        if ($ace.AccessMask -ne 0x10000000 -and $ace.AccessMask -ne 0x000f01ff) { throw 'service_rights_rejected' }
        $seen[$ace.SecurityIdentifier.Value] = $true
    }
    if ($seen.Count -ne 2) { throw 'service_control_rights_missing' }
}
function Get-R4CStopAction([string]$State) {
    switch ($State) {
        'Stopped' { return 'DONE' }
        'Running' { return 'STOP' }
        'Paused' { return 'STOP' }
        { $_ -in @('StartPending','StopPending','PausePending','ContinuePending') } { return 'WAIT' }
        default { throw 'unknown_service_state' }
    }
}
'@
    $install = @'
# R4C test-service installation contract — NOT EXECUTED
Separate explicit administrator authorization is required for the exact operations below.
This is a local unsigned candidate, not a trusted publisher or L4 assertion.
Fixed own-process/manual service: CmgRuntimeBoundaryR4ATest.
Virtual account: NT SERVICE\CmgRuntimeBoundaryR4ATest; SID type unrestricted.
No arguments, recovery commands, real Gateway, database, user data or secrets are permitted.

Before execution, independently verify the archive hash and manifest against the separately
reviewed receipt. Verify all ancestors and effective ACLs, including their ownership and
ability to rename/delete child directories. Program Files' name is not an ACL proof.
The conservative executable ACL checks below can stop on trusted Windows owner/ACE
variations: STOP for independent review, never bypass or weaken a check.
No command below is executed by preparation. Existing service or exact version target
causes failure. Existing base/releases parents may only be reused after the same strict
owner/ACL/reparse acceptance; their ACLs and unrelated contents must not be modified.

§§§powershell
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'separate_admin_authorization_required' }
$name = 'CmgRuntimeBoundaryR4ATest'
$base = 'C:\Program Files\TencentDBAgentMemory-L4Test'
$releases = Join-Path $base 'releases'
$target = '@@TARGET@@'
$exe = Join-Path $target 'cmg-runtime-boundary-test-service.exe'
$source = '@@CANDIDATE@@\cmg-runtime-boundary-test-service.exe'
@@CHECKS@@
if (@(Get-Service | Where-Object Name -ieq $name).Count -or (Test-Path -LiteralPath $target)) { throw 'installation_collision' }
Assert-NoReparse $source
if ((Get-Item -LiteralPath $source).Length -ne @@SIZE@@ -or (Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -cne '@@HASH@@') { throw 'candidate_binary_mismatch' }
Assert-WriteBoundary 'C:\Program Files'
# Independently verify the volume/root cannot replace the protected Program Files ancestor.
$serviceSidText = @(Invoke-FixedSc -Words @('showsid',$name)) -join [Environment]::NewLine
$sids = @([regex]::Matches($serviceSidText,'S-1-5-80(?:-\d+){5}') | ForEach-Object Value | Select-Object -Unique)
if ($sids.Count -ne 1) { throw 'service_sid_derivation_failed' }
$serviceSid = [Security.Principal.SecurityIdentifier]::new($sids[0])
if ((Read-Host 'Type INSTALL CmgRuntimeBoundaryR4ATest after independent ancestor ACL acceptance') -cne 'INSTALL CmgRuntimeBoundaryR4ATest') { throw 'cancelled' }
foreach ($directory in @($base,$releases,$target)) {
    if (Test-Path -LiteralPath $directory) {
        if ($directory -ceq $target) { throw 'directory_collision' }
        Assert-WriteBoundary $directory
        continue
    }
    [void][IO.Directory]::CreateDirectory($directory)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($serviceSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $directory -AclObject $acl
    Assert-WriteBoundary $directory
}
$inputStream = [IO.File]::Open($source,'Open','Read','Read')
try {
    $outputStream = [IO.File]::Open($exe,'CreateNew','Write','None')
    try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) } finally { $outputStream.Dispose() }
} finally { $inputStream.Dispose() }
Assert-DeployedBinary
$null = Invoke-FixedSc -Words @('create',$name,'binPath=',('"' + $exe + '"'),'type=','own','start=','demand','error=','normal','obj=',('NT SERVICE\' + $name),'DisplayName=','CMG Runtime Boundary R4A Test')
$null = Invoke-FixedSc -Words @('sidtype',$name,'unrestricted')
$null = Invoke-FixedSc -Words @('sdset',$name,'D:P(A;;GA;;;SY)(A;;GA;;;BA)')
Assert-ServiceConfiguration
Assert-DeployedBinary
# Deliberately no Start-Service. Independently accept the registered configuration first.
§§§

The executable imports VCRUNTIME140.dll in addition to the fixed Windows API allowlist.
The MSVC runtime is NOT bundled. Current System32 hash/version are in build-info.json.
Its provenance, protected loading and actual service token remain unverified.
Any partial installation failure: STOP and retain evidence; rollback needs separate approval.
Only this version directory's one exe is deployed. Keep diagnostics outside release code.
'@
    $acceptance = @'
# Independent Windows acceptance — NOT EXECUTED
Run only after separately approved installation, registration review and test START/STOP
authorization. A successful preparation does not establish a service SID/token or ACL.
Use the exact candidate receipt and current build-info.json for MSVC runtime identity.
Do not substitute an unreviewed mutable local receipt.

§§§powershell
$ErrorActionPreference = 'Stop'
$name = 'CmgRuntimeBoundaryR4ATest'
$base = 'C:\Program Files\TencentDBAgentMemory-L4Test'
$releases = Join-Path $base 'releases'
$target = '@@TARGET@@'
$exe = Join-Path $target 'cmg-runtime-boundary-test-service.exe'
@@CHECKS@@
Assert-ServiceConfiguration
Assert-DeployedBinary
$runtime = 'C:\Windows\System32\vcruntime140.dll'
Assert-NoReparse $runtime
if ((Get-FileHash -LiteralPath $runtime).Hash.ToLowerInvariant() -cne '@@VCRUNTIME@@') { throw 'runtime_prerequisite_changed' }
# Before confirming, independently accept protected DLL search/ancestors, actual token/SID
# observation method and trace capture. Registry SID type is not running-token attestation.
if ((Read-Host 'Type TEST CmgRuntimeBoundaryR4ATest after runtime and ACL acceptance') -cne 'TEST CmgRuntimeBoundaryR4ATest') { throw 'cancelled' }
$controller = Get-Service -Name $name
if ($controller.Status -ne 'Stopped') { throw 'unexpected_service_state' }
try {
    Start-Service -Name $name
    $controller.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    Assert-ServiceConfiguration
    Assert-DeployedBinary
    $null = Invoke-FixedSc -Words @('queryex',$name)
    # Independently capture actual process token/SID, image and SCM status trace.
} finally {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $lastState = 'UNKNOWN'
    try {
        do {
            $controller.Refresh()
            $lastState = [string]$controller.Status
            $action = Get-R4CStopAction $lastState
            if ($action -ceq 'DONE') { break }
            if ($action -ceq 'STOP') {
                try { Stop-Service -Name $name -NoWait -ErrorAction Stop }
                catch { $cleanupErrors.Add($_.Exception.Message) }
            }
            Start-Sleep -Milliseconds 200
        } while ($deadline.Elapsed -lt [TimeSpan]::FromSeconds(30))
        if ($lastState -cne 'Stopped') {
            throw ('STOP_NOT_VERIFIED_MAY_STILL_RUN:' + $lastState + ':' + ($cleanupErrors -join ';'))
        }
    } finally { $controller.Dispose(); $deadline.Stop() }
}
if ((Get-Service -Name $name).Status -ne 'Stopped') { throw 'stop_not_verified' }
Assert-ServiceConfiguration
Assert-DeployedBinary
§§§

Expected actual reports: START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED.
Polling can miss transient states; retain independent SCM/status trace/native errors.
The code above does not attest token identity, effective ACLs, or protected DLL loading.
Those independent acceptance records remain mandatory and NOT_EXECUTED here.
If START_PENDING never completes or STOP is refused, bounded cleanup reports
STOP_NOT_VERIFIED_MAY_STILL_RUN. The service may later run: acceptance is BLOCKED.
Retain errors and keep the administrator present for separately approved recovery;
do not delete its binary, claim stopped, continue installation, or terminate unrelated processes.
Verify no orphan worker/process, unexpected exit code, port, Gateway or database access.
R2/R3/runtime integration is NOT_IMPLEMENTED. L4 BLOCKED; F01 NOT_PROVEN.
'@
    $rollback = @'
# Exact test-service rollback — NOT EXECUTED
Separate authorization is required to stop/delete this service and its one version directory.
Retain installation logs (including which directories/service were actually created) outside
the release root. An operator must verify this version was created by that approved install.
The pre-registration branch handles a failed install with no service key. If a partial copy
does not match expected SHA256, STOP for separate evidence review; do not erase it.
Base/releases parents remain protected and reusable under the installation contract.
They and all other versions/resources/diagnostics are deliberately outside deletion scope.

§§§powershell
$ErrorActionPreference = 'Stop'
$name = 'CmgRuntimeBoundaryR4ATest'
$base = 'C:\Program Files\TencentDBAgentMemory-L4Test'
$releases = Join-Path $base 'releases'
$target = '@@TARGET@@'
$exe = Join-Path $target 'cmg-runtime-boundary-test-service.exe'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CmgRuntimeBoundaryR4ATest'
@@CHECKS@@
if (-not (Test-Path -LiteralPath $target)) { throw 'target_absent_review_partial_installation_log' }
foreach ($directory in @($base,$releases,$target)) { Assert-WriteBoundary $directory }
$entries = @(Get-ChildItem -LiteralPath $target -Force)
$hasBinary = Test-Path -LiteralPath $exe
if ($hasBinary) { Assert-DeployedBinary }
elseif ($entries.Count -ne 0) { throw 'unrecognized_partial_output_preserve_for_review' }
$hasService = Test-Path -LiteralPath $serviceKey
$scmPresent = @(Get-Service | Where-Object Name -ieq $name).Count -ne 0
$hasService = Assert-R4CServicePresence $hasService $scmPresent
if ($hasService) {
    $registration = Get-ItemProperty -LiteralPath $serviceKey
    if (-not $hasBinary -or $registration.ImagePath -cne ('"' + $exe + '"') -or
        $registration.ObjectName -ine 'NT SERVICE\CmgRuntimeBoundaryR4ATest' -or
        $registration.Start -ne 3 -or $registration.Type -ne 16) { throw 'service_identity_mismatch' }
}
if ((Read-Host 'Confirm this install created target and evidence retained; type REMOVE CmgRuntimeBoundaryR4ATest') -cne 'REMOVE CmgRuntimeBoundaryR4ATest') { throw 'cancelled' }
if ($hasService) {
    $controller = Get-Service -Name $name
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $errors = [Collections.Generic.List[string]]::new()
    try {
        do {
            $controller.Refresh()
            $lastState = [string]$controller.Status
            $action = Get-R4CStopAction $lastState
            if ($action -ceq 'DONE') { break }
            if ($action -ceq 'STOP') {
                try { Stop-Service -Name $name -NoWait -ErrorAction Stop } catch { $errors.Add($_.Exception.Message) }
            }
            Start-Sleep -Milliseconds 200
        } while ($deadline.Elapsed -lt [TimeSpan]::FromSeconds(30))
        if ($lastState -cne 'Stopped') { throw ('STOP_NOT_VERIFIED_MAY_STILL_RUN:' + $lastState + ':' + ($errors -join ';')) }
        $again = Get-ItemProperty -LiteralPath $serviceKey
        if ($again.ImagePath -cne $registration.ImagePath -or $again.ObjectName -cne $registration.ObjectName) { throw 'registration_changed' }
        Assert-DeployedBinary
        $null = Invoke-FixedSc -Words @('delete',$name)
    } finally { $controller.Dispose(); $deadline.Stop() }
    if (@(Get-Service | Where-Object Name -ieq $name).Count) { throw 'service_deletion_pending_review' }
}
# Pre-registration failure: never issue delete against an absent/unrecognized service.
# Exact verified binary only; empty target is valid for a failed pre-copy install.
Assert-WriteBoundary $target
if ($hasBinary) { Assert-DeployedBinary; Remove-Item -LiteralPath $exe }
if (@(Get-ChildItem -LiteralPath $target -Force).Count -ne 0) { throw 'directory_not_empty_preserve' }
Remove-Item -LiteralPath $target
§§§

If ACL provisioning failed before the target was created, no version directory exists:
record this and preserve the protected empty parent(s). A new approved install can reuse
them only after owner/ACL/reparse checks. If parent ACL setup is incomplete, STOP for
separate review; this plan does not change or delete those parents.
No recursive cleanup, service-name search, force deletion or deletion retry is permitted.
Administrator concurrency and path TOCTOU remain; a mismatch always preserves evidence.
'@
    foreach ($doc in @(@('INSTALLATION.md',$install),@('ACCEPTANCE.md',$acceptance),@('ROLLBACK.md',$rollback))) {
        $text = $doc[1].Replace('@@CHECKS@@',$checks).Replace('@@TARGET@@',$contract.targetDirectory).Replace('@@HASH@@',$binary.sha256).Replace('@@SIZE@@',[string]$binary.size).Replace('@@CANDIDATE@@',$candidate).Replace('@@VCRUNTIME@@',$vcRuntime.sha256)
        Write-R4CText (Join-Path $candidate $doc[0]) $text
    }
    $files = @(Get-ChildItem -LiteralPath $candidate -File | Where-Object Name -ne '.incomplete' | Sort-Object Name | ForEach-Object { Get-R4CFileIdentity $_.FullName })
    $manifest = [ordered]@{schema='cmg-r4c-candidate-v1';artifactId=$contract.artifactId;productionEligible=$false;files=$files}
    Write-R4CText (Join-Path $candidate 'candidate-manifest.json') ($manifest | ConvertTo-Json -Depth 10)
    # The only removed file is the marker created above in this fresh candidate.
    [IO.File]::Delete((Join-Path $candidate '.incomplete'))
    $null = Assert-R4CCandidate $candidate
    $archive = Join-Path $root 'candidate.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($candidate,$archive,[IO.Compression.CompressionLevel]::Optimal,$false)
    Assert-R4CArchive $archive $candidate
    $null = Get-R4CSourceIdentities
    $null = Get-R4CCollisionState $contract
    $receipt = [ordered]@{
        schema='cmg-r4c-preparation-receipt-v1';status='PASS_NONPRODUCTION'
        candidateDirectory=$candidate;archive=$archive;archiveIdentity=(Get-R4CFileIdentity $archive)
        manifestIdentity=(Get-R4CFileIdentity (Join-Path $candidate 'candidate-manifest.json'))
        binary=$binary;targetDirectory=$contract.targetDirectory;collisionCheck=$collision
        productionEligible=$false;installationPerformed=$false;completedUTC=[DateTime]::UtcNow.ToString('o')
    }
    Write-R4CText (Join-Path $root 'preparation-receipt.json') ($receipt | ConvertTo-Json -Depth 12)
    return $receipt
}
# Explicit IPC profile; the historical R4C functions and frozen cohort remain unchanged.
function Get-FixedIpcHash([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { [Convert]::ToHexString($sha.ComputeHash($Bytes)).ToLowerInvariant() } finally {$sha.Dispose()}
}
function Get-FixedIpcSources {
    $head=& 'F:\Software\Git\cmd\git.exe' --no-optional-locks -C $script:R4CRepo rev-parse HEAD
    if($LASTEXITCODE -ne 0 -or $head -cne '05640082d0c577ca2ec2304198dd4999aa920d24'){throw 'ipc_source_head_mismatch'}
    $allowed=@('Cargo.toml','Cargo.lock','src/lib.rs','src/main.rs','src/launch.rs','src/peer.rs','src/service.rs','src/release.rs','src/release_v2.rs','src/bin/cmg-runtime-boundary-ipc-child.rs','tests/launch_contract.rs','tests/peer_contract.rs','tests/service_contract.rs','tests/release_contract.rs','tests/release_v2_contract.rs','scripts/prepare-test-deployment.ps1','tests/prepare-test-deployment.test.ps1')
    foreach($f in Get-ChildItem $script:R4CCrate -Recurse -File -Force){
        $rel=[IO.Path]::GetRelativePath($script:R4CCrate,$f.FullName).Replace('\','/')
        if(($f.Extension -eq '.rs' -and $allowed -cnotcontains $rel) -or $f.Name -in @('build.rs','config','config.toml','rust-toolchain','rust-toolchain.toml')){throw 'ipc_unapproved_build_input'}
    }
    $ids=@(foreach($rel in $allowed){$id=Get-R4CFileIdentity (Join-Path $script:R4CCrate $rel); [ordered]@{path=$rel;size=$id.size;sha256=$id.sha256}})
    if(($ids|Where-Object path -ceq 'Cargo.lock').sha256 -cne 'c62b425901d72b9355bcc5d41894c45ea8c546cebbb8168435aaedb611e1cde1'){throw 'ipc_lock_changed'}
    return $ids
}
function Assert-FixedIpcCandidate {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$Directory)
    $null=Assert-R4CPath $Directory
    $authFile=Join-Path $Directory 'ipc-start-authorization.json'
    if ((Get-R4CFileIdentity $authFile).size -gt 16384){throw 'ipc_authorization_invalid'}
    $raw=[IO.File]::ReadAllBytes($authFile)
    if($raw.Length -gt 16384){throw 'ipc_authorization_invalid'}
    $doc=[Text.Json.JsonDocument]::Parse([Text.Encoding]::UTF8.GetString($raw))
    try {
        $names=@($doc.RootElement.EnumerateObject()|ForEach-Object Name|Sort-Object)
        $expected=@('schema_version','purpose','service_name','host_sha256','child_sha256','manifest_sha256','artifact_id')|Sort-Object
        if(($names -join ',') -cne ($expected -join ',')){throw 'ipc_authorization_invalid'}
    } finally {$doc.Dispose()}
    $a=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json
    if($a.schema_version -ne 1 -or $a.purpose -cne 'cmg-fixed-ipc-test-start' -or $a.service_name -cne 'CmgRuntimeBoundaryR4ATest'){throw 'ipc_authorization_invalid'}
    foreach($h in @($a.host_sha256,$a.child_sha256,$a.manifest_sha256)){if($h -cnotmatch '^[0-9a-f]{64}$'){throw 'ipc_authorization_invalid'}}
    $id='ipc-'+(Get-FixedIpcHash ([Text.Encoding]::ASCII.GetBytes($a.host_sha256+$a.child_sha256+$a.manifest_sha256)))
    if($id -cne $a.artifact_id -or (Split-Path $Directory -Leaf) -cne $id){throw 'ipc_identity_mismatch'}
    $hostPath=Join-Path $Directory 'cmg-runtime-boundary-test-service.exe'; $hostId=Get-R4CFileIdentity $hostPath
    $null=Assert-R4CBinary $hostPath $a.host_sha256 $hostId.size
    $mf=Join-Path $Directory 'ipc-manifest-v2.json'
    if((Get-R4CFileIdentity $mf).sha256 -cne $a.manifest_sha256){throw 'ipc_identity_mismatch'}
    $m=Get-Content -LiteralPath $mf -Raw|ConvertFrom-Json; $tree=Join-Path $Directory 'ipc-fixture'
    $expected=@('app/package.json','app/src/gateway/server.js','app/cmg-runtime-boundary-ipc-child.exe','closure-report.json','js-dependency-graph.json')|Sort-Object
    if($m.format_version -ne 2 -or $m.production_eligible -ne $false -or $m.files.Count -ne 5 -or
        ((@($m.files|ForEach-Object path|Sort-Object)) -join ',') -cne ($expected -join ',')){throw 'ipc_manifest_invalid'}
    if((@($m.directories) -join ',') -cne 'app,app/src,app/src/gateway,temp,work'){throw 'ipc_manifest_invalid'}
    foreach($f in Get-ChildItem -LiteralPath $Directory -Recurse -Force){$null=Assert-R4CPath $f.FullName}
    $actual=@(Get-ChildItem -LiteralPath $Directory -Force|ForEach-Object Name|Sort-Object)
    if(($actual -join ',') -cne 'cmg-runtime-boundary-test-service.exe,ipc-fixture,ipc-manifest-v2.json,ipc-start-authorization.json'){throw 'ipc_extra_file'}
    $actual=@(Get-ChildItem -LiteralPath $tree -Recurse -File|ForEach-Object {[IO.Path]::GetRelativePath($tree,$_.FullName).Replace('\','/')}|Sort-Object)
    if(($actual -join ',') -cne ($expected -join ',')){throw 'ipc_extra_file'}
    $actual=@(Get-ChildItem -LiteralPath $tree -Recurse -Directory|ForEach-Object {[IO.Path]::GetRelativePath($tree,$_.FullName).Replace('\','/')}|Sort-Object)
    if(($actual -join ',') -cne ((@($m.directories)|Sort-Object) -join ',')){throw 'ipc_extra_directory'}
    foreach($f in $m.files){$id=Get-R4CFileIdentity (Join-Path $tree $f.path); if($id.sha256 -cne $f.sha256 -or $id.size -ne $f.size){throw 'ipc_identity_mismatch'}}
    if((Get-R4CFileIdentity (Join-Path $tree 'app/cmg-runtime-boundary-ipc-child.exe')).sha256 -cne $a.child_sha256){throw 'ipc_identity_mismatch'}
    return $a
}
function Invoke-FixedIpcPreparation {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$TaskRoot)
    if(-not $IsWindows -or -not [Environment]::Is64BitProcess){throw 'windows_x64_host_required'}
    if(([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'nonadministrator_required'}
    $root=Assert-R4CPath $TaskRoot; $temp=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp'
    if(-not $root.StartsWith($temp+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'output_outside_temporary_area'}
    if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'task_directory_missing'}
    if(@(Get-ChildItem -LiteralPath $root -Force).Count){throw 'output_collision'}
    foreach($v in [Environment]::GetEnvironmentVariables().Keys){if($v -match '^(CARGO_|RUSTUP_|RUSTC|RUSTFLAGS$|CC$|CXX$|CL$|_CL_$|LINK$|_LINK_$|LIB$|LIBPATH$)'){throw "build_override_rejected:$v"}}
    foreach($d in @($script:R4CCrate,(Split-Path $script:R4CCrate),(Split-Path (Split-Path $script:R4CCrate)),$script:R4CRepo,'F:\AI','F:\',(Join-Path $env:USERPROFILE '.cargo'))){foreach($n in @('.cargo\config','.cargo\config.toml','config','config.toml')){if(Test-Path -LiteralPath (Join-Path $d $n)){throw 'cargo_configuration_requires_review'}}}
    $before=@(Get-FixedIpcSources)
    $tools='C:\Users\DeanX\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin'
    $cargo=Join-Path $tools 'cargo.exe'; $rustc=Join-Path $tools 'rustc.exe'
    $msvc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'; $linker=Join-Path $msvc 'bin\Hostx64\x64\link.exe'
    $toolIds=@(foreach($t in @($cargo,$rustc,$linker)){Get-R4CFileIdentity $t})
    $target=Join-Path $root 'cargo-target'; $scratch=Join-Path $root 'build-tmp'; [void][IO.Directory]::CreateDirectory($scratch)
    $args=@('build','--offline','--locked','--manifest-path',(Join-Path $script:R4CCrate 'Cargo.toml'),'--target-dir',$target,'--bin','cmg-runtime-boundary-test-service','--bin','cmg-runtime-boundary-ipc-child')
    $proc=[Diagnostics.Process]::new()
    try {
        $i=[Diagnostics.ProcessStartInfo]::new($cargo); $i.UseShellExecute=$false; $i.CreateNoWindow=$true; $i.WorkingDirectory=$script:R4CCrate
        $i.RedirectStandardOutput=$true; $i.RedirectStandardError=$true; $i.Environment.Clear()
        foreach($n in @('SystemRoot','WINDIR','USERPROFILE','LOCALAPPDATA','APPDATA')){$i.Environment[$n]=[Environment]::GetEnvironmentVariable($n)}
        $i.Environment['PATH']=$tools+';'+(Split-Path $linker)+';C:\Windows\System32;C:\Windows'; $i.Environment['RUSTC']=$rustc
        $i.Environment['CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER']=$linker
        $i.Environment['LIB']=(Join-Path $msvc 'lib\x64')+';C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64'
        $i.Environment['TEMP']=$scratch; $i.Environment['TMP']=$scratch
        foreach($a in $args){$i.ArgumentList.Add($a)}
        $proc.StartInfo=$i; if(-not $proc.Start()){throw 'offline_build_not_started'}
        $out=$proc.StandardOutput.ReadToEndAsync(); $err=$proc.StandardError.ReadToEndAsync(); $proc.WaitForExit(); $code=$proc.ExitCode
        Write-R4CText (Join-Path $root 'cargo.stdout') $out.GetAwaiter().GetResult(); Write-R4CText (Join-Path $root 'cargo.stderr') $err.GetAwaiter().GetResult()
    } finally {$proc.Dispose()}
    Write-R4CText (Join-Path $root 'build-receipt.json') (@{executable=$cargo;arguments=$args;exitCode=$code;tools=$toolIds;cargoVersion=(& $cargo --version);rustcVersion=(& $rustc --version);sourceHead='05640082d0c577ca2ec2304198dd4999aa920d24';productionEligible=$false;externalRuntimeLoading='NOT_PROVEN'}|ConvertTo-Json -Depth 8)
    if($code -ne 0){throw "offline_build_failed:$code"}
    $after=@(Get-FixedIpcSources)
    if(($before|ConvertTo-Json -Compress) -cne ($after|ConvertTo-Json -Compress)){throw 'source_changed_during_build'}
    $hostSource=Join-Path $target 'debug\cmg-runtime-boundary-test-service.exe'; $childSource=Join-Path $target 'debug\cmg-runtime-boundary-ipc-child.exe'
    $hostId=Get-R4CFileIdentity $hostSource; $childId=Get-R4CFileIdentity $childSource
    $candidate=Join-Path $root 'candidate'; [void][IO.Directory]::CreateDirectory($candidate); $tree=Join-Path $candidate 'ipc-fixture'
    foreach($d in @('app/src/gateway','temp','work')){[void][IO.Directory]::CreateDirectory((Join-Path $tree $d))}
    Write-R4CText (Join-Path $root '.incomplete') 'Not a completed or authorized release.'
    $source=[IO.File]::ReadAllText((Join-Path $script:R4CCrate 'src/launch.rs'))
    $match=[regex]::Match($source,'(?s)pub const SYNTHETIC_ENTRY_SOURCE: &str = r#"(.*?)"#;')
    if(-not $match.Success){throw 'fixed_fixture_source_missing'}
    $utf8=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $tree 'app/src/gateway/server.js'),$match.Groups[1].Value.Replace("`r`n","`n"),$utf8)
    [IO.File]::WriteAllText((Join-Path $tree 'app/package.json'),"{`"type`":`"module`",`"private`":true}`n",$utf8)
    Write-R4CText (Join-Path $tree 'js-dependency-graph.json') (@{format='gateway-js-dependency-staging/v1';edges=@(@{status='UNRESOLVED'});TRANSITIVE_CLOSURE_PROVEN=$false;NATIVE_LOAD_VERIFIED=$false;DEVELOPMENT_PATH_ESCAPE=$false}|ConvertTo-Json -Depth 8)
    $graphHash=(Get-R4CFileIdentity (Join-Path $tree 'js-dependency-graph.json')).sha256
    $node=@{version='v24.16.0';platform='win32';architecture='x64';moduleABI='137';napi='10';runtimeCompatibility='NOT_LOAD_VERIFIED'}
    $build=@{name='esbuild';version='0.28.2';typescriptVersion='6.0.3';lockVersionMatched=$true;lockSha256=('1'*64);jsEntrypoints=@(@{path='node_modules/esbuild/lib/main.js';bytes=1;sha256=('2'*64)});executableIdentity=@{bytes=1;sha256=('3'*64)};transformCalls=1}
    Write-R4CText (Join-Path $tree 'closure-report.json') (@{format='gateway-js-candidate-closure/v1';entryOutput='app/src/gateway/server.js';CANDIDATE_BUILD_SUCCESS=$true;buildExitCode=0;buildTool=$build;node=$node;jsDependencyStaging=@{graphPath='js-dependency-graph.json';graphSha256=$graphHash;unresolvedEdges=1;TRANSITIVE_CLOSURE_PROVEN=$false;NATIVE_LOAD_VERIFIED=$false;DEVELOPMENT_PATH_ESCAPE=$false};closureGateExitCode=2;RELEASE_ELIGIBLE=$false;RELEASE_DEPENDENCY_CLOSURE_COMPLETE=$false}|ConvertTo-Json -Depth 12)
    [IO.File]::Copy($childSource,(Join-Path $tree 'app/cmg-runtime-boundary-ipc-child.exe'),$false)
    $files=@(foreach($path in @('app/cmg-runtime-boundary-ipc-child.exe','app/package.json','app/src/gateway/server.js','closure-report.json','js-dependency-graph.json')){
        $id=Get-R4CFileIdentity (Join-Path $tree $path); $kind=if($path -like '*.exe'){'resource'}elseif($path -eq 'app/package.json'){'metadata'}elseif($path -like '*.js'){'gateway-js'}else{'report'}
        [ordered]@{path=$path;size=$id.size;sha256=$id.sha256;kind=$kind}
    })
    if(($files|Where-Object path -like '*.exe').sha256 -cne $childId.sha256){throw 'ipc_copy_identity_mismatch'}
    $manifest=[ordered]@{format_version=2;platform='windows';architecture='x86_64';validation_scope='candidate-static-tree';production_eligible=$false;entry='app/src/gateway/server.js';node=$node;node_identity_scope='reported-target-not-packaged';build_tool=$build;closure=@{path='closure-report.json';sha256=(Get-R4CFileIdentity (Join-Path $tree 'closure-report.json')).sha256;graph_path='js-dependency-graph.json';graph_sha256=$graphHash;unresolved_edges=1};runtime=@{dependency_closure_proven=$false;native_load_verified=$false;config_isolation=$false;protected_service=$false;trusted_issuer=$false};directories=@('app','app/src','app/src/gateway','temp','work');files=$files}
    Write-R4CText (Join-Path $candidate 'ipc-manifest-v2.json') ($manifest|ConvertTo-Json -Depth 16)
    $mh=(Get-R4CFileIdentity (Join-Path $candidate 'ipc-manifest-v2.json')).sha256
    $artifact='ipc-'+(Get-FixedIpcHash ([Text.Encoding]::ASCII.GetBytes($hostId.sha256+$childId.sha256+$mh)))
    [IO.File]::Copy($hostSource,(Join-Path $candidate 'cmg-runtime-boundary-test-service.exe'),$false)
    Write-R4CText (Join-Path $candidate 'ipc-start-authorization.json') (@{schema_version=1;purpose='cmg-fixed-ipc-test-start';service_name='CmgRuntimeBoundaryR4ATest';host_sha256=$hostId.sha256;child_sha256=$childId.sha256;manifest_sha256=$mh;artifact_id=$artifact}|ConvertTo-Json)
    $final=Join-Path $root $artifact; [IO.Directory]::Move($candidate,$final); $null=Assert-FixedIpcCandidate $final
    $targetDirectory='C:\Program Files\TencentDBAgentMemory-L4Test\releases\'+$artifact
    Write-R4CText (Join-Path $root 'installation-contract.json') (@{schema='cmg-fixed-ipc-test-installation-v1';serviceName='CmgRuntimeBoundaryR4ATest';account='NT SERVICE\CmgRuntimeBoundaryR4ATest';serviceSidType='unrestricted';startMode='demand';arguments=@();recoveryActions=@();targetDirectory=$targetDirectory;binaryPath=$targetDirectory+'\cmg-runtime-boundary-test-service.exe';serviceDacl='D:P(A;;GA;;;SY)(A;;GA;;;BA)';directoryPolicy='SYSTEM/Administrators write; service SID RX only; owners/ancestors verified; no reparse/developer write';installationApproved=$false;installationPerformed=$false;productionEligible=$false;missingAuthorization='Legacy idle; record deletion not distinguishable at runtime';externalRuntimeLoading='NOT_PROVEN'}|ConvertTo-Json -Depth 10)
    Write-R4CText (Join-Path $root 'INSTALLATION.md') "PLAN ONLY. Separate administrator approval and independent receipt acceptance required. Reuse R4C owner/ancestor/SCM protections, but NEVER its frozen one-file installer for this NEW layout. Publish ONLY the reviewed version tree at $targetDirectory. Verify every directory/file owner, DACL, reparse/rename/delete boundary and source/destination identity, including volume/root; SYSTEM/Administrators write, service SID RX only. Exact quoted host ImagePath, no arguments, fixed virtual account, manual own-process service, SYSTEM/Administrators service DACL, no recovery commands. Recheck all hashes and ACLs before start. Existing service requires separate exact update/rollback approval. No install commands are executed. Content hashes are not publisher authorization. MSVC DLL protected loading remains unproven. Synthetic V2 build metadata does not describe a real Gateway build."
    Write-R4CText (Join-Path $root 'ROLLBACK.md') "PLAN ONLY; explicit separate approval required. Match CmgRuntimeBoundaryR4ATest, exact ImagePath, host/child/manifest/authorization identities and $targetDirectory to this receipt first. Only then stop/delete the approved test service and remove ONLY that version directory. Preserve evidence and base/releases parents; never touch another version or mismatching service. No automatic cleanup."
    Write-R4CText (Join-Path $root 'source-identities.json') ($before|ConvertTo-Json -Depth 8)
    $inventory=@(Get-ChildItem -LiteralPath $final -Recurse -File|ForEach-Object {$id=Get-R4CFileIdentity $_.FullName; [ordered]@{path=[IO.Path]::GetRelativePath($final,$_.FullName).Replace('\','/');size=$id.size;sha256=$id.sha256}}|Sort-Object path)
    Write-R4CText (Join-Path $root 'package-files.json') ($inventory|ConvertTo-Json -Depth 8)
    [IO.File]::Delete((Join-Path $root '.incomplete'))
    $receipt=[ordered]@{schema='cmg-fixed-ipc-preparation-v1';status='PASS_NONPRODUCTION';candidateDirectory=$final;targetDirectory=$targetDirectory;artifactId=$artifact;host=$hostId;child=$childId;manifestSHA256=$mh;fileCount=$inventory.Count;packageIdentity=(Get-R4CFileIdentity (Join-Path $root 'package-files.json')).sha256;installationPerformed=$false;productionEligible=$false;aclAcceptance='NOT_EXECUTED';fixtureMetadata='SYNTHETIC_ONLY_NOT_A_GATEWAY_BUILD'}
    Write-R4CText (Join-Path $root 'preparation-receipt.json') ($receipt|ConvertTo-Json -Depth 10)
    return $receipt
}
if (-not $LibraryOnly) {
    if ([string]::IsNullOrEmpty($TaskRoot)) { throw 'task_root_required' }
    if ($FixedIpc) { Invoke-FixedIpcPreparation -TaskRoot $TaskRoot | ConvertTo-Json -Depth 12 }
    else { Invoke-R4CPreparation -TaskRoot $TaskRoot | ConvertTo-Json -Depth 12 }
}
