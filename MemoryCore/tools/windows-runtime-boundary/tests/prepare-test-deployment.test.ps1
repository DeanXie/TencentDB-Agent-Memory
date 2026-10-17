[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TaskRoot,
    [Parameter(Mandatory)][string]$FixtureBinary,
    [Parameter(Mandatory)][string]$FixtureSHA256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\scripts\prepare-test-deployment.ps1'
if (Test-Path -LiteralPath $scriptPath) { . $scriptPath -LibraryOnly -TaskRoot $TaskRoot }
$script:results = [System.Collections.Generic.List[object]]::new()
function Check([bool]$Value, [string]$Message) { if (-not $Value) { throw "assertion:$Message" } }
function Api([string]$Name) {
    if (-not (Get-Command -Name $Name -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "r4c_preparation_unavailable:$Name"
    }
}
function Reject([scriptblock]$Action, [string]$Code) {
    try { & $Action; throw 'unexpected_acceptance' }
    catch { if ($_.Exception.Message -notlike "*$Code*") { throw } }
}
function Case([string]$Name, [scriptblock]$Action) {
    try { & $Action; $script:results.Add([ordered]@{name=$Name;status='PASS'}); "PASS $Name" }
    catch { $script:results.Add([ordered]@{name=$Name;status='FAIL';error=$_.Exception.Message}); "FAIL $Name $($_.Exception.Message)" }
}
$fixture = Get-Item -LiteralPath $FixtureBinary
if ((Get-FileHash -LiteralPath $FixtureBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $FixtureSHA256) {
    throw 'fixture_hash_mismatch'
}
$size = $fixture.Length
$work = Join-Path $TaskRoot ('tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
Case 'real offline-built test service binary is accepted' {
    Api Assert-R4CBinary
    $id = Assert-R4CBinary $FixtureBinary $FixtureSHA256 $size
    Check ($id.sha256 -ceq $FixtureSHA256) 'real_binary_identity'
}
Case 'wrong executable filename is rejected' {
    Api Assert-R4CBinary
    $wrong = Join-Path $work 'wrong.exe'
    [IO.File]::Copy($FixtureBinary, $wrong)
    Reject { Assert-R4CBinary $wrong $FixtureSHA256 $size } 'binary_name_rejected'
}
Case 'tampered real binary is rejected' {
    Api Assert-R4CBinary
    $dir = Join-Path $work 'tampered'
    [void][IO.Directory]::CreateDirectory($dir)
    $path = Join-Path $dir 'cmg-runtime-boundary-test-service.exe'
    $bytes = [IO.File]::ReadAllBytes($FixtureBinary)
    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
    [IO.File]::WriteAllBytes($path, $bytes)
    Reject { Assert-R4CBinary $path $FixtureSHA256 $size } 'binary_identity_mismatch'
}
Case 'non PE data with expected filename cannot be accepted' {
    Api Assert-R4CBinary
    $dir = Join-Path $work 'non-pe'
    [void][IO.Directory]::CreateDirectory($dir)
    $path = Join-Path $dir 'cmg-runtime-boundary-test-service.exe'
    [IO.File]::WriteAllText($path, ('not an executable' * 8))
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Reject { Assert-R4CBinary $path $hash (Get-Item -LiteralPath $path).Length } 'pe_identity_rejected'
}
Case 'path traversal and alternate data streams are rejected' {
    Api Assert-R4CPath
    Reject { Assert-R4CPath (Join-Path $work '..\escape') } 'path_rejected'
    Reject { Assert-R4CPath ($FixtureBinary + ':payload') } 'path_rejected'
}
Case 'trailing dots and device paths are rejected' {
    Api Assert-R4CPath
    Reject { Assert-R4CPath ($work + '.\output') } 'path_rejected'
    Reject { Assert-R4CPath '\\?\C:\unsafe' } 'path_rejected'
}
Case 'actual junction path is rejected' {
    Api Assert-R4CPath
    $destination = Join-Path $work 'junction-target'
    [void][IO.Directory]::CreateDirectory($destination)
    $junction = Join-Path $work 'junction'
    [void](New-Item -ItemType Junction -Path $junction -Target $destination)
    Reject { Assert-R4CPath (Join-Path $junction 'candidate') } 'reparse_rejected'
}
Case 'only fixed service name is accepted' {
    Api New-R4CInstallationContract
    Reject { New-R4CInstallationContract $FixtureSHA256 $size 'TencentDBMemoryGateway' } 'service_name_rejected'
}
Case 'installation parameters cannot expand entry account or arguments' {
    Api New-R4CInstallationContract
    $c = New-R4CInstallationContract $FixtureSHA256 $size
    Check ($c.serviceName -ceq 'CmgRuntimeBoundaryR4ATest') 'name'
    Check ($c.account -ceq 'NT SERVICE\CmgRuntimeBoundaryR4ATest') 'account'
    Check ($c.startMode -ceq 'demand') 'manual'
    Check ($c.arguments.Count -eq 0) 'no_arguments'
    Check ($c.binaryPath -ceq ($c.targetDirectory + '\cmg-runtime-boundary-test-service.exe')) 'entry'
    Check ($c.recoveryActions.Count -eq 0) 'no_recovery_commands'
    Reject { New-R4CInstallationContract $FixtureSHA256 $size -Command 'cmd.exe' } 'parameter'
}
Case 'copy verifies both source and destination raw identity' {
    Api Copy-R4CBinary
    $dest = Join-Path $work 'copy\cmg-runtime-boundary-test-service.exe'
    $id = Copy-R4CBinary $FixtureBinary $dest $FixtureSHA256 $size
    Check ($id.sha256 -ceq $FixtureSHA256) 'copy_identity'
    Check ((Get-FileHash -LiteralPath $dest).Hash.ToLowerInvariant() -ceq $FixtureSHA256) 'destination_bytes'
}
Case 'existing output is never overwritten' {
    Api Copy-R4CBinary
    $dest = Join-Path $work 'collision\cmg-runtime-boundary-test-service.exe'
    [void][IO.Directory]::CreateDirectory((Split-Path $dest))
    [IO.File]::WriteAllText($dest, 'preserved')
    Reject { Copy-R4CBinary $FixtureBinary $dest $FixtureSHA256 $size } 'output_collision'
    Check ([IO.File]::ReadAllText($dest) -ceq 'preserved') 'existing_preserved'
}
Case 'source mutation is refused before copy' {
    Api Copy-R4CBinary
    $source = Join-Path $work 'tampered\cmg-runtime-boundary-test-service.exe'
    Reject { Copy-R4CBinary $source (Join-Path $work 'mutated-copy\cmg-runtime-boundary-test-service.exe') $FixtureSHA256 $size } 'binary_identity_mismatch'
    Check (-not (Test-Path -LiteralPath (Join-Path $work 'mutated-copy'))) 'no_partial_success'
}
Case 'package manifest denies incomplete or extra contents' {
    Api Assert-R4CCandidate
    $dir = Join-Path $work 'partial'
    [void][IO.Directory]::CreateDirectory($dir)
    [IO.File]::WriteAllText((Join-Path $dir '.incomplete'), 'pending')
    Reject { Assert-R4CCandidate $dir } 'candidate_incomplete'
}
Case 'production eligibility is unconditionally false' {
    Api New-R4CInstallationContract
    $c = New-R4CInstallationContract $FixtureSHA256 $size
    Check (-not $c.productionEligible) 'production_false'
    Check (-not $c.installationApproved) 'admin_not_approved'
    Check (-not $c.installationPerformed) 'not_installed'
    Check ($c.runtimeIntegration -ceq 'NOT_IMPLEMENTED') 'integration'
    Check ($c.serviceSidAttestation -ceq 'NOT_EXECUTED') 'no_sid_attestation'
}
Case 'normal script rejects external executable and service overrides' {
    Api Invoke-R4CPreparation
    Reject { Invoke-R4CPreparation -TaskRoot $work -ServiceName 'OtherService' } 'parameter'
    Reject { Invoke-R4CPreparation -TaskRoot $work -Executable 'cmd.exe' } 'parameter'
}
Case 'Cargo home wrapper and linker environment overrides are rejected' {
    Api Invoke-R4CPreparation
    foreach ($variable in @('CARGO_HOME','CARGO_BUILD_RUSTC_WRAPPER','CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER')) {
        $old = [Environment]::GetEnvironmentVariable($variable)
        try {
            [Environment]::SetEnvironmentVariable($variable, 'synthetic-unapproved')
            Reject { Invoke-R4CPreparation -TaskRoot $work } 'build_override_rejected'
        } finally {
            if ($null -eq $old) { Remove-Item -LiteralPath ('Env:\' + $variable) -ErrorAction SilentlyContinue }
            else { [Environment]::SetEnvironmentVariable($variable, $old) }
        }
    }
}
Case 'new unreviewed PE dependency is rejected' {
    Api Assert-R4CImports
    Reject { Assert-R4CImports @('kernel32.dll','unexpected-library.dll') } 'pe_dependency_requires_review'
}
Case 'fresh real package builds copies and independently verifies' {
    Api Invoke-R4CPreparation
    $run = Join-Path $work 'real-preparation'
    [void][IO.Directory]::CreateDirectory($run)
    $fakeTools = Join-Path $work 'unapproved-tools'
    [void][IO.Directory]::CreateDirectory($fakeTools)
    [IO.File]::WriteAllText((Join-Path $fakeTools 'cargo.exe'), 'This must never execute')
    $oldPath = $env:PATH
    try {
        $env:PATH = $fakeTools + ';' + $oldPath
        $script:prepared = Invoke-R4CPreparation -TaskRoot $run
    } finally { $env:PATH = $oldPath }
    Check ($script:prepared.status -ceq 'PASS_NONPRODUCTION') 'ready'
    Check ($script:prepared.binary.sha256.Length -eq 64) 'binary_hash'
    Check (Test-Path -LiteralPath $script:prepared.archive) 'real_archive'
    $manifest = Assert-R4CCandidate $script:prepared.candidateDirectory
    Check ($manifest.files.Count -eq 7) 'exact_contents'
    $build = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'build-info.json') -Raw | ConvertFrom-Json
    Check ($build.buildEnvironment -ceq 'EMPTY_PLUS_FIXED_WINDOWS_TOOLCHAIN_ALLOWLIST') 'clean_build_environment'
    Check ($build.buildWorkingDirectory -ceq [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'fixed_build_cwd'
}
Case 'generated operation plans have complete syntax and fail-closed guards' {
    Api Assert-R4CCandidate
    $dir = $script:prepared.candidateDirectory
    foreach ($document in @('INSTALLATION.md','ACCEPTANCE.md','ROLLBACK.md')) {
        $text = Get-Content -LiteralPath (Join-Path $dir $document) -Raw
        Check (-not $text.Contains('@@')) 'no_placeholders'
        foreach ($match in [regex]::Matches($text, '(?s)\x60{3}powershell\r?\n(.*?)\x60{3}')) {
            $tokens=$null; $errors=$null
            $null=[Management.Automation.Language.Parser]::ParseInput($match.Groups[1].Value,[ref]$tokens,[ref]$errors)
            Check ($errors.Count -eq 0) "syntax:$document"
        }
    }
    $install = Get-Content -LiteralPath (Join-Path $dir 'INSTALLATION.md') -Raw
    foreach ($required in @('installation_collision','directory_collision','CreateNew','Set-Acl','Assert-WriteBoundary','Assert-ServiceConfiguration','Assert-DeployedBinary','sc_failed')) { Check ($install.Contains($required)) "install_guard:$required" }
    $acceptance = Get-Content -LiteralPath (Join-Path $dir 'ACCEPTANCE.md') -Raw
    foreach ($required in @('service_configuration_mismatch','service_dacl_rejected','runtime_prerequisite_changed','try {','finally {','Stop-Service','stop_not_verified','Read-Host')) { Check ($acceptance.Contains($required)) "acceptance_guard:$required" }
}
Case 'candidate tamper and extra files are detected after packaging' {
    Api Assert-R4CCandidate
    Check ($null -ne $script:prepared) 'prior_real_package'
    $dir = Join-Path $work 'tampered-package'
    [void][IO.Directory]::CreateDirectory($dir)
    foreach ($file in Get-ChildItem -LiteralPath $script:prepared.candidateDirectory -File) {
        [IO.File]::Copy($file.FullName, (Join-Path $dir $file.Name))
    }
    [IO.File]::AppendAllText((Join-Path $dir 'ACCEPTANCE.md'), 'tamper')
    Reject { Assert-R4CCandidate $dir } 'candidate_identity_mismatch'
    [IO.File]::Copy((Join-Path $script:prepared.candidateDirectory 'ACCEPTANCE.md'), (Join-Path $dir 'ACCEPTANCE.md'), $true)
    [IO.File]::WriteAllText((Join-Path $dir 'secret.txt'), 'synthetic')
    Reject { Assert-R4CCandidate $dir } 'candidate_contents_rejected'
}
Case 'document cleanup state machine waits for pending and never claims stopped early' {
    Api Assert-R4CCandidate
    $text = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'ACCEPTANCE.md') -Raw
    $block = [regex]::Match($text,'(?s)\x60{3}powershell\r?\n(.*?)\x60{3}').Groups[1].Value
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($block,[ref]$tokens,[ref]$errors)
    $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-R4CStopAction'},$true)
    Check ($null -ne $definition) 'real_document_state_function'
    . ([scriptblock]::Create($definition.Extent.Text))
    foreach ($state in @('StartPending','StopPending','PausePending','ContinuePending')) { Check ((Get-R4CStopAction $state) -ceq 'WAIT') 'pending_is_not_stopped' }
    Check ((Get-R4CStopAction 'Running') -ceq 'STOP') 'late_running_must_stop'
    Check ((Get-R4CStopAction 'Stopped') -ceq 'DONE') 'actual_terminal_only'
    Reject { Get-R4CStopAction 'UNKNOWN' } 'unknown_service_state'
    Check ($text.Contains('STOP_NOT_VERIFIED_MAY_STILL_RUN')) 'timeout_explicitly_blocked'
    Check ($text.Contains('-NoWait')) 'stop_call_does_not_wait_unbounded'
}
Case 'rollback distinguishes pre-registration output and preserves reusable parents' {
    Api Assert-R4CCandidate
    $text = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'ROLLBACK.md') -Raw
    foreach ($required in @('$hasService = Test-Path','if ($hasService)','elseif ($entries.Count -ne 0)','unrecognized_partial_output_preserve_for_review','Remove-Item -LiteralPath $target','Base/releases parents remain protected and reusable')) { Check ($text.Contains($required)) "rollback_guard:$required" }
    Check (-not $text.Contains('Remove-Item -LiteralPath $base')) 'base_not_deleted'
    Check (-not $text.Contains('Remove-Item -LiteralPath $releases')) 'releases_not_deleted'
    $install = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'INSTALLATION.md') -Raw
    Check ($install.Contains('Assert-WriteBoundary $directory')) 'existing_parents_revalidated'
}
Case 'document ACL contract requires SYSTEM administrator and service positive rights' {
    Api Assert-R4CCandidate
    $text = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'INSTALLATION.md') -Raw
    $block = [regex]::Match($text,'(?s)\x60{3}powershell\r?\n(.*?)\x60{3}').Groups[1].Value
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($block,[ref]$tokens,[ref]$errors)
    $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-R4CRequiredRights'},$true)
    Check ($null -ne $definition) 'real_acl_document_function'
    . ([scriptblock]::Create($definition.Extent.Text))
    $sid='S-1-5-80-1-2-3-4-5'
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),'FullControl','Allow'))
    Reject { Assert-R4CRequiredRights ($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) $sid } 'required_directory_rights_missing'
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),'FullControl','Allow'))
    Reject { Assert-R4CRequiredRights ($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) $sid } 'required_directory_rights_missing'
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','Allow'))
    Assert-R4CRequiredRights ($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) $sid
}
Case 'document rollback rejects registry and SCM presence disagreement' {
    Api Assert-R4CCandidate
    $text = Get-Content -LiteralPath (Join-Path $script:prepared.candidateDirectory 'ROLLBACK.md') -Raw
    $block = [regex]::Match($text,'(?s)\x60{3}powershell\r?\n(.*?)\x60{3}').Groups[1].Value
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($block,[ref]$tokens,[ref]$errors)
    $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-R4CServicePresence'},$true)
    . ([scriptblock]::Create($definition.Extent.Text))
    Reject { Assert-R4CServicePresence $false $true } 'service_presence_inconsistent_preserve'
    Reject { Assert-R4CServicePresence $true $false } 'service_presence_inconsistent_preserve'
    Check (-not (Assert-R4CServicePresence $false $false)) 'pre_registration_only_when_both_absent'
    Check (Assert-R4CServicePresence $true $true) 'existing_registered_service'
}
Case 'archive entries independently match the verified candidate' {
    Api Assert-R4CArchive
    Assert-R4CArchive $script:prepared.archive $script:prepared.candidateDirectory
}
Case 'tampered archive payload is rejected without extraction' {
    Api Assert-R4CArchive
    $badZip = Join-Path $work 'tampered.zip'
    [IO.File]::Copy($script:prepared.archive, $badZip)
    $zip = [IO.Compression.ZipFile]::Open($badZip, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $zip.GetEntry('ACCEPTANCE.md')
        $entry.Delete()
        $replacement = $zip.CreateEntry('ACCEPTANCE.md')
        $stream = $replacement.Open()
        try { $bytes = [Text.Encoding]::UTF8.GetBytes('tampered'); $stream.Write($bytes,0,$bytes.Length) }
        finally { $stream.Dispose() }
    } finally { $zip.Dispose() }
    Reject { Assert-R4CArchive $badZip $script:prepared.candidateDirectory } 'archive_identity_mismatch'
}
Case 'real preparation refuses an existing candidate output' {
    Api Invoke-R4CPreparation
    Reject { Invoke-R4CPreparation -TaskRoot (Split-Path $script:prepared.candidateDirectory) } 'output_collision'
}
Case 'preparation refuses development and protected directory output' {
    Api Invoke-R4CPreparation
    Reject { Invoke-R4CPreparation -TaskRoot 'F:\AI\TencentDB-Agent-Memory' } 'output_outside_temporary_area'
    Reject { Invoke-R4CPreparation -TaskRoot 'C:\Program Files' } 'output_outside_temporary_area'
}
Case 'preparation invokes no service writes and rollback is exact and confirmed' {
    Api Assert-R4CCandidate
    Check ($null -ne $script:prepared) 'prior_real_package'
    $rollback = [IO.File]::ReadAllText((Join-Path $script:prepared.candidateDirectory 'ROLLBACK.md'))
    Check ($rollback.Contains('Read-Host')) 'confirmation'
    Check ($rollback.Contains('CmgRuntimeBoundaryR4ATest')) 'fixed_service'
    foreach ($forbidden in @('TencentDBMemoryGateway','CMGDirectVerifier','CmgDirectVerifierTest','Remove-Item -Recurse C:\')) {
        Check (-not $rollback.Contains($forbidden)) 'unrelated_resource'
    }
    $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    $commands = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]}, $true) | ForEach-Object { $_.GetCommandName() })
    foreach ($command in @('New-Service','Start-Service','Stop-Service','Remove-Service','Set-Service','sc.exe','Start-Process','Invoke-Expression')) {
        Check ($commands -notcontains $command) "no_execution:$command"
    }
    $collision = Get-R4CCollisionState (New-R4CInstallationContract $FixtureSHA256 $size)
    Check ($collision.serviceAbsent -and $collision.targetAbsent) 'still_not_installed'
}
$fail = @($script:results | Where-Object status -eq 'FAIL').Count
$summary = [ordered]@{tests=$script:results.Count;pass=$script:results.Count-$fail;fail=$fail;results=$script:results}
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $TaskRoot 'test-results.json') -Encoding utf8NoBOM
"SUMMARY tests=$($summary.tests) pass=$($summary.pass) fail=$fail"
if ($fail -gt 0) { exit 1 }
exit 0
