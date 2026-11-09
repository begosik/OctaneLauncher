param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$PatchedFixture,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Baseline $Baseline -PatchedFixture $PatchedFixture -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$PublicBaseline=(Resolve-Path $Baseline).Path
if((Get-FileHash $PublicBaseline).Hash.ToLowerInvariant()-ne'24196904fffd52d00113672c68d2dc6299f59b62fe42cddd13bab440ea7a3025'){throw 'Expected authenticated public57 baseline'}
# Reuse the actual native UI / lifecycle helpers, not another implementation of
# the product's file transaction. The test source contains no vendor DLL bytes.
$helperScriptDirectory=$PSScriptRoot
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'battlenet_162.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry{`n Check")
if($a-lt0-or$b-le$a){throw 'Unexpected BattleNet helper boundaries'}
Invoke-Expression ($t.Substring($a,$b-$a).Replace('$PSScriptRoot','$helperScriptDirectory'))
$harnessOut=Join-Path $Output 'harness';[IO.Directory]::CreateDirectory($harnessOut)|Out-Null
Copy-Item -LiteralPath (Join-Path $helperScriptDirectory 'bn_image162.cs') -Destination $harnessOut
Copy-Item -LiteralPath $PSCommandPath -Destination $harnessOut
Add-Type -Path (Join-Path $helperScriptDirectory 'bn_image162.cs')
$Events=New-Object 'System.Collections.Generic.List[object]';$mapOld=$null;$mapPatched=$null;$mapGuard=$null;$recordTemplate=$null;$originalFixture=$null
function Hex([byte[]]$b){return [BitConverter]::ToString($b).Replace('-','').ToLowerInvariant()}
function Snapshot([string]$label){
 $files=@(Get-ChildItem -LiteralPath $contents -File|ForEach-Object{
  $f=$_;$id='';try{$id=Hex ([NativeImage162]::FileIdentity($f.FullName))}catch{}
  $r=[ordered]@{name=$f.Name;bytes=$f.Length;attributes=$f.Attributes.ToString();sha256=[NativeImage162]::HashFile($f.FullName);identity=$id}
  if($f.Name.EndsWith('.record')-and$f.Length-eq160){$r.receipt_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName))}
  [pscustomobject]$r
 })
 $Events.Add([pscustomobject]@{phase=$label;utc=[DateTime]::UtcNow.ToString('o');parent_identity=(Hex ([NativeImage162]::ParentIdentity($dll)));files=$files})
}
function Held($m,[string]$label,[string]$hash,[string]$identity,[int]$machine=0x14c,[int]$magic=0x10b){
 Check ($m.IsMapped-and$m.MappedSignature-eq0x4550-and$m.MappedMachine-eq$machine-and$m.MappedOptionalMagic-eq$magic) ($label+' is the expected PE image mapped with SEC_IMAGE without entry or TLS execution')
 Check ($m.Hash-eq$hash) ($label+' held file object still has its authenticated old bytes')
 Check ((Hex $m.Identity)-eq$identity) ($label+' held file identity is unchanged')
 $Events.Add([pscustomobject]@{phase=$label;held_sha256=$m.Hash;held_identity=(Hex $m.Identity);mapped_header=(Hex $m.MappedHeader);mapped_signature=$m.MappedSignature;machine=$m.MappedMachine;optional_magic=$m.MappedOptionalMagic;bytes=$m.Length})
}
function StopGuards(){
 Get-Process -Name OctaneBattleNetGuard* -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object{Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue;try{$_.WaitForExit(5000)|Out-Null}catch{}}
}
function EndCase(){if($v){CloseMain $v;$script:v=$null};StopGuards}
function ResetCase(){
 EndCase
 # Every entry in this directory was created by this test, below its unique
 # runner-temporary root. Unknown fixtures are removed only by the test owner.
 Get-ChildItem -LiteralPath $contents -File|Remove-Item -Force
 Copy-Item -LiteralPath $originalFixture -Destination $dll
}
function CaptureProductionReceipt(){
 foreach($f in @(Get-ChildItem -LiteralPath $contents -Filter '*.record' -File)){
  $bytes=[IO.File]::ReadAllBytes($f.FullName)
  if($bytes.Length-eq160-and(Hex $bytes[32..63])-eq$original-and(Hex $bytes[64..95])-eq$patched){
   $script:recordTemplate=$bytes;$script:recordName=$f.Name
   [IO.File]::WriteAllBytes((Join-Path $Output 'actual-production-receipt.bin'),$bytes)
   return $true
  }
 }
 return $false
}
function SeedState([string]$target,[string]$hold,[string]$stage){
 ResetCase;Remove-Item -LiteralPath $dll -Force
 $record=Join-Path $contents $recordName;$script:oldPath=$record.Substring(0,$record.Length-7)+'.old';$script:newPath=$record.Substring(0,$record.Length-7)+'.new'
 if($target-eq'old'){Copy-Item $originalFixture $dll}elseif($target-eq'new'){Copy-Item $PatchedFixture $dll}elseif($target-eq'unknown'){[IO.File]::WriteAllText($dll,'EXTERNAL VENDOR UPDATE - DO NOT REPLACE')}
 if($hold-eq'old'){Copy-Item $originalFixture $oldPath}elseif($hold-eq'unknown'){[IO.File]::WriteAllText($oldPath,'UNKNOWN HELD OBJECT - DO NOT RESTORE')}
 if($stage-eq'new'){Copy-Item $PatchedFixture $newPath}elseif($stage-eq'unknown'){[IO.File]::WriteAllText($newPath,'UNKNOWN STAGE - DO NOT DELETE')}
 # This is a byte-for-byte receipt produced by the signed product in this
 # same directory, never a second writer/parser agreeing with itself.
 [IO.File]::WriteAllBytes($record,$recordTemplate)
}
function StartupState([string]$name,[string]$target,[string]$hold,[string]$stage){
 SeedState $target $hold $stage;Snapshot ($name+' synthetic crash-state before startup')
 $script:v=LaunchOne $name;RestoreDone ($name+' restores the authenticated original through actual signed startup recovery');GuardReady $v
 Snapshot ($name+' after actual signed startup recovery');EndCase
}
function ErrorDialog($view,[string]$label){
 $d=Until {$q=[OctaneNativeTest]::Title($view.p.Id,'RA3 // OCTANE');if($q-ne[IntPtr]::Zero-and[OctaneNativeTest]::Class($q)-eq'#32770'){return $q}} ($label+' stopped launch dialog') 40
 Check ([Octane162ExitDialog]::Body($d)-match'BattleNet (compatibility patch could not be applied safely|DLL operation failed:)') ($label+' blocks game launch with the BattleNet failure dialog')
 [OctaneNativeTest]::Screenshot($d,(Join-Path $Output ($label+'-dialog.png')))|Write-Host
 $ok=Until {$b=[Octane162ExitDialog]::SingleButton($d);if($b-ne[IntPtr]::Zero){return $b}} ($label+' ready dialog action')
 [OctaneNativeTest]::PostMessage($d,0x111,[IntPtr]([Octane162ExitDialog]::GetDlgCtrlID($ok)),$ok)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($d)} ($label+' dialog dismissed')|Out-Null
}
function AssertNativeError([string]$log,[int]$code,[string]$label){
 $text=[IO.File]::ReadAllText($log)
 Check ($text-match ('(?s)BattleNet DLL operation failed: open current DLL for verified rename[^\r\n]*[\r\n]+.{0,2048}?\[Win32 '+$code+'\]')) ($label+' preserves open current DLL for verified rename and exact Win32='+$code)
 $Events.Add([pscustomobject]@{phase=$label;operation='open current DLL for verified rename';win32=$code;native_error_lines=@($text.Split("`n")|Where-Object{$_-match 'BattleNet DLL operation failed:|\[Win32 '})})
}
try{
 Check ((Get-FileHash $PatchedFixture).Hash.ToLowerInvariant()-eq$patched) 'Mapped-image fixture is the exact authenticated NativeDll from the signed public pack'
 $game=Join-Path $Work 'InstalledGame';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 $enginePath=Join-Path $game 'Data\ra3_1.12.game';Copy-Item $env:ComSpec $enginePath
 [IO.File]::WriteAllText((Join-Path $game 'RA3_english_1.12.SkuDef'),"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
 $baselineRoot=Extract $PublicBaseline 'authenticated57'
 $oldGuard=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\BattleNetRecovery\OctaneBattleNetGuard.exe';[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($oldGuard))|Out-Null
 Copy-Item (Join-Path $baselineRoot 'RA3Octane.exe') $oldGuard
 $mapGuard=New-Object NativeImage162($oldGuard);$guardId=Hex $mapGuard.Identity;$guardHash=$mapGuard.Hash
 Check ($guardHash-eq'38d2ca2872915bddf50278a180673a594421a307dfb9049577046e1268cbbb96') 'Mapped old static guardian is byte-identical to authenticated public57'
 SeedPatch;$mapPatched=New-Object NativeImage162($dll);$patchedId=Hex $mapPatched.Identity
 $v=LaunchOne 'mapped-patched-startup';RestoreDone '58 startup restores a real SEC_IMAGE-mapped patched DLL';GuardReady $v
 Held $mapPatched 'Startup mapped patched image' $patched $patchedId
 Check ((Hex ([NativeImage162]::FileIdentity($dll)))-ne$patchedId) 'New path opens restored stock as a different file object while patched view remains mapped'
 Held $mapGuard 'Old57 static guardian image' $guardHash $guardId 0x8664 0x20b
 $newGuard=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\BattleNetRecovery\OctaneBattleNetGuard-1.2.62.exe'
 Check ((Get-FileHash $newGuard).Hash-eq(Get-FileHash (Join-Path $v.root 'RA3Octane.exe')).Hash) '58 installs its distinct versioned guardian while old57 static image remains mapped'
 Snapshot 'Mapped patched startup restore completed';EndCase;$mapPatched.Dispose();$mapPatched=$null
 $originalFixture=Join-Path $Work 'authenticated-original.dll';Copy-Item $dll $originalFixture
 Check ((Get-FileHash $originalFixture).Hash.ToLowerInvariant()-eq$original) 'Original fixture comes only from the signed product verified restore'
 # Prove the old kernel operation itself, including its actual native error.
 ResetCase;$mapOld=New-Object NativeImage162($dll);$oldId=Hex $mapOld.Identity
 $probeStage=Join-Path $contents 'negative-control-stage.dll';Copy-Item $PatchedFixture $probeStage
 $probe=[NativeImage162]::ProbeOldMove($probeStage,$dll)
 $Events.Add([pscustomobject]@{phase='Old MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH) negative control';success=$probe.Success;win32=$probe.Win32Error})
 Check (!$probe.Success-and$probe.Win32Error-ne0) 'Old replacement operation fails on the real mapped image and reports its native Win32 code'
 Check ((DllHash)-eq$original) 'Failed old replacement preserves the exact original at the target path';Remove-Item $probeStage
 # Exercise the exact old signed launcher too, with recognized frontend path.
 $clientPath=Join-Path $client 'Ra3.BattleNet.Client.exe';Copy-Item $env:ComSpec $clientPath
 $start=New-Object System.Diagnostics.ProcessStartInfo;$start.FileName=$clientPath;$start.Arguments='/d /c ping -n 180 127.0.0.1 >nul';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $clientProcess=New-Object System.Diagnostics.Process;$clientProcess.StartInfo=$start;Check ($clientProcess.Start()) 'Recognized frontend fixture starts for the public57 reproduction'
 [IO.File]::WriteAllText((Join-Path $baselineRoot 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nDirectory=$client`r`n")
 $v=Launch $baselineRoot;GuardReady $v;[OctaneNativeTest]::Click($v.w,350,495,1060,736);ErrorDialog $v 'baseline57-mapped-original'
 Check ((DllHash)-eq$original) 'Actual public57 reproduces the mapped-DLL install failure without changing the original'
 Held $mapOld 'Public57 failed mapped original' $original $oldId
 Copy-Item (Join-Path $v.root 'Logs\launcher.log') (Join-Path $Output 'baseline57-reproduction.log');EndCase
 Stop-Process -Id $clientProcess.Id -Force;$clientProcess.WaitForExit();$clientProcess=$null
 # The same still-mapped old object now succeeds through actual signed58.
 $v=LaunchOne 'mapped-original-install';GuardReady $v;[OctaneNativeTest]::Click($v.w,350,495,1060,736)
 $log=Join-Path $v.root 'Logs\launcher.log';Until {[IO.File]::ReadAllText($log).Contains('[BATTLENET] Installed-client session patch verified')} '58 installs compatibility DLL with real original image still mapped' 40|Out-Null
 $runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
 $started=Until {Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.Path-eq$runtime}|Select-Object -First 1} 'actual58 isolated game process' 20
 Check ((DllHash)-eq$patched) '58 install publishes the exact patched bytes at the installed path'
 Held $mapOld '58 successful mapped original install' $original $oldId
 Check ((Hex ([NativeImage162]::FileIdentity($dll)))-ne$oldId) '58 installed path has a new file identity while original mapped object remains intact'
 Until {CaptureProductionReceipt} 'actual immutable production receipt retained while old image is mapped' 10|Out-Null
 Check ($recordTemplate.Length-eq160) 'Crash-state template is an actual durable160-byte receipt written by the signed launcher'
 Snapshot 'Actual58 mapped install with production receipt'
 $mapPatched=New-Object NativeImage162($dll);$patchedId=Hex $mapPatched.Identity
 $heldHandle=$started.Handle;Stop-Process -Id $started.Id -Force;$started.WaitForExit();$exitHex=[Convert]::ToString([int]$started.ExitCode,16).PadLeft(8,'0');$started=$null
 RestoreDone '58 restores stock while real patched NativeDll image remains mapped'
 Held $mapOld 'Original image after symmetric restore' $original $oldId
 Held $mapPatched 'Patched image after symmetric restore' $patched $patchedId
 Check ((Hex ([NativeImage162]::FileIdentity($dll)))-ne$patchedId) 'Restored target has another file identity while old patched view remains intact'
 Snapshot 'Actual58 symmetric mapped restore';CompleteStoppedLaunch $v $exitHex 'Mapped-image';EndCase
 $mapOld.Dispose();$mapOld=$null;$mapPatched.Dispose();$mapPatched=$null
 StartupState 'receipt-before-stage' 'old' '' ''
 StartupState 'stage-before-park' 'old' '' 'new'
 StartupState 'parked-missing-target' '' 'old' 'new'
 StartupState 'published-before-cleanup' 'new' 'old' ''
 StartupState 'hold-deleted-before-receipt' 'new' '' ''
 # Alias/casing must not invalidate a receipt tied to the actual parent ID.
 SeedState '' 'old' 'new';$savedClient=$client;$client=$client.ToUpperInvariant()
 try{$v=LaunchOne 'case-alias-missing-target';RestoreDone 'Receipt survives equivalent directory path casing';GuardReady $v;Snapshot 'Case alias recovery';EndCase}finally{$client=$savedClient}
 SeedState '' 'old' 'unknown';$unknown=(Get-FileHash $newPath).Hash;$v=LaunchOne 'missing-target-unknown-stage';RestoreDone 'Missing target recovers verified old image even when staging object was changed';GuardReady $v
 Check ((Get-FileHash $newPath).Hash-eq$unknown) 'Recovery preserves the changed stage while restoring the authenticated old image';Snapshot 'Missing target with unknown stage preserved';EndCase
 SeedState 'unknown' 'old' 'new';$unknown=(DllHash);$v=LaunchOne 'unknown-target-conflict';Start-Sleep -Seconds 3
 Check ((DllHash)-eq$unknown) 'A vendor update occupying the target gap is never overwritten by recovery';Snapshot 'Unknown target conflict preserved';EndCase
 SeedState '' 'unknown' 'new';$unknown=(Get-FileHash $oldPath).Hash;$v=LaunchOne 'tampered-old-conflict';Start-Sleep -Seconds 3
 Check (!(Test-Path $dll)) 'Missing target is never reconstructed from a tampered held object'
 Check ((Get-FileHash $oldPath).Hash-eq$unknown) 'Tampered old slot object remains untouched';Snapshot 'Tampered old conflict preserved';EndCase
 SeedState 'old' '' 'unknown';$unknown=(Get-FileHash $newPath).Hash;$v=LaunchOne 'unknown-stage-conflict';Start-Sleep -Seconds 3
 Check ((DllHash)-eq$original) 'A reused valid receipt never authorizes replacement of the current original with an unknown stage'
 Check ((Get-FileHash $newPath).Hash-eq$unknown) 'Unknown staging object is never deleted merely because its slot name matches';Snapshot 'Unknown stage conflict preserved';EndCase
 # Cleanup must not clear readonly metadata through an external hardlink.
 SeedState 'old' 'old' '';$alias=Join-Path $Work 'external-held-alias.dll'
 New-Item -ItemType HardLink -Path $alias -Target $oldPath|Out-Null
 Check ((Hex ([NativeImage162]::FileIdentity($alias)))-eq(Hex ([NativeImage162]::FileIdentity($oldPath)))) 'Readonly alias fixture is a real second hardlink to the receipt-owned old object'
 [IO.File]::SetAttributes($alias,([IO.File]::GetAttributes($alias)-bor[IO.FileAttributes]::ReadOnly))
 try{
  $v=LaunchOne 'readonly-hardlink-preserved';RestoreDone 'Readonly hardlink cleanup leaves original target verified';GuardReady $v;Start-Sleep -Seconds 2
  Check ((([IO.File]::GetAttributes($alias)-band[IO.FileAttributes]::ReadOnly)-ne0)-and((Get-FileHash $alias).Hash.ToLowerInvariant()-eq$original)) 'Cleanup preserves readonly metadata and authenticated bytes through the external hardlink alias'
  Check (Test-Path $oldPath) 'Multiply linked readonly old artifact is retained rather than mutating its external alias'
  Snapshot 'Readonly external hardlink metadata preserved';EndCase
 }finally{[IO.File]::SetAttributes($alias,[IO.FileAttributes]::Normal);Remove-Item -LiteralPath $alias -Force}
 # Two genuinely different access failures must remain explicit failures.
 ResetCase;$v=LaunchOne 'sharing-denied';GuardReady $v
 $fileLock=[IO.File]::Open($dll,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 [OctaneNativeTest]::Click($v.w,350,495,1060,736);ErrorDialog $v 'sharing-denied'
 Check ((DllHash)-eq$original) 'Absolute sharing-deny is not bypassed and preserves original bytes'
 AssertNativeError (Join-Path $v.root 'Logs\launcher.log') 32 'Sharing-deny'
 $fileLock.Dispose();$fileLock=$null;EndCase
 ResetCase;$v=LaunchOne 'acl-denied';GuardReady $v
 $savedAcl=Get-Acl -LiteralPath $dll;$savedParentAcl=Get-Acl -LiteralPath $contents;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 try{
  $acl=Get-Acl -LiteralPath $dll;$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::Delete,[Security.AccessControl.AccessControlType]::Deny);$acl.AddAccessRule($rule);Set-Acl -LiteralPath $dll -AclObject $acl
  $parentAcl=Get-Acl -LiteralPath $contents;$parentRule=New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,[Security.AccessControl.AccessControlType]::Deny);$parentAcl.AddAccessRule($parentRule);Set-Acl -LiteralPath $contents -AclObject $parentAcl
  [OctaneNativeTest]::Click($v.w,350,495,1060,736);ErrorDialog $v 'acl-denied'
  Check ((DllHash)-eq$original) 'ACL delete denial is not bypassed and preserves original bytes'
  AssertNativeError (Join-Path $v.root 'Logs\launcher.log') 5 'ACL denial'
 }finally{Set-Acl -LiteralPath $dll -AclObject $savedAcl;Set-Acl -LiteralPath $contents -AclObject $savedParentAcl}
 EndCase;ResetCase
 # A known already-desired DLL needs no DELETE access and no rewrite.
 $v=LaunchOne 'already-patched-readonly-reuse';GuardReady $v
 $mutex=New-Object System.Threading.Mutex($false,'Local\Begosik.RA3Octane.BattleNet.IO.141');$taken=$false
 try{$taken=$mutex.WaitOne(10000);if(!$taken){throw 'Recovery IO mutex timeout'};SeedPatch;$fileLock=[IO.File]::Open($dll,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}finally{if($taken){$mutex.ReleaseMutex()};$mutex.Dispose()}
 $reuseId=Hex ([NativeImage162]::FileIdentity($dll));[OctaneNativeTest]::Click($v.w,350,495,1060,736)
 $log=Join-Path $v.root 'Logs\launcher.log';Until {[IO.File]::ReadAllText($log).Contains('[BATTLENET] Current session patch already verified; DLL reused without rewriting.')} 'already-desired signed DLL reuse without DELETE access' 40|Out-Null
 $started=Until {Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.Path-eq$runtime}|Select-Object -First 1} 'actual game starts with already-desired locked DLL' 20
 Check ((DllHash)-eq$patched) 'Already-desired locked DLL remains exact patched bytes'
 Check ((Hex ([NativeImage162]::FileIdentity($dll)))-eq$reuseId) 'Already-desired locked DLL is reused with unchanged file identity'
 Snapshot 'Already-desired locked DLL reuse'
 $heldHandle=$started.Handle;Stop-Process -Id $started.Id -Force;$started.WaitForExit();$exitHex=[Convert]::ToString([int]$started.ExitCode,16).PadLeft(8,'0');$started=$null
 $fileLock.Dispose();$fileLock=$null;RestoreDone 'Already-desired reuse restores stock after game exit and lock release';CompleteStoppedLaunch $v $exitHex 'Already-desired reuse';EndCase;ResetCase
 Held $mapGuard 'Old57 guardian after complete58 matrix' $guardHash $guardId 0x8664 0x20b
 Check ((DllHash)-eq$original) 'All controlled transactions finish with exact original installed bytes'
}catch{
 $Failure=$_.Exception.Message;Write-Host ('BN_SWAP162_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace
 if($v){try{[OctaneNativeTest]::Screenshot($v.w,(Join-Path $Output 'failure-launcher.png'))|Write-Host}catch{}}
}finally{
 if($started-and!$started.HasExited){Stop-Process -Id $started.Id -Force -ErrorAction SilentlyContinue}
 if($clientProcess-and!$clientProcess.HasExited){Stop-Process -Id $clientProcess.Id -Force -ErrorAction SilentlyContinue}
 if($fileLock){$fileLock.Dispose()};if($mapOld){$mapOld.Dispose()};if($mapPatched){$mapPatched.Dispose()};if($mapGuard){$mapGuard.Dispose()}
 if($v-and!$v.p.HasExited){Stop-Process -Id $v.p.Id -Force -ErrorAction SilentlyContinue};StopGuards
 $logOut=Join-Path $Output 'logs';[IO.Directory]::CreateDirectory($logOut)|Out-Null
 Get-ChildItem -LiteralPath $Work -Filter 'launcher.log' -File -Recurse|ForEach-Object{Copy-Item $_.FullName (Join-Path $logOut ($_.Directory.Parent.Parent.Name+'.log'))}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());events=@($Events.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();baseline_sha256=(Get-FileHash $PublicBaseline).Hash.ToLowerInvariant();scope='Actual signed57 failure and signed58 install/restoration, real x86 NativeDll SEC_IMAGE mappings with no entry/TLS execution, live held file identity/hash probes, actual versioned guardian migration, sharing/ACL errors. Synthetic crash states reuse the exact product-produced receipt in the same controlled parent; they are not injected crashes. Evidence records small receipts, hashes, identities and mapped headers instead of repeated DLL copies. No RA3 gameplay, full-client execution, network or desync certification.'}|ConvertTo-Json -Depth 12|Set-Content (Join-Path $Output 'BN_SWAP_WINDOWS_162.json') -Encoding UTF8
}
if($Failure){exit 1}
