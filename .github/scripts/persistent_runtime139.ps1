param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Baseline $Baseline -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop'
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract");if($a-lt0-or$b-le$a){throw 'Unexpected native helper definitions'}
Invoke-Expression $t.Substring($a,$b-$a)
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class Runtime139 {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint attr,c1,c2,a1,a2,w1,w2,volume,hi,lo,links,idhi,idlo;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static string Identity(string p){using(var f=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){Info i;if(!GetFileInformationByHandle(f.SafeFileHandle,out i))throw new Exception("File identity "+Marshal.GetLastWin32Error());return i.volume+":"+i.idhi+":"+i.idlo+":"+i.c1+":"+i.c2+":"+i.w1+":"+i.w2+":"+f.Length;}}
}
'@
function Snap([string]$dir){$r=@{};Get-ChildItem -LiteralPath $dir -Recurse -Force -File|ForEach-Object{$r[$_.FullName.Substring($dir.Length)]=([Runtime139]::Identity($_.FullName)+' '+(Get-FileHash -LiteralPath $_.FullName).Hash)};return $r}
function Same($before,[string]$dir,[string[]]$except=@()){$after=Snap $dir;foreach($k in $before.Keys){if($except-contains$k){continue};if(!$after.ContainsKey($k)-or$after[$k]-ne$before[$k]){Write-Host ('IDENTITY_DIFFERENCE '+$k);return $false}};return $true}
function Close139($v){$notice=[OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update');if($notice-ne[IntPtr]::Zero){[OctaneNativeTest]::PostMessage($notice,0x111,[IntPtr]7,[IntPtr]::Zero)|Out-Null;Start-Sleep -Milliseconds 200};CloseMain $v}
function Config([string]$root,[string]$game){[IO.File]::WriteAllText((Join-Path $root 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nAutoPatch=0`r`nPreferencePolicy=132`r`n[Firewall]`r`nRuntimeRule=1`r`n")}
function ReplayFail([string]$root,[string]$replay){$process=Start-Process (Join-Path $root 'RA3Octane.exe') -WorkingDirectory $root -ArgumentList ("--replay `""+$replay+"`"") -PassThru;$window=Until {[OctaneNativeTest]::Window($process.Id,'Begosik.RA3Octane.Native.v1')} 'replay launcher';$log=Join-Path $root 'Logs\launcher.log';Until {(Test-Path $log)-and[IO.File]::ReadAllText($log).Contains('Not a supported RA3 replay header.')} 'expected replay rejection'|Out-Null;Start-Sleep -Milliseconds 400;return @{p=$process;w=$window;root=$root}}
$lock=$null
try{
 $game=Join-Path $Work 'Game';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 $installed=Join-Path $game 'Data\ra3_1.12.game';[IO.File]::WriteAllText($installed,'Read-only installed game sentinel')
 $sku=Join-Path $game 'RA3_english_1.12.SkuDef';[IO.File]::WriteAllText($sku,"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
 $originalGame=(Get-FileHash $installed).Hash;$originalSku=(Get-FileHash $sku).Hash
 $replay=Join-Path $Work 'invalid.RA3Replay';[IO.File]::WriteAllText($replay,'Deliberately invalid replay for pre-process failure path')
 $old=Extract $Baseline 'old removal control';Config $old $game
 $session=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime'
 $v=ReplayFail $old $replay;Check (!(Test-Path $session)) 'Old public 1.2.38 reproduces deletion of prepared files on the launch-end path';Close139 $v
 $r=Extract $Package 'persistent installation';[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[BattleNet]`r`nAutoPatch=0`r`nPreferencePolicy=132`r`n")
 $v=Launch $r
 $exe=Join-Path $session 'Data\ra3_1.12.game';$core=Join-Path $session 'Data\Core13.big';$observer=Join-Path $session 'Data\OctaneDiagnostics.exe';$cursors=Join-Path $session 'Data\Data\Cursors'
 Check ((Test-Path $exe)-and(Test-Path $core)-and(Test-Path $observer)) 'First launcher open installs engine, Core13 and observer before starting a game'
 Check ((Get-ChildItem $cursors -File).Count-eq79) 'One complete set of 79 retained cursors is present'
 Check ((Get-FileHash $exe).Hash.ToLowerInvariant()-eq'dd8f0fc2e6c94900fa6c3a7af099c8b3936f99b55efb058fada7dc697e34672e') 'Installed engine is the exact join8 and 4GB final image'
 Check (!(Test-Path (Join-Path $session 'Data\Cursors'))) 'No duplicate cursor set is created'
 $before=Snap $session;Close139 $v;Check (Same $before $session) 'Closing the launcher retains bytes, NTFS IDs and creation/write times'
 for($i=0;$i-lt3;$i++){$v=Launch $r;Close139 $v;Check (Same $before $session) ('Unchanged open/close cycle '+($i+1)+' performs no runtime replacement')}
 Config $r $game;$v=Launch $r;Check (Same $before $session) 'Selecting an installed game does not rewrite common runtime members';Check (Test-Path (Join-Path $session 'RA3_english_1.12.SkuDef')) 'Selected game configuration is prepared before play';Close139 $v
 $before=Snap $session;$v=ReplayFail $r $replay;Check (Same $before $session) 'The actual game-worker failure/teardown path retains all prepared files';Close139 $v
 Get-ChildItem $session -Recurse -Force -File|ForEach-Object{$_.IsReadOnly=$true}
 try{$v=Launch $r;Check (Same $before $session) 'An entirely read-only valid runtime is reused without rewriting';Close139 $v}finally{Get-ChildItem $session -Recurse -Force -File|ForEach-Object{$_.IsReadOnly=$false}}
 $cursor=(Get-ChildItem $cursors -File|Select-Object -First 1).FullName;$key=$cursor.Substring($session.Length);$cursorHash=(Get-FileHash $cursor).Hash
 Remove-Item -LiteralPath $cursor;$v=Launch $r;Check ((Get-FileHash $cursor).Hash-eq$cursorHash) 'Only a missing member is restored from the signed package';Check (Same $before $session @($key)) 'Missing-cursor repair preserves every other file identity';Close139 $v
 $before=Snap $session;$coreKey=$core.Substring($session.Length);$coreHash=(Get-FileHash $core).Hash
 [IO.File]::WriteAllText($core,'Simulated partial old resource');$v=Launch $r;Check ((Get-FileHash $core).Hash-eq$coreHash) 'Changed or damaged resource is replaced by the verified version';Check (Same $before $session @($coreKey)) 'Selective resource repair never rebuilds the session directory';Close139 $v
 $before=Snap $session;[IO.File]::WriteAllText($core,'Locked previous resource fixture');$badHash=(Get-FileHash $core).Hash
 $lock=[IO.File]::Open($core,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$v=Launch $r;Check ((Get-FileHash $core).Hash-eq$badHash) 'A denied atomic replacement keeps the previous file, not a truncated image';Check (Same $before $session @($coreKey)) 'A locked update does not delete unrelated retained files';Close139 $v}finally{$lock.Dispose();$lock=$null}
 $v=Launch $r;Check ((Get-FileHash $core).Hash-eq$coreHash) 'Preparation retries and repairs after the file lock is released';Close139 $v
 $note=Join-Path $session 'user-note.txt';[IO.File]::WriteAllText($note,'Do not delete user-owned file');$before=Snap $session;$v=Launch $r;Close139 $v;Check (Same $before $session) 'Unrelated files in the retained directory survive another launch and close'
 $sourceDll=Join-Path $game 'Data\d3dx9_35.dll';$destDll=Join-Path $session 'Data\d3dx9_35.dll';[IO.File]::WriteAllText($sourceDll,'Local dependency A; never executed by this fixture');$v=Launch $r;Check ((Get-FileHash $sourceDll).Hash-eq(Get-FileHash $destDll).Hash) 'A local game dependency is initially copied into the persistent runtime';Close139 $v
 $before=Snap $session;$v=Launch $r;Close139 $v;Check (Same $before $session) 'Unchanged local dependency is not recreated'
 [IO.File]::WriteAllText($sourceDll,'Local dependency B; newer selected installation');$v=Launch $r;Check ((Get-FileHash $sourceDll).Hash-eq(Get-FileHash $destDll).Hash) 'Changed source dependency is refreshed instead of using stale cached DLL';Check (Same $before $session @('\Data\d3dx9_35.dll')) 'Dependency refresh leaves all other runtime files unchanged';Close139 $v
 Check ((Get-FileHash $installed).Hash-eq$originalGame-and(Get-FileHash $sku).Hash-eq$originalSku) 'Installed game and original configuration remain byte-for-byte unchanged'
 Check (@(Get-ChildItem $session -Recurse -Force -Filter '*.octane-new').Count-eq0) 'Completed or rejected installations leave no staging members'
 $before=Snap $session;$v=Launch $r;$v.p.Kill();$v.p.WaitForExit();Check (Same $before $session) 'Forced launcher termination does not remove installed runtime files'
 Copy-Item (Join-Path $r 'Logs\launcher.log') $Output
}catch{$Failure=$_.Exception.Message;Write-Host ('PERSISTENCE_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace;if($r-and(Test-Path (Join-Path $r 'Logs\launcher.log'))){Get-Content (Join-Path $r 'Logs\launcher.log') -Tail 35|Write-Host}}
finally{
 if($lock){$lock.Dispose()}
 Get-Process -Name RA3Octane,RA3OctaneUpdater -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 $result=[ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Unmodified signed launchers on Windows; real NTFS IDs, timestamps, locks, preparation and worker teardown. Invalid replay stops before RA3 execution. No eight-person network match.'}
 $result|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'PERSISTENT_RUNTIME_139.json') -Encoding UTF8
}
if($Failure){exit 1}
