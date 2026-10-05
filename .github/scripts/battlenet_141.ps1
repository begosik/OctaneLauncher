param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$PatchedFixture,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -PatchedFixture $PatchedFixture -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$Package=(Resolve-Path $Package).Path;$PatchedFixture=(Resolve-Path $PatchedFixture).Path
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract");if($a-lt0-or$b-le$a){throw 'Unexpected native helper boundaries'}
$Baseline=$Package;Invoke-Expression $t.Substring($a,$b-$a)
$env:APPDATA=Join-Path $Work 'Roaming';[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$original='c3332145b101c72ee07f6a1741461b28df0a941e7ea82401c70522faab844c8a'
$patched='00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'
$client=Join-Path $env:APPDATA 'RA3BattleNet';$contents=Join-Path $client 'contents';[IO.Directory]::CreateDirectory($contents)|Out-Null
$dll=Join-Path $contents 'NativeDll.dll';$v=$null;$engine=$null;$fileLock=$null
function DllHash {try{return (Get-FileHash -LiteralPath $dll).Hash.ToLowerInvariant()}catch{return ''}}
function SeedPatch {Copy-Item -LiteralPath $PatchedFixture -Destination $dll -Force}
function RestoreDone([string]$why){Until {(DllHash)-eq$original} $why 15|Out-Null;Check ((DllHash)-eq$original) $why}
function LaunchOne([string]$name){$r=Extract $Package $name;[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nDirectory=$client`r`nAutoPatch=0`r`n[Firewall]`r`nRuntimeRule=1`r`n");return Launch $r}
function GuardReady($view){$log=Join-Path $view.root 'Logs\launcher.log';Until {(Test-Path $log)-and[IO.File]::ReadAllText($log).Contains('Independent recovery guard ready;')} 'independent guard ready' 25|Out-Null}
function ManualRestore($view){[OctaneNativeTest]::Click($view.w,856,520,1060,736);$dialog=Until {[OctaneNativeTest]::Title($view.p.Id,'Restore Original - Warning')} 'manual restore dialog';Check (([OctaneNativeTest]::SendMessage($dialog,0x400,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()-band65535)-eq2) 'Manual restore defaults to Cancel';[OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null}
function SeedWhileRunning([int]$seconds,[int]$exitCode){
 $mutex=New-Object System.Threading.Mutex($false,'Local\Begosik.RA3Octane.BattleNet.IO.141');$taken=$false
 try{$taken=$mutex.WaitOne(10000);if(!$taken){throw 'Recovery IO mutex timeout'}
  $start=New-Object System.Diagnostics.ProcessStartInfo;$start.FileName=$enginePath;$start.Arguments="/d /c ping -n $seconds 127.0.0.1 >nul & exit /b $exitCode";$start.UseShellExecute=$false;$start.CreateNoWindow=$true
  $proc=New-Object System.Diagnostics.Process;$proc.StartInfo=$start;if(!$proc.Start()){throw 'Cannot create the process surrogate'}
  SeedPatch;return $proc
 }finally{if($taken){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
try{
 Check ((Get-FileHash $PatchedFixture).Hash.ToLowerInvariant()-eq$patched) 'Fixture is the actual published 1.2.40 patched NativeDll'
 $game=Join-Path $Work 'InstalledGame';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 $enginePath=Join-Path $game 'Data\ra3_1.12.game';Copy-Item $env:ComSpec $enginePath
 [IO.File]::WriteAllText((Join-Path $game 'RA3_english_1.12.SkuDef'),"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
 SeedPatch;$v=LaunchOne 'fresh-no-state';RestoreDone 'Startup repairs stranded patch with no .battlenet';GuardReady $v
 Check (!(Test-Path (Join-Path $v.root '.battlenet'))) 'No old transaction or backup was required'
 Start-Sleep -Seconds 2;Check ((DllHash)-eq$original) 'Opening/idle launcher does not install the patch'
 [OctaneNativeTest]::Screenshot($v.w,(Join-Path $Output 'launcher-141.png'))|Write-Host
 $helper=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\BattleNetRecovery\OctaneBattleNetGuard.exe'
 Check ((Get-FileHash $helper).Hash-eq(Get-FileHash (Join-Path $v.root 'RA3Octane.exe')).Hash) 'Persistent guardian is byte-identical to the verified launcher'
 $stamp=(Get-Item $helper).LastWriteTimeUtc
 [IO.Directory]::CreateDirectory((Join-Path $v.root '.battlenet'))|Out-Null
 [IO.File]::WriteAllText((Join-Path $v.root '.battlenet\transaction.ini'),'broken legacy record')
 [IO.File]::WriteAllText((Join-Path $v.root '.battlenet\NativeDll.original.dll'),'NOT A VENDOR ORIGINAL')
 SeedPatch;ManualRestore $v;RestoreDone 'Restore repairs real DLL even with invalid legacy metadata and backup'
 Check ([IO.File]::ReadAllText((Join-Path $v.root 'settings.ini')).Contains('AutoPatch=0')) 'Restore does not rewrite an obsolete preference as a disable action'
 $engine=SeedWhileRunning 4 0;Start-Sleep -Milliseconds 500
 Check ((DllHash)-eq$patched) 'Guardian does not unpatch a live engine path'
 Check ($engine.WaitForExit(10000)) 'Normal surrogate engine termination occurs'
 RestoreDone 'Original automatically restored after normal engine exit while launcher stays open';$engine=$null
 $engine=SeedWhileRunning 4 7;Check ($engine.WaitForExit(10000)) 'Nonzero surrogate engine termination occurs'
 Check ($engine.ExitCode-eq7) 'Abnormal-exit surrogate returns nonzero exit status'
 RestoreDone 'Original automatically restored after nonzero engine exit';$engine=$null
 $engine=SeedWhileRunning 90 0;Start-Sleep -Milliseconds 400;Stop-Process -Id $engine.Id -Force;$engine.WaitForExit();$engine=$null
 RestoreDone 'Original restored after force-terminating only the engine'
 $engine=SeedWhileRunning 90 0;Start-Sleep -Milliseconds 400
 $fileLock=[IO.File]::Open($dll,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 Stop-Process -Id $engine.Id -Force;$engine.WaitForExit();$engine=$null;Start-Sleep -Seconds 3
 Check ((DllHash)-eq$patched) 'A Windows sharing lock is not falsely reported as a completed restore'
 $fileLock.Dispose();$fileLock=$null;RestoreDone 'Deferred restore completes after the Windows lock is released'
 $engine=SeedWhileRunning 90 0;Start-Sleep -Milliseconds 500;CloseMain $v;$v=$null
 Check ((DllHash)-eq$patched) 'Normal launcher close does not rewrite a DLL used by a still-live engine'
 Stop-Process -Id $engine.Id -Force;$engine.WaitForExit();$engine=$null
 RestoreDone 'Independent guardian restores after launcher has already closed'
 $v=LaunchOne 'kill-parent';GuardReady $v
 Check ((Get-Item $helper).LastWriteTimeUtc-eq$stamp) 'Repeated launcher startup reuses the unchanged guardian file'
 $engine=SeedWhileRunning 90 0;Start-Sleep -Milliseconds 500;Stop-Process -Id $v.p.Id -Force;$v=$null
 Stop-Process -Id $engine.Id -Force;$engine.WaitForExit();$engine=$null
 RestoreDone 'Independent guardian restores after launcher and engine are force-terminated separately'
 Get-Process -Name OctaneBattleNetGuard -ErrorAction SilentlyContinue|Where-Object{$_.Path-eq$helper}|Stop-Process -Force
 SeedPatch;$v=LaunchOne 'restart-after-all-killed';RestoreDone 'Next launcher startup repairs after every previous process was killed';GuardReady $v
 [OctaneNativeTest]::Click($v.w,350,495,1060,736)
 $log=Join-Path $v.root 'Logs\launcher.log'
 Until {[IO.File]::ReadAllText($log).Contains('[BATTLENET] Session patch verified.')} 'mandatory patch before real launch attempt' 30|Out-Null
 Check ([IO.File]::ReadAllText($log).Contains('[BATTLENET] Session patch verified.')) 'Old AutoPatch=0 cannot disable patching on a real LAUNCH GAME action'
 Until {(DllHash)-eq$original} 'failed or short real engine launch restores original' 30|Out-Null
 Check ((DllHash)-eq$original) 'The real launch attempt restores the DLL after failure/termination'
 $dialog=[OctaneNativeTest]::Window($v.p.Id,'#32770');if($dialog-ne[IntPtr]::Zero){[OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Start-Sleep -Milliseconds 200}
 $runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
 Check (Test-Path $runtime) 'Session executable remains on disk after the game launch ends'
 Copy-Item $log (Join-Path $Output 'battle-net-lifecycle.log')
 CloseMain $v;$v=$null;RestoreDone 'Launcher shutdown rechecks original DLL'
}catch{$Failure=$_.Exception.Message;Write-Host ('BN_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($fileLock){$fileLock.Dispose()};if($engine-and!$engine.HasExited){Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue}
 if($v){$lp=Join-Path $v.root 'Logs\launcher.log';if(Test-Path $lp){Copy-Item $lp (Join-Path $Output 'last-launcher.log');Get-Content $lp -Tail 25|Write-Host};if(!$v.p.HasExited){Stop-Process -Id $v.p.Id -Force -ErrorAction SilentlyContinue}}
 Get-Process -Name OctaneBattleNetGuard,ra3_1.12 -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual final Windows launcher and independent guardian; real file replacement and sharing locks; surrogate kernel processes for lifecycle, plus real launch attempt without installed RA3 assets. No live multiplayer or gameplay.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'BATTLENET_141.json') -Encoding UTF8
}
if($Failure){exit 1}
