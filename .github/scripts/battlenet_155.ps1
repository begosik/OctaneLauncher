param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$PatchedFixture,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -PatchedFixture $PatchedFixture -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$Package=(Resolve-Path $Package).Path;$PatchedFixture=(Resolve-Path $PatchedFixture).Path
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract");if($a-lt0-or$b-le$a){throw 'Unexpected native helper boundaries'}
$Baseline=$Package;Invoke-Expression $t.Substring($a,$b-$a)
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class Octane155ExitDialog {
 public delegate bool EnumProc(IntPtr w,IntPtr p);
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent,EnumProc f,IntPtr p);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr w,StringBuilder b,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr w,StringBuilder b,int n);
 [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr w);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr w);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);
 public static IntPtr SingleButton(IntPtr dialog){IntPtr found=IntPtr.Zero;int count=0;EnumChildWindows(dialog,delegate(IntPtr w,IntPtr p){var cls=new StringBuilder(64);GetClassName(w,cls,cls.Capacity);if(cls.ToString()=="Button"&&IsWindowVisible(w)&&IsWindowEnabled(w)){found=w;count++;}return true;},IntPtr.Zero);return count==1?found:IntPtr.Zero;}
 public static string Controls(IntPtr dialog){var text=new StringBuilder();EnumChildWindows(dialog,delegate(IntPtr w,IntPtr p){var cls=new StringBuilder(64);var label=new StringBuilder(4096);GetClassName(w,cls,cls.Capacity);GetWindowText(w,label,label.Capacity);text.AppendFormat("id={0}; class={1}; enabled={2}; visible={3}; text={4}\n",GetDlgCtrlID(w),cls,IsWindowEnabled(w),IsWindowVisible(w),label);return true;},IntPtr.Zero);return text.ToString();}
 public static string Body(IntPtr dialog){var text=new StringBuilder();EnumChildWindows(dialog,delegate(IntPtr w,IntPtr p){var cls=new StringBuilder(64);GetClassName(w,cls,cls.Capacity);if(cls.ToString()=="Static"){var b=new StringBuilder(4096);GetWindowText(w,b,b.Capacity);if(b.Length>0)text.AppendLine(b.ToString());}return true;},IntPtr.Zero);return text.ToString();}
}
'@
$env:APPDATA=Join-Path $Work 'Roaming';[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$original='c3332145b101c72ee07f6a1741461b28df0a941e7ea82401c70522faab844c8a'
$patched='00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'
$client=Join-Path $env:APPDATA 'RA3BattleNet';$contents=Join-Path $client 'contents';[IO.Directory]::CreateDirectory($contents)|Out-Null
$dll=Join-Path $contents 'NativeDll.dll';$v=$null;$engine=$null;$fileLock=$null;$clientProcess=$null;$started=$null
function DllHash {try{return (Get-FileHash -LiteralPath $dll).Hash.ToLowerInvariant()}catch{return ''}}
function SeedPatch {Copy-Item -LiteralPath $PatchedFixture -Destination $dll -Force}
function RestoreDone([string]$why){Until {(DllHash)-eq$original} $why 15|Out-Null;Check ((DllHash)-eq$original) $why}
function LaunchOne([string]$name){$r=Extract $Package $name;[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nDirectory=$client`r`nAutoPatch=0`r`n[Firewall]`r`nRuntimeRule=1`r`n");return Launch $r}
function GuardReady($view){$log=Join-Path $view.root 'Logs\launcher.log';Until {(Test-Path $log)-and[IO.File]::ReadAllText($log).Contains('Independent recovery guard ready;')} 'independent guard ready' 25|Out-Null}
function ManualRestore($view){[OctaneNativeTest]::Click($view.w,856,520,1060,736);$dialog=Until {[OctaneNativeTest]::Title($view.p.Id,'Restore Original - Warning')} 'manual restore dialog';Check (([OctaneNativeTest]::SendMessage($dialog,0x400,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()-band65535)-eq2) 'Manual restore defaults to Cancel';[OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null}
function CompleteStoppedLaunch($view,[string]$exitHex,[string]$label){
 # Game termination precedes observer/log cleanup and WM_DONE. The unchanged
 # CloseMain helper may run only after WM_DONE has displayed its expected
 # abnormal-exit notification; an early WM_CLOSE instead opens a busy dialog.
 $logPath=Join-Path $view.root 'Logs\launcher.log'
 $expected='The game exited with code 0x'+$exitHex+'. Logs are in the launcher Logs folder.'
 Until {[IO.File]::ReadAllText($logPath).Contains($expected)} ($label+' launch worker reports completed abnormal exit') 30|Out-Null
 $dialog=Until {$d=[OctaneNativeTest]::Title($view.p.Id,'RA3 // OCTANE');if($d-ne[IntPtr]::Zero-and[OctaneNativeTest]::Class($d)-eq'#32770'){return $d}} ($label+' WM_DONE abnormal-exit dialog') 30
 # Use the observed button control, not the MessageBox return-value constant:
 # a single OK dialog may use a different internal control ID.
 $ok=Until {$button=[Octane155ExitDialog]::SingleButton($dialog);if($button-ne[IntPtr]::Zero-and[Octane155ExitDialog]::Body($dialog).Contains($expected)){return $button}} ($label+' completed message and single ready action') 15
 Check ([Octane155ExitDialog]::Body($dialog).Contains($expected)) ($label+' completion dialog matches the actual terminated process exit code')
 Check ([OctaneNativeTest]::Text($ok).Replace('&','')-eq'OK') ($label+' completion dialog exposes its OK action')
 $controlId=[Octane155ExitDialog]::GetDlgCtrlID($ok)
 Write-Host ($label+' completion dialog controls: '+[Octane155ExitDialog]::Controls($dialog))
 [OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]$controlId,$ok)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($dialog)-and[OctaneNativeTest]::IsWindow($view.w)-and[Octane155ExitDialog]::IsWindowEnabled($view.w)} ($label+' completion dialog dismissed and launcher enabled') 15|Out-Null
 Check ([Octane155ExitDialog]::IsWindowEnabled($view.w)) ($label+' launcher returns to enabled UI before normal close')
}
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
 [OctaneNativeTest]::Screenshot($v.w,(Join-Path $Output 'launcher-155.png'))|Write-Host
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
 # Stopped client: merely having a remembered folder must not install its DLL.
 Check (!(Get-Process -Name 'Ra3.BattleNet.Client' -ErrorAction SilentlyContinue)) 'No recognized client process is running for the offline case'
 [OctaneNativeTest]::Click($v.w,350,495,1060,736)
 $log=Join-Path $v.root 'Logs\launcher.log'
 Until {[IO.File]::ReadAllText($log).Contains('[BATTLENET] Client is not running; shared DLL patch skipped for this game session.')} 'offline launch bypasses the shared BattleNet patch' 30|Out-Null
 Check ((DllHash)-eq$original) 'Closed client with valid installed contents keeps the exact original DLL'
 Check (-not([IO.File]::ReadAllText($log).Contains('[BATTLENET] Session patch verified.'))) 'Offline launch has no BattleNet patch transaction'
 # Hosted runner has no installed RA3 assets. The actual launcher still writes
 # and starts the real session image; end only that isolated process below.
 $runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
 $started=Until {Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.Path-eq$runtime}|Select-Object -First 1} 'actual isolated offline RA3 process' 20
 Check ($null-ne$started) 'Offline LAUNCH GAME starts the real isolated .game image'
 $pe=[IO.File]::ReadAllBytes($runtime);$peoff=[BitConverter]::ToInt32($pe,60)
 Check (([BitConverter]::ToUInt16($pe,$peoff+22)-band0x20)-ne0) 'Offline launcher-created session retains the automatic 4GB flag'
 $heldHandle=$started.Handle # Retain identity/exit status even if the PID disappears.
 Stop-Process -Id $started.Id -Force;$started.WaitForExit();$exitHex=[Convert]::ToString([int]$started.ExitCode,16).PadLeft(8,'0');$started=$null
 RestoreDone 'Offline exit leaves the original BattleNet DLL intact'
 CompleteStoppedLaunch $v $exitHex 'Offline'
 Check (Test-Path $runtime) 'Session executable remains on disk after offline launch ends'
 Copy-Item $log (Join-Path $Output 'offline-lifecycle.log')
 CloseMain $v;$v=$null
 # Recognized running-client surrogate: only process/path detection is under
 # test. This does not authenticate or connect to BattleNet.
 $clientPath=Join-Path $client 'Ra3.BattleNet.Client.exe';Copy-Item $env:ComSpec $clientPath
 $start=New-Object System.Diagnostics.ProcessStartInfo;$start.FileName=$clientPath;$start.Arguments='/d /c ping -n 90 127.0.0.1 >nul';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $clientProcess=New-Object System.Diagnostics.Process;$clientProcess.StartInfo=$start
 Check ($clientProcess.Start()) 'Recognized client-path surrogate starts'
 $v=LaunchOne 'running-client-launch';GuardReady $v
 [OctaneNativeTest]::Click($v.w,350,495,1060,736)
 $log=Join-Path $v.root 'Logs\launcher.log'
 Until {[IO.File]::ReadAllText($log).Contains('[BATTLENET] Session patch verified.')} 'running client patch before real launch attempt' 30|Out-Null
 Check ([IO.File]::ReadAllText($log).Contains('[BATTLENET] Session patch verified.')) 'Running client still receives the compatibility patch despite obsolete AutoPatch=0'
 $started=Until {Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.Path-eq$runtime}|Select-Object -First 1} 'actual isolated online-route RA3 process' 20
 Check ($null-ne$started) 'Running-client LAUNCH GAME starts the isolated .game image'
 Check ((DllHash)-eq$patched) 'Running-client launch has the exact patched DLL on disk'
 $heldHandle=$started.Handle # Retain identity/exit status even if the PID disappears.
 Stop-Process -Id $started.Id -Force;$started.WaitForExit();$exitHex=[Convert]::ToString([int]$started.ExitCode,16).PadLeft(8,'0');$started=$null
 RestoreDone 'Running-client game exit restores the original DLL'
 CompleteStoppedLaunch $v $exitHex 'Running-client'
 Stop-Process -Id $clientProcess.Id -Force;$clientProcess.WaitForExit();$clientProcess=$null
 Copy-Item $log (Join-Path $Output 'battle-net-lifecycle.log')
 CloseMain $v;$v=$null;RestoreDone 'Launcher shutdown rechecks original DLL'
}catch{$Failure=$_.Exception.Message;Write-Host ('BN_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace;if($v){$d=[OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE');if($d-ne[IntPtr]::Zero){Write-Host ([Octane155ExitDialog]::Controls($d));[OctaneNativeTest]::Screenshot($d,(Join-Path $Output 'failure-dialog.png'))|Write-Host}}}
finally{
 if($started-and!$started.HasExited){Stop-Process -Id $started.Id -Force -ErrorAction SilentlyContinue}
 if($clientProcess-and!$clientProcess.HasExited){Stop-Process -Id $clientProcess.Id -Force -ErrorAction SilentlyContinue}
 if($fileLock){$fileLock.Dispose()};if($engine-and!$engine.HasExited){Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue}
 if($v){$lp=Join-Path $v.root 'Logs\launcher.log';if(Test-Path $lp){Copy-Item $lp (Join-Path $Output 'last-launcher.log');Get-Content $lp -Tail 25|Write-Host};if(!$v.p.HasExited){Stop-Process -Id $v.p.Id -Force -ErrorAction SilentlyContinue}}
 Get-Process -Name OctaneBattleNetGuard,ra3_1.12 -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual final Windows launcher and independent guardian; real file replacement and sharing locks; surrogate kernel processes for lifecycle and client-presence detection, plus real offline/online-route launch attempts without installed RA3 assets. No live multiplayer or gameplay.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'BATTLENET_155.json') -Encoding UTF8
}
if($Failure){exit 1}
