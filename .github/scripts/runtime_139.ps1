param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition -eq 'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Baseline $Baseline -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop'
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected native helper template'}
Invoke-Expression $t.Substring($a,$b-$a)
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;using System.Collections.Concurrent;
public static class Retained139 {
 [StructLayout(LayoutKind.Sequential)] public struct FT{public uint Low,High;}
 [StructLayout(LayoutKind.Sequential)] public struct Info{public uint Attr;public FT Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static string Identity(string path){using(var s=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){Info i;if(!GetFileInformationByHandle(s.SafeFileHandle,out i))throw new Exception("File identity "+Marshal.GetLastWin32Error());return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Created.High+":"+i.Created.Low+":"+i.Written.High+":"+i.Written.Low;}}
 public static ConcurrentQueue<string> Events=new ConcurrentQueue<string>();static FileSystemWatcher w;
 public static void Watch(string path){Events=new ConcurrentQueue<string>();w=new FileSystemWatcher(path);w.IncludeSubdirectories=true;w.InternalBufferSize=65536;w.NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size;w.Changed+=(s,e)=>Events.Enqueue("changed "+e.FullPath);w.Deleted+=(s,e)=>Events.Enqueue("deleted "+e.FullPath);w.Created+=(s,e)=>Events.Enqueue("created "+e.FullPath);w.Renamed+=(s,e)=>Events.Enqueue("renamed "+e.FullPath);w.Error+=(s,e)=>Events.Enqueue("WATCHER_ERROR");w.EnableRaisingEvents=true;}
 public static string[] Stop(){if(w!=null){w.EnableRaisingEvents=false;w.Dispose();w=null;}return Events.ToArray();}
}
'@
function Snapshot([string]$dir){$map=@{};Get-ChildItem -LiteralPath $dir -Recurse -Force -File|ForEach-Object{$map[$_.FullName.Substring($dir.Length)]=([Retained139]::Identity($_.FullName)+'|'+$_.Length+'|'+(Get-FileHash -LiteralPath $_.FullName).Hash)};return $map}
function SubsetSame($before,[string]$dir,[string]$except=''){foreach($name in $before.Keys){if($name-eq$except){continue};$p=$dir+$name;if(!(Test-Path -LiteralPath $p)){return $false};$f=Get-Item -LiteralPath $p -Force;$now=[Retained139]::Identity($p)+'|'+$f.Length+'|'+(Get-FileHash -LiteralPath $p).Hash;if($before[$name]-ne$now){Write-Host ('CHANGED '+$name);return $false}};return $true}
function Configure([string]$root,[string]$game){[IO.File]::WriteAllText((Join-Path $root 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nAutoPatch=0`r`n[Firewall]`r`nRuntimeRule=1`r`n")}
function ReplayAttempt([string]$root,[string]$replay){$pp=Start-Process -FilePath (Join-Path $root 'RA3Octane.exe') -ArgumentList ('--replay "'+$replay+'"') -WorkingDirectory $root -PassThru;$ww=Until {[OctaneNativeTest]::Window($pp.Id,'Begosik.RA3Octane.Native.v1')} 'replay launcher window';$ll=Join-Path $root 'Logs\launcher.log';Until{(Test-Path $ll)-and([IO.File]::ReadAllText($ll).Contains('Not a supported RA3 replay header.'))} 'intentional replay rejection'|Out-Null;Start-Sleep -Milliseconds 400;return @{p=$pp;w=$ww;root=$root}}
try {
 $root=Extract $Package 'persistent';$oldroot=Extract $Baseline 'old';$game=Join-Path $Work 'InstalledGame';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 $installed=Join-Path $game 'Data\ra3_1.12.game';[IO.File]::WriteAllText($installed,'INSTALLED GAME SENTINEL - NOT TO BE RUN OR MODIFIED');$ih=(Get-FileHash $installed).Hash
 $sku=Join-Path $game 'RA3_english_1.12.SkuDef';[IO.File]::WriteAllText($sku,"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n");$sh=(Get-FileHash $sku).Hash
 $replay=Join-Path $Work 'invalid.RA3Replay';[IO.File]::WriteAllText($replay,'Intentional invalid replay stops before an RA3 process is created')
 $env:LOCALAPPDATA=Join-Path $Work 'OldLocal';[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null;Configure $oldroot $game
 $v=ReplayAttempt $oldroot $replay;$oldsession=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime';CloseMain $v
 Check (!(Test-Path $oldsession)) 'Negative control: unmodified previous launcher deletes the prepared session on launch failure'
 $env:LOCALAPPDATA=Join-Path $Work 'NewLocal';[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null
 Configure $root ''; $v=Launch $root
 $session=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime';$data=Join-Path $session 'Data';$exe=Join-Path $data 'ra3_1.12.game';$core=Join-Path $data 'Core13.big';$observer=Join-Path $data 'OctaneDiagnostics.exe'
 Check ((Test-Path $exe)-and(Test-Path $core)-and(Test-Path $observer)) 'First launcher opening installs game, resources and observer before LAUNCH GAME'
 Check ((Get-ChildItem (Join-Path $data 'Data\Cursors') -File).Count-eq79) 'One persistent set of 79 cursor files exists'
 Check ((Get-FileHash $exe).Hash.ToLowerInvariant()-eq'52d6a269aaecf29320abec797f42c967727a7e291f07d8270208ebfd28938fa7') 'Installed session retains the exact verified 4GB game bytes'
 $initial=Snapshot $session;CloseMain $v;Check (SubsetSame $initial $session) 'Launcher close preserves every installed file identity and timestamp'
 [Retained139]::Watch($session)
 for($cycle=0;$cycle-lt3;$cycle++){$v=Launch $root;CloseMain $v;Check (SubsetSame $initial $session) ('Warm start/close '+$cycle+' keeps identical bytes, timestamps and NTFS file IDs')}
 Start-Sleep -Milliseconds 200;$events=[Retained139]::Stop();$events|Set-Content (Join-Path $Output 'warm-file-events.txt')
 Check ($events.Count-eq0) 'Filesystem watcher observes no creates, deletes, renames or writes during three warm starts'
 Configure $root $game;$v=Launch $root;CloseMain $v
 Check (SubsetSame $initial $session) 'Selecting an installation adds configuration without replacing runtime binaries'
 Check (Test-Path (Join-Path $session 'RA3_english_1.12.SkuDef')) 'Cloned configuration is installed at a stable path'
 # This inert fixture tests dependency copying only; no game runs in this suite.
 $dependency=Join-Path $game 'Data\d3dx9_35.dll';[IO.File]::WriteAllText($dependency,'DEPENDENCY FIXTURE ONE')
 $v=Launch $root;CloseMain $v;$localDependency=Join-Path $data 'd3dx9_35.dll'
 Check ([IO.File]::ReadAllText($localDependency)-eq'DEPENDENCY FIXTURE ONE') 'Required local dependency is prepared before game launch'
 [IO.File]::WriteAllText((Join-Path $session 'user-owned.txt'),'keep user content');$configured=Snapshot $session
 $v=ReplayAttempt $root $replay;CloseMain $v
 Check (SubsetSame $configured $session) 'Failed game launch uses the common teardown but does not delete or rewrite retained runtime files'
 Get-ChildItem $session -Recurse -Force -File|ForEach-Object{$_.IsReadOnly=$true}
 $v=Launch $root;CloseMain $v;Check (SubsetSame $configured $session) 'Unchanged read-only runtime files are reused successfully'
 Get-ChildItem $session -Recurse -Force -File|ForEach-Object{$_.IsReadOnly=$false}
 [IO.File]::WriteAllText($dependency,'DEPENDENCY FIXTURE TWO')
 $v=Launch $root;CloseMain $v
 Check ([IO.File]::ReadAllText($localDependency)-eq'DEPENDENCY FIXTURE TWO') 'Changed source dependency is updated rather than using an obsolete cached DLL'
 Check (SubsetSame $configured $session '\Data\d3dx9_35.dll') 'Updating one dependency leaves every other runtime file untouched'
 $configured=Snapshot $session;$cursor=(Get-ChildItem (Join-Path $data 'Data\Cursors') -File|Select-Object -First 1).FullName;$cursorName=$cursor.Substring($session.Length);Remove-Item -LiteralPath $cursor
 $v=Launch $root;CloseMain $v
 Check (Test-Path $cursor) 'A missing runtime member is restored'
 Check (SubsetSame $configured $session $cursorName) 'Restoring a missing cursor does not rebuild the session'
 $configured=Snapshot $session;$coreBytes=[IO.File]::ReadAllBytes($core);[IO.File]::WriteAllText($core,'INTENTIONAL DAMAGED CORE FIXTURE')
 $lock=[IO.File]::Open($core,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$v=Launch $root;CloseMain $v;Check ([IO.File]::ReadAllText($core)-eq'INTENTIONAL DAMAGED CORE FIXTURE') 'Locked outdated resource is not truncated or removed';Check (SubsetSame $configured $session '\Data\Core13.big') 'Failed replacement preserves every other file'}finally{$lock.Dispose()}
 $v=Launch $root;CloseMain $v
 Check ((Get-FileHash $core).Hash-eq([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($coreBytes)).Replace('-',''))) 'Replacement succeeds after the file lock is released'
 Check (SubsetSame $configured $session '\Data\Core13.big') 'Resource repair replaces only the resource that changed'
 Check ((Get-ChildItem $session -Force -Recurse -Filter '*.octane-new').Count-eq0) 'Completed operations leave no partial staging files'
 Check ([IO.File]::ReadAllText((Join-Path $session 'user-owned.txt'))-eq'keep user content') 'Unrelated user files in the session are retained'
 Check ((Get-FileHash $installed).Hash-eq$ih-and(Get-FileHash $sku).Hash-eq$sh) 'Installed game and original SkuDef are never rewritten'
 Copy-Item -LiteralPath (Join-Path $root 'Logs\launcher.log') -Destination $Output
} catch {$Failure=$_.Exception.Message;Write-Host ('PERSISTENCE_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace
 if($root-and(Test-Path (Join-Path $root 'Logs\launcher.log'))){Copy-Item (Join-Path $root 'Logs\launcher.log') $Output -Force}
} finally {
 [Retained139]::Stop()|Out-Null
 Get-Process -Name RA3Octane,RA3OctaneUpdater -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 $result=[ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();native_windows=$true;gameplay_tested=$false;dependency_fixture_is_inert=$true}
 $json=$result|ConvertTo-Json -Depth 8;$json|Set-Content (Join-Path $Output 'PERSISTENT_RUNTIME_139.json') -Encoding UTF8;Write-Host $json
}
if($Failure){exit 1}
