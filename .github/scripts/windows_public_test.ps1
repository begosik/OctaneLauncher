param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
# Public signed binaries only; no game, private source, publisher key or match fixture.
if ($PSVersionTable.PSEdition -eq 'Core') {
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Baseline $Baseline -Output $Output
 exit $LASTEXITCODE
}
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Baseline=(Resolve-Path $Baseline).Path
$Output=[IO.Path]::GetFullPath($Output);[IO.Directory]::CreateDirectory($Output)|Out-Null
$Work=Join-Path $env:RUNNER_TEMP ('Octane public '+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($Work)|Out-Null
$env:LOCALAPPDATA=Join-Path $Work 'LocalAppData';[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null
$Rows=New-Object 'System.Collections.Generic.List[object]';$Failure=$null
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Drawing;
public static class OctaneNativeTest {
 [StructLayout(LayoutKind.Sequential)] public struct Rect {public int L,T,R,B;}
 public delegate bool EnumProc(IntPtr w,IntPtr p);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f,IntPtr p);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr w,StringBuilder b,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr w,StringBuilder b,int n);
 [DllImport("user32.dll",EntryPoint="SendMessageW",CharSet=CharSet.Unicode)] public static extern IntPtr ReadText(IntPtr w,uint m,IntPtr n,StringBuilder b);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr w,int n);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr w,uint m,IntPtr a,IntPtr b);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr w,uint m,IntPtr a,IntPtr b);
 [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr w,out Rect r);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr w,out Rect r);
 [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr w,IntPtr z,int x,int y,int a,int b,uint f);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr w,IntPtr dc,uint f);
 [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr w);
 [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr w);
 [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr w,IntPtr dc);
 [DllImport("gdi32.dll")] public static extern uint GetPixel(IntPtr dc,int x,int y);
 public static string Text(IntPtr w){var b=new StringBuilder(4096);GetWindowText(w,b,b.Capacity);return b.ToString();}
 public static string ControlText(IntPtr w){var b=new StringBuilder(32768);ReadText(w,0x000d,new IntPtr(b.Capacity),b);return b.ToString();}
 public static string Class(IntPtr w){var b=new StringBuilder(256);GetClassName(w,b,b.Capacity);return b.ToString();}
 public static IntPtr Window(int pid,string cls){IntPtr r=IntPtr.Zero;EnumWindows(delegate(IntPtr w,IntPtr p){uint id;GetWindowThreadProcessId(w,out id);if(id==pid&&Class(w)==cls){r=w;return false;}return true;},IntPtr.Zero);return r;}
 public static IntPtr Title(int pid,string title){IntPtr r=IntPtr.Zero;EnumWindows(delegate(IntPtr w,IntPtr p){uint id;GetWindowThreadProcessId(w,out id);if(id==pid&&Text(w)==title){r=w;return false;}return true;},IntPtr.Zero);return r;}
 public static void Click(IntPtr w,int x,int y,int width,int height){Rect r;GetClientRect(w,out r);int xx=x*(r.R-r.L)/width,yy=y*(r.B-r.T)/height;IntPtr xy=new IntPtr((yy<<16)|(xx&65535));PostMessage(w,0x200,IntPtr.Zero,xy);PostMessage(w,0x201,new IntPtr(1),xy);PostMessage(w,0x202,IntPtr.Zero,xy);}
 public static string Screenshot(IntPtr w,string file){Rect r;GetWindowRect(w,out r);using(var b=new Bitmap(r.R-r.L,r.B-r.T)){using(var g=Graphics.FromImage(b)){var d=g.GetHdc();try{if(!PrintWindow(w,d,0))throw new Exception("PrintWindow failed");}finally{g.ReleaseHdc(d);}}b.Save(file,System.Drawing.Imaging.ImageFormat.Png);return b.Width+"x"+b.Height;}}
 public static uint Pixel(IntPtr w,int x,int y){var dc=GetDC(w);try{return GetPixel(dc,x,y);}finally{ReleaseDC(w,dc);}}
 public static void ResizeClient(IntPtr w,int width,int height){Rect a,c;GetWindowRect(w,out a);GetClientRect(w,out c);SetWindowPos(w,IntPtr.Zero,20,20,width+(a.R-a.L-c.R),height+(a.B-a.T-c.B),0x14);}
}
'@
function Check([bool]$ok,[string]$name){$Rows.Add([pscustomobject]@{name=$name;passed=$ok});Write-Host (($ok.ToString().ToUpper())+' '+$name);if(!$ok){throw $name}}
function Until([scriptblock]$test,[string]$name,[int]$seconds=25){$deadlineForProbe=[datetime]::UtcNow.AddSeconds($seconds);do{$probeValue=&$test;if($probeValue -is [IntPtr]){if($probeValue-ne[IntPtr]::Zero){return $probeValue}}elseif($probeValue){return $probeValue};Start-Sleep -Milliseconds 150}while([datetime]::UtcNow-lt$deadlineForProbe);throw ('Timeout: '+$name)}
function Extract([string]$zip,[string]$name){$d=Join-Path $Work $name;Expand-Archive -LiteralPath $zip -DestinationPath $d;return (Join-Path $d 'RA3Octane')}
function Launch([string]$root){$p=Start-Process -FilePath (Join-Path $root 'RA3Octane.exe') -WorkingDirectory $root -PassThru;$w=Until {[OctaneNativeTest]::Window($p.Id,'Begosik.RA3Octane.Native.v1')} 'launcher main window';return @{p=$p;w=$w;root=$root}}
function CloseMain($v){[OctaneNativeTest]::PostMessage($v.w,0x10,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null;if(!$v.p.WaitForExit(15000)){throw 'Launcher did not close'};Start-Sleep -Milliseconds 200}
function Current([string]$root){$exe=Join-Path $root 'RA3Octane.exe';$v=Until {$p=Get-Process -Name RA3Octane -ErrorAction SilentlyContinue|Where-Object {$_.Path-eq$exe}|Select-Object -First 1;if($p){$w=[OctaneNativeTest]::Window($p.Id,'Begosik.RA3Octane.Native.v1');if($w-ne[IntPtr]::Zero){return @{p=$p;w=$w;root=$root}}}} 'restarted launcher';return $v}
function CopyRuntime([string]$from,[string]$to){[IO.Directory]::CreateDirectory($to)|Out-Null;foreach($n in @('RA3Octane.exe','patches.octpack','release.oct')){Copy-Item -LiteralPath (Join-Path $from $n) -Destination (Join-Path $to $n) -Force}}
function SameRuntime([string]$a,[string]$b){foreach($n in @('RA3Octane.exe','patches.octpack','release.oct')){if((Get-FileHash -LiteralPath (Join-Path $a $n)).Hash-ne(Get-FileHash -LiteralPath (Join-Path $b $n)).Hash){return $false}};return $true}
function PrepareDebris([string]$root,[string]$backup){CopyRuntime $backup (Join-Path $root '.updates\backup');[IO.Directory]::CreateDirectory((Join-Path $root '.updates\worker'))|Out-Null;Copy-Item (Join-Path $root 'RA3Octane.exe') (Join-Path $root '.updates\worker\RA3OctaneUpdater.exe');return (Join-Path $root '.updates\worker\RA3OctaneUpdater.exe')}
try {
 $new=Extract $Package 'new reference';$old=Extract $Baseline 'old reference'
 Check ((Get-ChildItem -File $new).Count-eq3) 'Public archive has exactly three runtime files'
 Check ((Get-Item (Join-Path $new 'RA3Octane.exe')).VersionInfo.FileVersion-eq'1.2.33.0') 'Native VERSIONINFO is 1.2.33.0'
 $r=Extract $Package 'UI';$mods=Join-Path $r 'Mods';[IO.Directory]::CreateDirectory($mods)|Out-Null
 for($i=0;$i-lt24;$i++){[IO.File]::WriteAllText((Join-Path $mods ('TestMod_{0:D2}_long_name_for_catalog_selection.SkuDef'-f$i)),"mod-game 1.12`r`nadd-big Test.big`r`n")}
 $v=Launch $r;Start-Sleep -Milliseconds 500
 Check ([OctaneNativeTest]::Text($v.w)-eq'RA3 // OCTANE 1.2.33') 'Real signed launcher starts and displays the new title'
 $size=[OctaneNativeTest]::Screenshot($v.w,(Join-Path $Output 'launcher-native.png'));Write-Host ('SCREENSHOT '+$size)
 $pixel=[OctaneNativeTest]::Pixel($v.w,5,10);Check ($pixel-ne0xffffffff-and($pixel-band0xffffff)-ne0xffffff) 'Native launcher client is not an unpainted white surface'
 [OctaneNativeTest]::Click($v.w,941,520,1060,736)
 $warning=Until {[OctaneNativeTest]::Title($v.p.Id,'Restore Original - Warning')} 'Restore warning'
 $default=[OctaneNativeTest]::SendMessage($warning,0x400,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()-band0xffff
 Check ($default-eq2) 'Restore Original has Cancel as the default button'
 [OctaneNativeTest]::PostMessage($warning,0x111,[IntPtr]2,[IntPtr]::Zero)|Out-Null
 [OctaneNativeTest]::PostMessage($v.w,0x100,[IntPtr]0x75,[IntPtr]::Zero)|Out-Null
 $mw=Until {[OctaneNativeTest]::Window($v.p.Id,'Begosik.RA3Octane.Mods.v1')} 'F6 mod dialog'
 $list=[OctaneNativeTest]::GetDlgItem($mw,100);$count=[OctaneNativeTest]::SendMessage($list,0x18b,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()
 Check ($count-ge25) 'Real catalog discovers temporary standard SkuDef files and Vanilla'
 [OctaneNativeTest]::Screenshot($mw,(Join-Path $Output 'mods-native.png'))|Write-Host
 Check ([OctaneNativeTest]::Pixel($mw,5,10)-ne0xffffff) 'Mod dialog uses a dark client background'
 [OctaneNativeTest]::SendMessage($list,0x100,[IntPtr]0x23,[IntPtr]::Zero)|Out-Null
 $sel=[OctaneNativeTest]::SendMessage($list,0x188,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()
 Check ($sel-eq($count-1)) 'Native list End key reaches the last catalog entry'
 [OctaneNativeTest]::SendMessage($list,0x100,[IntPtr]0x24,[IntPtr]::Zero)|Out-Null
 Check ([OctaneNativeTest]::SendMessage($list,0x188,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()-eq0) 'Native list Home key reaches explicit Vanilla'
 [OctaneNativeTest]::SendMessage($list,0x186,[IntPtr]1,[IntPtr]::Zero)|Out-Null
 [OctaneNativeTest]::SendMessage($mw,0x111,[IntPtr]0x10064,$list)|Out-Null
 $chosen=[OctaneNativeTest]::ControlText([OctaneNativeTest]::GetDlgItem($mw,102))
 Check ($chosen.EndsWith('.SkuDef') -and (Test-Path -LiteralPath $chosen)) 'Selection exposes the full real mod path'
 [OctaneNativeTest]::ResizeClient($mw,900,565);Start-Sleep -Milliseconds 200
 [OctaneNativeTest]::Screenshot($mw,(Join-Path $Output 'mods-scaled-native.png'))|Write-Host
 [OctaneNativeTest]::PostMessage($mw,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($mw)} 'Accept mod dialog'|Out-Null
 Check ((Get-Content -LiteralPath (Join-Path $r 'settings.ini') -Raw)-match'SelectedSkuDef=u16:') 'Accepted mod is saved through the production selector'
 [OctaneNativeTest]::PostMessage($v.w,0x100,[IntPtr]0x75,[IntPtr]::Zero)|Out-Null
 $mw=Until {[OctaneNativeTest]::Window($v.p.Id,'Begosik.RA3Octane.Mods.v1')} 'reopen mods'
 $list=[OctaneNativeTest]::GetDlgItem($mw,100)
 Check ([OctaneNativeTest]::SendMessage($list,0x188,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()-eq1) 'Selected mod survives dialog close and reopen'
 [OctaneNativeTest]::SendMessage($list,0x186,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 [OctaneNativeTest]::PostMessage($mw,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($mw)} 'accept Vanilla'|Out-Null
 [OctaneNativeTest]::ResizeClient($v.w,848,589);Start-Sleep -Milliseconds 200
 [OctaneNativeTest]::Screenshot($v.w,(Join-Path $Output 'launcher-small-native.png'))|Write-Host
 [OctaneNativeTest]::Click($v.w,594,413,1060,736)
 $mw=Until {[OctaneNativeTest]::Window($v.p.Id,'Begosik.RA3Octane.Mods.v1')} 'scaled MODS hit region'
 Check ([OctaneNativeTest]::SendMessage([OctaneNativeTest]::GetDlgItem($mw,100),0x188,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()-eq0) 'Vanilla is restored and scaled MODS mouse hit region works'
 [OctaneNativeTest]::PostMessage($mw,0x111,[IntPtr]2,[IntPtr]::Zero)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($mw)} 'cancel selector'|Out-Null;CloseMain $v
 # Real old worker, real replacement, real new executable; stage is locally supplied.
 $r=Extract $Baseline 'update cycle';[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[UserTest]`r`nKeep=yes`r`n");[IO.File]::WriteAllText((Join-Path $r 'user-owned.txt'),'keep')
 $v=Launch $r;CopyRuntime $new (Join-Path $r '.updates\stage');$wp=PrepareDebris $r $old
 $worker=Start-Process $wp -ArgumentList ('--apply-update "'+$r+'" '+$v.p.Id) -PassThru;CloseMain $v
 $v=Current $r;Check (SameRuntime $r $new) 'Actual 1.2.32 worker installs byte-exact 1.2.33 and restarts it'
 Check ($worker.WaitForExit(15000)) 'Update worker exits normally'
 Until {!(Test-Path -LiteralPath (Join-Path $r '.updates'))} 'post-update worker and backup cleanup' 20|Out-Null
 Check (!(Test-Path -LiteralPath (Join-Path $r '.updates'))) 'Completed update leaves no known temporary directory'
 Check ((Get-Content (Join-Path $r 'settings.ini') -Raw)-match'Keep=yes') 'Self-update preserves existing settings'
 Check ((Get-Content (Join-Path $r 'user-owned.txt') -Raw)-eq'keep') 'Self-update preserves unrelated user files'
 CloseMain $v;$v=Launch $r;Check (!(Test-Path (Join-Path $r '.updates'))) 'Normal repeat launch does not recreate update debris';CloseMain $v
 $r=Extract $Package 'locked worker';$wp=PrepareDebris $r $old
 $lock=[IO.File]::Open($wp,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {$v=Launch $r;Check (Test-Path $wp) 'Locked worker is not deleted';Check (Test-Path (Join-Path $r '.updates\backup\release.oct')) 'Backup remains while worker cleanup is blocked'}finally{$lock.Dispose()}
 Until {!(Test-Path (Join-Path $r '.updates'))} 'deferred lock cleanup' 20|Out-Null
 Check (!(Test-Path (Join-Path $r '.updates'))) 'Idle retry cleans worker after its file lock is released';CloseMain $v
 $r=Extract $Package 'live worker';$wp=PrepareDebris $r $old;$worker=Start-Process $wp -ArgumentList '--help' -PassThru
 $help=Until {[OctaneNativeTest]::Title($worker.Id,'RA3 // OCTANE - Help')} 'live worker image'
 $v=Launch $r;Check (Test-Path $wp) 'A running worker image is retained';Check (Test-Path (Join-Path $r '.updates\backup\release.oct')) 'Backup is retained while worker process is live'
 [OctaneNativeTest]::PostMessage($help,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Check ($worker.WaitForExit(10000)) 'Controlled worker process closes'
 Until {!(Test-Path (Join-Path $r '.updates'))} 'cleanup after live worker exit' 20|Out-Null
 Check (!(Test-Path (Join-Path $r '.updates'))) 'Idle retry cleans up only after the actual worker exits';CloseMain $v
 $r=Extract $Package 'interrupted recovery';CopyRuntime $old (Join-Path $r '.updates\backup');CopyRuntime $new (Join-Path $r '.updates\stage')
 [IO.File]::WriteAllText((Join-Path $r '.updates\transaction.oct'),'OCTANE-UPDATE-1')
 [IO.File]::WriteAllText((Join-Path $r 'patches.octpack'),'incomplete interrupted copy')
 $first=Start-Process (Join-Path $r 'RA3Octane.exe') -WorkingDirectory $r -PassThru
 Check ($first.WaitForExit(15000)) 'Interrupted launch hands off recovery before using damaged payload'
 $v=Current $r;Check (SameRuntime $r $old) 'Actual new recovery worker restores all three verified previous files'
 Check (!(Test-Path (Join-Path $r '.updates\transaction.oct'))) 'Recovery journal is removed after successful restored-file verification';CloseMain $v
 $r=Extract $Package 'linked cleanup';$outside=Join-Path $Work 'outside';CopyRuntime $old (Join-Path $outside 'backup');[IO.File]::WriteAllText((Join-Path $outside 'untouched.txt'),'outside')
 & cmd.exe /c ('mklink /J "'+(Join-Path $r '.updates')+'" "'+$outside+'"')|Out-Null
 Check ($LASTEXITCODE-eq0) 'Controlled junction fixture created'
 $v=Launch $r;Check (SameRuntime (Join-Path $outside 'backup') $old) 'Cleanup does not follow a reparse-point update directory'
 Check ((Get-Content (Join-Path $outside 'untouched.txt') -Raw)-eq'outside') 'Unrelated linked data is untouched';CloseMain $v
 & cmd.exe /c ('rmdir "'+(Join-Path $r '.updates')+'"')|Out-Null
} catch {$Failure=$_.Exception.Message;Write-Host ('NATIVE_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally {
 Get-Process -Name RA3Octane,RA3OctaneUpdater -ErrorAction SilentlyContinue|Where-Object {$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 $report=[ordered]@{passed=($null-eq$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLower();windows=$env:OS;runtime='Real Windows public launcher and worker';http_download_tested=$false;ra3_or_multiplayer_tested=$false}
 $report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $Output 'windows-results.json') -Encoding UTF8
 $report|ConvertTo-Json -Depth 6|Write-Host
}
if($Failure){exit 1}
