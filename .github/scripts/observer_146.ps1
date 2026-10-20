param([Parameter(Mandatory=$true)][string]$OldObserver,[Parameter(Mandatory=$true)][string]$NewObserver,[Parameter(Mandatory=$true)][string]$Output)
# Actual extracted production helpers, real Windows debug events and a small x86
# synthetic child. Suspending a helper is fault injection by this test only.
# This does not reproduce an RA3 match, graphics driver or Alt+Tab operation.
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -OldObserver $OldObserver -NewObserver $NewObserver -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop'
$OldObserver=(Resolve-Path $OldObserver).Path;$NewObserver=(Resolve-Path $NewObserver).Path
$Output=[IO.Path]::GetFullPath($Output);[IO.Directory]::CreateDirectory($Output)|Out-Null
$work=Join-Path $env:RUNNER_TEMP ('Octane observer146 '+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($work)|Out-Null
$rows=New-Object 'System.Collections.Generic.List[object]';$cases=New-Object 'System.Collections.Generic.List[object]';$failure=$null
function Check([bool]$ok,[string]$name){$rows.Add([pscustomobject]@{name=$name;passed=$ok});Write-Host (($ok.ToString().ToUpper())+' '+$name);if(!$ok){throw $name}}
function Until([scriptblock]$test,[string]$name,[int]$seconds=25){$end=[datetime]::UtcNow.AddSeconds($seconds);do{$v=&$test;if($v){return $v};Start-Sleep -Milliseconds 50}while([datetime]::UtcNow-lt$end);throw ('Timeout: '+$name)}
function ReadTextShared([string]$path){if(!(Test-Path -LiteralPath $path)){return ''};$f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete));$r=New-Object IO.StreamReader($f,[Text.Encoding]::UTF8);try{return $r.ReadToEnd()}finally{$r.Dispose()}}
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Diagnostics; using System.Runtime.InteropServices;
public static class Observer146Kernel {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CheckRemoteDebuggerPresent(IntPtr process,out bool present);
 public static bool Debugger(int pid) {using(var p=Process.GetProcessById(pid)){bool yes;if(!CheckRemoteDebuggerPresent(p.Handle,out yes))throw new System.ComponentModel.Win32Exception();return yes;}}
 public static IntPtr[] PauseHelper(int pid) {
  var handles=new List<IntPtr>();
  try {using(var p=Process.GetProcessById(pid)){foreach(ProcessThread t in p.Threads){
   var h=OpenThread(2,false,(uint)t.Id);if(h==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();
   uint before=SuspendThread(h);if(before==UInt32.MaxValue){CloseHandle(h);throw new System.ComponentModel.Win32Exception();}
   handles.Add(h);if(before!=0)throw new Exception("Helper already suspended before this test");
  }}if(handles.Count==0)throw new Exception("No collector thread found");return handles.ToArray();}
  catch {ResumeHelper(handles.ToArray());throw;}
 }
 public static void ResumeHelper(IntPtr[] handles){if(handles==null)return;foreach(var h in handles){ResumeThread(h);CloseHandle(h);}}
}
'@
$source=@'
using System; using System.IO.MemoryMappedFiles; using System.Threading; using System.Runtime.InteropServices;
public static class SyntheticObserverTarget146 {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern void OutputDebugStringW(string text);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr LoadLibraryW(string name);
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
 static long heartbeat,strings,exceptions,threads,libraries;static volatile bool done;
 public static int Main(string[] args) {
  if(args.Length!=2)return 91;
  using(var map=MemoryMappedFile.OpenExisting(args[0]))using(var view=map.CreateViewAccessor())using(var stop=EventWaitHandle.OpenExisting(args[1])) {
   var beat=new Thread(delegate(){while(!done){view.Write(0,Interlocked.Increment(ref heartbeat));view.Write(8,Interlocked.Read(ref strings));view.Write(16,Interlocked.Read(ref exceptions));view.Write(24,Interlocked.Read(ref threads));view.Write(32,Interlocked.Read(ref libraries));Thread.Sleep(1);}});beat.IsBackground=true;beat.Start();
   int n=0;
   try {while(!stop.WaitOne(0)) {
    OutputDebugStringW("Octane146 synthetic event: managed child only");Interlocked.Increment(ref strings);n++;
    if(n%8==0){try{throw new InvalidOperationException("handled synthetic exception");}catch(InvalidOperationException){Interlocked.Increment(ref exceptions);}}
    if(n%16==0){var t=new Thread(delegate(){Interlocked.Increment(ref threads);});t.Start();t.Join();var module=LoadLibraryW("version.dll");if(module!=IntPtr.Zero){FreeLibrary(module);Interlocked.Increment(ref libraries);}}
    Thread.Sleep(2);
   }}finally{done=true;beat.Join(3000);}
  }
  return 37;
 }
}
'@
$targetSource=Join-Path $work 'SyntheticObserverTarget.cs';$targetImage=Join-Path $work 'SyntheticObserverTarget.exe'
[IO.File]::WriteAllText($targetSource,$source,[Text.UTF8Encoding]::new($false))
$compiler=Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
Check (Test-Path -LiteralPath $compiler) 'Windows .NET Framework x86 target compiler is available'
& $compiler /nologo /target:exe /platform:x86 /optimize+ ('/out:'+$targetImage) $targetSource
Check ($LASTEXITCODE-eq0-and(Test-Path $targetImage)) 'Synthetic heartbeat/event target compiles for x86'

function ReadCounters($view){return [ordered]@{heartbeat=$view.ReadInt64(0);debug_strings=$view.ReadInt64(8);handled_exceptions=$view.ReadInt64(16);thread_bursts=$view.ReadInt64(24);dll_bursts=$view.ReadInt64(32)}}
function RunCase([string]$label,[string]$helper,[bool]$debuggerExpected){
 $id=[guid]::NewGuid().ToString('N');$mapName='Local\Octane.Observer146.Map.'+$id;$stopName='Local\Octane.Observer146.Stop.'+$id;$readyName='Local\Octane.Observer146.Ready.'+$id
 $map=[IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($mapName,64);$view=$map.CreateViewAccessor()
 $stop=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::ManualReset,$stopName)
 $ready=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::ManualReset,$readyName)
 $logs=Join-Path $Output $label;[IO.Directory]::CreateDirectory($logs)|Out-Null;$log=Join-Path $logs 'octane_diagnostics.log'
 $target=$null;$observer=$null;$paused=$null;$before=$null;$during1=$null;$during2=$null
 try{
  $target=Start-Process -FilePath $targetImage -ArgumentList @($mapName,$stopName) -WorkingDirectory $work -PassThru
  Until {((ReadCounters $view).heartbeat-ge4)} ($label+' child heartbeat starts')|Out-Null
  Check (![Observer146Kernel]::Debugger($target.Id)) ($label+' child starts without a debugger')
  $arguments=@($target.Id,('"'+$targetImage+'"'),('"'+$logs+'"'),('"'+$readyName+'"'))
  $observer=Start-Process -FilePath $helper -ArgumentList $arguments -WorkingDirectory $work -PassThru
  Check ($ready.WaitOne(25000)) ($label+' actual production helper signals readiness')
  Check (!$observer.HasExited) ($label+' actual production helper remains active')
  Until {([Observer146Kernel]::Debugger($target.Id))-eq$debuggerExpected} ($label+' expected kernel debugger state')|Out-Null
  Check (([Observer146Kernel]::Debugger($target.Id))-eq$debuggerExpected) ($label+' kernel debugger state matches collector mode')
  $base=ReadCounters $view
  Until {$v=ReadCounters $view;$v.heartbeat-ge$base.heartbeat+4-and$v.debug_strings-ge$base.debug_strings+16-and$v.handled_exceptions-gt$base.handled_exceptions-and$v.thread_bursts-gt$base.thread_bursts-and$v.dll_bursts-gt$base.dll_bursts} ($label+' debug strings, caught exceptions, thread/DLL bursts continue under the real helper')|Out-Null
  $before=ReadCounters $view
  Check ($before.debug_strings-gt0-and$before.handled_exceptions-gt0-and$before.thread_bursts-gt0-and$before.dll_bursts-gt0) ($label+' synthetic event sources all executed')
  if(!$debuggerExpected){
   Until {(ReadTextShared $log).Contains('[RUNTIME]')} 'passive helper reaches periodic snapshot path'|Out-Null
   $text=ReadTextShared $log
   Check ($text.Contains('[MONITOR_READY]')-and$text.Contains('no debugger attached')) 'Passive production helper identifies its read-only mode'
   Check ($text.Contains('[MODULE]')) 'Passive helper reads the real synthetic child module map'
   Check (!$text.Contains('[ATTACHED]')) 'Passive production helper never reports debugger attachment'
  }
  Check ($observer.Id-ne$target.Id) ($label+' fault injection selects only the helper process')
  $paused=[Observer146Kernel]::PauseHelper($observer.Id)
  Check ($paused.Length-gt0) ($label+' helper is deliberately blocked by test-only SuspendThread')
  Start-Sleep -Milliseconds 350;$during1=ReadCounters $view
  Start-Sleep -Milliseconds 650;$during2=ReadCounters $view
  if($debuggerExpected){
   Check ($during2.heartbeat-eq$during1.heartbeat) '145 negative control: pending debug event globally stops even the independent heartbeat while collector is blocked'
   Check ($during2.debug_strings-eq$during1.debug_strings) '145 negative control: target event producer is blocked behind the paused debugger'
  }else{
   Check ($during2.heartbeat-ge$during1.heartbeat+2) '146 passive helper blocked: independent child heartbeat continues'
   Check ($during2.debug_strings-gt$during1.debug_strings) '146 passive helper blocked: target OutputDebugString producer continues'
   Check ($during2.handled_exceptions-gt$during1.handled_exceptions) '146 passive helper blocked: target handles its own exceptions'
   Check ($during2.thread_bursts-gt$during1.thread_bursts-and$during2.dll_bursts-gt$during1.dll_bursts) '146 passive helper blocked: target thread and DLL activity continues'
   Check (![Observer146Kernel]::Debugger($target.Id)) '146 remains unattached while its collector is suspended'
  }
  [Observer146Kernel]::ResumeHelper($paused);$paused=$null
  $resumeCount=(ReadCounters $view).heartbeat
  Until {((ReadCounters $view).heartbeat-ge$resumeCount+3)} ($label+' target advances after helper resume')|Out-Null
  Check (!$target.HasExited) ($label+' helper fault injection did not terminate the child')
  $stop.Set()|Out-Null
  Check ($target.WaitForExit(20000)) ($label+' controlled child exits normally')
  Check ($target.ExitCode-eq37) ($label+' child preserves its intentional exit code 37')
  Check ($observer.WaitForExit(20000)) ($label+' helper exits after its target')
  Check ($observer.ExitCode-eq0) ($label+' helper returns success')
  $text=ReadTextShared $log
  Check ($text.Contains('[PROCESS_EXIT]')-and$text.Contains('code=00000025')) ($label+' helper records the actual child exit code')
  if(!$debuggerExpected){Check ($text.Contains('exitCodeRead=1 monitor=read-only')) 'Passive collector records a verified kernel exit code without debugger events'}
  $cases.Add([pscustomobject]@{case=$label;helper_sha256=(Get-FileHash $helper).Hash.ToLowerInvariant();expected_debugger=$debuggerExpected;before=$before;collector_suspended_first=$during1;collector_suspended_second=$during2;target_exit_code=$target.ExitCode;helper_exit_code=$observer.ExitCode})
 }finally{
  if($paused){[Observer146Kernel]::ResumeHelper($paused)}
  if($target-and!$target.HasExited){$stop.Set()|Out-Null;if(!$target.WaitForExit(5000)){Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue}}
  if($observer-and!$observer.HasExited){if(!$observer.WaitForExit(5000)){Stop-Process -Id $observer.Id -Force -ErrorAction SilentlyContinue}}
  $ready.Dispose();$stop.Dispose();$view.Dispose();$map.Dispose()
 }
}
try{
 RunCase 'old145-debugger-control' $OldObserver $true
 RunCase 'new146-passive' $NewObserver $false
}catch{$failure=$_.Exception.Message;Write-Host ('OBSERVER_TEST_FAILURE '+$failure);Write-Host $_.ScriptStackTrace}
finally{
 [ordered]@{passed=(!$failure);failure=$failure;assertions=$rows.Count;checks=@($rows.ToArray());cases=@($cases.ToArray());scope='Actual production helpers extracted from signed public launchers. Real Windows native debugging events, external debugger query, test-only collector suspension and independent shared-memory heartbeat. Synthetic managed x86 child only; no game, GPU, focus switch, multiplayer or Alt+Tab timing measurement.'}|ConvertTo-Json -Depth 9|Set-Content (Join-Path $Output 'OBSERVER_WINDOWS_146.json') -Encoding UTF8
}
if($failure){exit 1}
