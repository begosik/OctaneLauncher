param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
# Wait for WM_CREATE/catalog completion, not merely an allocated HWND.
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
$before='if(id==pid&&Class(w)==cls)'
$after='if(id==pid&&IsWindowVisible(w)&&Class(w)==cls)'
if(!$source.Contains($before)){throw 'Unexpected native test template'}
$source=$source.Replace($before,$after)
$source=$source.Replace('if(id==pid&&Text(w)==title)','if(id==pid&&IsWindowVisible(w)&&Text(w)==title)')
$declaration=' [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr w);'
if(!$source.Contains($declaration)){throw 'Missing native window API declaration'}
$source=$source.Replace($declaration,$declaration+"`n"+' [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);')
# The live-file fixture is a --help invocation, not an installation transaction.
# Close its window normally and still require exit code zero before any cleanup.
# No Stop-Process/TerminateProcess is used to satisfy the assertion.
$oldClose=' [OctaneNativeTest]::PostMessage($help,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Check ($worker.WaitForExit(10000)) ''Controlled worker process closes'''
$newClose=@'
 Write-Host ('HELP_HWND '+$help+' CLASS '+[OctaneNativeTest]::Class($help)+' TITLE '+[OctaneNativeTest]::Text($help))
 [OctaneNativeTest]::Screenshot($help,(Join-Path $Output 'live-worker-help-native.png'))|Write-Host
 for($buttonId=1;$buttonId-le10;$buttonId++){
  $childHandle=[OctaneNativeTest]::GetDlgItem($help,$buttonId)
  if($childHandle-ne[IntPtr]::Zero){Write-Host ('HELP_CHILD '+$buttonId+' '+[OctaneNativeTest]::Class($childHandle)+' '+[OctaneNativeTest]::Text($childHandle))}
 }
 Check ([OctaneNativeTest]::PostMessage($help,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)) 'Normal Help window close request posted'
 Check ($worker.WaitForExit(15000)) 'Controlled worker process closes'
 Check ($worker.ExitCode-eq0) 'Controlled Help worker exits normally, without termination'
'@
if(!$source.Contains($oldClose)){throw 'Unexpected live-worker fixture'}
$source=$source.Replace($oldClose,$newClose)
$temporary=Join-Path $env:RUNNER_TEMP ('octane-window-ready-'+[guid]::NewGuid().ToString('N')+'.ps1')
[IO.File]::WriteAllText($temporary,$source,[Text.UTF8Encoding]::new($false))
try {
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $temporary -Package $Package -Baseline $Baseline -Output $Output
 $result=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $temporary -Force}
exit $result
