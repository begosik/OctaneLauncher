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
$api=@'
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);
 [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr w);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr w);
'@
$source=$source.Replace($declaration,$declaration+"`n"+$api)
# A real MessageBox button notification has a child HWND. The old fixture posted
# a menu-style WM_COMMAND with a null child. Use the native button instead; do not
# terminate the process or weaken the subsequent live-worker cleanup assertions.
$oldClose=' [OctaneNativeTest]::PostMessage($help,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Check ($worker.WaitForExit(10000)) ''Controlled worker process closes'''
$newClose=@'
 $helpButton=Until {
  $buttonHandle=[OctaneNativeTest]::GetDlgItem($help,1)
  if($buttonHandle-ne[IntPtr]::Zero-and[OctaneNativeTest]::IsWindowVisible($buttonHandle)-and[OctaneNativeTest]::IsWindowEnabled($buttonHandle)){return $buttonHandle}
 } 'ready Help OK button'
 [OctaneNativeTest]::Screenshot($help,(Join-Path $Output 'live-worker-help-native.png'))|Write-Host
 Write-Host ('HELP_BUTTON_CLASS '+[OctaneNativeTest]::Class($helpButton))
 [OctaneNativeTest]::SetForegroundWindow($help)|Out-Null
 Start-Sleep -Milliseconds 200
 Check ([OctaneNativeTest]::PostMessage($helpButton,0x00f5,[IntPtr]::Zero,[IntPtr]::Zero)) 'Native Help OK click was posted'
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
