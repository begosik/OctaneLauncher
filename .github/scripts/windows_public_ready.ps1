param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$before='if(id==pid&&Class(w)==cls)'
$after='if(id==pid&&IsWindowVisible(w)&&Class(w)==cls)'
if(!$source.Contains($before)){throw 'Unexpected native test template'}
$source=$source.Replace($before,$after)
$source=$source.Replace('if(id==pid&&Text(w)==title)','if(id==pid&&IsWindowVisible(w)&&Text(w)==title)')
$declaration=' [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr w);'
if(!$source.Contains($declaration)){throw 'Missing native window API declaration'}
$source=$source.Replace($declaration,$declaration+"`n"+' [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);')
$oldClose=' [OctaneNativeTest]::PostMessage($help,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Check ($worker.WaitForExit(10000)) ''Controlled worker process closes'''
$newClose=@'
 Write-Host ('HELP_CLASS '+[OctaneNativeTest]::Class($help))
 [OctaneNativeTest]::Screenshot($help,(Join-Path $Output 'live-worker-help-native.png'))|Write-Host
 Check ([OctaneNativeTest]::PostMessage($help,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)) 'Normal Help window close request posted'
 Check ($worker.WaitForExit(15000)) 'Controlled worker process closes'
 Check ($worker.ExitCode-eq0) 'Controlled Help worker exits normally, without termination'
'@
if(!$source.Contains($oldClose)){throw 'Unexpected live-worker fixture'}
$source=$source.Replace($oldClose,$newClose.Replace("`r`n","`n"))
$hook="finally {`n Get-Process -Name RA3Octane,RA3OctaneUpdater"
$inspection=@'
finally {
 if($Failure){
  Write-Host 'FAILED_FIXTURE_FILES'
  Get-ChildItem -LiteralPath $r -Force -Recurse -File | ForEach-Object {Write-Host ($_.FullName.Substring($r.Length)+' bytes='+$_.Length+' sha256='+(Get-FileHash -LiteralPath $_.FullName).Hash)}
  foreach($name in @('launcher.log','update.log')){
   $log=Join-Path $r ('Logs\'+$name)
   if(Test-Path -LiteralPath $log){Write-Host ('FIXTURE_LOG '+$name);Get-Content -LiteralPath $log -Tail 60|Write-Host}
  }
  Get-Process -Name RA3Octane,RA3OctaneUpdater -ErrorAction SilentlyContinue|Where-Object {$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object {
   Write-Host ('FIXTURE_PROCESS '+$_.Id+' '+$_.Path+' title='+$_.MainWindowTitle)
   $diagWindow=[OctaneNativeTest]::Window($_.Id,'#32770')
   if($diagWindow-ne[IntPtr]::Zero){
    Write-Host ('FIXTURE_DIALOG '+[OctaneNativeTest]::Text($diagWindow))
    [OctaneNativeTest]::Screenshot($diagWindow,(Join-Path $Output ('failure-dialog-'+$_.Id+'.png')))|Write-Host
    foreach($cid in @(65535,100,101,102,103,104,105,106)){
     $ch=[OctaneNativeTest]::GetDlgItem($diagWindow,$cid)
     if($ch-ne[IntPtr]::Zero){Write-Host ('DIALOG_CHILD '+$cid+' '+[OctaneNativeTest]::ControlText($ch))}
    }
   }
  }
 }
 Get-Process -Name RA3Octane,RA3OctaneUpdater
'@
if(!$source.Contains($hook)){throw 'Unexpected cleanup block'}
$source=$source.Replace($hook,$inspection.Replace("`r`n","`n"))
$temporary=Join-Path $env:RUNNER_TEMP ('octane-window-ready-'+[guid]::NewGuid().ToString('N')+'.ps1')
[IO.File]::WriteAllText($temporary,$source,[Text.UTF8Encoding]::new($false))
try {
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $temporary -Package $Package -Baseline $Baseline -Output $Output
 $result=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $temporary -Force}
exit $result
