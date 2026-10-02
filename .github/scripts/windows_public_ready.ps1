param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
# EnumWindows also sees a new HWND while WM_CREATE is still creating its list.
# ShowWindow is called only after the production catalog is fully populated.
# Preserve all assertions; wait for that observable native readiness boundary.
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
$before='if(id==pid&&Class(w)==cls)'
$after='if(id==pid&&IsWindowVisible(w)&&Class(w)==cls)'
if(!$source.Contains($before)){throw 'Unexpected native test template'}
$source=$source.Replace($before,$after)
$declaration=' [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr w);'
if(!$source.Contains($declaration)){throw 'Missing native window API declaration'}
$source=$source.Replace($declaration,$declaration+"`n"+' [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr w);')
$temporary=Join-Path $env:RUNNER_TEMP ('octane-window-ready-'+[guid]::NewGuid().ToString('N')+'.ps1')
[IO.File]::WriteAllText($temporary,$source,[Text.UTF8Encoding]::new($false))
try {
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $temporary -Package $Package -Baseline $Baseline -Output $Output
 $result=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $temporary -Force}
exit $result
