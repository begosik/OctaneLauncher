param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Baseline=(Resolve-Path $Baseline).Path
$Output=[IO.Path]::GetFullPath($Output)
$fixture=Join-Path $env:RUNNER_TEMP ('octane134-native-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
try {
 $template=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
 if(!$template.Contains('1.2.33.0') -or !$template.Contains('interrupted recovery')){throw 'Unexpected native baseline fixture'}
 $template=$template.Replace('1.2.33','1.2.34')
 [IO.File]::WriteAllText((Join-Path $fixture 'windows_public_test.ps1'),$template,[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_public_ready.ps1') -Destination $fixture
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $fixture 'windows_public_ready.ps1') -Package $Package -Baseline $Baseline -Output $Output
 $code=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
exit $code
