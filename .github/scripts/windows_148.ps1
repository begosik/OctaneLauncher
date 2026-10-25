param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output,[ValidateSet('native','http')][string]$Mode='native')
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Baseline=(Resolve-Path $Baseline).Path;$Output=[IO.Path]::GetFullPath($Output)
if((Get-FileHash $Baseline).Hash.ToLowerInvariant()-ne'191362c8cd487f45b913a10a9447f74a7d4d80fcf07386e56fcfb27aa7a1874e'){throw 'Use the exact public 1.2.47 baseline'}
$fixture=Join-Path $env:RUNNER_TEMP ('octane148-native-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($fixture)|Out-Null
try{
 $t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
 if(!$t.Contains('1.2.33.0')-or!$t.Contains('interrupted recovery')){throw 'Unexpected native test template'}
 $t=$t.Replace('1.2.33','1.2.48').Replace('1.2.32','1.2.47')
 [IO.File]::WriteAllText((Join-Path $fixture 'windows_public_test.ps1'),$t,[Text.UTF8Encoding]::new($false))
 Copy-Item (Join-Path $PSScriptRoot 'windows_public_ready.ps1') $fixture
 $entry=Join-Path $fixture 'windows_public_ready.ps1'
 if($Mode-eq'http'){
  $t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'http_update_134.ps1'))
  if(!$t.Contains('1.2.34.0')-or!$t.Contains('manual_staging=$false')){throw 'Unexpected HTTP test template'}
  $t=$t.Replace('1.2.34','1.2.48').Replace('1.2.32','1.2.47').Replace('HTTP_UPDATE_134.json','HTTP_UPDATE_148.json')
  $entry=Join-Path $fixture 'http_update_148.ps1';[IO.File]::WriteAllText($entry,$t,[Text.UTF8Encoding]::new($false))
 }
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry -Package $Package -Baseline $Baseline -Output $Output
 $code=$LASTEXITCODE
}finally{Remove-Item $fixture -Recurse -Force}
exit $code
