param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output,[ValidateSet('native','http')][string]$Mode='native')
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Baseline=(Resolve-Path $Baseline).Path
$Output=[IO.Path]::GetFullPath($Output)
if([IO.Path]::GetFileName($Baseline)-ne'RA3Octane_1.2.34_Players_Compact.zip'){throw 'Use the current 1.2.34 release as the upgrade baseline'}
if((Get-FileHash -LiteralPath $Baseline).Hash.ToLowerInvariant()-ne'd3206d34589b7c2a558549fcc111f454a66eb91b15567a3ea05f976cf214e9e8'){throw 'Baseline archive identity mismatch'}
$fixture=Join-Path $env:RUNNER_TEMP ('octane135-native-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
try {
 $template=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
 if(!$template.Contains('1.2.33.0') -or !$template.Contains('interrupted recovery')){throw 'Unexpected native baseline fixture'}
 $template=$template.Replace('1.2.33','1.2.35').Replace('1.2.32','1.2.34')
 [IO.File]::WriteAllText((Join-Path $fixture 'windows_public_test.ps1'),$template,[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_public_ready.ps1') -Destination $fixture
 $entry=Join-Path $fixture 'windows_public_ready.ps1'
 if($Mode-eq'http'){
  $http=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'http_update_134.ps1'))
  if(!$http.Contains('1.2.34.0') -or !$http.Contains('manual_staging=$false')){throw 'Unexpected HTTP fixture'}
  $http=$http.Replace('1.2.34','1.2.35').Replace('1.2.32','1.2.34').Replace('HTTP_UPDATE_134.json','HTTP_UPDATE_135.json')
  $entry=Join-Path $fixture 'http_update_135.ps1'
  [IO.File]::WriteAllText($entry,$http,[Text.UTF8Encoding]::new($false))
 }
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry -Package $Package -Baseline $Baseline -Output $Output
 $code=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
exit $code
