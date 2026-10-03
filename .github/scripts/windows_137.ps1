param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output,[ValidateSet('native','http','notice')][string]$Mode='native')
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Baseline=(Resolve-Path $Baseline).Path
$Output=[IO.Path]::GetFullPath($Output)
if([IO.Path]::GetFileName($Baseline)-ne'RA3Octane_1.2.36_Players_Compact.zip'){throw 'Use the current 1.2.36 release as the upgrade baseline'}
if((Get-FileHash -LiteralPath $Baseline).Hash.ToLowerInvariant()-ne'dba6780e96f58ab0ceb4b255faeb6f3004e4cb59bd32533eea8b1603fa88b924'){throw 'Baseline archive identity mismatch'}
$fixture=Join-Path $env:RUNNER_TEMP ('octane137-native-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
try {
 $template=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
 if(!$template.Contains('1.2.33.0') -or !$template.Contains('interrupted recovery')){throw 'Unexpected native baseline fixture'}
 $template=$template.Replace('1.2.33','1.2.37').Replace('1.2.32','1.2.36')
 [IO.File]::WriteAllText((Join-Path $fixture 'windows_public_test.ps1'),$template,[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_public_ready.ps1') -Destination $fixture
 $entry=Join-Path $fixture 'windows_public_ready.ps1'
 if($Mode-eq'http'){
  $http=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'http_update_134.ps1'))
  if(!$http.Contains('1.2.34.0') -or !$http.Contains('manual_staging=$false')){throw 'Unexpected HTTP fixture'}
  $http=$http.Replace('1.2.34','1.2.37').Replace('1.2.32','1.2.36').Replace('HTTP_UPDATE_134.json','HTTP_UPDATE_137.json')
  $entry=Join-Path $fixture 'http_update_137.ps1'
  [IO.File]::WriteAllText($entry,$http,[Text.UTF8Encoding]::new($false))
 }
 if($Mode-eq'notice'){
  $notice=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'notice_136.ps1'))
  $notice=$notice.Replace('1.2.39','1.2.40').Replace('1.2.38','1.2.39').Replace('1.2.37','1.2.38').Replace('1.2.36','1.2.37')
  $notice=$notice.Replace('Offer 39','Offer 40').Replace('Offer 38','Offer 39').Replace('Offer 37','Offer 38')
  $notice=$notice.Replace('1dbbc15f88202d21871cedc3c8df5d4532d79b60dc9dbc632265786aa4c4f089','185251c0aa86d6f6d483b9f90792026cc996449fb4f20a60cacce499ece5b51a').Replace('NOTICE_136.json','NOTICE_137.json')
  $entry=Join-Path $fixture 'notice_137.ps1'
  [IO.File]::WriteAllText($entry,$notice,[Text.UTF8Encoding]::new($false))
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry -Package $Package -Output $Output
 }else{
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry -Package $Package -Baseline $Baseline -Output $Output
 }
 $code=$LASTEXITCODE
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}
exit $code
