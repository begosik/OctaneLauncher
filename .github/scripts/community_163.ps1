param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
# Execute the retained142 test byte-for-byte with only a compact fixture cache.
$ErrorActionPreference='Stop';$Package=(Resolve-Path -LiteralPath $Package).Path;$Output=[IO.Path]::GetFullPath($Output)
$communityFixture163=Join-Path ([IO.Path]::GetFullPath($env:RUNNER_TEMP)) ('community163-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($communityFixture163)|Out-Null
$cacheHelper163=(Join-Path $PSScriptRoot 'compact_cache163.ps1').Replace("'","''")
try{
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'community_142.ps1') -Destination $communityFixture163
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1'))
 $cacheLine='$env:LOCALAPPDATA=Join-Path $Work ''LocalAppData'';[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null'
 if(!$source.Contains($cacheLine)){throw 'Unexpected retained native cache fixture'}
 $source=$source.Replace($cacheLine,". '$cacheHelper163'")
 [IO.File]::WriteAllText((Join-Path $communityFixture163 'windows_public_test.ps1'),$source,[Text.UTF8Encoding]::new($false))
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $communityFixture163 'community_142.ps1') -Package $Package -Output $Output
 $result=$LASTEXITCODE
}finally{
 $checkedFixture163=[IO.Path]::GetFullPath($communityFixture163);$checkedParent163=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
 if(!$checkedFixture163.StartsWith($checkedParent163,[StringComparison]::OrdinalIgnoreCase)-or(Split-Path -Leaf $checkedFixture163)-notmatch'^community163-[0-9a-f]{32}$'){throw 'Refusing fixture cleanup outside its checked test directory'}
 Remove-Item -LiteralPath $checkedFixture163 -Recurse -Force
}
exit $result
