param([Parameter(Mandatory=$true)][string]$NativePath,[Parameter(Mandatory=$true)][string]$Output,[string]$Metadata)
$ErrorActionPreference='Stop'
$NativePath=(Resolve-Path -LiteralPath $NativePath).Path
$Output=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output)|Out-Null
$repository=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source=Join-Path $repository 'transport162\network-test\connection162_fixture.c'
& (Join-Path $PSScriptRoot 'connection162_build.ps1') -Source $source -Output $Output *> (Join-Path $Output 'build.log')
if($LASTEXITCODE-ne0){throw 'Native endpoint fixture build failed'}
$connectionArgs=@((Join-Path $PSScriptRoot 'connection162.py'),$NativePath,'--fixture',(Join-Path $Output 'connection162_fixture.exe'),'--output',(Join-Path $Output 'CONNECTION_NATIVE_162.json'))
if($Metadata){$connectionArgs+=@('--metadata',(Resolve-Path -LiteralPath $Metadata).Path)}
& python @connectionArgs
if($LASTEXITCODE-ne0){throw 'Native endpoint fixture failed'}
