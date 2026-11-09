param([string]$Source=(Join-Path $PSScriptRoot 'connection162_fixture.c'),[string]$Output=$PSScriptRoot)
$ErrorActionPreference='Stop'
$Source=(Resolve-Path -LiteralPath $Source).Path
$Output=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output)|Out-Null
$vswhere=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if(!(Test-Path -LiteralPath $vswhere)){throw 'Visual Studio Build Tools with x86 C++ compiler required'}
$installation=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1)
if(!$installation){throw 'C++ x86 build tools not found'}
$msvc=(Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory|Sort-Object {[Version]$_.Name} -Descending|Select-Object -First 1).FullName
$sdk=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
$version=(Get-ChildItem -LiteralPath (Join-Path $sdk 'Include') -Directory|Where-Object{Test-Path -LiteralPath (Join-Path $_.FullName 'um\winsock2.h')}|Sort-Object {[Version]$_.Name} -Descending|Select-Object -First 1).Name
if(!$msvc-or!$version){throw 'MSVC and Windows SDK required'}
$env:INCLUDE="$msvc\include;$sdk\Include\$version\ucrt;$sdk\Include\$version\shared;$sdk\Include\$version\um"
$env:LIB="$msvc\lib\x86;$sdk\Lib\$version\ucrt\x86;$sdk\Lib\$version\um\x86"
$env:PATH="$msvc\bin\Hostx64\x86;$sdk\bin\$version\x86;"+$env:PATH
& "$msvc\bin\Hostx64\x86\cl.exe" /nologo /W4 /O2 /MT $Source "/Fo:$Output\connection162_fixture.obj" /link /MACHINE:X86 /MANIFEST:EMBED "/MANIFESTUAC:level='asInvoker' uiAccess='false'" "/OUT:$Output\connection162_fixture.exe" ws2_32.lib
if($LASTEXITCODE-ne0){throw 'Native connection fixture compilation failed'}
