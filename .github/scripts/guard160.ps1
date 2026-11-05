param([Parameter(Mandatory=$true)][string]$GamePath,[Parameter(Mandatory=$true)][string]$NativePath,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$GamePath=(Resolve-Path -LiteralPath $GamePath).Path
$NativePath=(Resolve-Path -LiteralPath $NativePath).Path
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Output))|Out-Null
$Output=(Resolve-Path -LiteralPath $Output).Path
$gameHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $GamePath).Hash.ToLowerInvariant()
$nativeHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $NativePath).Hash.ToLowerInvariant()
if($gameHash-ne'f1b4ede3229921abd474e0a251fe1880ca98981d9cbf45e4b5c3b8fee08c7a31'){throw 'Expected authenticated canonical V134Z/FPS136 game fixture'}
if($nativeHash-ne'9bac88fed4023e272594d93a5178c5e5af6b9531badd9757e79b1d9e8ab8a0a7'){throw 'Expected exact signed NativeDll160 candidate'}
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(!$vs){throw 'Visual C++ tools missing'}
$vc=Get-ChildItem -LiteralPath "$vs/VC/Tools/MSVC" -Directory|Sort-Object Name -Descending|Select-Object -First 1
$sdk=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10'
$ver=Get-ChildItem -LiteralPath "$sdk/Include" -Directory|Where-Object{Test-Path "$($_.FullName)/um/windows.h"}|Sort-Object Name -Descending|Select-Object -First 1
$env:INCLUDE="$($vc.FullName)/include;$sdk/Include/$($ver.Name)/ucrt;$sdk/Include/$($ver.Name)/shared;$sdk/Include/$($ver.Name)/um"
$env:LIB="$($vc.FullName)/lib/x86;$sdk/Lib/$($ver.Name)/ucrt/x86;$sdk/Lib/$($ver.Name)/um/x86"
$env:PATH="$sdk/bin/$($ver.Name)/x86;$($vc.FullName)/bin/Hostx64/x86;"+$env:PATH
$build=Join-Path $Output 'build.log'
$fixture=Join-Path $Output 'guard160.exe'
$runner=Join-Path $Output 'run_guard160.exe'
& "$($vc.FullName)/bin/Hostx64/x86/cl.exe" /nologo /O2 /MT /W3 "$PSScriptRoot/guard160.c" "/Fo:$Output/guard160.obj" /link /MACHINE:X86 /BASE:0x20000000 /DYNAMICBASE:NO /MANIFEST:EMBED "/MANIFESTUAC:level='asInvoker' uiAccess='false'" "/OUT:$fixture" *> $build
if($LASTEXITCODE-ne0){Get-Content -LiteralPath $build;throw 'Runtime guard fixture build failed'}
& "$($vc.FullName)/bin/Hostx64/x86/cl.exe" /nologo /O2 /MT /W3 "$PSScriptRoot/run_guard160.c" "/Fo:$Output/run_guard160.obj" /link /MACHINE:X86 /MANIFEST:EMBED "/MANIFESTUAC:level='asInvoker' uiAccess='false'" "/OUT:$runner" *>> $build
if($LASTEXITCODE-ne0){Get-Content -LiteralPath $build;throw 'Runtime guard runner build failed'}
$log=Join-Path $Output 'runtime-installer.log'
$runnerLog=Join-Path $Output 'runner.log'
& $runner $fixture $NativePath $GamePath $log *> $runnerLog
$code=$LASTEXITCODE
Get-Content -LiteralPath $runnerLog
if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log}
if($code-ne0){throw "Actual native installer test failed: $code"}
$result=[IO.File]::ReadAllText($log)
if($result-notmatch'PASS installer_cases=(\d+) assertions=(\d+) failures=0 no_game_code_executed=1'){throw 'Native installer success receipt missing'}
$cases=[int]$Matches[1];$assertions=[int]$Matches[2]
if($cases-ne27-or$assertions-ne140){throw 'Incomplete native installer case matrix'}
if($result-notmatch'installed_instruction_spans=3 span_bytes=17 actual_changed_bytes=17'){throw 'Unexpected native game edit scope'}
[ordered]@{passed=$true;cases=$cases;assertions=$assertions;native_sha256=$nativeHash;game_sha256=$gameHash;native_windows_installer_executed=$true;whole_game_outside_17_bytes_preserved=$true;game_code_executed=$false;game_files_changed=$false;game_data_base='0x400000';unsupported_base_tested='0x10000000';VirtualProtect_denial_cases=@(1,2,3);real_kernel_VirtualProtect_and_Flush_executed=$true;partial_and_incompatible_games_preserved=$true;protections_restored=$true;asInvoker_test_process=$true;scope='Actual compiled DLL capture wrapper and runtime installer execute against the authenticated game PE copied as read-only data. A new suspended fixture child reserves the game address before loader codepage mappings; only that owned test process is managed. No game entry point, TLS callback, lobby or gameplay executes. API substitutions provide the artificial main-module address and prevent co_spawn from starting network threads. Exact changes, idempotence, malformed/unsupported/partial guards and protection preparation failure rollback are checked natively.'}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Output 'GUARD_NATIVE_160.json') -Encoding UTF8
