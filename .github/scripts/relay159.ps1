param([Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$PatchedFixture,[Parameter(Mandatory=$true)][string]$Manifest,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$Output=(Resolve-Path $Output).Path
$Baseline=(Resolve-Path $Baseline).Path
$PatchedFixture=(Resolve-Path $PatchedFixture).Path
$meta=Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$meta.archive_sha256=$meta.base_zip_sha256
$baseManifest=Join-Path $Output 'baseline-manifest.json'
$meta | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $baseManifest
python "$PSScriptRoot/extract_native141.py" $Baseline $Baseline $baseManifest "$Output/baseline"
if($LASTEXITCODE -ne 0){throw 'Baseline fixture extraction failed'}
$oldDll=Join-Path $Output 'baseline/patched.dll'
if((Get-FileHash -Algorithm SHA256 -LiteralPath $oldDll).Hash.ToLower() -ne '00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'){throw 'Unexpected old DLL'}
if((Get-FileHash -Algorithm SHA256 -LiteralPath $PatchedFixture).Hash.ToLower() -ne '13ef9630178c974f2e0b12f3eecc860c0cd781fe664bfb84f8e3cbc11f2e107a'){throw 'Unexpected new DLL'}
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(!$vs){throw 'Visual C++ tools missing'}
$vc=Get-ChildItem -LiteralPath "$vs/VC/Tools/MSVC" -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdk=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10'
$ver=Get-ChildItem -LiteralPath "$sdk/Include" -Directory | Where-Object {Test-Path "$($_.FullName)/um/windows.h"} | Sort-Object Name -Descending | Select-Object -First 1
$env:INCLUDE="$($vc.FullName)/include;$sdk/Include/$($ver.Name)/ucrt;$sdk/Include/$($ver.Name)/shared;$sdk/Include/$($ver.Name)/um"
$env:LIB="$($vc.FullName)/lib/x86;$sdk/Lib/$($ver.Name)/ucrt/x86;$sdk/Lib/$($ver.Name)/um/x86"
& "$($vc.FullName)/bin/Hostx64/x86/cl.exe" /nologo /O2 /MT /W3 "$PSScriptRoot/relay159_windows.c" "/Fo:$Output/harness.obj" /link /MACHINE:X86 "/OUT:$Output/harness.exe" ws2_32.lib *> "$Output/build.log"
if($LASTEXITCODE -ne 0){Get-Content "$Output/build.log";throw 'Native harness build failed'}
foreach($case in @('baseline','patched','relocated')) {
 $fixture=if($case -eq 'baseline'){$oldDll}else{$PatchedFixture}
 if($case -eq 'relocated'){& "$Output/harness.exe" $fixture reserve *> "$Output/$case.log"}
 else {& "$Output/harness.exe" $fixture *> "$Output/$case.log"}
 $code=$LASTEXITCODE;Get-Content "$Output/$case.log"
 if($code -ne 0){throw "Native relay case $case failed: $code"}
}
python -m pip install --disable-pip-version-check unicorn==2.1.4 pefile==2024.8.26
if($LASTEXITCODE -ne 0){throw 'Machine-code test dependencies failed'}
python "$PSScriptRoot/probe159.py" $oldDll $PatchedFixture "$Output/probe.json"
if($LASTEXITCODE -ne 0){throw 'Probe machine-code regression failed'}
@{passed=$true;scope='Real NativeDll receive loop, Asio coroutine scheduling, cached CONNECT replies and original x86 probe classifier';live_multiplayer_tested=$false;remote_traffic_sent=$false;cases=@('baseline-queue','patched-queue','128-cached-replies','31-duplicates','16-task-bound','8-overflow','slot-reuse','Windows-ASLR','198-probe-cases')} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$Output/summary.json"
