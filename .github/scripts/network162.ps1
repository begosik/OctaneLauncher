param([Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$GamePath,[Parameter(Mandatory=$true)][string]$NativePath,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$env:PYTHONUTF8='1'
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Output))|Out-Null
$Output=(Resolve-Path -LiteralPath $Output).Path
$Baseline=(Resolve-Path -LiteralPath $Baseline).Path
$GamePath=(Resolve-Path -LiteralPath $GamePath).Path
$NativePath=(Resolve-Path -LiteralPath $NativePath).Path
if((Get-FileHash -LiteralPath $NativePath -Algorithm SHA256).Hash.ToLower() -ne 'c7de4f1968831e6b66103f52739bd6afea2758f7f0b42ffe8f590543b8427b58'){throw 'Unexpected Native162 fixture'}
$repo=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$Metadata=Join-Path $repo 'transport162/network-test/relay162.json'
$manifest=Get-Content -LiteralPath (Join-Path $repo 'transport162/1.2.62/manifest.json') -Raw|ConvertFrom-Json
$manifest.archive_sha256=$manifest.base_zip_sha256
$baseManifest=Join-Path $Output 'baseline-manifest.json'
$manifest|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $baseManifest -Encoding utf8
python "$PSScriptRoot/extract_native141.py" $Baseline $Baseline $baseManifest "$Output/baseline"
if($LASTEXITCODE-ne0){throw 'Baseline Native extraction failed'}
$old=Join-Path $Output 'baseline/patched.dll'
if((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash.ToLower() -ne '00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'){throw 'Unexpected original Native fixture'}
python -m pip install --disable-pip-version-check unicorn==2.1.4 pefile==2024.8.26
if($LASTEXITCODE-ne0){throw 'Machine-code fixture dependencies failed'}
& "$PSScriptRoot/network162_build.ps1" -Output $Output
if($LASTEXITCODE-ne0){throw 'Receiver fixture build failed'}
& "$Output/relay162_baseline.exe" $old *> "$Output/baseline.log"
if($LASTEXITCODE-ne0){Get-Content "$Output/baseline.log";throw 'Baseline queue fixture failed'}
foreach($case in @('patched','relocated')){
 if($case-eq'relocated'){& "$Output/network162.exe" $NativePath reserve *> "$Output/$case.log"}
 else{& "$Output/network162.exe" $NativePath *> "$Output/$case.log"}
 if($LASTEXITCODE-ne0){Get-Content "$Output/$case.log";throw "Receiver/exception fixture failed: $case"}
 Get-Content "$Output/$case.log"
}
python "$PSScriptRoot/probe162.py" $old $NativePath "$Output/probe.json"
if($LASTEXITCODE-ne0){throw 'Probe machine-code regression failed'}
python "$PSScriptRoot/remote_tiny162.py" $NativePath --output "$Output/remote-tiny-x86.json"
if($LASTEXITCODE-ne0){throw 'Remote minimum-frame bridge regression failed'}
python "$PSScriptRoot/native_audit162.py" $old $NativePath $Metadata "$Output/native-audit.json"
if($LASTEXITCODE-ne0){throw 'Native byte/SafeSEH/packet-policy audit failed'}
python "$PSScriptRoot/terminal162.py" --native $NativePath --game $GamePath --metadata $Metadata --output "$Output/terminal.json"
if($LASTEXITCODE-ne0){throw 'Terminal guard regression failed'}
python "$PSScriptRoot/recovery162.py" --native $NativePath --game $GamePath --metadata $Metadata --output "$Output/recovery.json" --expected-native-sha 'c7de4f1968831e6b66103f52739bd6afea2758f7f0b42ffe8f590543b8427b58'
if($LASTEXITCODE-ne0){throw 'SDK synchronous failure recovery failed'}
& "$PSScriptRoot/installer162_build.ps1" -Output (Join-Path $Output 'installer-bin')
if($LASTEXITCODE-ne0){throw 'Installer fixture build failed'}
python "$PSScriptRoot/installer162.py" --native $NativePath --game $GamePath --metadata $Metadata --fixture-dir (Join-Path $Output 'installer-bin') --output "$Output/installer.json"
if($LASTEXITCODE-ne0){throw 'Native Windows installer regression failed'}
& "$PSScriptRoot/connection162_windows.ps1" -NativePath $NativePath -Metadata $Metadata -Output (Join-Path $Output 'connections')
if($LASTEXITCODE-ne0){throw 'Connection endpoint/cache/lifetime regression failed'}
@{
 passed=$true;native_sha256=(Get-FileHash -LiteralPath $NativePath -Algorithm SHA256).Hash.ToLower();
 scope='Actual x86 Native scheduling, C++ exception fault injection, endpoint/cache/lifecycle, installer APIs and isolated original-game instructions';
 live_multiplayer_tested=$false;external_relay_handshake_tested=$false;VPN_transition_tested=$false;
 packet_capacity_or_truncation_changed=$false;SafeSEH_preserved_and_extended=$true
}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath "$Output/summary.json" -Encoding utf8
