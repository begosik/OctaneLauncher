param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Layout,[Parameter(Mandatory=$true)][string]$Output)
# Real production launcher preparation plus real Windows PE32 loader controls.
# Local derived game fixtures never enter the uploaded evidence directory.
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Layout $Layout -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$Package=(Resolve-Path $Package).Path;$Layout=(Resolve-Path $Layout).Path
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected public helper boundaries'}
$Baseline=$Package;Invoke-Expression $t.Substring($a,$b-$a)
$env:APPDATA=Join-Path $Work 'Roaming';[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$cfg=Get-Content -LiteralPath $Layout -Raw|ConvertFrom-Json
$game=Join-Path $Work 'InstalledGame';$data=Join-Path $game 'Data';[IO.Directory]::CreateDirectory($data)|Out-Null
Copy-Item $env:ComSpec (Join-Path $data 'ra3_1.12.game')
[IO.File]::WriteAllText((Join-Path $game 'RA3_english_1.12.SkuDef'),"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
$runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
$privateData=Split-Path $runtime;[IO.Directory]::CreateDirectory($privateData)|Out-Null
$installedProxy=Join-Path $data 'XINPUT1_3.dll';$cachedProxy=Join-Path $privateData 'XINPUT1_3.dll'
$generator=Join-Path $PSScriptRoot 'xinput_loader155.py';$view=$null;$fixtures=$null
function StopOwnFixture(){
 Get-Process -ErrorAction SilentlyContinue|Where-Object {try{$_.Path-eq$runtime}catch{$false}}|ForEach-Object {Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue}
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
}
function RunLoader([string]$Path,[string]$Cwd){
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$Path;$start.WorkingDirectory=$Cwd;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $child=[Diagnostics.Process]::Start($start)
 if(!$child.WaitForExit(20000)){$child.Kill();throw 'Controlled loader fixture timed out'}
 return $child.ExitCode
}
try{
 & python $generator --sentinel $installedProxy
 Check ($LASTEXITCODE-eq0-and(Test-Path -LiteralPath $installedProxy)) 'Native ordinal2 sentinel DLL generated without compiler dependencies'
 Copy-Item -LiteralPath $installedProxy -Destination $cachedProxy
 $sentinelHash=(Get-FileHash -LiteralPath $installedProxy).Hash.ToLowerInvariant()
 $r=Extract $Package 'XInput production';[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n[Display]`r`nFPS=75`r`nFPSMode=Fixed`r`n")
 $view=Launch $r
 Until {
  try{$image=[IO.File]::ReadAllBytes($runtime);return $image.Length-gt0x713aa4-and([BitConverter]::ToString($image,0x713a9c,8))-eq'B8-8F-04-00-00-C2-08-00'}catch{return $false}
 } 'Production launcher writes detached XInput controller stub'|Out-Null
 Check ((Get-FileHash -LiteralPath $installedProxy).Hash.ToLowerInvariant()-eq$sentinelHash) 'Installed legacy DLL bytes are unchanged by production preparation'
 Check ((Get-FileHash -LiteralPath $cachedProxy).Hash.ToLowerInvariant()-eq$sentinelHash) 'Pre-existing private proxy file does not prevent import isolation'
 $source=Join-Path $Work 'prepared-runtime.game';Copy-Item -LiteralPath $runtime -Destination $source
 StopOwnFixture
 $fixtureRoot=Join-Path $Work 'XInput loader fixtures'
 & python $generator $source $fixtureRoot
 Check ($LASTEXITCODE-eq0) 'Actual prepared runtime retains17 imports and native no-controller stub'
 $fixtures=Get-Content -LiteralPath (Join-Path $fixtureRoot 'fixtures.json') -Raw|ConvertFrom-Json
 Check ($fixtures.retained_imports.Count-eq17) 'All17 non-XInput import descriptors retained in derived loader fixture'
 Check ($fixtures.retained_IAT_entries-eq474) 'Loader fixture covers every474 surviving imported function slot'
 $marker=Join-Path $fixtures.game_data_directory 'xinput-loaded.marker'
 Check (!(Test-Path -LiteralPath $marker)) 'Fresh loader-control working directory has no marker'
 $negative=RunLoader $fixtures.fixtures.negative.path $fixtures.game_data_directory
 Check ($negative-eq0) ('Negative control resolves all18 imports and calls native stub; exit='+$negative)
 Check (Test-Path -LiteralPath $marker) 'Negative control actually executes legacy-style XInput DllMain'
 $negativeMarkerHash=(Get-FileHash -LiteralPath $marker).Hash.ToLowerInvariant()
 Remove-Item -LiteralPath $marker
 $positive=RunLoader $fixtures.fixtures.positive.path $fixtures.game_data_directory
 Check ($positive-eq0) ('Protected fixture resolves17 imports and returns1167 with stdcall/stack/buffer intact; exit='+$positive)
 Check (!(Test-Path -LiteralPath $marker)) 'Detached game import does not execute XInput DllMain despite DLL in application and working directories'
 foreach($path in @((Join-Path $fixtures.game_data_directory 'XINPUT1_3.dll'),(Join-Path (Split-Path $fixtures.fixtures.positive.path) 'XINPUT1_3.dll'),(Join-Path (Split-Path $fixtures.fixtures.negative.path) 'XINPUT1_3.dll'))){
  Check ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-eq$fixtures.sentinel_sha256) 'Sentinel DLL remains byte-exact after both loader controls'
 }
 $loaderProof=[ordered]@{source_runtime_sha256=$fixtures.source_runtime_sha256;retained_imports=$fixtures.retained_imports;retained_import_descriptors_sha256=$fixtures.retained_import_descriptors_sha256;retained_IAT_entries=$fixtures.retained_IAT_entries;sentinel_sha256=$fixtures.sentinel_sha256;negative_exit=$negative;positive_exit=$positive;negative_DllMain_marker=$true;positive_DllMain_marker=$false;negative_marker_sha256=$negativeMarkerHash;fixture_hashes=@{negative=$fixtures.fixtures.negative.sha256;positive=$fixtures.fixtures.positive.sha256};scope=$fixtures.scope}
 $loaderProof|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Output 'loader-proof.json') -Encoding UTF8
}catch{$Failure=$_.Exception.Message;Write-Host ('XINPUT155_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 StopOwnFixture
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual signed launcher prepares isolated runtime. Derived PE32 loader fixtures retain17 imports/474IATs; legacy CRT andD3DX are inert export fixtures; original TLS/CRT activation and game entry are bypassed. Sentinel DLL_PROCESS_ATTACH negative and positive controls, native stub ABI/error/buffer, source files unchanged. No RA3 gameplay/GPU/network certification.'}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Output 'XINPUT_WINDOWS_155.json') -Encoding UTF8
}
if($Failure){exit 1}
