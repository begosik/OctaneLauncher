param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path
$Output=[IO.Path]::GetFullPath($Output)
$work=Join-Path $env:RUNNER_TEMP ('octane-position-audit-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work)|Out-Null
[IO.Directory]::CreateDirectory($Output)|Out-Null
$env:LOCALAPPDATA=Join-Path $work 'Local'
$env:APPDATA=Join-Path $work 'Roaming'
[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null
[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$game=Join-Path $work 'InstalledGame'
[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $game 'Data\ra3_1.12.game')
[IO.File]::WriteAllText((Join-Path $game 'RA3_english_1.12.SkuDef'),"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
Expand-Archive -LiteralPath $Package -DestinationPath (Join-Path $work 'Public')
$root=Join-Path $work 'Public\RA3Octane'
[IO.File]::WriteAllText((Join-Path $root 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n[Display]`r`nFPS=60`r`n")
$runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
$launcher=$null
try{
 $launcher=Start-Process -FilePath (Join-Path $root 'RA3Octane.exe') -WorkingDirectory $root -PassThru
 $deadline=[datetime]::UtcNow.AddSeconds(70)
 while(!(Test-Path -LiteralPath $runtime)-and[datetime]::UtcNow-lt$deadline){
  if($launcher.HasExited){throw 'Public launcher exited before preparing its runtime'}
  Start-Sleep -Milliseconds 400
 }
 if(!(Test-Path -LiteralPath $runtime)){throw 'No runtime image prepared within the bounded fixture'}
 Start-Sleep -Seconds 3
 # The image remains runner-local and must not be included in uploaded evidence.
 $copy=Join-Path $work 'runtime-for-analysis.game'
 Copy-Item -LiteralPath $runtime -Destination $copy
 Write-Host ('Prepared public runtime SHA256 '+(Get-FileHash -LiteralPath $copy).Hash)
 & python .github/scripts/position_bounds_audit.py $copy $Output
 if($LASTEXITCODE-ne0){throw 'Read-only position disassembly failed'}
 & python -m pip install --disable-pip-version-check unicorn==2.1.4
 if($LASTEXITCODE-ne0){throw 'Pinned x86 emulator dependency unavailable'}
 & python .github/scripts/position_bounds_probe.py $copy $Output
 if($LASTEXITCODE-ne0){throw 'Original coordinate guard probe failed'}
}finally{
 if($launcher-and!$launcher.HasExited){
  $null=$launcher.CloseMainWindow()
  if(!$launcher.WaitForExit(10000)){Stop-Process -Id $launcher.Id -Force -ErrorAction SilentlyContinue}
 }
 Get-Process -ErrorAction SilentlyContinue|Where-Object {try{$_.Path-and$_.Path.StartsWith($work,[StringComparison]::OrdinalIgnoreCase)}catch{$false}}|Stop-Process -Force -ErrorAction SilentlyContinue
 # No installed RA3 game is available or launched. This is not a gameplay test.
}
