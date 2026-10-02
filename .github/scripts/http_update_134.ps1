param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition -eq 'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Baseline $Baseline -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop'
# Reuse only the public native-window helper definitions, not the local staging tests.
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected native helper template'}
Invoke-Expression $t.Substring($a,$b-$a)
try {
 $reference=Extract $Package 'reference only';$r=Extract $Baseline 'HTTP update 132 to 134'
 Check ((Get-Item (Join-Path $r 'RA3Octane.exe')).VersionInfo.FileVersion-eq'1.2.32.0') 'Real signed 1.2.32 is the starting launcher'
 $settings="[Preserved]`r`nValue=DoNotChange`r`n";[IO.File]::WriteAllText((Join-Path $r 'settings.ini'),$settings)
 [IO.File]::WriteAllText((Join-Path $r 'user-file.txt'),'preserve user file')
 [IO.Directory]::CreateDirectory((Join-Path $r 'Logs'))|Out-Null
 [IO.File]::WriteAllText((Join-Path $r 'Logs\user-note.txt'),'preserve unrelated log')
 Check (!(Test-Path (Join-Path $r '.updates'))) 'No update is prestaged or copied into the installation'
 $v=Launch $r;Start-Sleep -Seconds 2
 $deadline=[datetime]::UtcNow.AddSeconds(100);$dialog=[IntPtr]::Zero
 do {
  [OctaneNativeTest]::Click($v.w,550,702,1060,736)
  Start-Sleep -Seconds 2
  $dialog=[OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update')
 } while($dialog-eq[IntPtr]::Zero-and[datetime]::UtcNow-lt$deadline)
 Check ($dialog-ne[IntPtr]::Zero) 'The real online signed-manifest check offers Install Update'
 [OctaneNativeTest]::Screenshot($dialog,(Join-Path $Output 'http-update-confirmation.png'))|Write-Host
 [OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]6,[IntPtr]::Zero)|Out-Null
 Check ($v.p.WaitForExit(120000)) 'Confirmed HTTP update closes the old launcher without manual staging'
 $new=Current $r
 Check (SameRuntime $r $reference) 'WinHTTP download and signed installation produce the byte-exact published 1.2.34 files'
 Check ((Get-Item (Join-Path $r 'RA3Octane.exe')).VersionInfo.FileVersion-eq'1.2.34.0') 'The restarted executable has embedded version 1.2.34.0'
 Check ([OctaneNativeTest]::Text($new.w)-eq'RA3 // OCTANE 1.2.34') 'The new launcher restarts automatically'
 Until {!(Test-Path (Join-Path $r '.updates'))} 'completed HTTP update cleanup' 40|Out-Null
 Check (!(Test-Path (Join-Path $r '.updates'))) 'The completed HTTP update leaves no updater or backup debris'
 Check ([IO.File]::ReadAllText((Join-Path $r 'settings.ini')).Contains('Value=DoNotChange')) 'Existing settings are preserved'
 Check ([IO.File]::ReadAllText((Join-Path $r 'user-file.txt'))-eq'preserve user file') 'Unrelated user files are preserved'
 Check ([IO.File]::ReadAllText((Join-Path $r 'Logs\user-note.txt'))-eq'preserve unrelated log') 'Unrelated log data is preserved'
 [OctaneNativeTest]::Screenshot($new.w,(Join-Path $Output 'http-updated-launcher.png'))|Write-Host
 CloseMain $new;$again=Launch $r
 Check (!(Test-Path (Join-Path $r '.updates'))) 'A subsequent normal launch does not recreate update debris'
 CloseMain $again
 Copy-Item -LiteralPath (Join-Path $r 'Logs\launcher.log') -Destination $Output
} catch {$Failure=$_.Exception.Message;Write-Host ('HTTP_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace
 if($r-and(Test-Path (Join-Path $r 'Logs\launcher.log'))){Copy-Item -LiteralPath (Join-Path $r 'Logs\launcher.log') -Destination $Output -Force}
} finally {
 Get-Process -Name RA3Octane,RA3OctaneUpdater -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 $result=[ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());source_version='1.2.32';target_version='1.2.34';package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();http_download_tested=$true;manual_staging=$false;ra3_or_multiplayer_tested=$false}
 $json=$result|ConvertTo-Json -Depth 8;$json|Set-Content -LiteralPath (Join-Path $Output 'HTTP_UPDATE_134.json') -Encoding UTF8;Write-Host $json
}
if($Failure){exit 1}
