param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Layout,[Parameter(Mandatory=$true)][string]$Output)
# Reads the actual game image written by the signed Windows launcher. This is
# artifact/configuration validation; it does not represent a match or GPU test.
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Layout $Layout -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$Package=(Resolve-Path $Package).Path;$Layout=(Resolve-Path $Layout).Path
$cfg=Get-Content -LiteralPath $Layout -Raw|ConvertFrom-Json
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected native helper boundaries'}
$Baseline=$Package;Invoke-Expression $t.Substring($a,$b-$a)
Add-Type -TypeDefinition @'
public static class E18ArtifactChecksum {
 public static uint Sum(byte[] bytes,int skip) {
  ulong sum=0;
  for(int at=0;at<bytes.Length;at+=2) {
   if(at<skip||at>=skip+4)sum+=(ulong)bytes[at]+(at+1<bytes.Length?((ulong)bytes[at+1]<<8):0);
   sum=(sum&65535)+(sum>>16);
  }
  sum=(sum&65535)+(sum>>16);sum=(sum&65535)+(sum>>16);
  return (uint)(sum+(ulong)bytes.Length);
 }
}
'@
$env:APPDATA=Join-Path $Work 'Roaming';[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$game=Join-Path $Work 'InstalledGame';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
Copy-Item $env:ComSpec (Join-Path $game 'Data\ra3_1.12.game')
[IO.File]::WriteAllText((Join-Path $game 'RA3_english_1.12.SkuDef'),"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
$runtime=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game';$view=$null
function StartFixture([string]$name){
 $r=Extract $Package $name
 [IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n")
 return Launch $r
}
function HashBytes([byte[]]$bytes,[int]$at=0,[int]$n=-1){if($n-lt0){$n=$bytes.Length};$alg=[Security.Cryptography.SHA256]::Create();try{return ,($alg.ComputeHash($bytes,$at,$n))}finally{$alg.Dispose()}}
function HexBytes([byte[]]$bytes){return ([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()}
function RawVa([long]$va,[int]$n=1){
 $rva=$va-[long]$cfg.image_base
 foreach($s in $sections){if($rva-ge$s.va-and$rva-$s.va+$n-le$s.bytes){return [int]($s.raw+$rva-$s.va)}}
 throw ('Unbacked game address '+$va)
}
function ReadU32([long]$va){return [BitConverter]::ToUInt32($pe,(RawVa $va 4))}
function Target([long]$va,[int]$opcode,[string]$why){$at=RawVa $va 5;Check ($pe[$at]-eq$opcode) ($why+' opcode');return $va+5+[BitConverter]::ToInt32($pe,$at+1)}
function ValidateImage([string]$label){
 $script:pe=[IO.File]::ReadAllBytes($runtime);$po=[BitConverter]::ToInt32($pe,60)
 Check ([Text.Encoding]::ASCII.GetString($pe,$po,4)-eq"PE`0`0") ($label+' runtime is a PE image')
 Check (([BitConverter]::ToUInt16($pe,$po+22)-band0x20)-ne0) ($label+' automatic 4GB flag retained')
 Check ([BitConverter]::ToUInt32($pe,$po+88)-eq[E18ArtifactChecksum]::Sum($pe,$po+88)) ($label+' PE checksum includes the final log binding')
 $st=$po+24+[BitConverter]::ToUInt16($pe,$po+20);$count=[BitConverter]::ToUInt16($pe,$po+6);$script:sections=@()
 for($i=0;$i-lt$count;$i++){$s=$st+$i*40;$script:sections+=@{name=[Text.Encoding]::ASCII.GetString($pe,$s,8).Trim([char]0);va=[long][BitConverter]::ToUInt32($pe,$s+12);raw=[long][BitConverter]::ToUInt32($pe,$s+20);bytes=[long][BitConverter]::ToUInt32($pe,$s+16)}}
 $fps=@($sections|Where-Object{$_.name.StartsWith('.fps')})
 Check (($fps.name-join',')-eq'.fpsrx,.fpsrw,.fpsbk') ($label+' exactly one E18 RX/RW/backup section set')
 Check (@($sections|Where-Object{$_.name-eq'.O132FPS'}).Count-eq0) ($label+' prior FPS logging section is absent')
 $opt=[int]$cfg.runtime_log_options_file_offset
 Check ([Text.Encoding]::ASCII.GetString($pe,$opt,8)-eq'R3LOG028') ($label+' runtime log options use the supplied E18 schema marker')
 Check ([BitConverter]::ToUInt32($pe,$opt+8)-eq1) ($label+' runtime log options schema is one')
 Check ([BitConverter]::ToUInt32($pe,$opt+12)-eq1) ($label+' existing E18 logger is enabled')
 $bound=[Text.Encoding]::Unicode.GetString($pe,$opt+16,2048).Split([char]0)[0]
 Check ($bound-eq(Join-Path $view.root 'Logs')) ($label+' wide runtime log directory is bound to this launcher Logs folder')
 $start=[int]$cfg.fps_payload_hash_start;$size=[int]$cfg.fps_payload_hash_bytes;$record=[int]$cfg.fps_payload_hash_record
 $hash=HashBytes $pe $start $size
 Check ((HexBytes $hash)-eq(HexBytes ([byte[]]$pe[$record..($record+31)]))) ($label+' payload integrity digest includes the runtime log binding')
 $ex=$cfg.exports
 Check ((ReadU32 ([long]$ex.lab_config))-eq1) ($label+' active E18 lab mode is one')
 Check ((ReadU32 0xcb4098)-eq15-and(ReadU32 0xcb409c)-eq60) ($label+' logic 15Hz and render 60Hz configuration retained')
 Check ((HexBytes ([byte[]]$pe[(RawVa 0x52fed1 7)..((RawVa 0x52fed1 7)+6)]))-eq'e90bac83009090') ($label+' original 8P checksum wrapper dispatch is retained')
 Check ((Target 0xd6acaf 0xe9 '8P wrapper tail')-eq[long]$ex.LabCompareObserver) ($label+' 8P wrapper tail executes the E18 checksum observer')
 Check ((Target 0x4d7bc0 0xe9 'GPU publisher')-eq[long]$ex.GPUTimePublish) ($label+' GPU publisher points to E18')
 Check ((Target 0x70c0f4 0xe8 'GPU reader')-eq[long]$ex.GPUTimeRead) ($label+' GPU reader points to E18')
 foreach($va in @(0x4d7bc8,0x6ffd90,0x6ffd96)){Check ((ReadU32 $va)-eq[long]$ex.gpu_clock_ms) ($label+' GPU clock operand points to the shared E18 sample at '+$va)}
 # Revert the documented session logging options and derived integrity/checksum
 # values to compare the whole
 # image with the independently built signed-target-derived 4GB session hash.
 $neutral=[byte[]]$pe.Clone();[Array]::Clear($neutral,$opt+12,4+2048)
 $unbound=HashBytes $neutral $start $size;[Array]::Copy($unbound,0,$neutral,$record,32)
 [Array]::Copy([BitConverter]::GetBytes([E18ArtifactChecksum]::Sum($neutral,$po+88)),0,$neutral,$po+88,4)
 Check ((HexBytes (HashBytes $neutral))-eq$cfg.unbound_session_sha256) ($label+' entire runtime differs from the source-built 4GB image only by the approved log binding')
 [ordered]@{label=$label;runtime_sha256=(HexBytes (HashBytes $pe));unbound_sha256=(HexBytes (HashBytes $neutral));log_directory=$bound;sections=@($sections|ForEach-Object{$_.name})}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Output ($label+'-runtime.json')) -Encoding UTF8
 Copy-Item (Join-Path $view.root 'Logs\launcher.log') (Join-Path $Output ($label+'-launcher.log'))
}
try{
 $view=StartFixture 'E18-first';ValidateImage 'first';$firstLogs=Join-Path $view.root 'Logs';CloseMain $view;$view=$null
 $view=StartFixture 'E18-second';ValidateImage 'second';Check ((Join-Path $view.root 'Logs')-ne$firstLogs) 'The second fixture uses a different launcher Logs directory'
 CloseMain $view;$view=$null
}catch{$Failure=$_.Exception.Message;Write-Host ('E18_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual final Windows launcher writes and binds the authenticated E18/8P runtime. PE flags, hooks, mode, directories and integrity digest validated. No RA3 gameplay, GPU execution, network lobby or online desync test.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'E18_WINDOWS_143.json') -Encoding UTF8
}
if($Failure){exit 1}
