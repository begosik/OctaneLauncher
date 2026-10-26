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
public static class FPSArtifactChecksum {
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
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class FPS149Input {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetPrivateProfileString(string section,string key,string fallback,StringBuilder value,uint size,string file);
 public static string Saved(string file){var value=new StringBuilder(64);GetPrivateProfileString("Display","FPS","",value,64,file);return value.ToString();}
}
'@
function SavedFPS(){return [FPS149Input]::Saved((Join-Path $view.root 'settings.ini'))}
function Pointer([uint32]$message,[int]$x,[int]$y,[int]$buttons=0){
 $rect=New-Object OctaneNativeTest+Rect;[OctaneNativeTest]::GetClientRect($view.w,[ref]$rect)|Out-Null
 $xx=[int]($x*($rect.R-$rect.L)/1060);$yy=[int]($y*($rect.B-$rect.T)/736)
 $xy=[IntPtr](($yy-shl16)-bor($xx-band65535));[OctaneNativeTest]::SendMessage($view.w,$message,[IntPtr]$buttons,$xy)|Out-Null
}
function FPSKey([int]$key,[int]$expected,[string]$why){
 [OctaneNativeTest]::SendMessage($view.w,0x100,[IntPtr]$key,[IntPtr]::Zero)|Out-Null
 Check ((SavedFPS)-eq[string]$expected) $why
}
function FPSClick([int]$x){Pointer 0x201 $x 196 1;Pointer 0x202 $x 196 0}
function ClickThumb([int]$fps){
 $rect=New-Object OctaneNativeTest+Rect;[OctaneNativeTest]::GetClientRect($view.w,[ref]$rect)|Out-Null
 $left=[int][Math]::Floor(894*($rect.R-$rect.L)/1060);$right=[int][Math]::Floor(1004*($rect.R-$rect.L)/1060)
 $x=$left+[int][Math]::Floor((($fps-60)*($right-$left)+30)/60);$y=[int][Math]::Floor(196*($rect.B-$rect.T)/736)
 $xy=[IntPtr](($y-shl16)-bor$x)
 [OctaneNativeTest]::SendMessage($view.w,0x201,[IntPtr]1,$xy)|Out-Null
 [OctaneNativeTest]::SendMessage($view.w,0x202,[IntPtr]::Zero,$xy)|Out-Null
}
function WaitRuntime([int]$target){
 Until {
  try{
   $bytes=[IO.File]::ReadAllBytes($runtime)
   $fpsAt=[int]$cfg.render_target_file_offset;$logAt=[int]$cfg.runtime_log_options_file_offset
   if($bytes.Length-le$logAt+2064){return $false}
   $bound=[Text.Encoding]::Unicode.GetString($bytes,$logAt+16,2048).Split([char]0)[0]
   return [BitConverter]::ToUInt32($bytes,$fpsAt)-eq$target-and$bound-eq(Join-Path $view.root 'Logs')
  }catch{return $false}
 } ('Runtime bound to selected '+$target+' FPS')|Out-Null
}
function EndLaunchFixture(){
 # Only this fixture's signed runtime child may be stopped; no installed game
 # or other process is touched. The fixture does not certify GPU/game startup.
 Get-Process -ErrorAction SilentlyContinue|Where-Object {try{$_.Path-eq$runtime}catch{$false}}|ForEach-Object {Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue}
 for($i=0;$i-lt20;$i++){
  $dialog=[OctaneNativeTest]::Title($view.p.Id,'RA3 // OCTANE')
  if($dialog-ne[IntPtr]::Zero){[OctaneNativeTest]::PostMessage($dialog,0x111,[IntPtr]1,[IntPtr]::Zero)|Out-Null;Start-Sleep -Milliseconds 150}
  else{Start-Sleep -Milliseconds 100}
 }
}
function StartFixture([string]$name,[string]$setting=""){
 $r=Extract $Package $name
 [IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n[Display]`r`nFPS=$setting`r`n[UserTest]`r`nKeep=yes`r`n")
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
function ValidateImage([string]$label,[int]$target=60){
 $script:pe=[IO.File]::ReadAllBytes($runtime);$po=[BitConverter]::ToInt32($pe,60)
 Check ([Text.Encoding]::ASCII.GetString($pe,$po,4)-eq"PE`0`0") ($label+' runtime is a PE image')
 Check (([BitConverter]::ToUInt16($pe,$po+22)-band0x20)-ne0) ($label+' automatic 4GB flag retained')
 Check ([BitConverter]::ToUInt32($pe,$po+88)-eq[FPSArtifactChecksum]::Sum($pe,$po+88)) ($label+' PE checksum includes the final log binding')
 $st=$po+24+[BitConverter]::ToUInt16($pe,$po+20);$count=[BitConverter]::ToUInt16($pe,$po+6);$script:sections=@()
 for($i=0;$i-lt$count;$i++){$s=$st+$i*40;$script:sections+=@{name=[Text.Encoding]::ASCII.GetString($pe,$s,8).Trim([char]0);va=[long][BitConverter]::ToUInt32($pe,$s+12);raw=[long][BitConverter]::ToUInt32($pe,$s+20);bytes=[long][BitConverter]::ToUInt32($pe,$s+16)}}
 $fps=@($sections|Where-Object{$_.name.StartsWith('.fps')})
 Check (($fps.name-join',')-eq'.fpsrx,.fpsrw,.fpsbk') ($label+' exactly one RA3FPS 1.0.22 RX/RW/backup section set')
 Check (@($sections|Where-Object{$_.name-eq'.O132FPS'}).Count-eq0) ($label+' prior FPS logging section is absent')
 $opt=[int]$cfg.runtime_log_options_file_offset
 Check ([Text.Encoding]::ASCII.GetString($pe,$opt,8)-eq'R3LOG028') ($label+' runtime log options use the supplied RA3FPS 1.0.22 schema marker')
 Check ([BitConverter]::ToUInt32($pe,$opt+8)-eq1) ($label+' runtime log options schema is one')
 Check ([BitConverter]::ToUInt32($pe,$opt+12)-eq1) ($label+' existing RA3FPS 1.0.22 logger is enabled')
 $bound=[Text.Encoding]::Unicode.GetString($pe,$opt+16,2048).Split([char]0)[0]
 Check ($bound-eq(Join-Path $view.root 'Logs')) ($label+' wide runtime log directory is bound to this launcher Logs folder')
 $start=[int]$cfg.fps_payload_hash_start;$size=[int]$cfg.fps_payload_hash_bytes;$record=[int]$cfg.fps_payload_hash_record
 $hash=HashBytes $pe $start $size
 Check ((HexBytes $hash)-eq(HexBytes ([byte[]]$pe[$record..($record+31)]))) ($label+' payload integrity digest includes the runtime log binding')
 $ex=$cfg.exports
 Check ((ReadU32 ([long]$ex.lab_config))-eq1) ($label+' active RA3FPS 1.0.22 lab mode is one')
 Check ((ReadU32 0xcb4098)-eq15-and(ReadU32 0xcb409c)-eq$target) ($label+' logic 15Hz and selected render FPS retained')
 Check ((HexBytes ([byte[]]$pe[(RawVa 0x52fed1 7)..((RawVa 0x52fed1 7)+6)]))-eq'e90bac83009090') ($label+' original 8P checksum wrapper dispatch is retained')
 $edits=@($cfg.patched_instruction_checks)
 Check ($edits.Count-eq[int]$cfg.profile_component_edits) ($label+' validation covers every supplied active profile edit')
 foreach($edit in $edits){
  $at=RawVa ([long]$edit.va) ([int]($edit.bytes.Length/2));$n=[int]($edit.bytes.Length/2)
  $expectedBytes=$edit.bytes;if([long]$edit.va-eq0xcb409c){$expectedBytes=HexBytes ([BitConverter]::GetBytes([uint32]$target))}
  Check ((HexBytes ([byte[]]$pe[$at..($at+$n-1)]))-eq$expectedBytes) ($label+' final patched instructions match '+$edit.name)
 }
 foreach($edit in $cfg.native_instruction_checks){$at=RawVa ([long]$edit.va) ([int]($edit.bytes.Length/2));$n=[int]($edit.bytes.Length/2);Check ((HexBytes ([byte[]]$pe[$at..($at+$n-1)]))-eq$edit.bytes) ($label+' native instructions match '+$edit.name)}
 $ascii=[Text.Encoding]::ASCII.GetString($pe)
 foreach($stem in $cfg.runtime_log_stems){Check ($ascii.Contains($stem)) ($label+' payload retains its actual supplied logger stem '+$stem)}
 # Revert the documented session logging options and derived integrity/checksum
 # values to compare the whole
 # image with the independently built signed-target-derived 4GB session hash.
 # Find the actual rollback record independently; a selected frame rate must
 # match both the native instruction and the official remove guard.
 $backup=@($sections|Where-Object{$_.name-eq'.fpsbk'})[0];$b=[int]$backup.raw
 $countEdits=[BitConverter]::ToUInt32($pe,$b+16);$headers=[BitConverter]::ToUInt32($pe,$b+12)
 $at=$b+128+$headers;$renderAt=RawVa 0xcb409c 4;$found=0;$backupFps=0
 for($i=0;$i-lt$countEdits;$i++){
  $off=[BitConverter]::ToUInt32($pe,$at);$len=[BitConverter]::ToUInt32($pe,$at+4);$at+=8
  if($off-eq$renderAt){Check ($len-eq4) ($label+' render rollback record is exactly one DWORD');Check ([BitConverter]::ToUInt32($pe,$at)-eq30) ($label+' render rollback original value remains vanilla30');$backupFps=$at+$len;Check ([BitConverter]::ToUInt32($pe,$backupFps)-eq$target) ($label+' rollback guard matches selected FPS');$found++}
  $at+=2*$len
 }
 Check ($found-eq1) ($label+' exactly one render FPS rollback record exists')
 Check ($renderAt-eq[int]$cfg.render_target_file_offset-and$backupFps-eq[int]$cfg.fpsbk_target_fps_file_offset) ($label+' independent native/rollback offsets match reviewed layout')
 $neutral=[byte[]]$pe.Clone();[Array]::Copy([BitConverter]::GetBytes([uint32]60),0,$neutral,$renderAt,4);[Array]::Copy([BitConverter]::GetBytes([uint32]60),0,$neutral,$backupFps,4);[Array]::Clear($neutral,$opt+12,4+2048)
 $unbound=HashBytes $neutral $start $size;[Array]::Copy($unbound,0,$neutral,$record,32)
 [Array]::Copy([BitConverter]::GetBytes([FPSArtifactChecksum]::Sum($neutral,$po+88)),0,$neutral,$po+88,4)
 Check ((HexBytes (HashBytes $neutral))-eq$cfg.unbound_session_sha256) ($label+' entire runtime differs from the profile-derived 4GB image only by the approved log binding')
 $launchLog=[IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log'))
 Check ($launchLog.Contains('[BUILD] package='+$cfg.package_label)) ($label+' launch metadata identifies the authenticated package label')
 Check ($launchLog.Contains('[BUILD] '+$cfg.profile_log_field+'='+$cfg.profile_component_sha256)) ($label+' launch metadata records the exact supplied RPF fingerprint')
 [ordered]@{label=$label;runtime_sha256=(HexBytes (HashBytes $pe));unbound_sha256=(HexBytes (HashBytes $neutral));log_directory=$bound;sections=@($sections|ForEach-Object{$_.name})}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Output ($label+'-runtime.json')) -Encoding UTF8
 Copy-Item (Join-Path $view.root 'Logs\launcher.log') (Join-Path $Output ($label+'-launcher.log'))
}
try{
 Check ([int]$cfg.target_fps_min-eq60-and[int]$cfg.target_fps_max-eq120-and[int]$cfg.target_fps_default-eq60) 'Supplied FPS122 supported range is60 through120 with default60'
 $view=StartFixture 'FPS-default';WaitRuntime 60;ValidateImage 'default60' 60
 $initialRuntime=(Get-FileHash $runtime).Hash
 FPSClick 1008;Check ((SavedFPS)-eq'120') 'Mouse selects and persists maximum120'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'slider-120-native.png'))|Write-Host
 FPSKey 0x27 120 'Right at maximum remains120'
 FPSKey 0x24 60 'Home selects60'
 FPSKey 0x25 60 'Left at minimum remains60'
 FPSKey 0x21 65 'PageUp advances by5'
 FPSKey 0x27 66 'Right advances by1'
 FPSKey 0x26 67 'Up advances by1'
 FPSKey 0x22 62 'PageDown decreases by5'
 FPSKey 0x28 61 'Down decreases by1'
 FPSKey 0x23 120 'End selects120'
 FPSKey 0x25 119 'Left selects integer119'
 Pointer 0x201 950 196 1;Pointer 0x200 1040 196 1;Pointer 0x202 1040 196 0
 Check ((SavedFPS)-eq'120') 'Captured drag beyond right endpoint clamps120'
 Pointer 0x201 950 196 1;Pointer 0x200 850 196 1;Pointer 0x202 850 196 0
 Check ((SavedFPS)-eq'60') 'Captured drag beyond left endpoint clamps60'
 FPSKey 0x0d 60 'Enter while slider focused does not change FPS'
 FPSKey 0x20 60 'Space while slider focused does not change FPS'
 FPSKey 0x23 120 'Slider remains responsive after Enter and Space'
 [OctaneNativeTest]::ResizeClient($view.w,848,589)
 FPSClick 890;Check ((SavedFPS)-eq'60') 'Scaled-window minimum hit region works'
 FPSClick 1008;Check ((SavedFPS)-eq'120') 'Scaled-window maximum hit region works'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'slider-120-scaled-native.png'))|Write-Host
 foreach($size in @(@(1325,920),@(1590,1104))){
  [OctaneNativeTest]::ResizeClient($view.w,$size[0],$size[1])
  FPSKey 0x24 60 'Home at enlarged window'
  FPSKey 0x27 61 'Integer61 at enlarged window'
  ClickThumb 61;Check ((SavedFPS)-eq'61') ('Clicking visible61 thumb preserves value at width'+$size[0])
  FPSKey 0x24 60 'Home before fractional-scale75'
  FPSKey 0x21 65 'Step65 at enlarged window'
  FPSKey 0x21 70 'Step70 at enlarged window'
  FPSKey 0x21 75 'Step75 at enlarged window'
  ClickThumb 75;Check ((SavedFPS)-eq'75') ('Clicking visible75 thumb preserves value at width'+$size[0])
 }
 [OctaneNativeTest]::ResizeClient($view.w,848,589)
 FPSKey 0x24 60 'Return slider to60 before applying pending value'
 FPSKey 0x21 65 'PageUp65 before launch'
 FPSKey 0x21 70 'PageUp70 before launch'
 FPSKey 0x21 75 'PageUp75 before launch'
 Check ((Get-FileHash $runtime).Hash-eq$initialRuntime) 'Changing slider leaves the prepared file unchanged until launch'
 Check ((Get-Content -LiteralPath (Join-Path $view.root 'settings.ini') -Raw)-match'Keep=yes') 'FPS persistence preserves unrelated settings'
 # Exercise the real launch action: prepare_launch must rewrite the signed
 # runtime with75 before any game process can execute.
 [OctaneNativeTest]::Click($view.w,320,494,1060,736)
 WaitRuntime 75;ValidateImage 'launch75' 75;EndLaunchFixture
 $savedRoot=$view.root;CloseMain $view;$view=$null
 $view=Launch $savedRoot;WaitRuntime 75;ValidateImage 'reopen75' 75
 Check ((SavedFPS)-eq'75') 'Selected75 survives launcher close/reopen'
 FPSClick 1008;CloseMain $view;$view=$null
 $view=Launch $savedRoot;WaitRuntime 120;ValidateImage 'reopen120' 120
 Check ((SavedFPS)-eq'120') 'Selected120 survives launcher close/reopen'
 CloseMain $view;$view=$null
 foreach($case in @(@('integer61','61',61),@('integer119','119',119),@('below','59',60),@('above','121',60),@('negative','-1',60),@('malformed','75x',60),@('overflow','9999999999999999',60))){
  $view=StartFixture ('FPS-'+$case[0]) ([string]$case[1]);WaitRuntime ([int]$case[2]);ValidateImage ([string]$case[0]) ([int]$case[2]);CloseMain $view;$view=$null
 }
}catch{$Failure=$_.Exception.Message;Write-Host ('FPS1022_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Real canvas mouse/keyboard and selected-FPS persistence/launch preparation are exercised. Actual final Windows launcher writes and binds the authenticated RA3FPS 1.0.22/8P runtime. PE flags, hooks, mode, directories and integrity digest validated. No RA3 gameplay, GPU execution, network lobby or online desync test.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'FPS_SLIDER_WINDOWS_149.json') -Encoding UTF8
}
if($Failure){exit 1}
