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
public static class FPS156Input {
 [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern uint GetPrivateProfileString(string section,string key,string fallback,System.Text.StringBuilder value,uint size,string file);
 [System.Runtime.InteropServices.DllImport("user32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,EntryPoint="EnumDisplaySettingsExW")] public static extern bool EnumDisplaySettingsEx(string device,int mode,System.IntPtr data,uint flags);
 public static string Saved(string key,string file){var value=new System.Text.StringBuilder(64);GetPrivateProfileString("Display",key,"",value,64,file);return value.ToString();}
 public static int Refresh(){var dm=System.Runtime.InteropServices.Marshal.AllocHGlobal(220);try{for(int i=0;i<220;i++)System.Runtime.InteropServices.Marshal.WriteByte(dm,i,0);System.Runtime.InteropServices.Marshal.WriteInt16(dm,68,220);if(!EnumDisplaySettingsEx(null,-1,dm,0))return 60;var fields=System.Runtime.InteropServices.Marshal.ReadInt32(dm,72);var hz=System.Runtime.InteropServices.Marshal.ReadInt32(dm,184);return (fields&0x400000)!=0&&hz>=30&&hz<=1000?hz:60;}finally{System.Runtime.InteropServices.Marshal.FreeHGlobal(dm);}}
}
'@
function SavedFPS(){return [FPS156Input]::Saved('FPS',(Join-Path $view.root 'settings.ini'))}
function SavedMode(){return [FPS156Input]::Saved('FPSMode',(Join-Path $view.root 'settings.ini'))}
function Pointer([uint32]$message,[int]$x,[int]$y,[int]$buttons=0){
 $rect=New-Object OctaneNativeTest+Rect;[OctaneNativeTest]::GetClientRect($view.w,[ref]$rect)|Out-Null
 $xx=[int]($x*($rect.R-$rect.L)/1060);$yy=[int]($y*($rect.B-$rect.T)/736)
 $xy=[IntPtr](($yy-shl16)-bor($xx-band65535));[OctaneNativeTest]::SendMessage($view.w,$message,[IntPtr]$buttons,$xy)|Out-Null
}
function SelectorKey([int]$key){[OctaneNativeTest]::SendMessage($view.w,0x100,[IntPtr]$key,[IntPtr]::Zero)|Out-Null}
function OpenSelector(){Pointer 0x201 949 200 1;Pointer 0x202 949 200 0}
function ChooseRow([int]$index){OpenSelector;$y=218+$index*27+13;Pointer 0x201 916 $y 1;Pointer 0x202 916 $y 0}
function ChooseFixed([int]$target){$index=[Array]::IndexOf([int[]]@(60,75,90,120,144,180,240),$target);if($index-lt0){throw 'Unknown fixed preset'};ChooseRow ($index+1);Check ((SavedFPS)-eq[string]$target-and(SavedMode)-eq'Fixed') ('Mouse selects and persists fixed '+$target)}
function FrameBuildCount(){return @(([IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log')))-split"`n"|Where-Object{$_.Contains('[BUILD] package=')}).Count}
function WaitRuntime([int]$target,[int]$vsync=0){
 Until {
  try{
   $bytes=[IO.File]::ReadAllBytes($runtime)
   $fpsAt=[int]$cfg.render_target_file_offset;$logAt=[int]$cfg.runtime_log_options_file_offset
   if($bytes.Length-le$logAt+2064){return $false}
   $bound=[Text.Encoding]::Unicode.GetString($bytes,$logAt+16,2048).Split([char]0)[0]
   return [BitConverter]::ToUInt32($bytes,$fpsAt)-eq$target-and[BitConverter]::ToUInt32($bytes,([int]$cfg.display_options.file_offset+12))-eq$vsync-and$bound-eq(Join-Path $view.root 'Logs')
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
function StartFixture([string]$name,[string]$setting="",[string]$mode=""){
 $r=Extract $Package $name
 [IO.File]::WriteAllText((Join-Path $r 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n[Display]`r`nFPS=$setting`r`nFPSMode=$mode`r`n[UserTest]`r`nKeep=yes`r`n")
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
function ImportNames([int]$at){
 $names=New-Object 'System.Collections.Generic.List[string]'
 for($i=0;$i-lt64;$i++){
  $d=$at+$i*20;if($d-lt0-or$d+20-gt$pe.Length){throw 'Import descriptor is outside the written runtime'}
  $allZero=$true;for($j=0;$j-lt20;$j++){if($pe[$d+$j]-ne0){$allZero=$false;break}}
  if($allZero){return ,($names.ToArray())}
  $nameRva=[BitConverter]::ToUInt32($pe,$d+12);if($nameRva-eq0){throw 'Non-null descriptor has no dependency name'}
  $off=RawVa ([long]$cfg.image_base+$nameRva) 1;$n=0
  while($n-lt128-and$off+$n-lt$pe.Length-and$pe[$off+$n]-ne0){$n++}
  if($n-eq0-or$n-ge128-or$off+$n-ge$pe.Length){throw 'Dependency name is not terminated'}
  $names.Add([Text.Encoding]::ASCII.GetString($pe,$off,$n))
 }
 throw 'Import table does not terminate within the bounded descriptor limit'
}
function Target([long]$va,[int]$opcode,[string]$why){$at=RawVa $va 5;Check ($pe[$at]-eq$opcode) ($why+' opcode');return $va+5+[BitConverter]::ToInt32($pe,$at+1)}
function ValidateImage([string]$label,[int]$target=60,[int]$vsync=0){
 $script:pe=[IO.File]::ReadAllBytes($runtime);$po=[BitConverter]::ToInt32($pe,60)
 Check ([Text.Encoding]::ASCII.GetString($pe,$po,4)-eq"PE`0`0") ($label+' runtime is a PE image')
 Check (([BitConverter]::ToUInt16($pe,$po+22)-band0x20)-ne0) ($label+' automatic 4GB flag retained')
 Check ([BitConverter]::ToUInt32($pe,$po+88)-eq[FPSArtifactChecksum]::Sum($pe,$po+88)) ($label+' PE checksum includes the final log binding')
 $st=$po+24+[BitConverter]::ToUInt16($pe,$po+20);$count=[BitConverter]::ToUInt16($pe,$po+6);$script:sections=@()
 for($i=0;$i-lt$count;$i++){$s=$st+$i*40;$script:sections+=@{name=[Text.Encoding]::ASCII.GetString($pe,$s,8).Trim([char]0);va=[long][BitConverter]::ToUInt32($pe,$s+12);raw=[long][BitConverter]::ToUInt32($pe,$s+20);bytes=[long][BitConverter]::ToUInt32($pe,$s+16)}}
 $fps=@($sections|Where-Object{$_.name.StartsWith('.fps')})
 Check (($fps.name-join',')-eq'.fpsrx,.fpsrw,.fpsbk') ($label+' exactly one RA3FPS 1.0.36 RX/RW/backup section set')
 Check (@($sections|Where-Object{$_.name-eq'.O132FPS'}).Count-eq0) ($label+' prior FPS logging section is absent')
 $opt=[int]$cfg.runtime_log_options_file_offset
 Check ([Text.Encoding]::ASCII.GetString($pe,$opt,8)-eq'R3LOG028') ($label+' runtime log options use the supplied RA3FPS 1.0.36 schema marker')
 Check ([BitConverter]::ToUInt32($pe,$opt+8)-eq1) ($label+' runtime log options schema is one')
 Check ([BitConverter]::ToUInt32($pe,$opt+12)-eq1) ($label+' existing RA3FPS 1.0.36 logger is enabled')
 $bound=[Text.Encoding]::Unicode.GetString($pe,$opt+16,2048).Split([char]0)[0]
 Check ($bound-eq(Join-Path $view.root 'Logs')) ($label+' wide runtime log directory is bound to this launcher Logs folder')
 $start=[int]$cfg.fps_payload_hash_start;$size=[int]$cfg.fps_payload_hash_bytes;$record=[int]$cfg.fps_payload_hash_record
 $hash=HashBytes $pe $start $size
 Check ((HexBytes $hash)-eq(HexBytes ([byte[]]$pe[$record..($record+31)]))) ($label+' payload integrity digest includes the runtime log binding')
 $ex=$cfg.exports
 Check ((ReadU32 ([long]$ex.lab_config))-eq1) ($label+' active RA3FPS 1.0.36 lab mode is one')
 $display=[int]$cfg.display_options.file_offset
 Check ([Text.Encoding]::ASCII.GetString($pe,$display,8)-eq'R3DSP128') ($label+' supplied display options magic retained')
 Check ([BitConverter]::ToUInt32($pe,$display+8)-eq1) ($label+' supplied display options schema one')
 Check ([BitConverter]::ToUInt32($pe,$display+12)-eq$vsync) ($label+' selected VSync flag matches the real runtime')
 $camera=[int]$cfg.camera_options.file_offset
 Check ($cfg.camera_options.magic-eq'R3CAM133'-and[int]$cfg.camera_options.schema-eq1-and[long]$cfg.camera_options.default_bits-eq1065353216) ($label+' provider camera option metadata retains its original default')
 Check ([Text.Encoding]::ASCII.GetString($pe,$camera,8)-eq'R3CAM133'-and[BitConverter]::ToUInt32($pe,$camera+8)-eq1) ($label+' provider camera option marker and schema are preserved')
 Check ([BitConverter]::ToUInt32($pe,$camera+12)-eq1065353216) ($label+' fixed and Auto FPS selection preserve provider camera speed 1.0')
 Check ((ReadU32 0xcb4098)-eq15-and(ReadU32 0xcb409c)-eq$target) ($label+' logic 15Hz and selected render FPS retained')
 $xi=$cfg.xinput_isolation
 Check ($null-ne$xi-and[long]$xi.thunk_va-eq0xb13a9c-and$xi.disabled_thunk_hex-eq'b88f040000c20800') ($label+' XInput transform metadata is independently bounded')
 $stubAt=RawVa 0xb13a9c 8
 Check ((HexBytes ([byte[]]$pe[$stubAt..($stubAt+7)]))-eq'b88f040000c20800') ($label+' XInputGetState uses the guarded stdcall disconnected stub')
 Check ($stubAt-eq[int]$xi.thunk_file_offset) ($label+' independently mapped XInput thunk offset matches the reviewed transform')
 $importRva=[BitConverter]::ToUInt32($pe,$po+128);$importSize=[BitConverter]::ToUInt32($pe,$po+132)
 $importAt=RawVa ([long]$cfg.image_base+$importRva) 20
 Check ($importRva-eq0x8a0f6c-and$importAt-eq[int]$xi.import_directory_file_offset-and$importSize-eq360-and$importSize-eq[int]$xi.disabled_size) ($label+' import directory retains its location and removes exactly one descriptor')
 $imports=ImportNames $importAt
 $approved=@('MSVCR80.dll','KERNEL32.dll','SHELL32.dll','SHLWAPI.dll','GDI32.dll','USER32.dll','ADVAPI32.dll','d3d9.dll','d3dx9_35.dll','DSOUND.dll','MSVCP80.dll','IMM32.dll','WS2_32.dll','NETAPI32.dll','USP10.dll','WINMM.dll','ole32.dll')
 Check (@($imports).Count-eq17-and($imports-join',')-ceq($approved-join',')) ($label+' all seventeen remaining imported dependencies retain their original order and names')
 Check (@($imports|Where-Object{$_-match'(?i)^xinput.*\.dll$'}).Count-eq0) ($label+' no legacy XInput DLL can be requested by the runtime import table')
 Check (($imports-join',')-ceq(@($xi.approved_remaining_imports)-join',')) ($label+' imported dependencies match the separately reviewed transform layout')
 Check ((HexBytes (HashBytes $pe $importAt $importSize))-eq$xi.disabled_import_table_sha256) ($label+' exact compacted import descriptor bytes match the independently reviewed transform')
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
 $neutral=[byte[]]$pe.Clone();[Array]::Copy([BitConverter]::GetBytes([uint32]60),0,$neutral,$renderAt,4);[Array]::Copy([BitConverter]::GetBytes([uint32]60),0,$neutral,$backupFps,4);[Array]::Clear($neutral,$opt+12,4+2048);[Array]::Clear($neutral,$display+12,4)
 $unbound=HashBytes $neutral $start $size;[Array]::Copy($unbound,0,$neutral,$record,32)
 [Array]::Copy([BitConverter]::GetBytes([FPSArtifactChecksum]::Sum($neutral,$po+88)),0,$neutral,$po+88,4)
 Check ((HexBytes (HashBytes $neutral))-eq$cfg.unbound_session_sha256) ($label+' entire runtime differs from the profile-derived 4GB image only by the approved FPS/log binding and fixed XInput isolation')
 $launchLog=[IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log'))
 Check ($launchLog.Contains('[BUILD] package='+$cfg.package_label)) ($label+' launch metadata identifies the authenticated package label')
 Check ($launchLog.Contains('[BUILD] '+$cfg.profile_log_field+'='+$cfg.profile_component_sha256)) ($label+' launch metadata records the exact supplied RPF fingerprint')
 [ordered]@{label=$label;runtime_sha256=(HexBytes (HashBytes $pe));unbound_sha256=(HexBytes (HashBytes $neutral));log_directory=$bound;target=$target;vsync=$vsync;sections=@($sections|ForEach-Object{$_.name})}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Output ($label+'-runtime.json')) -Encoding UTF8
 Copy-Item (Join-Path $view.root 'Logs\launcher.log') (Join-Path $Output ($label+'-launcher.log'))
}
try{
 Check ([int]$cfg.profile_component_edits-eq128-and[int]$cfg.profile_component_guards-eq235) 'The supplied 1.0.36 profile retains all 128 edits and 235 guards'
 Check (([int[]]$cfg.display_options.fixed_presets-join',')-eq'60,75,90,120,144,180,240') 'Exact supplied fixed presets retained'
 Check ([int]$cfg.display_options.default_flags-eq0-and[int]$cfg.target_fps_default-eq60) 'Default is fixed60 without VSync'
 Check ([int]$cfg.ui_selector.control_index-eq13) 'Selector retains the FPS feature position'
 $view=StartFixture 'FPS-selector';WaitRuntime 60
 [OctaneNativeTest]::ResizeClient($view.w,1060,736);Start-Sleep -Milliseconds 150
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'selector-closed-100.png'))|Write-Host
 $savedFPS=SavedFPS;$savedMode=SavedMode
 OpenSelector;[OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'selector-open-100.png'))|Write-Host
 SelectorKey 0x1b;Check ((SavedFPS)-eq$savedFPS-and(SavedMode)-eq$savedMode) 'Escape cancels without persisting a new choice'
 [OctaneNativeTest]::ResizeClient($view.w,848,589);OpenSelector
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'selector-open-scaled.png'))|Write-Host
 SelectorKey 0x1b;ChooseFixed 144;[OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'selector-closed-scaled.png'))|Write-Host
 [OctaneNativeTest]::ResizeClient($view.w,1060,736)
 ValidateImage 'default60' 60
 ChooseFixed 60
 SelectorKey 0x73;SelectorKey 0x23;SelectorKey 0x1b
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed') 'F4 opens the list and Escape cancels its End highlight'
 OpenSelector;Pointer 0x200 916 (218+2*27+13) 0;SelectorKey 0x28
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed') 'Open-list hover and arrow navigation do not prematurely persist'
 SelectorKey 0x1b
 OpenSelector;SelectorKey 0x23;SelectorKey 0x09
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed') 'Tab cancels provisional selection'
 Start-Sleep -Milliseconds 150;$builds=FrameBuildCount
 OpenSelector;Pointer 0x201 320 494 1;Pointer 0x202 320 494 0;Start-Sleep -Milliseconds 300
 Check ((FrameBuildCount)-eq$builds) 'Outside click closes the popup and is consumed before the launch button'
 foreach($target in @(60,75,90,120,144,180,240)){
  ChooseFixed $target
  Check ((Get-Content -LiteralPath (Join-Path $view.root 'settings.ini') -Raw)-match'Keep=yes') 'Selector persistence preserves unrelated settings'
  [OctaneNativeTest]::Click($view.w,320,494,1060,736);WaitRuntime $target 0;ValidateImage ('fixed'+$target) $target 0;EndLaunchFixture
 }
 OpenSelector;SelectorKey 0x1b
 SelectorKey 0x0d;SelectorKey 0x24;SelectorKey 0x23;SelectorKey 0x0d
 Check ((SavedFPS)-eq'240'-and(SavedMode)-eq'Fixed') 'Keyboard End commits fixed240'
 SelectorKey 0x20;SelectorKey 0x24;SelectorKey 0x0d
 Check ((SavedFPS)-eq'240'-and(SavedMode)-eq'VSync') 'Keyboard Home selects Auto while preserving the last fixed FPS'
 $auto=[FPS156Input]::Refresh()
 [OctaneNativeTest]::Click($view.w,320,494,1060,736);WaitRuntime $auto 1;ValidateImage 'auto-keyboard' $auto 1;EndLaunchFixture
 $savedRoot=$view.root;CloseMain $view;$view=$null
 $view=Launch $savedRoot;WaitRuntime $auto 1;ValidateImage 'auto-reopen' $auto 1
 Check ((SavedFPS)-eq'240'-and(SavedMode)-eq'VSync') 'Auto mode and last fixed value survive close/reopen'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'selector-auto-native.png'))|Write-Host
 ChooseFixed 75;[OctaneNativeTest]::Click($view.w,320,494,1060,736);WaitRuntime 75 0;ValidateImage 'fixed75-after-auto' 75 0;EndLaunchFixture
 CloseMain $view;$view=$null;$view=Launch $savedRoot;WaitRuntime 75 0;ValidateImage 'fixed75-reopen' 75 0
 ChooseRow 0;Check ((SavedMode)-eq'VSync'-and(SavedFPS)-eq'75') 'Mouse Auto selection preserves fixed75'
 [OctaneNativeTest]::Click($view.w,320,494,1060,736);WaitRuntime $auto 1;ValidateImage 'auto-mouse' $auto 1;EndLaunchFixture
 CloseMain $view;$view=$null
 foreach($custom in @(61,119)){
  $view=StartFixture ('legacy'+$custom) ([string]$custom) 'Fixed';WaitRuntime $custom 0;ValidateImage ('legacy'+$custom) $custom 0
  OpenSelector;SelectorKey 0x1b
  Check ((SavedFPS)-eq[string]$custom) 'Opening/cancelling preserves an existing non-preset FPS'
  OpenSelector;SelectorKey 0x23;SelectorKey 0x0d
  Check ((SavedFPS)-eq'240') 'Popup End reaches the eighth source choice without a legacy/custom row'
  CloseMain $view;$view=$null
 }
 foreach($case in @(@('below','59'),@('unlisted','121'),@('negative','-1'),@('malformed','75x'),@('overflow','9999999999999999'))){
  $view=StartFixture ('invalid-'+$case[0]) ([string]$case[1]) 'Fixed';WaitRuntime 60 0;ValidateImage ([string]$case[0]) 60 0;CloseMain $view;$view=$null
 }
}catch{$Failure=$_.Exception.Message;Write-Host ('FPS136_SELECTOR_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Real canvas popup mouse/keyboard cancellation, persistence, fixed/Auto selection and launch preparation are exercised. Actual final Windows launcher writes and binds the authenticated RA3FPS 1.0.36/8P runtime. PE flags, hooks, mode, directories and integrity digest validated. The runtime XInput import table and disconnected stub are checked at every target; actual DLL-loader proof is the separate XInput sentinel test. No RA3 gameplay, GPU execution, network lobby or online desync test.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'FPS_SELECTOR_WINDOWS_156.json') -Encoding UTF8
}
if($Failure){exit 1}
