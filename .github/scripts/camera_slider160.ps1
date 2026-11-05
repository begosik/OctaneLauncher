param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Layout,[Parameter(Mandatory=$true)][string]$Output)
# Real signed Windows launcher, camera input and prepared-image bytes. The
# derived game startup fixtures do not certify RA3 gameplay or GPU performance.
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Layout $Layout -Output $Output;exit $LASTEXITCODE}
$Package=(Resolve-Path $Package).Path;$Layout=(Resolve-Path $Layout).Path
$camera160ScriptDirectory=$PSScriptRoot
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fps_slider160.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry{`n Check")
if($a-lt0-or$b-le$a){throw 'Unexpected FPS validation helper boundaries'}
$camera160Helpers=$t.Substring($a,$b-$a).Replace('$PSScriptRoot','$camera160ScriptDirectory')
Invoke-Expression $camera160Helpers
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class Camera160Input {
 [StructLayout(LayoutKind.Sequential)] public struct Point {public int X,Y;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetPrivateProfileString(string section,string key,string fallback,StringBuilder value,uint size,string file);
 [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr w,ref Point p);
 [StructLayout(LayoutKind.Sequential)] public struct CommonControls {public uint Size,Classes;}
 [DllImport("comctl32.dll")] public static extern bool InitCommonControlsEx(ref CommonControls value);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr CreateWindowEx(uint ex,string cls,string title,uint style,int x,int y,int width,int height,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr data);
 [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr window);
 [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr window);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr window,uint message,IntPtr w,IntPtr l);
 static int Position(IntPtr slider){return SendMessage(slider,0x400,IntPtr.Zero,IntPtr.Zero).ToInt32();}
 static void Reset(IntPtr slider){SendMessage(slider,0x405,new IntPtr(1),new IntPtr(10));}
 static void Wheel(IntPtr slider,int delta){SendMessage(slider,0x20a,new IntPtr(delta<<16),IntPtr.Zero);}
 public static int[] NativeWheelProbe(){
  var controls=new CommonControls{Size=8,Classes=4};if(!InitCommonControlsEx(ref controls))throw new Exception("Native common-controls initialization failed");
  IntPtr host=CreateWindowEx(0,"STATIC","Octane native trackbar parity",0x90000000,-10000,-10000,300,100,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
  if(host==IntPtr.Zero)throw new Exception("Native trackbar host creation failed");
  try{
   IntPtr slider=CreateWindowEx(0,"msctls_trackbar32","",0x50000001,5,5,280,35,host,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
   if(slider==IntPtr.Zero)throw new Exception("Native trackbar creation failed");
   SendMessage(slider,0x406,new IntPtr(1),new IntPtr((30<<16)|5));SetFocus(slider);
   int min=SendMessage(slider,0x401,IntPtr.Zero,IntPtr.Zero).ToInt32(),max=SendMessage(slider,0x402,IntPtr.Zero,IntPtr.Zero).ToInt32();
   Reset(slider);int start=Position(slider);Wheel(slider,120);int plus=Position(slider);
   Reset(slider);Wheel(slider,-120);int minus=Position(slider);
   Reset(slider);Wheel(slider,60);int half=Position(slider);Wheel(slider,60);int full=Position(slider);
   return new int[]{min,max,start,plus,minus,half,full};
  }finally{DestroyWindow(host);}
 }
 public static string Saved(string file){var value=new StringBuilder(64);GetPrivateProfileString("Camera","SpeedTenths","",value,64,file);return value.ToString();}
}
'@
$cameraMutex=$null;$cameraMutexTaken=$false
function SavedCamera(){return [Camera160Input]::Saved((Join-Path $view.root 'settings.ini'))}
function CameraX([int]$tenths){return [int][Math]::Round(728.0+($tenths-5)*280.0/25.0)}
function ChooseCamera([int]$tenths){$x=CameraX $tenths;Pointer 0x201 $x 269 1;Pointer 0x202 $x 269 0;Check ((SavedCamera)-eq[string]$tenths) ('Camera mouse selection persists '+$tenths+' tenths')}
function DragCamera([int]$from,[int]$toX){Pointer 0x201 (CameraX $from) 269 1;Pointer 0x200 $toX 269 1}
function CameraWheel([int]$delta,[int]$x=868,[int]$y=269){
 $rect=New-Object OctaneNativeTest+Rect;[OctaneNativeTest]::GetClientRect($view.w,[ref]$rect)|Out-Null
 $point=New-Object Camera160Input+Point;$point.X=[int]($x*($rect.R-$rect.L)/1060);$point.Y=[int]($y*($rect.B-$rect.T)/736)
 [Camera160Input]::ClientToScreen($view.w,[ref]$point)|Out-Null
 $xy=[IntPtr](($point.Y-shl16)-bor($point.X-band65535));$wp=[IntPtr](($delta-band65535)-shl16)
 [OctaneNativeTest]::SendMessage($view.w,0x20a,$wp,$xy)|Out-Null
}
function CameraKey([int]$key,[int]$expected,[string]$why){SelectorKey $key;Check ((SavedCamera)-eq[string]$expected) $why}
function LaunchCamera([string]$label,[int]$camera,[int]$target=60,[int]$vsync=0){
 [OctaneNativeTest]::Click($view.w,320,494,1060,736);WaitRuntime $target $vsync $camera;ValidateImage $label $target $vsync $camera;EndLaunchFixture
}
try{
 $native=[Camera160Input]::NativeWheelProbe()
 Check ($native[0]-eq5-and$native[1]-eq30-and$native[2]-eq10) 'Native horizontal trackbar probe uses provider range5..30 and default10'
 $nativePlus=$native[3]-10;$nativeMinus=$native[4]-10
 Check ($nativePlus-ne0-and$nativeMinus-ne0-and[Math]::Sign($nativePlus)-eq(-[Math]::Sign($nativeMinus))) 'Native horizontal trackbar probe establishes opposite nonzero wheel directions'
 $nativePlusSign=[Math]::Sign($nativePlus);$nativeMinusSign=[Math]::Sign($nativeMinus)
 [ordered]@{class='msctls_trackbar32';min=$native[0];max=$native[1];start=$native[2];plus120_position=$native[3];minus120_position=$native[4];first60_position=$native[5];second60_position=$native[6];plus_delta=$nativePlus;minus_delta=$nativeMinus;custom_tenths_per_full_notch=1;native_magnitude_is_observed_not_assumed=$true;scope='Real Windows standard horizontal trackbar; independently measures the standalone FPS launcher native-control wheel behavior.'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $Output 'native-trackbar-wheel160.json') -Encoding UTF8
 Check ([int]$cfg.camera_options.min_tenths-eq5-and[int]$cfg.camera_options.max_tenths-eq30-and[int]$cfg.camera_options.default_tenths-eq10-and[int]$cfg.camera_options.step_tenths-eq1) 'Camera range/step/default match the standalone FPS launcher'
 Check ($cfg.camera_options.setting_section-eq'Camera'-and$cfg.camera_options.setting_key-eq'SpeedTenths') 'Camera uses the standalone setting section and key'
 Check ([int]$cfg.ui_camera.control_index-eq14) 'Camera has its dedicated keyboard-focus index'
 Check (($cfg.camera_options.speed_bits-join',')-eq($CameraBitPatterns-join',')) 'All26 camera binary32 values match the independently extracted provider lookup table'
 $view=StartFixture 'Camera-default' '60' 'Fixed';WaitRuntime 60 0 10;ValidateImage 'camera-default' 60 0 10
 Check ((SavedCamera)-eq'') 'Missing camera setting uses1.0 without writing a new preference during startup'
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed') 'Adding camera support preserves pre-existing Display FPS and FPSMode on startup'
 [OctaneNativeTest]::ResizeClient($view.w,1060,736);Start-Sleep -Milliseconds 150
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'camera-default-100.png'))|Write-Host
 foreach($tenths in 5..30){ChooseCamera $tenths}
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed') 'All26 camera mouse steps leave selected FPS/mode unchanged'
 Check ((Get-Content -LiteralPath (Join-Path $view.root 'settings.ini') -Raw)-match'Keep=yes') 'Camera persistence preserves unrelated sections'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'camera-maximum-100.png'))|Write-Host
 DragCamera 30 690;Pointer 0x202 690 269 0;Check ((SavedCamera)-eq'5') 'Captured drag beyond the left end clamps to0.5'
 DragCamera 5 1040;Pointer 0x202 1040 269 0;Check ((SavedCamera)-eq'30') 'Captured drag beyond the right end clamps to3.0'
 ChooseCamera 10;DragCamera 10 (CameraX 30)
 Check ((SavedCamera)-eq'10') 'Dragging previews the new value without premature disk persistence'
 SelectorKey 0x41;Check ((SavedCamera)-eq'10') 'An unrelated letter key leaves active drag preview uncommitted'
 SelectorKey 0x1b;Pointer 0x202 (CameraX 30) 269 0
 Check ((SavedCamera)-eq'10') 'Escape cancels a drag and preserves its starting value'
 DragCamera 10 (CameraX 20);[OctaneNativeTest]::SendMessage($view.w,0x215,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 Check ((SavedCamera)-eq'20') 'Capture loss commits the last valid preview and ends the drag'
 Pointer 0x202 (CameraX 20) 269 0;Check ((SavedCamera)-eq'20') 'A stale mouse-up after capture loss does not change the value'
 DragCamera 20 (CameraX 15);[OctaneNativeTest]::ResizeClient($view.w,848,589);Start-Sleep -Milliseconds 150
 Check ((SavedCamera)-eq'15') 'Resize commits the last valid preview without retaining mouse capture'
 Pointer 0x202 (CameraX 15) 269 0;ChooseCamera 23
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'camera-scaled-23.png'))|Write-Host
 [OctaneNativeTest]::ResizeClient($view.w,1060,736)
 DragCamera 23 (CameraX 25);[OctaneNativeTest]::SendMessage($view.w,0x8,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 Check ((SavedCamera)-eq'25') 'Focus loss commits the last valid preview'
 [OctaneNativeTest]::SendMessage($view.w,0x7,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 ChooseCamera 10
 CameraKey 0x24 5 'Keyboard Home selects0.5'
 CameraKey 0x25 5 'Left arrow cannot go below0.5'
 CameraKey 0x27 6 'Right arrow advances exactly0.1'
 CameraKey 0x26 5 'Up arrow reduces exactly0.1 like the native horizontal trackbar'
 CameraKey 0x28 6 'Down arrow advances exactly0.1 like the native horizontal trackbar'
 CameraKey 0x23 30 'Keyboard End selects3.0'
 CameraKey 0x27 30 'Right arrow cannot go above3.0'
 CameraKey 0x21 25 'PageUp reduces the multiplier by0.5'
 CameraKey 0x22 30 'PageDown raises the multiplier by0.5'
 CameraKey 0x20 30 'Space consumes slider focus without invoking another action'
 CameraKey 0x0d 30 'Enter consumes slider focus without starting a game'
 ChooseCamera 20;CameraWheel 60
 Check ((SavedCamera)-eq'20') 'A partial wheel delta preserves the custom0.1 step until one full notch'
 CameraWheel 60;Check ((SavedCamera)-eq[string](20+$nativePlusSign)) 'Two partial wheel deltas produce one0.1 step in the independently observed native direction'
 CameraWheel -240;$afterWheel=20+$nativePlusSign+2*$nativeMinusSign;Check ((SavedCamera)-eq[string]$afterWheel) 'Negative wheel deltas use the native direction with the declared0.1 step per notch';ChooseCamera 19
 CameraWheel 120 650 269;Check ((SavedCamera)-eq'19') 'Wheel outside the slider does not change camera speed'
 SelectorKey 9;SelectorKey 0x27;Check ((SavedCamera)-eq'19') 'Tab leaves the slider and arrows no longer adjust it'
 OpenSelector;SelectorKey 0x1b;CameraWheel 120;Check ((SavedCamera)-eq'19') 'Wheel over slider without its focus is ignored'
 OpenSelector;Pointer 0x201 740 269 1;Pointer 0x202 740 269 0
 Check ((SavedCamera)-eq'19') 'First outside click closes the FPS popup without changing the slider underneath'
 Pointer 0x201 740 269 1;Pointer 0x202 740 269 0;Check ((SavedCamera)-eq'6') 'A subsequent explicit slider click adjusts the camera normally'
 OpenSelector;Pointer 0x201 900 269 1;Pointer 0x202 900 269 0
 Check ((SavedFPS)-eq'60'-and(SavedMode)-eq'Fixed'-and(SavedCamera)-eq'6') 'FPS popup rows keep priority over the overlapping camera row'
 foreach($tenths in @(5,13,30)){ChooseCamera $tenths;LaunchCamera ('camera-runtime-'+$tenths) $tenths}
 ChooseCamera 19
 $cameraMutex=New-Object System.Threading.Mutex($false,'Local\Begosik.RA3Octane.BattleNet.IO.141');$cameraMutexTaken=$cameraMutex.WaitOne(5000)
 Check $cameraMutexTaken 'Controlled launch lock acquired for deterministic busy-state input validation'
 [OctaneNativeTest]::Click($view.w,320,494,1060,736);Start-Sleep -Milliseconds 150
 Pointer 0x201 (CameraX 30) 269 1;Pointer 0x200 (CameraX 5) 269 1;Pointer 0x202 (CameraX 5) 269 0;SelectorKey 0x24;CameraWheel 120
 Check ((SavedCamera)-eq'19') 'Mouse, keyboard and wheel cannot change camera speed while launch is busy'
 $cameraMutex.ReleaseMutex();$cameraMutexTaken=$false;$cameraMutex.Dispose();$cameraMutex=$null
 WaitRuntime 60 0 19;ValidateImage 'camera-busy-snapshot' 60 0 19;EndLaunchFixture
 ChooseRow 0;$auto=[FPS160Input]::Refresh();LaunchCamera 'camera-auto' 19 $auto 1
 $savedRoot=$view.root;CloseMain $view;$view=$null;$view=Launch $savedRoot;WaitRuntime $auto 1 19;ValidateImage 'camera-reopen-auto' $auto 1 19
 Check ((SavedCamera)-eq'19'-and(SavedMode)-eq'VSync'-and(SavedFPS)-eq'60') 'Camera and Auto mode survive close/reopen independently'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'camera-auto-19.png'))|Write-Host
 CloseMain $view;$view=$null
 foreach($case in @(@('leading-zero','05',5),@('minimum','5',5),@('maximum','30',30),@('below','4',10),@('above','31',10),@('zero','0',10),@('negative','-1',10),@('suffix','15x',10),@('too-many-digits','005',10),@('overflow','9999999999999999',10))){
  $view=StartFixture ('camera-'+$case[0]) '75' 'Fixed' ([string]$case[1]);WaitRuntime 75 0 ([int]$case[2]);ValidateImage ('camera-setting-'+$case[0]) 75 0 ([int]$case[2])
  Check ((SavedCamera)-eq[string]$case[1]) ('Loading camera setting '+$case[0]+' preserves the stored preference until explicit selection')
  CloseMain $view;$view=$null
 }
 $view=StartFixture 'camera-migration-auto' '144' 'VSync';$auto=[FPS160Input]::Refresh();WaitRuntime $auto 1 10;ValidateImage 'camera-migration-auto' $auto 1 10
 Check ((SavedCamera)-eq''-and(SavedFPS)-eq'144'-and(SavedMode)-eq'VSync') 'Existing Auto FPS settings migrate to camera1.0 without creating or rewriting preferences'
 CloseMain $view;$view=$null
}catch{$Failure=$_.Exception.Message;Write-Host ('CAMERA160_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace;if($view){[OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'camera-failure.png'))|Write-Host}}
finally{
 if($cameraMutexTaken){$cameraMutex.ReleaseMutex()};if($cameraMutex){$cameraMutex.Dispose()}
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual styled Windows camera slider: mouse steps/dragging/capture, cancellation, focus, resize, wheel, keyboard, persistence, defaults/invalid inputs, busy-state exclusion and FPS popup priority. Selected runtime float bits match the standalone provider table; complete image neutralization, payload hash, FPS, XInput and PE checks are reused. No RA3 gameplay/GPU/network certification.'}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Output 'CAMERA_WINDOWS_160.json') -Encoding UTF8
}
if($Failure){exit 1}
