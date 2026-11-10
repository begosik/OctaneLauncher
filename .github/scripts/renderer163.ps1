param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Layout,[Parameter(Mandatory=$true)][string]$Output,[switch]$RequireChildEnvironment)
# Public signed launcher, real styled control and actual isolated session files.
# This checks preparation and input; it does not certify GPU/gameplay performance.
if($PSVersionTable.PSEdition-eq'Core'){$arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Package',$Package,'-Layout',$Layout,'-Output',$Output);if($RequireChildEnvironment){$arguments+='-RequireChildEnvironment'};& powershell.exe @arguments;exit $LASTEXITCODE}
$Package=(Resolve-Path $Package).Path;$Layout=(Resolve-Path $Layout).Path
$renderer163ScriptDirectory=$PSScriptRoot
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fps_slider163.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry{`n Check")
if($a-lt0-or$b-le$a){throw 'Unexpected FPS validation helper boundaries'}
Invoke-Expression $t.Substring($a,$b-$a).Replace('$PSScriptRoot','$renderer163ScriptDirectory')
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Collections.Generic;using System.Runtime.InteropServices;
public static class Renderer163Input {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]public static extern uint GetPrivateProfileString(string section,string key,string fallback,StringBuilder value,uint size,string file);
 [DllImport("kernel32.dll")]static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll")]static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] data,int size,out IntPtr read);
 [DllImport("ntdll.dll")]static extern int NtQueryInformationProcess(IntPtr process,int type,ref IntPtr value,int bytes,out int returned);
 public static string Saved(string file){var v=new StringBuilder(64);GetPrivateProfileString("Renderer","Backend","",v,64,file);return v.ToString();}
 static uint U32(IntPtr p,uint at){byte[] b=new byte[4];IntPtr n;if(!ReadProcessMemory(p,new IntPtr(at),b,4,out n)||n.ToInt64()!=4)throw new Exception("Remote pointer unavailable");return BitConverter.ToUInt32(b,0);}
 public static Dictionary<string,string> Environment(int pid){
  var p=OpenProcess(0x410,false,pid);if(p==IntPtr.Zero)return null;
  try{IntPtr peb=IntPtr.Zero;int used;if(NtQueryInformationProcess(p,26,ref peb,IntPtr.Size,out used)!=0||peb==IntPtr.Zero)return null;
   uint parameters=U32(p,checked((uint)peb.ToInt64())+0x10),environment=U32(p,parameters+0x48);if(environment==0)return null;
   var bytes=new List<byte>();int terminator=-1;
   for(int at=0;at<65536;at+=4096){var block=new byte[4096];IntPtr n;ReadProcessMemory(p,new IntPtr((long)environment+at),block,block.Length,out n);int count=(int)n.ToInt64();if(count<=0)break;
    for(int i=0;i<count;i++)bytes.Add(block[i]);for(int i=2;i+3<bytes.Count;i+=2)if(bytes[i]==0&&bytes[i+1]==0&&bytes[i+2]==0&&bytes[i+3]==0){terminator=i;break;}if(terminator>=0)break;
   }
   if(terminator<0)return null;var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
   foreach(var line in Encoding.Unicode.GetString(bytes.ToArray(),0,terminator+4).Split('\0')){int eq=line.IndexOf('=');if(eq>0)result[line.Substring(0,eq)]=line.Substring(eq+1);}return result;
  }catch{return null;}finally{CloseHandle(p);}
 }
}
'@
$rendererMutex=$null;$rendererMutexTaken=$false;$script:EnvironmentObservations=New-Object 'System.Collections.Generic.List[object]'
$parentDXVK=@{};foreach($name in @('DXVK_CONFIG_FILE','DXVK_LOG_LEVEL','DXVK_LOG_PATH','DXVK_SHADER_CACHE_PATH','DXVK_OCTANE_CI_SENTINEL')){$parentDXVK[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
function SavedRenderer(){return [Renderer163Input]::Saved((Join-Path $view.root 'settings.ini'))}
function RendererClick(){Pointer 0x201 944 52 1;Pointer 0x202 944 52 0}
function ObserveChildEnvironment([string]$backend){
 $captured=$null;$limit=[datetime]::UtcNow.AddSeconds(3)
 do{foreach($p in @(Get-Process -Name 'ra3_1.12' -ErrorAction SilentlyContinue)){try{if($p.Path-eq$runtime){$captured=[Renderer163Input]::Environment($p.Id);if($captured){break}}}catch{}};if($captured){break};Start-Sleep -Milliseconds 20}while([datetime]::UtcNow-lt$limit)
 if(!$captured){$script:EnvironmentObservations.Add([pscustomobject]@{backend=$backend;observed=$false;reason='The prepared x86 child exited before a complete environment snapshot; deterministic production environment fixture is separate.'});if($RequireChildEnvironment){throw 'A complete child environment snapshot was required but unavailable'};return}
 $dxvk=@{};foreach($entry in $captured.GetEnumerator()){if($entry.Key.StartsWith('DXVK_',[StringComparison]::OrdinalIgnoreCase)){$dxvk[$entry.Key]=$entry.Value}}
 if($backend-eq'Vulkan'){$data=Split-Path -Parent $runtime;Check ($dxvk.Count-eq4-and$dxvk['DXVK_CONFIG_FILE']-eq(Join-Path $data 'dxvk.conf')-and$dxvk['DXVK_LOG_LEVEL']-eq'info'-and$dxvk['DXVK_LOG_PATH']-eq$data-and$dxvk['DXVK_SHADER_CACHE_PATH']-eq$data) 'Observed Vulkan child has only four renderer variables, all paths private'}
 else{Check ($dxvk.Count-eq0) 'Observed DirectX9 child has no inherited or Vulkan DXVK variables'}
 $script:EnvironmentObservations.Add([pscustomobject]@{backend=$backend;observed=$true;DXVK_variables=$dxvk})
}
function ValidateRenderer([string]$backend,[string]$label,[int]$fps=75,[int]$vsync=0,[int]$camera=17){
 WaitRuntime $fps $vsync $camera;ValidateImage $label $fps $vsync $camera
 $data=Split-Path -Parent $runtime;$options=$cfg.renderer_options;$expectedSession=if($backend-eq'Vulkan'){$options.vulkan_session}else{$options.directx9_session}
 Check ($options.same_canonical_Data_path-and$options.existing_firewall_path_unchanged-and$expectedSession-eq'session-runtime'-and(Split-Path -Leaf (Split-Path -Parent $data))-eq$expectedSession) ($backend+' retains the existing canonical private Data and firewall path')
 $dll=Join-Path $data $options.dll_name;$config=Join-Path $data $options.config_name
 if($backend-eq'Vulkan'){
  Check ((Test-Path -LiteralPath $dll)-and(Get-Item -LiteralPath $dll).Length-eq[long]$options.bytes-and(Get-FileHash -LiteralPath $dll).Hash.ToLowerInvariant()-eq$options.sha256) 'Vulkan materializes exact authenticated x86 DXVK 3.1.1 bytes beside the private engine'
  Check ((Test-Path -LiteralPath $config)-and(Get-Item -LiteralPath $config).Length-eq[long]$options.config_bytes-and(Get-FileHash -LiteralPath $config).Hash.ToLowerInvariant()-eq$options.config_sha256) 'Vulkan config retains upstream defaults without quality reductions'
 }else{Check (!(Test-Path -LiteralPath $dll)-and!(Test-Path -LiteralPath $config)) 'DirectX9 private Data contains no DXVK DLL or config'}
 Check (!(Test-Path -LiteralPath (Join-Path $view.root 'd3d9.dll'))-and!(Test-Path -LiteralPath (Join-Path $view.root 'dxvk.conf'))) 'Renderer files are absent from the launcher directory'
 Check ((Get-FileHash -LiteralPath $installedSentinel).Hash-eq$installedSentinelHash) 'Installed-game renderer sentinel remains byte identical'
 Check ($env:DXVK_CONFIG_FILE-eq'parent-config-kept'-and$env:DXVK_OCTANE_CI_SENTINEL-eq'parent-only') 'Renderer preparation preserves the calling process environment'
}
function LaunchRenderer([string]$backend,[string]$label){
 $script:runtime=RuntimePath $backend
 $script:rendererMutex=New-Object System.Threading.Mutex($false,'Local\Begosik.RA3Octane.BattleNet.IO.141');$script:rendererMutexTaken=$rendererMutex.WaitOne(5000)
 Check $rendererMutexTaken 'Controlled launch lock acquired for deterministic renderer busy-state check'
 Pointer 0x201 320 494 1;Pointer 0x202 320 494 0;Start-Sleep -Milliseconds 150
 $saved=SavedRenderer;RendererClick;SelectorKey 0x25;SelectorKey 0x27;SelectorKey 0x20
 Check ((SavedRenderer)-eq$saved) 'Mouse and keyboard cannot change renderer while preparation is busy'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output ($label+'-busy.png')))|Write-Host
 ValidateRenderer $backend $label
 $rendererMutex.ReleaseMutex();$script:rendererMutexTaken=$false;$rendererMutex.Dispose();$script:rendererMutex=$null
 ObserveChildEnvironment $backend;EndLaunchFixture
}
try{
 Check ($cfg.engine_lab.version-eq'0.6.2'-and$cfg.engine_lab.variant-eq'optimized'-and$cfg.engine_lab.same_optimized_game_both_renderers) 'Both renderers retain the exact optimized 0.6.2 profile and canonical game'
 Check ([int]$cfg.ui_renderer.control_index-eq15-and[int]$cfg.ui_renderer.button_count-eq16) 'Styled renderer extends the current button map without moving FPS or camera'
 Check ($cfg.ui_renderer.default-eq'DirectX9'-and$cfg.renderer_options.default-eq'DirectX9') 'Existing users default to DirectX9'
 $env:DXVK_CONFIG_FILE='parent-config-kept';$env:DXVK_OCTANE_CI_SENTINEL='parent-only';$env:DXVK_LOG_LEVEL='trace'
 $installedSentinel=Join-Path $game 'Data\d3d9.dll';[IO.File]::WriteAllText($installedSentinel,'Installed game renderer sentinel; never replace this fixture file.');$installedSentinelHash=(Get-FileHash -LiteralPath $installedSentinel).Hash
 $view=StartFixture 'renderer-default' '75' 'Fixed' '17';WaitRuntime 75 0 17;ValidateRenderer 'DirectX9' 'renderer-native-default'
 Check ((SavedRenderer)-eq'') 'Opening the launcher does not persist a renderer default'
 [OctaneNativeTest]::ResizeClient($view.w,1060,736);Start-Sleep -Milliseconds 100;[OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'renderer-directx9-100.png'))|Write-Host
 Pointer 0x201 944 52 1;Check ((SavedRenderer)-eq'') 'Press alone does not commit renderer';Pointer 0x202 1030 70 0;Check ((SavedRenderer)-eq'') 'Releasing outside the pressed renderer cancels the click'
 OpenSelector;RendererClick;Check ((SavedRenderer)-eq'') 'The FPS popup consumes an outside click before renderer activation'
 RendererClick;Check ((SavedRenderer)-eq'Vulkan') 'Mouse release inside renderer selects and persists Vulkan'
 SelectorKey 0x25;Check ((SavedRenderer)-eq'DirectX9') 'Left selects DirectX9';SelectorKey 0x27;Check ((SavedRenderer)-eq'Vulkan') 'Right selects Vulkan'
 SelectorKey 0x24;Check ((SavedRenderer)-eq'DirectX9') 'Home selects DirectX9';SelectorKey 0x23;Check ((SavedRenderer)-eq'Vulkan') 'End selects Vulkan'
 SelectorKey 0x20;Check ((SavedRenderer)-eq'DirectX9') 'Space toggles renderer';SelectorKey 0x0d;Check ((SavedRenderer)-eq'Vulkan') 'Enter toggles renderer'
 Check ((SavedFPS)-eq'75'-and(SavedMode)-eq'Fixed'-and[IO.File]::ReadAllText((Join-Path $view.root 'settings.ini')).Contains('SpeedTenths=17')-and[IO.File]::ReadAllText((Join-Path $view.root 'settings.ini')).Contains('Keep=yes')) 'Renderer persistence preserves FPS, camera and unrelated INI settings'
 [OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'renderer-vulkan-focus-100.png'))|Write-Host
 [OctaneNativeTest]::ResizeClient($view.w,795,552);Start-Sleep -Milliseconds 100;RendererClick;Check ((SavedRenderer)-eq'DirectX9') 'Scaled renderer hit testing matches its painted field';[OctaneNativeTest]::Screenshot($view.w,(Join-Path $Output 'renderer-directx9-75.png'))|Write-Host
 LaunchRenderer 'DirectX9' 'renderer-directx9-session'
 RendererClick;Check ((SavedRenderer)-eq'Vulkan') 'Renderer is enabled again after the native session completes'
 [OctaneNativeTest]::ResizeClient($view.w,1325,920);LaunchRenderer 'Vulkan' 'renderer-vulkan-session'
 $savedRoot=$view.root;CloseMain $view;$view=$null;$view=Launch $savedRoot;$script:runtime=RuntimePath 'Vulkan';ValidateRenderer 'Vulkan' 'renderer-vulkan-reopen';Check ((SavedRenderer)-eq'Vulkan') 'Vulkan preference survives launcher close/reopen'
 CloseMain $view;$view=$null
 $view=StartFixture 'renderer-invalid' '75' 'Fixed' '17' 'unsupported';ValidateRenderer 'DirectX9' 'renderer-invalid-falls-back';Check ((SavedRenderer)-eq'unsupported') 'Unknown saved value falls back in memory without rewriting the INI';CloseMain $view;$view=$null
}catch{$Failure=$_.Exception.Message;Write-Host ('RENDERER163_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($rendererMutexTaken){$rendererMutex.ReleaseMutex()};if($rendererMutex){$rendererMutex.Dispose()}
 if($view-and!$view.p.HasExited){EndLaunchFixture;Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 foreach($name in $parentDXVK.Keys){[Environment]::SetEnvironmentVariable($name,$parentDXVK[$name],'Process')}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());child_environment_observations=@($script:EnvironmentObservations.ToArray());child_environment_required=[bool]$RequireChildEnvironment;package_sha256=(Get-FileHash -LiteralPath $Package).Hash.ToLowerInvariant();scope='Real signed Windows launcher: styled renderer mouse/keyboard, scaled screenshots, persistence, deterministic busy exclusion, existing canonical Data/firewall path across both backends, exact private DXVK/config, canonical optimized EngineLab image and retained FPS/camera/XInput validation. Child environment is asserted when observed; a required snapshot can be enabled explicitly. No GPU rendering, gameplay, online match or performance certification.'}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Output 'RENDERER_WINDOWS_163.json') -Encoding UTF8
}
if($Failure){exit 1}
