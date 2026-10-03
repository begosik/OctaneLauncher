param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Package=(Resolve-Path $Package).Path;$Output=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output)|Out-Null
$work=Join-Path $env:RUNNER_TEMP ('Octane4GB-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work)|Out-Null
$env:LOCALAPPDATA=Join-Path $work 'LocalAppData'
[IO.Directory]::CreateDirectory($env:LOCALAPPDATA)|Out-Null
$rows=New-Object 'System.Collections.Generic.List[object]';$failure=$null;$p=$null
function Check([bool]$ok,[string]$name){$rows.Add([pscustomobject]@{name=$name;passed=$ok});Write-Host ($ok.ToString()+' '+$name);if(!$ok){throw $name}}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.IO;using System.Threading;using System.Security.Cryptography;using System.Runtime.InteropServices;
public static class Memory136 {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct SI {public int cb;public string a,b,c;public uint d,e,f,g,h,i,j,k;public short l,m;public IntPtr n,o,p,q;}
 [StructLayout(LayoutKind.Sequential)] public struct PI {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr p,IntPtr at,UIntPtr n,uint kind,uint protect);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualFreeEx(IntPtr p,IntPtr at,UIntPtr n,uint kind);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr p,IntPtr at,byte[] b,UIntPtr n,out UIntPtr got);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr p,IntPtr at,byte[] b,UIntPtr n,out UIntPtr got);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr p);
 [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr p,uint code);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr p,uint ms);
 static Thread capture;public static volatile bool Captured=false,Stop=false;
 public static string Hash(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
 public static void StartCapture(string source,string destination,string hash){
  Stop=false;Captured=false;capture=new Thread(delegate(){while(!Stop){try{using(var f=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){
   if(f.Length==9637888){var b=new byte[9637888];int at=0,n;while(at<b.Length&&(n=f.Read(b,at,b.Length-at))>0)at+=n;if(at==b.Length&&Hash(b)==hash){File.WriteAllBytes(destination,b);Captured=true;return;}}
  }}catch(IOException){}catch(UnauthorizedAccessException){}Thread.Sleep(5);}});capture.IsBackground=true;capture.Start();
 }
 public static void EndCapture(){Stop=true;if(capture!=null)capture.Join(2000);}
 // Independent suspended child: never executes RA3 code or requires game assets.
 public static string Probe(string path,bool expectedLAA){SI si=new SI();si.cb=Marshal.SizeOf(si);PI pi;
  if(!CreateProcess(path,new StringBuilder("\""+path+"\""),IntPtr.Zero,IntPtr.Zero,false,4,IntPtr.Zero,Path.GetDirectoryName(path),ref si,out pi))throw new Exception("CreateProcess "+Marshal.GetLastWin32Error());
  try {byte[] dos=new byte[64];UIntPtr got;if(!ReadProcessMemory(pi.process,new IntPtr(0x400000),dos,(UIntPtr)dos.Length,out got)||got.ToUInt64()!=64)throw new Exception("Read DOS");
   int off=BitConverter.ToInt32(dos,60);byte[] pe=new byte[96];if(!ReadProcessMemory(pi.process,new IntPtr(0x400000+off),pe,(UIntPtr)pe.Length,out got)||got.ToUInt64()!=96)throw new Exception("Read PE");
   bool laa=(BitConverter.ToUInt16(pe,22)&32)!=0;if(laa!=expectedLAA)throw new Exception("Actual mapped LAA differs");
   IntPtr address=VirtualAllocEx(pi.process,new IntPtr(0x90000000L),(UIntPtr)65536,0x3000,4);
   if(address==IntPtr.Zero){if(expectedLAA)throw new Exception("Upper-half allocation rejected "+Marshal.GetLastWin32Error());return "LAA_OFF_upper_half_refused";}
   try{byte[] x=new byte[]{3,1,2,36,4,0,255,128},y=new byte[8];if(!WriteProcessMemory(pi.process,address,x,(UIntPtr)8,out got)||got.ToUInt64()!=8||!ReadProcessMemory(pi.process,address,y,(UIntPtr)8,out got)||got.ToUInt64()!=8||BitConverter.ToString(x)!=BitConverter.ToString(y))throw new Exception("Upper-half read/write failed");}
   finally{VirtualFreeEx(pi.process,address,UIntPtr.Zero,0x8000);}
   return expectedLAA?"LAA_ON_0x90000000_read_write_verified":"LAA_OFF_external_allocation_allowed";
  }finally{TerminateProcess(pi.process,0);WaitForSingleObject(pi.process,5000);CloseHandle(pi.thread);CloseHandle(pi.process);}
 }
}
'@
try{
 Expand-Archive -LiteralPath $Package -DestinationPath (Join-Path $work 'launcher')
 $root=Join-Path $work 'launcher\RA3Octane';$game=Join-Path $work 'InstalledGame';[IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 # The shipped launcher must use its signed isolated payload, never this sentinel.
 $installed=Join-Path $game 'Data\ra3_1.12.game';[IO.File]::WriteAllText($installed,'DO NOT PATCH OR RUN THIS INSTALLED GAME SENTINEL')
 $before=(Get-FileHash $installed).Hash
 $sku=Join-Path $game 'RA3_english_1.12.SkuDef';[IO.File]::WriteAllText($sku,"set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n")
 $skuHash=(Get-FileHash $sku).Hash
 [IO.File]::WriteAllText((Join-Path $root 'settings.ini'),"[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[BattleNet]`r`nAutoPatch=0`r`nPreferencePolicy=132`r`n[Firewall]`r`nRuntimeRule=1`r`n")
 $session=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime\Data\ra3_1.12.game'
 $captured=Join-Path $work 'captured.game';$expected='52d6a269aaecf29320abec797f42c967727a7e291f07d8270208ebfd28938fa7'
 [Memory136]::StartCapture($session,$captured,$expected)
 $p=Start-Process (Join-Path $root 'RA3Octane.exe') -ArgumentList '--vanilla' -WorkingDirectory $root -PassThru
 $log=Join-Path $root 'Logs\launcher.log';$end=[datetime]::UtcNow.AddSeconds(50);$text=''
 do {Start-Sleep -Milliseconds 100;if(Test-Path $log){$text=[IO.File]::ReadAllText($log)}}while(![Memory136]::Captured-and[datetime]::UtcNow-lt$end)
 Check ($text.Contains('[4GB] Applied automatically to the isolated session executable;')) 'The shipped launcher applies 4GB to the session without another verification stage'
 Check ($text.Contains($session)) 'The logged target is the isolated session, not the installed game'
 Check ((Get-FileHash $installed).Hash-eq$before) 'Installed game sentinel is never modified'
 Check ((Get-FileHash $sku).Hash-eq$skuHash) 'Original SkuDef is never modified'
 [Memory136]::EndCapture()
 Check ([Memory136]::Captured) 'Actual launcher-written session captured with independent expected SHA-256'
 $image=[IO.File]::ReadAllBytes($captured);$pe=[BitConverter]::ToInt32($image,60)
 Check (([BitConverter]::ToUInt16($image,$pe+22)-band32)-ne0) 'Captured final game has LARGE_ADDRESS_AWARE'
 Check ([Memory136]::Hash($image)-eq$expected) 'Final session matches production C and independent Python preparation'
 $probe=[Memory136]::Probe($captured,$true);Check ($probe-eq'LAA_ON_0x90000000_read_write_verified') 'Actual session process can commit, write and read memory at 0x90000000'
 $image[$pe+22]=$image[$pe+22]-band0xdf;$negative=Join-Path $work 'no-laa.game';[IO.File]::WriteAllBytes($negative,$image)
 $negativeProbe=[Memory136]::Probe($negative,$false);Write-Host ('NEGATIVE_CONTROL '+$negativeProbe)
 Check ($negativeProbe-eq'LAA_OFF_upper_half_refused') 'Same image with only LAA cleared cannot allocate above 2 GiB'
} catch {$failure=$_.Exception.Message;Write-Host ('MEMORY_TEST_FAILURE '+$failure);Write-Host $_.ScriptStackTrace}
finally{
 [Memory136]::EndCapture()
 if($log-and(Test-Path $log)){Copy-Item $log (Join-Path $Output 'launcher-memory.log');Get-Content $log -Tail 35|Write-Host}
 if($p-and!$p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}
 $r=[ordered]@{passed=(!$failure);failure=$failure;checks=@($rows.ToArray());assertions=$rows.Count;package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();final_session_sha256=$expected;upper_address='0x90000000';scope='Native Windows production launcher writes the final session; independent suspended real session image and small upper-half allocation; no game assets, gameplay, GPU or network test.'}
 $r|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'MEMORY_136.json') -Encoding UTF8
 # No game binary, original user files or private source in uploaded evidence.
}
if($failure){exit 1}
