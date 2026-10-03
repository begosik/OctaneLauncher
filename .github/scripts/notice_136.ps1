param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop'
$Baseline=$Package
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected native helper template'}
Invoke-Expression $t.Substring($a,$b-$a)
# Controlled notification state in a disposable copy of the exact signed public
# EXE. No server/manifest is forged and no install accepted. RVAs are hash-bound.
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class Notice136 {
 public delegate bool EnumProc(IntPtr w,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr at,byte[] b,UIntPtr n,out UIntPtr got);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h,IntPtr at,byte[] b,UIntPtr n,out UIntPtr got);
 [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr w,EnumProc cb,IntPtr p);
 [DllImport("user32.dll",EntryPoint="SendMessageW",CharSet=CharSet.Unicode)] static extern IntPtr ReadText(IntPtr h,uint m,IntPtr n,StringBuilder b);
 public static uint Read32(IntPtr h,long at){byte[] b=new byte[4];UIntPtr got;if(!ReadProcessMemory(h,new IntPtr(at),b,(UIntPtr)4,out got)||got.ToUInt64()!=4)throw new Exception("Read fixture state");return BitConverter.ToUInt32(b,0);}
 public static void Set32(IntPtr h,long at,uint value){byte[] b=BitConverter.GetBytes(value);UIntPtr got;if(!WriteProcessMemory(h,new IntPtr(at),b,(UIntPtr)4,out got)||got.ToUInt64()!=4)throw new Exception("Write fixture state");}
 public static string Body(IntPtr w){string text="";EnumChildWindows(w,delegate(IntPtr c,IntPtr p){var b=new StringBuilder(2048);ReadText(c,13,new IntPtr(b.Capacity),b);text+=b.ToString()+"\n";return true;},IntPtr.Zero);return text;}
}
'@
try{
 $r=Extract $Package 'notification fixture';$exe=Join-Path $r 'RA3Octane.exe'
 Check ((Get-FileHash $exe).Hash.ToLowerInvariant()-eq'1dbbc15f88202d21871cedc3c8df5d4532d79b60dc9dbc632265786aa4c4f089') 'Exact public executable matches the native notification fixture layout'
 $v=Launch $r;Start-Sleep -Seconds 2;$base=$v.p.MainModule.BaseAddress.ToInt64();$ph=$v.p.Handle
 Until { [Notice136]::Read32($ph,($base+0x66dd4))-eq0 } 'initial signed check finishes' 40|Out-Null
 function Offer([uint32]$patch){
  [Notice136]::Set32($ph,($base+0x66da0),1);[Notice136]::Set32($ph,($base+0x66da4),2);[Notice136]::Set32($ph,($base+0x66da8),$patch)
  [Notice136]::Set32($ph,($base+0x66dd0),1);[Notice136]::Set32($ph,($base+0x66de4),1)
  [OctaneNativeTest]::PostMessage($v.w,0x8008,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 }
 function Popup {return (Until {[OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update')} 'queued update popup')}
 function Decline($w){[OctaneNativeTest]::PostMessage($w,0x111,[IntPtr]7,[IntPtr]::Zero)|Out-Null;Until {![OctaneNativeTest]::IsWindow($w)} 'No closes the popup'|Out-Null}
 Offer 37;$w=Popup
 Check ([Notice136]::Body($w).Contains('Installed version: 1.2.36')-and[Notice136]::Body($w).Contains('New version: 1.2.37')) 'Popup shows real installed version and controlled offered version'
 Check (([OctaneNativeTest]::SendMessage($w,0x400,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64()-band0xffff)-eq7) 'No is the default button; installation requires explicit acceptance'
 [OctaneNativeTest]::Screenshot($w,(Join-Path $Output 'update-popup-native.png'))|Write-Host
 Decline $w
 Check ([Notice136]::Read32($ph,($base+0x66de4))-eq0-and[Notice136]::Read32($ph,($base+0x66de8))-eq0) 'Notification is consumed and modal state cleared'
 for($i=0;$i-lt10;$i++){[OctaneNativeTest]::PostMessage($v.w,0x8008,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null}
 Start-Sleep -Milliseconds 500
 Check ([OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update')-eq[IntPtr]::Zero) 'Repeated UI polls do not duplicate a dismissed popup'
 Check (!(Test-Path (Join-Path $r '.updates'))) 'No update files are staged after declining'
 [OctaneNativeTest]::Click($v.w,550,702,1060,736);$w=Popup;Decline $w
 Check ($true) 'INSTALL UPDATE can reopen the declined offer'
 [Notice136]::Set32($ph,($base+0x61c94),1);Offer 38;Start-Sleep -Milliseconds 400
 Check ([OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update')-eq[IntPtr]::Zero) 'Busy game/operation state defers the popup'
 [Notice136]::Set32($ph,($base+0x61c94),0)
 $w=Popup;Check ([Notice136]::Body($w).Contains('New version: 1.2.38')) 'Idle timer shows the queued offer after the operation';Decline $w
 [OctaneNativeTest]::PostMessage($v.w,0x100,[IntPtr]0x75,[IntPtr]::Zero)|Out-Null
 $mw=Until {[OctaneNativeTest]::Window($v.p.Id,'Begosik.RA3Octane.Mods.v1')} 'open mod selector'
 Offer 39;Start-Sleep -Milliseconds 400
 Check ([OctaneNativeTest]::Title($v.p.Id,'RA3 // OCTANE - Update')-eq[IntPtr]::Zero) 'An open mod selector is not interrupted'
 [OctaneNativeTest]::PostMessage($mw,0x111,[IntPtr]2,[IntPtr]::Zero)|Out-Null
 Until {![OctaneNativeTest]::IsWindow($mw)} 'close mod selector'|Out-Null
 $w=Popup;Check ([Notice136]::Body($w).Contains('New version: 1.2.39')) 'Queued offer appears after the selector closes';Decline $w
 Check ((Get-FileHash $exe).Hash.ToLowerInvariant()-eq'1dbbc15f88202d21871cedc3c8df5d4532d79b60dc9dbc632265786aa4c4f089') 'Executable on disk is unmodified throughout the fixture'
 CloseMain $v
} catch {$Failure=$_.Exception.Message;Write-Host ('NOTICE_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 Get-Process -Name RA3Octane -ErrorAction SilentlyContinue|Where-Object{$_.Path-and$_.Path.StartsWith($Work,[StringComparison]::OrdinalIgnoreCase)}|Stop-Process -Force -ErrorAction SilentlyContinue
 $result=[ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Exact signed public EXE and real Windows message box; controlled volatile offer state, no live newer release, no install accepted';network_offer_simulated=$true;gameplay_tested=$false}
 $result|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'NOTICE_136.json') -Encoding UTF8
}
if($Failure){exit 1}
