param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Baseline,[Parameter(Mandatory=$true)][string]$Manifest,[Parameter(Mandatory=$true)][string]$Layout,[Parameter(Mandatory=$true)][string]$Output,[switch]$RequireChildEnvironment)
# Focused release163 changes. The complete retained regression workflow remains required.
$ErrorActionPreference='Stop'
$Package=(Resolve-Path -LiteralPath $Package).Path;$Baseline=(Resolve-Path -LiteralPath $Baseline).Path;$Manifest=(Resolve-Path -LiteralPath $Manifest).Path;$Layout=(Resolve-Path -LiteralPath $Layout).Path
$Output=[IO.Path]::GetFullPath($Output);[IO.Directory]::CreateDirectory($Output)|Out-Null
$results=New-Object 'System.Collections.Generic.List[object]';$failure=$null
try{
 & python (Join-Path $PSScriptRoot 'verify_fps_profile163.py') $Baseline $Package $Manifest $Layout (Join-Path $Output 'PUBLIC_FPS_RENDERER_PROFILE_163.json')
 if($LASTEXITCODE-ne0){throw 'Public optimized FPS/DXVK component verification failed'}
 $results.Add([pscustomobject]@{script='verify_fps_profile163.py';passed=$true})
 foreach($script in @('fps_slider163.ps1','camera_slider163.ps1','renderer163.ps1')){
  $sub=Join-Path $Output ([IO.Path]::GetFileNameWithoutExtension($script));[IO.Directory]::CreateDirectory($sub)|Out-Null
  $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot $script),'-Package',$Package,'-Layout',$Layout,'-Output',$sub)
  if($script-eq'renderer163.ps1'-and$RequireChildEnvironment){$arguments+='-RequireChildEnvironment'}
  & powershell.exe @arguments
  $ok=$LASTEXITCODE-eq0;$results.Add([pscustomobject]@{script=$script;passed=$ok});if(!$ok){throw ($script+' failed')}
 }
}catch{$failure=$_.Exception.Message;Write-Host ('FPS_RENDERER_163_FAILURE '+$failure)}
finally{[ordered]@{passed=(!$failure);failure=$failure;results=@($results.ToArray());package_sha256=(Get-FileHash -LiteralPath $Package).Hash.ToLowerInvariant();scope='Focused public signed-package FPS/renderer changes. Existing update, BattleNet, recovery, mod, Community, Native C7 and asInvoker/autofix suites remain separate required regressions.'}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $Output 'FPS_RENDERER_WINDOWS_163.json') -Encoding UTF8}
if($failure){exit 1}
