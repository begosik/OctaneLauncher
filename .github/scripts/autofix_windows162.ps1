param([Parameter(Mandatory=$true)][string]$Transport,[Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Transport=(Resolve-Path $Transport).Path;$Package=(Resolve-Path $Package).Path;$Output=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output)|Out-Null
python "$PSScriptRoot/autofix_package162.py" $Package (Join-Path $Output 'AUTOFIX_PACKAGE_162.json')
if($LASTEXITCODE-ne0){throw 'Actual package execution-level contract failed'}
$meta=Get-Content -LiteralPath (Join-Path $Transport 'manifest.json') -Raw|ConvertFrom-Json
if($meta.format-ne'OCTANE_AUTOFIX_WINDOWS_TEST_162'-or$meta.file-ne'autofix_windows.exe'-or$meta.bytes-lt512-or$meta.bytes-gt262144){throw 'Invalid bounded automatic-fix test manifest'}
if($meta.sha256-notmatch'^[0-9a-f]{64}$'-or$meta.production_module_sha256-notmatch'^[0-9a-f]{64}$'-or$meta.parts.Count-lt1-or$meta.parts.Count-gt40){throw 'Invalid automatic-fix test identity'}
$encoded='';$seen=@{}
foreach($part in $meta.parts){
 if($part-notmatch'^autofix[0-9]{2}\.b64$'-or$seen.ContainsKey($part)){throw 'Invalid automatic-fix part name'}
 $seen[$part]=$true;$text=[IO.File]::ReadAllText((Join-Path $Transport $part)).Trim()
 if($text.Length-gt11000-or$text-notmatch'^[A-Za-z0-9+/=]+$'){throw 'Invalid automatic-fix part encoding'}
 $encoded+=$text
}
$bytes=[Convert]::FromBase64String($encoded);$alg=[Security.Cryptography.SHA256]::Create()
try{$digest=([BitConverter]::ToString($alg.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$alg.Dispose()}
if($bytes.Length-ne$meta.bytes-or$digest-ne$meta.sha256){throw 'Automatic-fix test executable failed authentication'}
$temp=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
$work=Join-Path $temp ('octane162-autofix-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($work)|Out-Null
$exe=Join-Path $work 'autofix_windows.exe';[IO.File]::WriteAllBytes($exe,$bytes)
$fixture=Join-Path $work 'fixture';$report=Join-Path $Output 'AUTOFIX_WINDOWS_162.json'
if(Test-Path -LiteralPath $report){Remove-Item -LiteralPath $report -Force}
$start=New-Object System.Diagnostics.ProcessStartInfo
$start.FileName=$exe;$start.Arguments=('"'+$fixture+'" "'+$report+'"');$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$process=New-Object System.Diagnostics.Process;$process.StartInfo=$start;$started=$false
try{
 $started=$process.Start();if(!$started){throw 'Automatic-fix Windows test did not start'}
 if(!$process.WaitForExit(120000)){$process.Kill();$process.WaitForExit();throw 'Automatic-fix test exceeded its120second bound'}
 if(!(Test-Path -LiteralPath $report)){throw ('Automatic-fix test produced no report; exit='+$process.ExitCode)}
 $result=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
 if($process.ExitCode-ne0-or$result.passed-ne$true-or$result.assertions-ne191){throw ('Automatic-fix Windows test failed; exit='+$process.ExitCode)}
 if(@($result.checks).Count-ne$result.assertions-or@($result.checks|Where-Object{$_.passed-ne$true}).Count){throw 'Automatic-fix assertion matrix failed'}
 if($result.optional_environment_skips-gt1){throw 'Unexpected automatic-fix environment skips'}
 [ordered]@{exe_sha256=$digest;exe_bytes=$bytes.Length;production_module_sha256=$meta.production_module_sha256;assertions=$result.assertions;parent_token_elevated=$result.parent_token_elevated;parent_token_elevation_type=$result.parent_token_elevation_type;non_elevated_inheritance_observed=$result.non_elevated_inheritance_observed;optional_environment_skips=$result.optional_environment_skips;scope=$meta.scope}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'AUTOFIX_TEST_IDENTITY_162.json') -Encoding UTF8
 Write-Host ('AUTOFIX_WINDOWS_TEST_PASSED '+$result.assertions+' assertions; '+$digest)
}finally{
 if($started-and!$process.HasExited){$process.Kill();$process.WaitForExit()}
 $process.Dispose()
}
