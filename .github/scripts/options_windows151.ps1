param([Parameter(Mandatory=$true)][string]$Transport,[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Transport=(Resolve-Path $Transport).Path;$Output=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($Output)|Out-Null
$meta=Get-Content -LiteralPath (Join-Path $Transport 'manifest.json') -Raw|ConvertFrom-Json
if($meta.format-ne'OCTANE_OPTIONS_WINDOWS_TEST_151'-or$meta.file-ne'options_windows.exe'-or$meta.bytes-lt512-or$meta.bytes-gt262144){throw 'Invalid bounded Options test manifest'}
if($meta.sha256-notmatch'^[0-9a-f]{64}$'-or$meta.parts.Count-lt1-or$meta.parts.Count-gt40){throw 'Invalid Options test digest or part count'}
$encoded='';$seen=@{}
foreach($part in $meta.parts){
 if($part-notmatch'^options[0-9]{2}\.b64$'-or$seen.ContainsKey($part)){throw 'Invalid Options test part name'}
 $seen[$part]=$true;$text=[IO.File]::ReadAllText((Join-Path $Transport $part)).Trim()
 if($text.Length-gt11000-or$text-notmatch'^[A-Za-z0-9+/=]+$'){throw 'Invalid Options test part encoding'}
 $encoded+=$text
}
$bytes=[Convert]::FromBase64String($encoded)
$alg=[Security.Cryptography.SHA256]::Create()
try{$digest=([BitConverter]::ToString($alg.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$alg.Dispose()}
if($bytes.Length-ne$meta.bytes-or$digest-ne$meta.sha256){throw 'Options test executable failed authentication'}
$work=Join-Path $env:RUNNER_TEMP ('octane151-options-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work)|Out-Null
$exe=Join-Path $work 'options_windows.exe';[IO.File]::WriteAllBytes($exe,$bytes)
$fixture=Join-Path $work 'fixture';$report=Join-Path $Output 'OPTIONS_WINDOWS_151.json'
if(Test-Path -LiteralPath $report){Remove-Item -LiteralPath $report -Force}
$start=New-Object System.Diagnostics.ProcessStartInfo
$start.FileName=$exe;$start.Arguments=('"'+$fixture+'" "'+$report+'"')
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$process=New-Object System.Diagnostics.Process;$process.StartInfo=$start
$started=$false
try{
 $started=$process.Start();if(!$started){throw 'Options Windows test did not start'}
 if(!$process.WaitForExit(120000)){$process.Kill();$process.WaitForExit();throw 'Options Windows test exceeded its120second bound'}
 if(!(Test-Path -LiteralPath $report)){throw ('Options test produced no report; exit='+$process.ExitCode)}
 $result=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
 if($process.ExitCode-ne0-or$result.passed-ne$true-or$result.assertions-lt1){throw ('Options Windows test failed; exit='+$process.ExitCode)}
 if(@($result.checks).Count-ne$result.assertions){throw 'Options Windows assertion count does not match its results'}
 if(@($result.checks|Where-Object{$_.passed-ne$true}).Count){throw 'Options Windows test contains a failed assertion'}
 [ordered]@{exe_sha256=$digest;exe_bytes=$bytes.Length;assertions=$result.assertions;scope=$meta.scope}|ConvertTo-Json|Set-Content (Join-Path $Output 'OPTIONS_WINDOWS_TEST_IDENTITY.json') -Encoding UTF8
 Write-Host ('OPTIONS_WINDOWS_TEST_PASSED '+$result.assertions+' assertions; '+$digest)
}finally{
 if($started-and!$process.HasExited){$process.Kill();$process.WaitForExit()}
 $process.Dispose()
}
