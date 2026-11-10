# Keep fixture caches realistic while preserving the production manifest bound.
# RUNNER_TEMP itself must be short; Windows hosted runners use D:\a\_temp.
if(!$env:RUNNER_TEMP){throw 'RUNNER_TEMP is required for the isolated fixture cache'}
$compactCacheBase163=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
$compactCache163=Join-Path $compactCacheBase163 ('oc63'+[guid]::NewGuid().ToString('N').Substring(0,8))
$compactData163=Join-Path $compactCache163 'Begosik\RA3Octane\Sessions\session-runtime\Data'
if([Text.Encoding]::UTF8.GetByteCount($compactData163)-ge128){throw 'Fixture RUNNER_TEMP is too long for the unchanged 128-byte private Data manifest bound; use a shorter isolated test directory'}
[IO.Directory]::CreateDirectory($compactCache163)|Out-Null
$env:LOCALAPPDATA=$compactCache163
