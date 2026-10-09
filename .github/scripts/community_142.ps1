param([Parameter(Mandatory=$true)][string]$Package,[Parameter(Mandatory=$true)][string]$Output)
# Executes the signed public launcher. All game/CP resources here are tiny test
# fixtures; this verifies configuration preparation and does not claim gameplay.
if($PSVersionTable.PSEdition-eq'Core'){& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Package $Package -Output $Output;exit $LASTEXITCODE}
$ErrorActionPreference='Stop';$Package=(Resolve-Path $Package).Path
$t=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_public_test.ps1')).Replace("`r`n","`n")
$a=$t.IndexOf("`$ErrorActionPreference='Stop'");$b=$t.IndexOf("`ntry {`n `$new=Extract")
if($a-lt0-or$b-le$a){throw 'Unexpected native helper boundaries'}
$Baseline=$Package;Invoke-Expression $t.Substring($a,$b-$a)
$env:APPDATA=Join-Path $Work 'Roaming';[IO.Directory]::CreateDirectory($env:APPDATA)|Out-Null
$game=Join-Path $Work 'InstalledGame';$cp=Join-Path $game 'CommunityPatch'
$session=Join-Path $env:LOCALAPPDATA 'Begosik\RA3Octane\Sessions\session-runtime'
$rootConfig=Join-Path $session 'RA3_english_1.12.SkuDef';$view=$null
function Fixture([string]$path,[string]$text){[IO.Directory]::CreateDirectory((Split-Path -Parent $path))|Out-Null;[IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))}
function SessionText([string]$name){return [IO.File]::ReadAllText((Join-Path $session $name))}
function StartCase([string]$name,[string]$selection=''){
 $r=Extract $Package $name
 $saved="[Launcher]`r`nGameDirectory=$game`r`nSkuDef=RA3_english_1.12.SkuDef`r`n[Firewall]`r`nRuntimeRule=1`r`n[Mods]`r`nSelectedSkuDef=$selection`r`n"
 Fixture (Join-Path $r 'settings.ini') $saved
 return Launch $r
}
function RootLines(){return @((SessionText 'RA3_english_1.12.SkuDef') -split "`r?`n"|Where-Object{$_})}
function HashInstalled(){return ((Get-ChildItem -LiteralPath $game -Recurse -File|Sort-Object FullName|ForEach-Object{$_.FullName+'='+((Get-FileHash -LiteralPath $_.FullName).Hash)})-join"`n")}
function SaveConfigEvidence([string]$case){$dest=Join-Path $Output $case;[IO.Directory]::CreateDirectory($dest)|Out-Null;foreach($n in @('RA3_english_1.12.SkuDef','config-01.SkuDef','config-02.SkuDef')){if(Test-Path (Join-Path $session $n)){Copy-Item (Join-Path $session $n) $dest}};Copy-Item (Join-Path $view.root 'Logs\launcher.log') $dest}
try{
 [IO.Directory]::CreateDirectory((Join-Path $game 'Data'))|Out-Null
 Copy-Item $env:ComSpec (Join-Path $game 'Data\ra3_1.12.game')
 Fixture (Join-Path $game 'RA3_english_1.12.SkuDef') "set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n"
 $before=HashInstalled;$view=StartCase 'cp-absent';$lines=RootLines
 Check ($lines[0]-match'^add-big .*Core13\.big$') 'Absent Community Patch retains exactly one first Core13 mount'
 Check (@($lines|Where-Object{$_-match'^add-config '}).Count-eq0) 'Absent Community Patch leaves the original simple vanilla chain'
 Check ((HashInstalled)-eq$before) 'Vanilla startup does not rewrite installed game files'
 SaveConfigEvidence 'absent';CloseMain $view;$view=$null

 Fixture (Join-Path $cp 'RA3_.SkuDef') "set-exe Data\ra3_1.12.game`r`nadd-big Community.big`r`nadd-config Data\Data.SkuDef`r`nset-search-path big:;Data`r`n"
 Fixture (Join-Path $cp 'Data\Data.SkuDef') "add-big ..\Nested.big`r`n"
 Fixture (Join-Path $cp 'Community.big') 'Fixture archive only; no game data.'
 Fixture (Join-Path $cp 'Nested.big') 'Second fixture archive; no game data.'
 Fixture (Join-Path $game 'RA3_english_1.12.SkuDef') "add-config CommunityPatch\RA3_.SkuDef`r`nadd-big CommunityPatch\Community.big`r`nset-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n"
 $before=HashInstalled;$view=StartCase 'cp-present';$lines=RootLines
 Check ($lines[0]-match'^add-big .*Core13\.big$') 'Core13 is first when Community Patch is installed'
 Check ($lines[1]-match'^add-config .*config-01\.SkuDef$') 'Community Patch is mounted directly after Core13'
 Check (@($lines|Where-Object{$_-match'^add-config '}).Count-eq1) 'Inherited Community Patch config include is deduplicated'
 Check (@($lines|Where-Object{$_-match'^add-big '}).Count-eq1) 'Inherited Community Patch archive include is deduplicated'
 $one=SessionText 'config-01.SkuDef';$two=SessionText 'config-02.SkuDef'
 Check ($one-match'add-big .*Community\.big') 'Community Patch archive resolves inside its installed folder'
 Check ($two-match'add-big .*Nested\.big') 'Nested Community Patch config retains its relative archive'
 Check ($one-match'add-config .*config-02\.SkuDef') 'Nested Community Patch config is cloned into the persistent session'
 $exeLines=@(($one+"`n"+(SessionText 'RA3_english_1.12.SkuDef'))-split"`r?`n"|Where-Object{$_-match'^set-exe '})
 Check ($exeLines.Count-eq2-and$exeLines[0]-eq$exeLines[1]) 'Every Community/vanilla set-exe points to the same Octane runtime'
 Check (($one+"`n"+$two)-notmatch'Core13\.big') 'Nested configs do not mount Core13 again'
 Check ((HashInstalled)-eq$before) 'Community startup does not modify installed CP/game files'
 Check ([IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log')).Contains('[COMMUNITY] Detected installed patch; enabled automatically for vanilla.')) 'Actual launcher log confirms automatic vanilla detection'
 SaveConfigEvidence 'present';$stamp=(Get-Item $rootConfig).LastWriteTimeUtc;CloseMain $view;$view=$null
 $view=StartCase 'cp-repeat';Check ((Get-Item $rootConfig).LastWriteTimeUtc-eq$stamp) 'Repeated startup reuses an unchanged Community session config';CloseMain $view;$view=$null

 $mod=Join-Path $Work 'Mods\DataMod.SkuDef';Fixture $mod "mod-game 1.12`r`nadd-big Test.big`r`n";Fixture (Join-Path (Split-Path $mod -Parent) 'Test.big') 'Tiny data mod fixture.'
 $view=StartCase 'cp-mod' $mod;$lines=RootLines
 Check (@($lines|Where-Object{$_-match'^add-config '}).Count-eq0) 'A selected data mod excludes inherited Community config includes'
 Check (@($lines|Where-Object{$_-match'Community\.big|Nested\.big'}).Count-eq0) 'A selected data mod excludes Community archives'
 Check ($lines[0]-match'^add-big .*Core13\.big$') 'A selected data mod retains the Core13 extension'
 Check ([IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log')).Contains('[COMMUNITY] Selected data mod: Community Patch is excluded.')) 'Actual launcher confirms Community Patch exclusion for mods'
 SaveConfigEvidence 'mod';CloseMain $view;$view=$null

 Remove-Item -LiteralPath (Join-Path $cp 'Nested.big')
 $view=StartCase 'cp-incomplete-vanilla';$log=[IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log'))
 Check ($log.Contains('Community Patch installation is incomplete. Required archive is missing:')) 'Incomplete Community Patch reports the missing required archive'
 SaveConfigEvidence 'incomplete';CloseMain $view;$view=$null
 $view=StartCase 'cp-incomplete-mod' $mod;$lines=RootLines
 Check (@($lines|Where-Object{$_-match'^add-config '}).Count-eq0) 'An incomplete Community install still stays excluded for a selected mod'
 CloseMain $view;$view=$null
 Remove-Item -LiteralPath (Join-Path $cp 'RA3_.SkuDef')
 $view=StartCase 'cp-no-manifest';$log=[IO.File]::ReadAllText((Join-Path $view.root 'Logs\launcher.log'))
 Check ($log.Contains('Community Patch installation is incomplete. Expected configuration:')) 'A stranded Community directory cannot silently become vanilla'
 CloseMain $view;$view=$null
 Remove-Item -LiteralPath $cp -Recurse -Force
 Fixture (Join-Path $game 'RA3_english_1.12.SkuDef') "set-exe Data\ra3_1.12.game`r`nset-search-path big:`r`n"
 $view=StartCase 'cp-removed';$lines=RootLines
 Check (@($lines|Where-Object{$_-match'^add-config '}).Count-eq0) 'Removing Community Patch is detected on next startup without a switch'
 CloseMain $view;$view=$null
}catch{$Failure=$_.Exception.Message;Write-Host ('COMMUNITY_TEST_FAILURE '+$Failure);Write-Host $_.ScriptStackTrace}
finally{
 if($view-and!$view.p.HasExited){Stop-Process -Id $view.p.Id -Force -ErrorAction SilentlyContinue}
 [ordered]@{passed=(!$Failure);failure=$Failure;assertions=$Rows.Count;checks=@($Rows.ToArray());package_sha256=(Get-FileHash $Package).Hash.ToLowerInvariant();scope='Actual signed final Windows launcher. Configuration preparation, resource path resolution, duplicate include filtering, mod exclusion and persistent file reuse using tiny fixtures. No RA3 gameplay or complete Community asset set.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'COMMUNITY_142.json') -Encoding UTF8
}
if($Failure){exit 1}
