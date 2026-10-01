# RA3 Octane 1.2.31

This is a launcher and distribution update. The game patch remains byte-for-byte identical to Octane 1.2.30 (V134W).

## Launcher changes

- One faction-neutral interface; faction-theme selectors and their embedded backgrounds are removed.
- Restore Original now displays an English confirmation explaining that it disables Octane's BattleNet compatibility patch and may affect multiplayer connections/eight-player lobbies. Cancel is the default choice.
- The version is compiled into the launcher and its Windows VERSIONINFO resource. A mismatching signed release is rejected.
- Update checks use this repository's signed release asset, not DivisionLauncher version/link text files. Checks run at startup and every 30 minutes while idle.
- Install Update downloads the immutable version-tagged ZIP, verifies the publisher signature, file hashes and actual executable version, then stages the files and restarts through the transactional updater. User confirmation is retained; files are not replaced while a game is running through the launcher.
- The compact package contains only RA3Octane.exe, patches.octpack and release.oct. Attribution/third-party notices are in the About window.

## Validation

105 offline assertions exercised the production version, signed-manifest, ZIP-staging, PE-version and URL-validation functions with real RSA/SHA-256 verification. File-system operations were mocked. Separate inherited launcher tests passed 119 process-guard scenarios / 486 assertions and 161 logging/preferences/environment checks, including a 4,200-file retention test.

Actual Windows/RA3 execution, live download/restart through GitHub and visual rendering of the new interface were not tested in the build environment.

## Known remaining issues

This release does not fix the reported persistent building-effect flicker or the mod-specific ESC menu that still displays six players. It retains the existing Javelin/locomotor fixes from the 1.2.30 game payload.

Install the entire matching package, not individual files from different releases. Existing pre-1.2.31 launchers require a one-time manual installation to switch to this GitHub update channel.
