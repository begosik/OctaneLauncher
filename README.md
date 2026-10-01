# RA3 Octane

Public distribution repository for the RA3 Octane launcher and its signed 8-player / 60 FPS patch package. Author source archives and private signing keys are **not** distributed here.

## Downloads and installation

Published builds appear on the [Releases page](https://github.com/begosik/OctaneLauncher/releases). Download the release asset named `RA3Octane_<version>_Players_Compact.zip`, not GitHub's automatically generated source archive.

Extract the entire package into a writable folder and run `RA3Octane.exe`. A working Red Alert 3 1.12 installation is required. Do not mix files from different releases. Multiplayer participants should use the same release.

The compact package contains exactly:

```
RA3Octane.exe
patches.octpack
release.oct
```

Third-party notices are available inside the launcher's **About** window. Game installation files are not replaced by the isolated-session launch path.

## Updates starting with launcher 1.2.31

The current version is compiled into the launcher and its Windows VERSIONINFO resource. It is not loaded from a separately editable local version file.

The launcher checks the signed `release.oct` asset of this repository's latest published release at startup and every 30 minutes while idle. It compares the three numeric version components with its compiled version; for example, `1.2.10` is newer than `1.2.9`.

When a newer release is available, **Install Update** downloads the version-specific ZIP from this repository. Installation is confirmed by the user and is not performed while the launcher is running a game. The updater validates the publisher signature, the signed file sizes and SHA-256 hashes, and the downloaded executable's embedded version. It also requires the downloaded manifest to match the one verified during the update check. Failed checks leave the current installation in place.

The updater stages the three runtime files, retains a verified backup, and uses a transaction journal for interrupted-update recovery. Settings and logs are not part of the replacement set. An unavailable update server does not prevent offline play.

No GitHub login or token is required on a player's computer. This update path does not read version/link text files from `DivisionLauncher`.

## Maintainer publication

The existing **Publish signed public Octane package** workflow publishes a locally built, signed package without uploading author sources or private keys.

Upload the unchanged `RA3Octane_<version>_Players_Compact.zip` to the repository root or `incoming/` on `main`. The workflow requires the three-file `OCTREL02` package, verifies it using `public-release-key.pem`, and checks the actual executable version against its signed manifest. It creates a draft release, uploads the ZIP and `release.oct`, downloads both back to compare hashes, and only then marks the release published/latest. Existing release versions are not overwritten.

Never upload an `Author_PRIVATE` archive, `private/` directory, key material, raw game installation, personal logs, or a differently repacked ZIP. The public verification key is not a signing key.

## Validation scope

The 1.2.31 package is a launcher/distribution update. Its game patch is unchanged from 1.2.30. It does not claim to fix the reported persistent building-effect flicker or the mod-specific six-player ESC panel.

Offline tests exercise the version, signature, ZIP and executable-version validation paths. Actual Windows/RA3 execution and an end-to-end live self-update still require runtime validation.
