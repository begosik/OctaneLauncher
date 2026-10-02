"""Clear release text only; never change release assets, tags or update data."""
import json
import os
import subprocess

REPOSITORY = "begosik/OctaneLauncher"


def api(method, path, payload=None):
    command = ["gh", "api", "--method", method, path]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(
        command,
        input=None if payload is None else json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError("GitHub request failed: " + result.stderr[:500])
    return json.loads(result.stdout)


def identity(release):
    return (
        release["id"], release["tag_name"], release["name"],
        release["draft"], release["prerelease"],
        sorted((a["id"], a["name"], a["size"], a.get("digest"))
               for a in release.get("assets", [])),
    )


def main():
    if os.environ.get("GH_REPO") != REPOSITORY:
        raise RuntimeError("Unexpected repository")
    releases = []
    page = 1
    while True:
        batch = api("GET", f"repos/{REPOSITORY}/releases?per_page=100&page={page}")
        if not isinstance(batch, list):
            raise RuntimeError("Unexpected release listing")
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 100:
            raise RuntimeError("Release listing exceeded safety limit")
    changed = 0
    for release in releases:
        endpoint = f"repos/{REPOSITORY}/releases/{release['id']}"
        if release.get("body"):
            updated = api("PATCH", endpoint, {"body": ""})
            if identity(updated) != identity(release):
                raise RuntimeError("Unexpected change outside the release description")
            changed += 1
        verified = api("GET", endpoint)
        if verified.get("body") not in (None, ""):
            raise RuntimeError("Release description is not empty")
        if identity(verified) != identity(release):
            raise RuntimeError("Release identity or downloads changed")
        print(f"{verified['tag_name']}: description empty; downloads unchanged")
    print(json.dumps({"checked": len(releases), "cleared": changed,
                      "descriptions_empty": True, "assets_unchanged": True}))


if __name__ == "__main__":
    main()
