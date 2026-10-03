"""Verify private installed executable modules against exact published npm bytes."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from urllib.request import urlopen

root = Path(__file__).resolve().parents[4] / "reference-server" / "node_modules"
receipt = {}
for name in ("better-auth", "@better-auth/core", "@better-auth/memory-adapter"):
    url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-1.7.6.tgz"
    with urlopen(url) as response:
        archive = response.read()
    modules = []
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        for member in package.getmembers():
            if not member.isfile() or not member.name.endswith(".mjs"):
                continue
            path = member.name.removeprefix("package/")
            published = package.extractfile(member).read()
            assert (root / name / path).read_bytes() == published, (name, path)
            modules.append((path, hashlib.sha256(published).hexdigest()))
    receipt[name] = {
        "version": "1.7.6", "tarball": url,
        "tarballSha256": hashlib.sha256(archive).hexdigest(),
        "executableModules": len(modules), "identicalToPublishedTarball": True,
        "moduleDigest": hashlib.sha256(json.dumps(sorted(modules)).encode()).hexdigest(),
    }
Path(__file__).with_name("published-integrity.json").write_text(json.dumps(receipt, indent=2) + "\n")
print("All installed executable bytes identical to published 1.7.6 for Better Auth, core and memory adapter")
