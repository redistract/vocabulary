"""Verify a vocabulary site (deployed URL or local directory): catalog, generation, pack sizes/hashes,
bundle equivalence and licenses. Optionally check that already-published pack paths are unchanged. No publishing."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import urlopen


def artifact_url(base, path):
    if not path or "\\" in path or "%" in path or urlsplit(path).scheme or path.startswith("/"):
        raise ValueError(f"Invalid artifact path: {path}")
    base = base.rstrip("/") + "/"
    result = urljoin(base, path)
    origin, target = urlsplit(base), urlsplit(result)
    if (origin.scheme != "https" or origin.username or origin.query or origin.fragment
            or target.netloc != origin.netloc or not target.path.startswith(origin.path)
            or target.query or target.fragment):
        raise ValueError(f"Artifact escapes HTTPS site: {path}")
    return result


def url_reader(base):
    def read(path, limit):
        url = artifact_url(base, path)
        with urlopen(url, timeout=30) as response:
            if response.status != 200 or response.url != url:
                raise ValueError(f"Unexpected response or redirect: {path}")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"Artifact too large: {path}")
        return data
    return read


def local_reader(root):
    root = Path(root).resolve()

    def read(path, limit):
        artifact_url("https://local.invalid/", path)  # same path rules as the app
        target = (root / path).resolve()
        if root not in target.parents:
            raise ValueError(f"Artifact escapes site directory: {path}")
        data = target.read_bytes()
        if len(data) > limit:
            raise ValueError(f"Artifact too large: {path}")
        return data
    return read


def verify(read, label, expect_generation=None):
    def checked(descriptor, limit):
        data = read(descriptor["path"], limit)
        if len(data) != descriptor["bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"Integrity mismatch: {descriptor['path']}")
        return data

    catalog = json.loads(read("v1/catalog.json", 100_000))
    if catalog["schemaVersion"] != 1:
        raise ValueError("Unsupported catalog")
    generation = catalog.get("generation")
    if not generation:
        raise ValueError("Catalog has no content generation; current apps reject it")
    if expect_generation and generation != expect_generation:
        raise ValueError(f"Catalog generation {generation} != expected {expect_generation}")
    course = next(c for c in catalog["courses"] if c["id"] == "de-en")
    manifest = json.loads(read(course["manifestPath"], 200_000))
    if manifest["schemaVersion"] != 1 or manifest["courseId"] != "de-en":
        raise ValueError("Invalid manifest")
    entries, pack_ids, licenses = {}, set(), set()
    for descriptor in manifest["packs"]:
        if descriptor["id"] in pack_ids or descriptor["revision"] < 1:
            raise ValueError("Duplicate pack or invalid revision")
        if descriptor["path"] != f"v1/packs/{descriptor['id']}/{descriptor['revision']}.json":
            raise ValueError(f"Pack path is not immutable id/revision form: {descriptor['path']}")
        pack_ids.add(descriptor["id"])
        document = json.loads(checked(descriptor, 2_000_000))
        if document["schemaVersion"] != 1 or document["courseId"] != "de-en":
            raise ValueError("Invalid pack header")
        if document.get("generation") != generation:
            raise ValueError(f"Pack generation differs from catalog: {descriptor['id']}")
        if len(document["entries"]) != descriptor["entryCount"]:
            raise ValueError("Pack count mismatch")
        for entry in document["entries"]:
            if entry["id"] in entries or entry["level"] != descriptor["level"]:
                raise ValueError("Duplicate entry or wrong band")
            entries[entry["id"]] = entry
            licenses.update(source["license"] for source in entry["sources"])
    if not entries:
        raise ValueError("Empty release")
    if "bundle" in manifest:
        descriptor = manifest["bundle"]
        with gzip.GzipFile(fileobj=io.BytesIO(checked(descriptor, 5_000_000))) as stream:
            raw = stream.read(20_000_001)
        if len(raw) > 20_000_000:
            raise ValueError("Expanded bundle too large")
        bundle = json.loads(raw)
        if (bundle["revision"] != descriptor["revision"] or bundle["courseId"] != "de-en"
                or bundle["schemaVersion"] != 1 or bundle["totalEntries"] != len(entries)
                or descriptor["entryCount"] != len(entries) or len(bundle["entries"]) != len(entries)
                or {e["id"]: e for e in bundle["entries"]} != entries):
            raise ValueError("Bundle does not match pack contents")
    for license_name in sorted(licenses):
        if not read(f"licenses/{license_name}.txt", 200_000).strip():
            raise ValueError("Empty license file")
    return {"source": label, "integrityPassed": True, "generation": generation, "packs": len(pack_ids),
            "entries": len(entries), "semanticApproval": "NOT VERIFIED", "manifest": manifest}


def check_immutable(manifest, live_base):
    """A pack path that is already live must keep identical bytes; new paths are fine."""
    read = url_reader(live_base)
    for descriptor in manifest["packs"]:
        try:
            live = read(descriptor["path"], 2_000_000)
        except HTTPError as error:
            if error.code == 404:
                continue
            raise
        if hashlib.sha256(live).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"Published pack would change: {descriptor['path']}. Bump its revision.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", help="HTTPS base URL or local site directory")
    parser.add_argument("--expect-generation")
    parser.add_argument("--immutable-against", metavar="URL",
                        help="live base URL whose existing pack paths must not change")
    parser.add_argument("--report", type=Path,
                        default=Path(__file__).resolve().parents[1] / "build/vocabulary-public-audit.json")
    args = parser.parse_args()
    local = not args.site.startswith("https://")
    report = verify(local_reader(args.site) if local else url_reader(args.site), args.site, args.expect_generation)
    if args.immutable_against:
        check_immutable(report["manifest"], args.immutable_against)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {report['generation']}: {report['packs']} packs, {report['entries']} entries and license files. "
          f"Semantic approval not verified. Report: {args.report}")
