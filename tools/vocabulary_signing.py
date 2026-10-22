"""Ed25519 signing for the vocabulary release index (v1/release.json).

The index pins the exact bytes of the catalog and every course manifest; manifests already pin
every pack, so one signature covers the whole release. The app accepts only indexes signed by a
key in vocabulary-content/signing/trusted-keys.json (mirrored in ReleaseVerifier.kt), with a
sequence no lower than the last one it installed, and before expiresAt.

Private keys stay offline (default %USERPROFILE%/.redistract-signing/), never in a repository
or CI secret: whoever holds GitHub access alone must not be able to publish content."""
import argparse
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_KEYS = ROOT / "vocabulary-content/signing/trusted-keys.json"
REVOCATIONS = ROOT / "vocabulary-content/signing/revocations.json"
KEY_DIR = Path.home() / ".redistract-signing"
RELEASE_PATH = "v1/release.json"
DOMAIN = b"redistract-vocabulary-release-v1\n"
DEFAULT_VALID_DAYS = 180


def b64(data):
    return base64.b64encode(data).decode("ascii")


def describe(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load_trusted(path=TRUSTED_KEYS):
    keys = json.loads(Path(path).read_text(encoding="utf-8"))
    return {key_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value)) for key_id, value in keys.items()}


def open_release(envelope_bytes, trusted, now=None, min_sequence=0):
    """Return the verified payload dict, or raise ValueError. Mirrors ReleaseVerifier.kt."""
    envelope = json.loads(envelope_bytes)
    payload_bytes = base64.b64decode(envelope["payload"], validate=True)
    if not any(sig.get("keyId") in trusted and _valid(trusted[sig["keyId"]], sig["signature"], payload_bytes)
               for sig in envelope.get("signatures", [])):
        raise ValueError("Release index has no valid signature from a trusted key")
    payload = json.loads(payload_bytes)
    if payload["schemaVersion"] != 1:
        raise ValueError("Unsupported release index")
    now = now or datetime.now(timezone.utc)
    if datetime.fromisoformat(payload["expiresAt"].replace("Z", "+00:00")) <= now:
        raise ValueError(f"Release index expired at {payload['expiresAt']}")
    if payload["sequence"] < min_sequence:
        raise ValueError("Release index rollback rejected")
    return payload


def _valid(public_key, signature, payload_bytes):
    try:
        public_key.verify(base64.b64decode(signature, validate=True), DOMAIN + payload_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False


def build_payload(site, sequence, valid_days, now=None):
    site = Path(site)
    catalog_bytes = (site / "v1/catalog.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    files = {"v1/catalog.json": describe(catalog_bytes)}
    for course in catalog["courses"]:
        files[course["manifestPath"]] = describe((site / course["manifestPath"]).read_bytes())
    revocations = json.loads(REVOCATIONS.read_text(encoding="utf-8")) if REVOCATIONS.exists() else {}
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    return {
        "schemaVersion": 1,
        "sequence": sequence,
        "generation": catalog["generation"],
        "issuedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(days=valid_days)).isoformat().replace("+00:00", "Z"),
        "files": files,
        "revokedPacks": sorted(revocations.get("packs", [])),
        "revokedEntries": sorted(revocations.get("entries", [])),
    }


def sign(site, key_path, key_id, valid_days=DEFAULT_VALID_DAYS, sequence=None):
    site = Path(site)
    trusted = load_trusted()
    if key_id not in trusted:
        raise SystemExit(f"{key_id} is not in {TRUSTED_KEYS}")
    private_key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if private_key.public_key().public_bytes_raw() != trusted[key_id].public_bytes_raw():
        raise SystemExit(f"{key_path} does not match trusted key {key_id}")
    target = site / RELEASE_PATH
    previous = 0
    if target.exists():
        previous = json.loads(base64.b64decode(json.loads(target.read_bytes())["payload"]))["sequence"]
    payload_bytes = json.dumps(build_payload(site, sequence or previous + 1, valid_days),
                               sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(DOMAIN + payload_bytes)
    envelope = {"payload": b64(payload_bytes), "signatures": [{"keyId": key_id, "signature": b64(signature)}]}
    target.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8", newline="\n")
    payload = open_release(target.read_bytes(), trusted)
    print(f"Signed {target} with {key_id}: sequence {payload['sequence']}, expires {payload['expiresAt']}")


def keygen(key_id, directory=KEY_DIR):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{key_id}.pem"
    if path.exists():
        raise SystemExit(f"Refusing to overwrite {path}")
    private_key = Ed25519PrivateKey.generate()
    path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    trusted = json.loads(TRUSTED_KEYS.read_text(encoding="utf-8")) if TRUSTED_KEYS.exists() else {}
    trusted[key_id] = b64(private_key.public_key().public_bytes_raw())
    TRUSTED_KEYS.parent.mkdir(parents=True, exist_ok=True)
    TRUSTED_KEYS.write_text(json.dumps(trusted, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Private key: {path} (keep offline, back it up; never commit)")
    print(f"Public key {key_id} added to {TRUSTED_KEYS}; mirror it in ReleaseVerifier.kt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen", help="create a new signing key outside the repository")
    generate.add_argument("key_id")
    signing = commands.add_parser("sign", help="write a signed v1/release.json into a site directory")
    signing.add_argument("--site", default=str(ROOT / "vocabulary-content/site"))
    signing.add_argument("--key-id", required=True)
    signing.add_argument("--key", help="private key PEM (default: <key dir>/<key-id>.pem)")
    signing.add_argument("--days", type=int, default=DEFAULT_VALID_DAYS)
    signing.add_argument("--sequence", type=int, help="override the default previous+1")
    args = parser.parse_args()
    if args.command == "keygen":
        keygen(args.key_id)
    else:
        sign(args.site, args.key or KEY_DIR / f"{args.key_id}.pem", args.key_id, args.days, args.sequence)
