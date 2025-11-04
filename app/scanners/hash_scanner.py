import hashlib
import os
from typing import Dict

try:
    import magic  # type: ignore
except Exception:
    magic = None


def _hash_file(path: str, algo_name: str, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.new(algo_name)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_hashes(path: str) -> Dict[str, str]:
    return {
        "sha256": _hash_file(path, "sha256"),
        "sha1": _hash_file(path, "sha1"),
        "md5": _hash_file(path, "md5"),
    }


def get_file_metadata(path: str, original_name: str | None = None) -> Dict[str, str]:
    size_bytes = os.path.getsize(path)
    _, ext = os.path.splitext(original_name or path)
    mime = None
    if magic is not None:
        try:
            mime = magic.from_file(path, mime=True)
        except Exception:
            mime = None
    return {
        "filename": original_name or os.path.basename(path),
        "size_bytes": str(size_bytes),
        "extension": ext or "",
        "mime": mime or "unknown",
    }


