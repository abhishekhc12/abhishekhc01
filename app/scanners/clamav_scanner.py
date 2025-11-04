import shutil
import subprocess
from typing import Dict, Any


def run_clamav_scan(file_path: str) -> Dict[str, Any]:
    clamscan_path = shutil.which("clamscan")
    if not clamscan_path:
        return {"enabled": False, "available": False, "infected": None, "detections": None, "reason": "clamscan not found"}

    try:
        proc = subprocess.run(
            [clamscan_path, "--no-summary", file_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        infected = "FOUND" in output
        detections = 0
        if output:
            detections = sum(1 for line in output.splitlines() if line.strip().endswith("FOUND"))
        return {
            "enabled": True,
            "available": True,
            "infected": infected,
            "detections": detections,
            "raw": output.strip(),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "available": True,
            "infected": None,
            "detections": None,
            "error": str(exc),
        }


