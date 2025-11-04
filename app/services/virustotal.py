import os
from typing import Any, Dict, Optional
import requests


def query_virustotal(sha256: Optional[str]) -> Dict[str, Any]:
    if not sha256:
        return {"enabled": False, "reason": "missing sha256"}

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"enabled": False, "reason": "VIRUSTOTAL_API_KEY not set"}

    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return {
                "enabled": True,
                "found": True,
                "stats": stats,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        elif resp.status_code == 404:
            return {"enabled": True, "found": False}
        else:
            return {
                "enabled": True,
                "error": f"HTTP {resp.status_code}",
                "body": resp.text[:2000],
            }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}


