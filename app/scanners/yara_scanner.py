import os
from typing import Any, Dict, List, Optional

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yara = None


def run_yara_rules(file_path: str, rules_folder: str) -> Optional[List[Dict[str, Any]]]:
    if yara is None:
        return None

    rules_folder_abs = os.path.abspath(rules_folder)
    if not os.path.isdir(rules_folder_abs):
        return []

    rule_files = [
        os.path.join(rules_folder_abs, f)
        for f in os.listdir(rules_folder_abs)
        if f.lower().endswith((".yar", ".yara"))
    ]
    if not rule_files:
        return []

    # Compile all rules together
    namespace_map = {
        os.path.splitext(os.path.basename(p))[0]: p for p in rule_files
    }
    compiled = yara.compile(filepaths=namespace_map)
    matches = compiled.match(filepath=file_path)

    results: List[Dict[str, Any]] = []
    for m in matches:
        results.append(
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "meta": dict(m.meta) if getattr(m, "meta", None) else {},
                "tags": list(m.tags) if getattr(m, "tags", None) else [],
            }
        )
    return results


