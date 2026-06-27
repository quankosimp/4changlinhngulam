from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import RepoGuardReport


def write_report(report: RepoGuardReport, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
