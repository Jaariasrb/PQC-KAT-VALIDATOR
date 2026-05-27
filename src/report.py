"""Generación de informes de validación en JSON y TXT."""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

from src.pipeline import ValidationRun

logger = logging.getLogger(__name__)


def _breakdown(run: ValidationRun) -> dict[str, dict[str, int]]:
    total: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    for cr in run.report.case_results:
        total[cr.operation] += 1
        if not cr.passed:
            failed[cr.operation] += 1
    return {op: {"total": total[op], "passed": total[op] - failed[op], "failed": failed[op]}
            for op in sorted(total)}


class ReportGenerator:
    def __init__(self, output_dir: Path) -> None:
        self._dir = output_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, run: ValidationRun, formats: list[str] | None = None) -> dict[str, Path]:
        active = formats or ["json", "txt"]
        generated_at = datetime.now().isoformat(timespec="seconds")
        ts   = generated_at.replace(":", "").replace("-", "")
        stem = f"{run.algorithm}_{run.library}_{ts}"

        paths = {}
        if "json" in active:
            paths["json"] = self._json(run, stem, generated_at)
        if "txt" in active:
            paths["txt"] = self._txt(run, stem, generated_at)
        return paths

    def _json(self, run: ValidationRun, stem: str, generated_at: str) -> Path:
        bd   = _breakdown(run)
        rep  = run.report
        data = {
            "generated_at": generated_at, "algorithm": run.algorithm, "library": run.library,
            "conformance": {"level": rep.level.value, "total_cases": rep.total_cases,
                            "failed_cases": rep.failed_cases, "passed_cases": rep.passed_cases,
                            "failure_rate": round(rep.failure_rate, 6)},
            "operations": bd,
            "case_results": [
                {"tc_id": cr.tc_id, "operation": cr.operation, "passed": cr.passed,
                 "fields": [{"field": fr.field, "match": fr.match,
                             "first_diff_byte": fr.first_diff_byte,
                             "expected_preview": fr.expected[:32],
                             "actual_preview": fr.actual[:32]} for fr in cr.fields]}
                for cr in rep.case_results
            ],
            "run_errors": [{"tc_id": e.tc_id, "operation": e.operation, "error": e.error}
                           for e in run.run_errors],
        }
        path = self._dir / f"{stem}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def _txt(self, run: ValidationRun, stem: str, generated_at: str) -> Path:
        rep = run.report
        lines = [
            "=" * 60, "PQC KAT VALIDATOR — INFORME DE CONFORMANCIA", "=" * 60,
            f"Algoritmo  : {run.algorithm}", f"Librería   : {run.library}",
            f"Generado   : {generated_at}", "",
            f"NIVEL      : {rep.level.value}", f"Test cases : {rep.total_cases}",
            f"Correctos  : {rep.passed_cases}", f"Fallidos   : {rep.failed_cases}",
            f"Tasa fallo : {rep.failure_rate * 100:.1f}%", "",
            "POR OPERACIÓN", "-" * 40,
        ]
        for op, st in _breakdown(run).items():
            lines.append(f"  {op:<8}  {st['passed']}/{st['total']} OK"
                         + (f"  ({st['failed']} fallidos)" if st["failed"] else ""))
        lines.append("")
        if run.has_run_errors:
            lines += [f"ERRORES DE EJECUCIÓN ({len(run.run_errors)})", "-" * 40]
            lines += [f"  {e.operation} tcId={e.tc_id}: {e.error}" for e in run.run_errors]
            lines.append("")
        failed = [cr for cr in rep.case_results if not cr.passed]
        if failed:
            lines += [f"TEST CASES FALLIDOS ({len(failed)})", "-" * 40]
            for cr in failed:
                lines.append(f"  {cr.operation} tcId={cr.tc_id}  campos: {', '.join(cr.failed_fields)}")
                for fr in cr.fields:
                    if not fr.match and fr.first_diff_byte >= 0:
                        lines.append(f"    {fr.field}: primer byte distinto en offset {fr.first_diff_byte}")
            lines.append("")
        lines.append("=" * 60)
        path = self._dir / f"{stem}.txt"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
