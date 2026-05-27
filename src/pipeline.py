"""Comparación byte a byte, clasificación de conformancia y pipeline de validación."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from src.harness import Harness
from src.parser import ACVPTestCase, Operation, PQCValidatorError, load_test_cases

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, ACVPTestCase], None]


class ConformanceLevel(str, Enum):
    CONFORMANTE   = "CONFORMANTE"    # 0 % fallos
    PUNTUAL       = "PUNTUAL"        # < 5 %
    INDETERMINADO = "INDETERMINADO"  # 5 – 80 %
    SISTEMATICO   = "SISTEMATICO"    # > 80 %


@dataclass
class FieldResult:
    field: str
    match: bool
    expected: str
    actual: str
    first_diff_byte: int


@dataclass
class CaseResult:
    algorithm: str
    operation: str
    tc_id: int
    fields: list[FieldResult]

    @property
    def passed(self) -> bool:
        return all(f.match for f in self.fields)

    @property
    def failed_fields(self) -> list[str]:
        return [f.field for f in self.fields if not f.match]


@dataclass
class ConformanceReport:
    algorithm: str
    level: ConformanceLevel
    total_cases: int
    failed_cases: int
    failure_rate: float
    case_results: list[CaseResult]

    @property
    def passed_cases(self) -> int:
        return self.total_cases - self.failed_cases

    def summary(self) -> str:
        return (f"{self.algorithm}: {self.level.value} "
                f"({self.passed_cases}/{self.total_cases} OK, {self.failure_rate * 100:.1f}% fallos)")


def _normalize_hex(value: str, field_name: str) -> str:
    cleaned = value.strip().upper()
    if not cleaned:
        raise PQCValidatorError(f"Campo '{field_name}' está vacío")
    if len(cleaned) % 2 != 0:
        raise PQCValidatorError(f"Campo '{field_name}' tiene longitud hex impar")
    invalid = set(cleaned) - set("0123456789ABCDEF")
    if invalid:
        raise PQCValidatorError(f"Campo '{field_name}' contiene caracteres no hexadecimales: {invalid}")
    return cleaned


def _first_diff_byte(expected: str, actual: str) -> int:
    max_bytes = max(len(expected), len(actual)) // 2
    for i in range(max_bytes):
        e = expected[i * 2: i * 2 + 2] if i * 2 + 2 <= len(expected) else ""
        a = actual[i * 2: i * 2 + 2] if i * 2 + 2 <= len(actual) else ""
        if e != a:
            return i
    return 0


def compare_case(case: ACVPTestCase, actual: dict[str, str]) -> CaseResult:
    field_results = []
    for fname, expected_raw in case.expected.items():
        if fname not in actual:
            raise PQCValidatorError(
                f"[{case.algorithm}] {case.operation.value} tcId={case.tc_id}: "
                f"el harness no produjo el campo '{fname}'"
            )
        # El campo "verify" del harness se compara como texto plano (PASS/FAIL),
        # no como hex.
        if fname == "verify":
            expected = expected_raw.strip().upper()
            got      = actual[fname].strip().upper()
            diff     = -1
        else:
            expected = _normalize_hex(expected_raw, fname)
            got      = _normalize_hex(actual[fname], fname)
            diff     = -1 if expected == got else _first_diff_byte(expected, got)

        field_results.append(FieldResult(field=fname, match=expected == got,
                                         expected=expected, actual=got, first_diff_byte=diff))
    return CaseResult(algorithm=case.algorithm, operation=case.operation.value,
                      tc_id=case.tc_id, fields=field_results)


def classify(algorithm: str, results: list[CaseResult]) -> ConformanceReport:
    if not results:
        return ConformanceReport(algorithm=algorithm, level=ConformanceLevel.INDETERMINADO,
                                 total_cases=0, failed_cases=0, failure_rate=0.0, case_results=[])
    total  = len(results)
    failed = sum(1 for r in results if not r.passed)
    rate   = failed / total
    level  = (ConformanceLevel.CONFORMANTE if rate == 0.0
              else ConformanceLevel.PUNTUAL if rate < 0.05
              else ConformanceLevel.INDETERMINADO if rate <= 0.80
              else ConformanceLevel.SISTEMATICO)
    return ConformanceReport(algorithm=algorithm, level=level, total_cases=total,
                             failed_cases=failed, failure_rate=rate, case_results=results)


@dataclass
class RunError:
    tc_id: int
    operation: str
    error: str


@dataclass
class ValidationRun:
    algorithm: str
    library: str
    kat_dir: Path
    report: ConformanceReport
    run_errors: list[RunError] = field(default_factory=list)

    @property
    def has_run_errors(self) -> bool:
        return bool(self.run_errors)


class Orchestrator:
    def __init__(self, library: str = "liboqs") -> None:
        self._library = library

    def validate(self, algorithm: str, kat_dir: Path,
                 progress_cb: ProgressCallback | None = None) -> ValidationRun:
        harness = Harness(self._library, algorithm)
        cases   = load_test_cases(kat_dir, algorithm)
        total   = len(cases)

        case_results = []
        run_errors = []

        for i, case in enumerate(cases, start=1):
            try:
                case_results.append(self._run_case(harness, case))
            except PQCValidatorError as exc:
                logger.warning("[%s] tcId=%d error de ejecución: %s", algorithm, case.tc_id, exc)
                run_errors.append(RunError(tc_id=case.tc_id, operation=case.operation.value, error=str(exc)))
            if progress_cb is not None:
                progress_cb(i, total, case)

        return ValidationRun(algorithm=algorithm, library=self._library, kat_dir=kat_dir,
                             report=classify(algorithm, case_results), run_errors=run_errors)

    def _run_case(self, harness: Harness, case: ACVPTestCase) -> CaseResult:
        output = harness.run(case)
        if case.operation == Operation.SIGN and not case.deterministic:
            return self._functional_sign_check(harness, case, output["signature"])
        return compare_case(case, output)

    def _functional_sign_check(self, harness: Harness, sign_case: ACVPTestCase,
                                produced_signature: str) -> CaseResult:
        verify_case = ACVPTestCase(
            algorithm=sign_case.algorithm, operation=Operation.VERIFY,
            tc_id=sign_case.tc_id, source=sign_case.source,
            inputs={"pk": sign_case.inputs["pk"], "message": sign_case.inputs["message"],
                    "signature": produced_signature, "context": sign_case.inputs.get("context", "")},
            expected={"verify": "PASS"},
        )
        result = compare_case(verify_case, harness.run(verify_case))
        result.operation = sign_case.operation.value
        return result
