"""Tipos de dominio, excepción única y parser de vectores ACVP del NIST (FIPS 203/204/205)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PQCValidatorError(Exception):
    """Cualquier error del validador: KAT mal formado, algoritmo no soportado,
    fallo del harness, etc."""


KEM_ALGORITHMS: frozenset[str] = frozenset({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
MLDSA_ALGORITHMS: frozenset[str] = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
SLHDSA_ALGORITHMS: frozenset[str] = frozenset({"SLH-DSA-SHA2-128s"})
SIG_ALGORITHMS: frozenset[str] = MLDSA_ALGORITHMS | SLHDSA_ALGORITHMS
SUPPORTED_ALGORITHMS: frozenset[str] = KEM_ALGORITHMS | SIG_ALGORITHMS


class Operation(str, Enum):
    KEYGEN = "keygen"
    ENCAPS = "encaps"
    DECAPS = "decaps"
    SIGN   = "sign"
    VERIFY = "verify"


# Directorios ACVP (dentro de kat_vectors/) por familia
_ACVP_DIRS_KEM: tuple[str, ...] = ("ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203")
_ACVP_DIRS_MLDSA: tuple[str, ...] = ("ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204", "ML-DSA-sigVer-FIPS204")
_ACVP_DIRS_SLHDSA: tuple[str, ...] = ("SLH-DSA-keyGen-FIPS205", "SLH-DSA-sigGen-FIPS205", "SLH-DSA-sigVer-FIPS205")


@dataclass
class ACVPTestCase:
    """Un test case ACVP normalizado listo para pasar al harness."""

    algorithm: str
    operation: Operation
    tc_id: int
    source: str
    inputs: dict[str, str] = field(default_factory=dict)
    expected: dict[str, str] = field(default_factory=dict)
    deterministic: bool = False
    prehash: str = "pure"

    def is_kem(self) -> bool:
        return self.algorithm in KEM_ALGORITHMS

    def is_sig(self) -> bool:
        return self.algorithm in SIG_ALGORITHMS


def _req(test: dict[str, Any], key: str, source: str, tc_id: int) -> str:
    if key not in test:
        raise PQCValidatorError(f"[{source}] tcId={tc_id}: falta el campo '{key}'")
    return str(test[key])


def _parse_group(group: dict[str, Any], mode: str, algorithm: str, source: str) -> list[ACVPTestCase]:
    tg_id = group.get("tgId", "?")

    if mode == "encapDecap" and group.get("function", "") not in ("encapsulation", "decapsulation"):
        logger.warning("[%s] grupo %s omitido (función no soportada)", source, tg_id)
        return []

    if mode in ("sigGen", "sigVer"):
        if group.get("preHash", "pure") != "pure":
            logger.warning("[%s] grupo %s omitido (preHash != pure)", source, tg_id)
            return []
        if group.get("externalMu", False) or group.get("signatureInterface", "external") != "external":
            logger.warning("[%s] grupo %s omitido", source, tg_id)
            return []

    deterministic = bool(group.get("deterministic", False))
    prehash = str(group.get("preHash", "pure"))
    cases: list[ACVPTestCase] = []

    for test in group.get("tests", []):
        tc_id = int(test.get("tcId", -1))
        if test.get("deferred", False):
            continue

        if mode == "keyGen":
            operation = Operation.KEYGEN
            if algorithm in KEM_ALGORITHMS:
                inputs = {"d": _req(test, "d", source, tc_id), "z": _req(test, "z", source, tc_id)}
                expected = {"ek": _req(test, "ek", source, tc_id), "dk": _req(test, "dk", source, tc_id)}
            elif algorithm in MLDSA_ALGORITHMS:
                inputs = {"seed": _req(test, "seed", source, tc_id)}
                expected = {"pk": _req(test, "pk", source, tc_id), "sk": _req(test, "sk", source, tc_id)}
            else:
                inputs = {"skSeed": _req(test, "skSeed", source, tc_id),
                          "skPrf": _req(test, "skPrf", source, tc_id),
                          "pkSeed": _req(test, "pkSeed", source, tc_id)}
                expected = {"pk": _req(test, "pk", source, tc_id), "sk": _req(test, "sk", source, tc_id)}

        elif mode == "encapDecap":
            if group["function"] == "encapsulation":
                operation = Operation.ENCAPS
                inputs = {"ek": _req(test, "ek", source, tc_id), "m": _req(test, "m", source, tc_id)}
                expected = {"c": _req(test, "c", source, tc_id), "k": _req(test, "k", source, tc_id)}
            else:
                operation = Operation.DECAPS
                inputs = {"dk": _req(test, "dk", source, tc_id), "c": _req(test, "c", source, tc_id)}
                expected = {"k": _req(test, "k", source, tc_id)}

        elif mode == "sigGen":
            operation = Operation.SIGN
            inputs = {"sk": _req(test, "sk", source, tc_id), "pk": _req(test, "pk", source, tc_id),
                      "message": _req(test, "message", source, tc_id),
                      "context": str(test.get("context", ""))}
            expected = {"signature": _req(test, "signature", source, tc_id)}

        elif mode == "sigVer":
            operation = Operation.VERIFY
            inputs = {"pk": _req(test, "pk", source, tc_id),
                      "message": _req(test, "message", source, tc_id),
                      "signature": _req(test, "signature", source, tc_id),
                      "context": str(test.get("context", ""))}
            expected = {"verify": "PASS" if test.get("testPassed", False) else "FAIL"}

        else:
            raise PQCValidatorError(f"[{source}] modo ACVP desconocido: '{mode}'")

        cases.append(ACVPTestCase(algorithm=algorithm, operation=operation, tc_id=tc_id,
                                  source=source, inputs=inputs, expected=expected,
                                  deterministic=deterministic, prehash=prehash))
    return cases


def parse_acvp_file(json_path: Path, algorithm: str) -> list[ACVPTestCase]:
    if not json_path.exists():
        raise PQCValidatorError(f"Fichero ACVP no encontrado: {json_path}")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PQCValidatorError(f"[{json_path.name}] JSON inválido: {exc}") from exc

    mode = data.get("mode")
    if not mode:
        raise PQCValidatorError(f"[{json_path.name}] falta el campo 'mode'")

    source = json_path.parent.name
    cases: list[ACVPTestCase] = []
    for group in data.get("testGroups", []):
        if group.get("parameterSet") == algorithm:
            cases.extend(_parse_group(group, mode, algorithm, source))
    return cases


def load_test_cases(kat_dir: Path, algorithm: str) -> list[ACVPTestCase]:
    """Carga todos los test cases ACVP de un algoritmo desde el directorio de vectores."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise PQCValidatorError(
            f"Algoritmo '{algorithm}' no soportado. Opciones: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )

    dirs = (_ACVP_DIRS_KEM if algorithm in KEM_ALGORITHMS
            else _ACVP_DIRS_MLDSA if algorithm in MLDSA_ALGORITHMS
            else _ACVP_DIRS_SLHDSA)

    all_cases: list[ACVPTestCase] = []
    found_any = False
    for dir_name in dirs:
        json_path = kat_dir / dir_name / "internalProjection.json"
        if not json_path.exists():
            logger.warning("Fichero ACVP ausente: %s (omitido)", json_path)
            continue
        found_any = True
        all_cases.extend(parse_acvp_file(json_path, algorithm))

    if not found_any:
        raise PQCValidatorError(
            f"No se encontró ningún fichero ACVP para {algorithm} en {kat_dir}. "
            "Ejecuta ./scripts/fetch_kats.sh primero."
        )
    return all_cases
