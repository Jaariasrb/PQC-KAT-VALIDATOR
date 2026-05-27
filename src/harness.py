"""Inyección de entropía KAT (LD_PRELOAD) y ejecución de harnesses nativos."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from src.parser import SLHDSA_ALGORITHMS, ACVPTestCase, Operation, PQCValidatorError

logger = logging.getLogger(__name__)

LIBRARIES: tuple[str, ...] = ("liboqs", "pqclean", "pqcrystals")

_BUILD      = Path(__file__).resolve().parents[1] / "native" / "build"
_SO_PATH    = _BUILD / "libkat_entropy.so"
_TIMEOUT    = 60
_SIGN_RND   = 64  # bytes de ceros para firma ML-DSA determinista

_LIBOQS_ALG_NAMES: dict[str, str] = {
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
}


def _build_seed(case: ACVPTestCase) -> bytes | None:
    """Devuelve la aleatoriedad que consume la operación (None si es determinista)."""
    op = case.operation

    if op in (Operation.DECAPS, Operation.VERIFY):
        return None

    if op == Operation.ENCAPS:
        return bytes.fromhex(case.inputs["m"])

    if op == Operation.SIGN:
        if case.deterministic and case.algorithm in SLHDSA_ALGORITHMS:
            pk = bytes.fromhex(case.inputs["pk"])
            return pk[: len(pk) // 2]
        return bytes(_SIGN_RND)

    if op == Operation.KEYGEN:
        if case.is_kem():
            return bytes.fromhex(case.inputs["d"]) + bytes.fromhex(case.inputs["z"])
        if "seed" in case.inputs:
            return bytes.fromhex(case.inputs["seed"])
        return (bytes.fromhex(case.inputs["skSeed"])
                + bytes.fromhex(case.inputs["skPrf"])
                + bytes.fromhex(case.inputs["pkSeed"]))

    raise PQCValidatorError(f"Operación sin semilla definida: {op}")


@contextmanager
def _seed_file(case: ACVPTestCase) -> Generator[Path | None, None, None]:
    seed = _build_seed(case)
    if seed is None:
        yield None
        return
    with tempfile.NamedTemporaryFile(prefix="kat_seed_", suffix=".bin", delete=True) as tmp:
        tmp.write(seed)
        tmp.flush()
        yield Path(tmp.name)


def _injection_env(seed_path: Path) -> dict[str, str]:
    if not _SO_PATH.exists():
        raise PQCValidatorError(
            f"libkat_entropy.so no encontrado en {_SO_PATH}. "
            "Ejecuta ./scripts/build_liboqs.sh primero."
        )
    env = dict(os.environ)
    env["LD_PRELOAD"]    = str(_SO_PATH)
    env["KAT_SEED_FILE"] = str(seed_path)
    return env


def _parse_output(stdout: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if ": " not in line:
            raise PQCValidatorError(f"Salida del harness con formato inesperado: {line!r}")
        field, _, value = line.partition(": ")
        result[field.strip().lower()] = value.strip()
    return result


class Harness:
    """Ejecuta el harness nativo de una librería para un ACVPTestCase."""

    def __init__(self, library: str, algorithm: str) -> None:
        if library not in LIBRARIES:
            raise PQCValidatorError(f"Librería no soportada: '{library}'. Opciones: {', '.join(LIBRARIES)}")
        self._library  = library
        self._algorithm = algorithm
        self._dir = _BUILD / "liboqs" if library == "liboqs" else _BUILD / library / algorithm
        if not self._dir.exists():
            raise PQCValidatorError(
                f"Harness de '{library}' para {algorithm} no encontrado en {self._dir}. "
                f"Ejecuta ./scripts/build_{library}.sh primero."
            )

    def run(self, case: ACVPTestCase) -> dict[str, str]:
        binary = "kem_harness" if case.is_kem() else "sig_harness"
        args   = self._args(case)
        with _seed_file(case) as seed_path:
            env = _injection_env(seed_path) if seed_path is not None else None
            return self._exec(binary, args, env)

    def _exec(self, binary: str, args: list[str], env: dict[str, str] | None) -> dict[str, str]:
        path = self._dir / binary
        if not path.exists():
            raise PQCValidatorError(
                f"Binario '{binary}' no encontrado en {self._dir}. "
                f"Ejecuta ./scripts/build_{self._library}.sh primero."
            )
        try:
            r = subprocess.run([str(path), *args], env=env,
                               capture_output=True, text=True, timeout=_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise PQCValidatorError(f"Timeout ({_TIMEOUT}s) ejecutando {binary}") from exc
        if r.returncode != 0:
            raise PQCValidatorError(
                f"{binary} {' '.join(args[:2])} terminó con código {r.returncode}.\n"
                f"stderr: {r.stderr.strip()}"
            )
        return _parse_output(r.stdout)

    def _args(self, case: ACVPTestCase) -> list[str]:
        op  = case.operation
        alg = _LIBOQS_ALG_NAMES.get(case.algorithm, case.algorithm) if self._library == "liboqs" else case.algorithm

        if op == Operation.KEYGEN:
            return ["keygen", alg]
        if op == Operation.ENCAPS:
            return ["encaps", alg, case.inputs["ek"]]
        if op == Operation.DECAPS:
            return ["decaps", alg, case.inputs["dk"], case.inputs["c"]]
        if op == Operation.SIGN:
            args = ["sign", alg, case.inputs["sk"], case.inputs["message"]]
            if case.inputs.get("context", ""):
                args.append(case.inputs["context"])
            return args
        if op == Operation.VERIFY:
            args = ["verify", alg, case.inputs["pk"], case.inputs["message"], case.inputs["signature"]]
            if case.inputs.get("context", ""):
                args.append(case.inputs["context"])
            return args
        raise PQCValidatorError(f"Operación no soportada: {op}")
