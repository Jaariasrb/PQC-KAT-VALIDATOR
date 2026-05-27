#!/usr/bin/env bash
# fetch_kats.sh — copia los vectores KAT (formato ACVP) del NIST a kat_vectors/
#
# Uso:
#   ./scripts/fetch_kats.sh [directorio_destino]
#
# Por defecto copia en: kat_vectors/
#
# Fuente: los vectores ACVP oficiales (FIPS 203/204/205) vienen incluidos en el
# código fuente de liboqs, que build_liboqs.sh clona en build/liboqs-src/.
# Cada algoritmo aporta varios directorios con un fichero internalProjection.json.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${1:-${PROJECT_ROOT}/kat_vectors}"
ACVP_SRC="${PROJECT_ROOT}/build/liboqs-src/tests/ACVP_Vectors"

info()  { echo "[fetch-kats] $*"; }
error() { echo "[fetch-kats] ERROR: $*" >&2; exit 1; }

# Directorios ACVP que necesita el validador (KEM + DSA)
ACVP_DIRS=(
    "ML-KEM-keyGen-FIPS203"
    "ML-KEM-encapDecap-FIPS203"
    "ML-DSA-keyGen-FIPS204"
    "ML-DSA-sigGen-FIPS204"
    "ML-DSA-sigVer-FIPS204"
    "SLH-DSA-keyGen-FIPS205"
    "SLH-DSA-sigGen-FIPS205"
    "SLH-DSA-sigVer-FIPS205"
)

# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
if [ ! -d "${ACVP_SRC}" ]; then
    error "No se encuentra ${ACVP_SRC}. Ejecuta ./scripts/build_liboqs.sh primero."
fi

mkdir -p "${OUTPUT_DIR}"
info "Directorio de destino: ${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Copia
# ---------------------------------------------------------------------------
COUNT=0
MISSING=()

for dir_name in "${ACVP_DIRS[@]}"; do
    src="${ACVP_SRC}/${dir_name}"
    if [ ! -f "${src}/internalProjection.json" ]; then
        MISSING+=("${dir_name}")
        continue
    fi
    rm -rf "${OUTPUT_DIR:?}/${dir_name}"
    cp -r "${src}" "${OUTPUT_DIR}/${dir_name}"
    info "${dir_name} → copiado"
    COUNT=$((COUNT + 1))
done

info "Directorios ACVP copiados: ${COUNT}/${#ACVP_DIRS[@]} en ${OUTPUT_DIR}"

if [ ${#MISSING[@]} -gt 0 ]; then
    info "Advertencia: no encontrados en liboqs:"
    for d in "${MISSING[@]}"; do
        info "  - ${d}"
    done
    exit 1
fi
