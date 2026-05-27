#!/usr/bin/env bash
# build_pqcrystals.sh — compila los harnesses KAT para pq-crystals
# (Kyber → ML-KEM, Dilithium → ML-DSA).
#
# Estructura del repo pq-crystals:
#   kyber/ref/       — toda la implementación, parameterizada con -DKYBER_K=N
#   dilithium/ref/   — toda la implementación, parameterizada con -DDILITHIUM_MODE=N
#
# NOTA ACADÉMICA:
#   Kyber y Dilithium son los predecesores de ML-KEM y ML-DSA. A pesar de
#   compartir los mismos tamaños de salida en algunos casos, difieren en la
#   derivación de claves y en otros detalles internos. Validarlos contra los
#   KAT del NIST (FIPS 203/204) permite documentar la divergencia e ilustrar
#   la relevancia de la estandarización.
#
# Resultado:
#   native/build/pqcrystals/<ALGORITMO>/kem_harness   (Kyber)
#   native/build/pqcrystals/<ALGORITMO>/sig_harness   (Dilithium)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

KYBER_SRC="${PROJECT_ROOT}/build/kyber-src"
DILITHIUM_SRC="${PROJECT_ROOT}/build/dilithium-src"

KYBER_REPO="https://github.com/pq-crystals/kyber.git"
DILITHIUM_REPO="https://github.com/pq-crystals/dilithium.git"

# Harness genérico para KEM (mismo que PQClean, compatible con Kyber)
HARNESS_KEM="${PROJECT_ROOT}/native/pqclean/kem_harness.c"
# Harness específico para Dilithium (API de 7 parámetros)
HARNESS_SIG="${PROJECT_ROOT}/native/pqcrystals/sig_harness.c"

OUT_BASE="${PROJECT_ROOT}/native/build/pqcrystals"

KYBER_REF="${KYBER_SRC}/ref"
DILITHIUM_REF="${DILITHIUM_SRC}/ref"

info()  { echo "[build-pqcrystals] $*"; }
error() { echo "[build-pqcrystals] ERROR: $*" >&2; exit 1; }

check_dep() { command -v "$1" >/dev/null 2>&1 || error "Dependencia no encontrada: $1"; }
for dep in git gcc; do check_dep "$dep"; done

# ---------------------------------------------------------------------------
# 1. Clonar repositorios
# ---------------------------------------------------------------------------
if [ ! -d "${KYBER_SRC}/.git" ]; then
    info "Clonando pq-crystals/kyber…"
    git clone --depth 1 "${KYBER_REPO}" "${KYBER_SRC}"
else
    info "kyber ya presente."
fi

if [ ! -d "${DILITHIUM_SRC}/.git" ]; then
    info "Clonando pq-crystals/dilithium…"
    git clone --depth 1 "${DILITHIUM_REPO}" "${DILITHIUM_SRC}"
else
    info "dilithium ya presente."
fi

# ---------------------------------------------------------------------------
# Función: compila harness KEM para Kyber con KYBER_K dado
#
#   compile_kyber <ALGORITMO_SALIDA> <KYBER_K> <NAMESPACE> <PK> <SK> <CT> <SS>
#
# El repo kyber/ref/ usa KYBER_K para seleccionar el nivel de seguridad.
# Los nombres de función son: pqcrystals_kyber{512|768|1024}_ref_keypair, etc.
# ---------------------------------------------------------------------------
compile_kyber() {
    local alg="$1" k="$2" ns="$3"
    local pk="$4" sk="$5" ct="$6" ss="$7"
    local out_dir="${OUT_BASE}/${alg}"
    mkdir -p "${out_dir}"

    info "Compilando KEM harness (Kyber${k}) para ${alg}…"
    gcc -O2 \
        -DKYBER_K="${k}" \
        -DKEM_KEYPAIR="${ns}_keypair" \
        -DKEM_ENC="${ns}_enc" \
        -DKEM_DEC="${ns}_dec" \
        -DKEM_PK_BYTES="${pk}" \
        -DKEM_SK_BYTES="${sk}" \
        -DKEM_CT_BYTES="${ct}" \
        -DKEM_SS_BYTES="${ss}" \
        -I"${KYBER_REF}" \
        "${HARNESS_KEM}" \
        "${KYBER_REF}"/*.c \
        -o "${out_dir}/kem_harness"
    info "  → ${out_dir}/kem_harness"
}

# ---------------------------------------------------------------------------
# Función: compila harness SIG para Dilithium con DILITHIUM_MODE dado
#
#   compile_dilithium <ALGORITMO_SALIDA> <MODE> <NAMESPACE> <PK> <SK> <SIG_MAX>
# ---------------------------------------------------------------------------
compile_dilithium() {
    local alg="$1" mode="$2" ns="$3"
    local pk="$4" sk="$5" sig_max="$6"
    local out_dir="${OUT_BASE}/${alg}"
    mkdir -p "${out_dir}"

    info "Compilando SIG harness (Dilithium${mode}) para ${alg}…"
    gcc -O2 \
        -DDILITHIUM_MODE="${mode}" \
        -DSIG_KEYPAIR="${ns}_keypair" \
        -DSIG_SIGN="${ns}_signature" \
        -DSIG_VERIFY="${ns}_verify" \
        -DSIG_PK_BYTES="${pk}" \
        -DSIG_SK_BYTES="${sk}" \
        -DSIG_MAX_SIG_BYTES="${sig_max}" \
        -I"${DILITHIUM_REF}" \
        "${HARNESS_SIG}" \
        "${DILITHIUM_REF}"/*.c \
        -o "${out_dir}/sig_harness"
    info "  → ${out_dir}/sig_harness"
}

# ---------------------------------------------------------------------------
# 2. Kyber → equivalente a ML-KEM (mismos tamaños de salida)
# ---------------------------------------------------------------------------
compile_kyber "ML-KEM-512"  2 "pqcrystals_kyber512_ref"   800  1632  768  32
compile_kyber "ML-KEM-768"  3 "pqcrystals_kyber768_ref"  1184  2400 1088  32
compile_kyber "ML-KEM-1024" 4 "pqcrystals_kyber1024_ref" 1568  3168 1568  32

# ---------------------------------------------------------------------------
# 3. Dilithium → equivalente a ML-DSA (SK y SIG tienen tamaños distintos)
#    Tamaños reales de Dilithium (distintos de FIPS 204):
#      dilithium2: SK=2560 (ML-DSA-44: 2528), SIG=2420
#      dilithium3: SK=4032 (ML-DSA-65: 4000), SIG=3309 (ML-DSA-65: 3293)
#      dilithium5: SK=4896 (ML-DSA-87: 4864), SIG=4627 (ML-DSA-87: 4595)
# ---------------------------------------------------------------------------
compile_dilithium "ML-DSA-44" 2 "pqcrystals_dilithium2_ref" 1312 2560 2420
compile_dilithium "ML-DSA-65" 3 "pqcrystals_dilithium3_ref" 1952 4032 3309
compile_dilithium "ML-DSA-87" 5 "pqcrystals_dilithium5_ref" 2592 4896 4627

info "build_pqcrystals.sh completado (SLH-DSA no disponible en pq-crystals)."
info "Binarios en ${OUT_BASE}/:"
ls -1 "${OUT_BASE}/"
