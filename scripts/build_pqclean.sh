#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PQCLEAN_SRC="${PROJECT_ROOT}/build/pqclean-src"
PQCLEAN_REPO="https://github.com/PQClean/PQClean.git"
PQCLEAN_TAG="master"

NATIVE_PQCLEAN="${PROJECT_ROOT}/native/pqclean"
OUT_BASE="${PROJECT_ROOT}/native/build/pqclean"

info()  { echo "[build-pqclean] $*"; }
error() { echo "[build-pqclean] ERROR: $*" >&2; exit 1; }

check_dep() {
    command -v "$1" >/dev/null 2>&1 || error "Dependencia no encontrada: $1"
}

# ---------------------------------------------------------------------------
# Dependencias
# ---------------------------------------------------------------------------
for dep in git gcc; do check_dep "$dep"; done

# ---------------------------------------------------------------------------
# 1. Clonar PQClean
# ---------------------------------------------------------------------------
if [ ! -d "${PQCLEAN_SRC}/.git" ]; then
    info "Clonando PQClean en ${PQCLEAN_SRC}…"
    git clone --depth 1 --branch "${PQCLEAN_TAG}" "${PQCLEAN_REPO}" "${PQCLEAN_SRC}"
else
    info "PQClean ya presente, omitiendo clone."
fi

COMMON="${PQCLEAN_SRC}/common"

# ---------------------------------------------------------------------------
# Función auxiliar: compila un harness KEM para una variante de PQClean
#
#   compile_kem <ALGORITMO_SALIDA> <DIR_ALG_PQCLEAN> <PREFIX> <PK> <SK> <CT> <SS>
# ---------------------------------------------------------------------------
compile_kem() {
    local alg="$1"   # nombre de salida, p.ej. "ML-KEM-512"
    local alg_dir="$2"
    local prefix="$3"
    local pk="$4" sk="$5" ct="$6" ss="$7"

    local out_dir="${OUT_BASE}/${alg}"
    mkdir -p "${out_dir}"

    info "Compilando KEM harness para ${alg}…"
    gcc -O2 \
        -DKEM_KEYPAIR="${prefix}crypto_kem_keypair" \
        -DKEM_ENC="${prefix}crypto_kem_enc" \
        -DKEM_DEC="${prefix}crypto_kem_dec" \
        -DKEM_PK_BYTES="${pk}" \
        -DKEM_SK_BYTES="${sk}" \
        -DKEM_CT_BYTES="${ct}" \
        -DKEM_SS_BYTES="${ss}" \
        -I"${alg_dir}" \
        -I"${COMMON}" \
        "${NATIVE_PQCLEAN}/kem_harness.c" \
        "${alg_dir}"/*.c \
        "${COMMON}/randombytes.c" \
        "${COMMON}/fips202.c" \
        -o "${out_dir}/kem_harness"
    info "  → ${out_dir}/kem_harness"
}

# ---------------------------------------------------------------------------
# Función auxiliar: compila un harness SIG para una variante de PQClean
#
#   compile_sig <ALGORITMO_SALIDA> <DIR_ALG_PQCLEAN> <PREFIX> <PK> <SK> <SIG_MAX>
#               [archivos_comunes_adicionales...]
# ---------------------------------------------------------------------------
compile_sig() {
    local alg="$1"
    local alg_dir="$2"
    local prefix="$3"
    local pk="$4" sk="$5" sig_max="$6"
    shift 6
    local extra_common=("$@")

    local out_dir="${OUT_BASE}/${alg}"
    mkdir -p "${out_dir}"

    info "Compilando SIG harness para ${alg}…"

    local common_files=("${COMMON}/randombytes.c" "${COMMON}/fips202.c")
    for f in "${extra_common[@]}"; do
        common_files+=("${COMMON}/${f}")
    done

    gcc -O2 \
        -DSIG_KEYPAIR="${prefix}crypto_sign_keypair" \
        -DSIG_SIGN="${prefix}crypto_sign_signature" \
        -DSIG_VERIFY="${prefix}crypto_sign_verify" \
        -DSIG_PK_BYTES="${pk}" \
        -DSIG_SK_BYTES="${sk}" \
        -DSIG_MAX_SIG_BYTES="${sig_max}" \
        -I"${alg_dir}" \
        -I"${COMMON}" \
        "${NATIVE_PQCLEAN}/sig_harness.c" \
        "${alg_dir}"/*.c \
        "${common_files[@]}" \
        -o "${out_dir}/sig_harness"
    info "  → ${out_dir}/sig_harness"
}

# ---------------------------------------------------------------------------
# 2. ML-KEM (FIPS 203) — KEM harnesses
# ---------------------------------------------------------------------------
compile_kem "ML-KEM-512"  "${PQCLEAN_SRC}/crypto_kem/ml-kem-512/clean"  \
    "PQCLEAN_MLKEM512_CLEAN_"   800  1632  768  32

compile_kem "ML-KEM-768"  "${PQCLEAN_SRC}/crypto_kem/ml-kem-768/clean"  \
    "PQCLEAN_MLKEM768_CLEAN_"  1184  2400 1088  32

compile_kem "ML-KEM-1024" "${PQCLEAN_SRC}/crypto_kem/ml-kem-1024/clean" \
    "PQCLEAN_MLKEM1024_CLEAN_" 1568  3168 1568  32

# ---------------------------------------------------------------------------
# 3. ML-DSA (FIPS 204) — SIG harnesses
#    ML-DSA usa sha2 internamente además de fips202.
# ---------------------------------------------------------------------------
compile_sig "ML-DSA-44" "${PQCLEAN_SRC}/crypto_sign/ml-dsa-44/clean" \
    "PQCLEAN_MLDSA44_CLEAN_" 1312 2560 2420 "sha2.c"

compile_sig "ML-DSA-65" "${PQCLEAN_SRC}/crypto_sign/ml-dsa-65/clean" \
    "PQCLEAN_MLDSA65_CLEAN_" 1952 4032 3309 "sha2.c"

compile_sig "ML-DSA-87" "${PQCLEAN_SRC}/crypto_sign/ml-dsa-87/clean" \
    "PQCLEAN_MLDSA87_CLEAN_" 2592 4896 4627 "sha2.c"

# ---------------------------------------------------------------------------
# 4. SLH-DSA-SHA2-128s (FIPS 205) — mapeado a sphincs-sha2-128s-simple
# ---------------------------------------------------------------------------
compile_sig "SLH-DSA-SHA2-128s" \
    "${PQCLEAN_SRC}/crypto_sign/sphincs-sha2-128s-simple/clean" \
    "PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_" 32 64 7856 "sha2.c"

info "build_pqclean.sh completado. Binarios en ${OUT_BASE}/:"
ls -1 "${OUT_BASE}/"
