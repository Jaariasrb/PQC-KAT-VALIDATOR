#!/usr/bin/env bash
# build_liboqs.sh — compila liboqs, libkat_entropy.so y los harnesses nativos
#
# Uso:
#   ./scripts/build_liboqs.sh
#
# Resultado:
#   build/liboqs/              → instalación de liboqs (headers + .so)
#   native/build/libkat_entropy.so
#   native/build/liboqs/kem_harness
#   native/build/liboqs/sig_harness

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LIBOQS_SRC="${PROJECT_ROOT}/build/liboqs-src"
LIBOQS_INSTALL="${PROJECT_ROOT}/build/liboqs"
LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"
LIBOQS_TAG="0.15.0"

NATIVE_DIR="${PROJECT_ROOT}/native"

JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

info()  { echo "[build] $*"; }
error() { echo "[build] ERROR: $*" >&2; exit 1; }

check_dep() {
    command -v "$1" >/dev/null 2>&1 || error "Dependencia no encontrada: $1. Instálala antes de continuar."
}

# ---------------------------------------------------------------------------
# Comprobación de dependencias
# ---------------------------------------------------------------------------
info "Comprobando dependencias…"
for dep in git cmake gcc make; do
    check_dep "$dep"
done
info "Dependencias OK."

# ---------------------------------------------------------------------------
# 1. Clonar y compilar liboqs (si no existe ya)
# ---------------------------------------------------------------------------
if [ ! -d "${LIBOQS_SRC}/.git" ]; then
    info "Clonando liboqs ${LIBOQS_TAG} en ${LIBOQS_SRC}…"
    git clone --depth 1 --branch "${LIBOQS_TAG}" "${LIBOQS_REPO}" "${LIBOQS_SRC}"
else
    info "Código fuente de liboqs ya presente, omitiendo clone."
fi

info "Compilando liboqs (puede tardar varios minutos)…"
cmake -S "${LIBOQS_SRC}" \
      -B "${LIBOQS_SRC}/build" \
      -DCMAKE_INSTALL_PREFIX="${LIBOQS_INSTALL}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DOQS_ALGS_ENABLED=STD \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON

cmake --build "${LIBOQS_SRC}/build" --parallel "${JOBS}"
cmake --install "${LIBOQS_SRC}/build"
info "liboqs instalado en ${LIBOQS_INSTALL}."

# ---------------------------------------------------------------------------
# 2. Compilar libkat_entropy.so y los harnesses (un solo proyecto CMake)
# ---------------------------------------------------------------------------
info "Compilando libkat_entropy.so y los harnesses…"
cmake -S "${NATIVE_DIR}" \
      -B "${NATIVE_DIR}/build" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLIBOQS_DIR="${LIBOQS_INSTALL}"

cmake --build "${NATIVE_DIR}/build" --parallel "${JOBS}"

[ -f "${NATIVE_DIR}/build/libkat_entropy.so" ] || error "No se generó libkat_entropy.so"
for artifact in kem_harness sig_harness; do
    [ -f "${NATIVE_DIR}/build/liboqs/${artifact}" ] || error "No se generó liboqs/${artifact}"
done

info "Build completado correctamente."
info "  liboqs          : ${LIBOQS_INSTALL}"
info "  libkat_entropy  : ${NATIVE_DIR}/build/libkat_entropy.so"
info "  kem_harness     : ${NATIVE_DIR}/build/liboqs/kem_harness"
info "  sig_harness     : ${NATIVE_DIR}/build/liboqs/sig_harness"
