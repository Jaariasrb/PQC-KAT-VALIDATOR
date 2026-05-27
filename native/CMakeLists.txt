cmake_minimum_required(VERSION 3.16)
project(pqc_native C)

# ---------------------------------------------------------------------------
# libkat_entropy.so — wrapper LD_PRELOAD que inyecta la semilla KAT
# ---------------------------------------------------------------------------
add_library(kat_entropy SHARED kat_entropy.c)
target_link_libraries(kat_entropy PRIVATE dl)   # dlsym(RTLD_NEXT, ...)
set_target_properties(kat_entropy PROPERTIES OUTPUT_NAME kat_entropy)

# ---------------------------------------------------------------------------
# liboqs (compilada por scripts/build_liboqs.sh) — la usan los harnesses
# ---------------------------------------------------------------------------
set(LIBOQS_DIR "${CMAKE_SOURCE_DIR}/../build/liboqs"
    CACHE PATH "Ruta al directorio de instalación de liboqs")

find_library(OQS_LIB oqs
    HINTS "${LIBOQS_DIR}/lib" "${LIBOQS_DIR}/lib64"
    REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h
    HINTS "${LIBOQS_DIR}/include"
    REQUIRED)

# ---------------------------------------------------------------------------
# Harnesses liboqs — ejecutan ML-KEM / ML-DSA / SLH-DSA con liboqs
# Los binarios se generan en <build>/liboqs/ para consistencia multi-librería.
# ---------------------------------------------------------------------------
add_executable(kem_harness liboqs/kem_harness.c)
target_include_directories(kem_harness PRIVATE ${OQS_INCLUDE})
target_link_libraries(kem_harness PRIVATE ${OQS_LIB})
set_target_properties(kem_harness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/liboqs")

add_executable(sig_harness liboqs/sig_harness.c)
target_include_directories(sig_harness PRIVATE ${OQS_INCLUDE})
target_link_libraries(sig_harness PRIVATE ${OQS_LIB})
set_target_properties(sig_harness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/liboqs")
