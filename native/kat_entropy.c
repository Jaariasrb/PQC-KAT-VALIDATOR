/*
 * kat_entropy.c
 *
 * Librería LD_PRELOAD que intercepta las llamadas al RNG del sistema operativo
 * y las sustituye por los bytes de la semilla KAT del NIST.
 *
 * Uso:
 *   LD_PRELOAD=libkat_entropy.so KAT_SEED_FILE=/tmp/seed.bin ./kem_harness keygen ML-KEM-768
 *
 * Funciones interceptadas:
 *   randombytes(buf, n)        — API histórica de los KAT del NIST
 *   getrandom(buf, n, flags)   — llamada estándar del kernel de Linux
 *   getentropy(buf, n)         — la que usa liboqs (OQS_randombytes_system)
 *
 * Modelo SECUENCIAL:
 *   El fichero de semilla es la concatenación exacta de la aleatoriedad que el
 *   algoritmo consume, en orden. Un offset global avanza con cada llamada:
 *   la 1ª lectura toma los bytes [0, n), la 2ª toma [n, 2n), etc. Así keygen
 *   puede pedir aleatoriedad varias veces (p. ej. d y luego z) y cada llamada
 *   recibe el bloque correcto en lugar de releer siempre desde el principio.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

/* Bytes ya consumidos del fichero de semilla en este proceso. */
static size_t g_seed_offset = 0;

/*
 * Lee los siguientes n bytes de la semilla KAT (desde g_seed_offset) y los
 * copia en buf, avanzando el offset. La ruta del fichero viene de la variable
 * de entorno KAT_SEED_FILE.
 */
static void read_seed_file(void *buf, size_t n)
{
    const char *path = getenv("KAT_SEED_FILE");
    if (!path) {
        fprintf(stderr, "[kat_entropy] ERROR: KAT_SEED_FILE no está definida\n");
        abort();
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[kat_entropy] ERROR: no se puede abrir %s\n", path);
        abort();
    }

    /* Saltar los bytes ya consumidos por llamadas anteriores. */
    if (fseek(f, (long)g_seed_offset, SEEK_SET) != 0) {
        fprintf(stderr,
            "[kat_entropy] ERROR: no se puede posicionar en offset %zu de %s\n",
            g_seed_offset, path);
        fclose(f);
        abort();
    }

    size_t got = fread(buf, 1, n, f);
    fclose(f);

    if (got != n) {
        fprintf(stderr,
            "[kat_entropy] ERROR: pedí %zu bytes en offset %zu pero solo había %zu "
            "(semilla agotada)\n",
            n, g_seed_offset, got);
        abort();
    }

    g_seed_offset += n;
}

/*
 * randombytes — API histórica de los KAT del NIST. liboqs no la usa por
 * defecto, pero se intercepta por compatibilidad con otras implementaciones.
 */
void randombytes(uint8_t *buf, size_t n)
{
    read_seed_file(buf, n);
}

/*
 * getrandom — llamada estándar del kernel de Linux.
 * Si KAT_SEED_FILE está definida usamos la semilla; si no, la real.
 */
int getrandom(void *buf, size_t n, unsigned int flags)
{
    if (getenv("KAT_SEED_FILE")) {
        read_seed_file(buf, n);
        return (int)n;
    }

    typedef int (*getrandom_fn)(void *, size_t, unsigned int);
    getrandom_fn real_getrandom = (getrandom_fn)dlsym(RTLD_NEXT, "getrandom");
    if (!real_getrandom) {
        fprintf(stderr, "[kat_entropy] ERROR: no se encontró getrandom real\n");
        abort();
    }
    return real_getrandom(buf, n, flags);
}

/*
 * getentropy — la que usa liboqs internamente (OQS_randombytes_system).
 * Si KAT_SEED_FILE está definida usamos la semilla; si no, la real.
 * Devuelve 0 en éxito, igual que la getentropy real.
 */
int getentropy(void *buf, size_t n)
{
    if (getenv("KAT_SEED_FILE")) {
        read_seed_file(buf, n);
        return 0;
    }

    typedef int (*getentropy_fn)(void *, size_t);
    getentropy_fn real_getentropy = (getentropy_fn)dlsym(RTLD_NEXT, "getentropy");
    if (!real_getentropy) {
        fprintf(stderr, "[kat_entropy] ERROR: no se encontró getentropy real\n");
        abort();
    }
    return real_getentropy(buf, n);
}
