/*
 * kem_harness.c  —  harness genérico para KEM (PQClean / pq-crystals)
 *
 * Los símbolos de la librería y los tamaños se inyectan en tiempo de
 * compilación mediante flags -D.  El binario resultante es específico
 * de un único algoritmo (el argv[2] se ignora).
 *
 * Defines requeridos (ejemplo para PQClean ML-KEM-512):
 *   KEM_KEYPAIR  = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
 *   KEM_ENC      = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
 *   KEM_DEC      = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
 *   KEM_PK_BYTES = 800
 *   KEM_SK_BYTES = 1632
 *   KEM_CT_BYTES = 768
 *   KEM_SS_BYTES = 32
 *
 * Sub-comandos (igual que el harness de liboqs):
 *   kem_harness keygen <alg>                  → EK: <hex>  DK: <hex>
 *   kem_harness encaps <alg> <ek_hex>         → C: <hex>   K: <hex>
 *   kem_harness decaps <alg> <dk_hex> <c_hex> → K: <hex>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Declaraciones de las funciones de la librería (resueltas por el linker). */
extern int KEM_KEYPAIR(uint8_t *pk, uint8_t *sk);
extern int KEM_ENC(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int KEM_DEC(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

static size_t hex_to_bytes(const char *hex, uint8_t **out)
{
    size_t hex_len  = strlen(hex);
    size_t byte_len = hex_len / 2;
    *out = malloc(byte_len > 0 ? byte_len : 1);
    if (!*out) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int b;
        sscanf(hex + 2 * i, "%02X", &b);
        (*out)[i] = (uint8_t)b;
    }
    return byte_len;
}

static int do_keygen(void)
{
    uint8_t pk[KEM_PK_BYTES];
    uint8_t sk[KEM_SK_BYTES];
    if (KEM_KEYPAIR(pk, sk) != 0) {
        fprintf(stderr, "ERROR: keygen falló\n");
        return 1;
    }
    print_hex("EK", pk, KEM_PK_BYTES);
    print_hex("DK", sk, KEM_SK_BYTES);
    return 0;
}

static int do_encaps(const char *ek_hex)
{
    uint8_t *ek = NULL;
    size_t ek_len = hex_to_bytes(ek_hex, &ek);
    if (!ek || ek_len != KEM_PK_BYTES) {
        fprintf(stderr, "ERROR: ek inválida (esperados %d bytes, recibidos %zu)\n",
                KEM_PK_BYTES, ek_len);
        free(ek);
        return 1;
    }
    uint8_t ct[KEM_CT_BYTES];
    uint8_t ss[KEM_SS_BYTES];
    if (KEM_ENC(ct, ss, ek) != 0) {
        fprintf(stderr, "ERROR: encaps falló\n");
        free(ek);
        return 1;
    }
    print_hex("C", ct, KEM_CT_BYTES);
    print_hex("K", ss, KEM_SS_BYTES);
    free(ek);
    return 0;
}

static int do_decaps(const char *dk_hex, const char *c_hex)
{
    uint8_t *dk = NULL, *ct = NULL;
    size_t dk_len = hex_to_bytes(dk_hex, &dk);
    size_t c_len  = hex_to_bytes(c_hex,  &ct);

    if (!dk || dk_len != KEM_SK_BYTES) {
        fprintf(stderr, "ERROR: dk inválida (esperados %d bytes)\n", KEM_SK_BYTES);
        free(dk); free(ct);
        return 1;
    }
    if (!ct || c_len != KEM_CT_BYTES) {
        fprintf(stderr, "ERROR: c inválido (esperados %d bytes)\n", KEM_CT_BYTES);
        free(dk); free(ct);
        return 1;
    }

    uint8_t ss[KEM_SS_BYTES];
    if (KEM_DEC(ss, ct, dk) != 0) {
        fprintf(stderr, "ERROR: decaps falló\n");
        free(dk); free(ct);
        return 1;
    }
    print_hex("K", ss, KEM_SS_BYTES);
    free(dk); free(ct);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Uso: %s keygen|encaps|decaps <alg> [args...]\n", argv[0]);
        return 2;
    }
    const char *op = argv[1];
    /* argv[2] es el nombre del algoritmo — ignorado (binario por algoritmo) */

    if (strcmp(op, "keygen") == 0)
        return do_keygen();

    if (strcmp(op, "encaps") == 0) {
        if (argc != 4) { fprintf(stderr, "Uso: %s encaps <alg> <ek_hex>\n", argv[0]); return 2; }
        return do_encaps(argv[3]);
    }

    if (strcmp(op, "decaps") == 0) {
        if (argc != 5) { fprintf(stderr, "Uso: %s decaps <alg> <dk_hex> <c_hex>\n", argv[0]); return 2; }
        return do_decaps(argv[3], argv[4]);
    }

    fprintf(stderr, "ERROR: operación desconocida: '%s'\n", op);
    return 2;
}
