#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

/* Imprime un array de bytes en hexadecimal con un prefijo. */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

/* Convierte una cadena hex (ej. "AABB0C") a bytes. Devuelve la longitud en bytes. */
static size_t hex_to_bytes(const char *hex, uint8_t **out)
{
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    *out = malloc(byte_len);
    if (!*out) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02X", &byte);
        (*out)[i] = (uint8_t)byte;
    }
    return byte_len;
}

/* keygen: genera el par de claves usando la aleatoriedad inyectada. */
static int do_keygen(OQS_KEM *kem)
{
    uint8_t *ek = malloc(kem->length_public_key);
    uint8_t *dk = malloc(kem->length_secret_key);
    if (!ek || !dk) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        return 1;
    }

    if (OQS_KEM_keypair(kem, ek, dk) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_keypair falló\n");
        return 1;
    }

    print_hex("EK", ek, kem->length_public_key);
    print_hex("DK", dk, kem->length_secret_key);

    free(ek);
    free(dk);
    return 0;
}

/* encaps: encapsula usando la ek dada y la aleatoriedad inyectada. */
static int do_encaps(OQS_KEM *kem, const char *ek_hex)
{
    uint8_t *ek = NULL;
    size_t ek_len = hex_to_bytes(ek_hex, &ek);
    if (!ek) {
        fprintf(stderr, "ERROR: fallo al convertir ek hex\n");
        return 1;
    }
    if (ek_len != kem->length_public_key) {
        fprintf(stderr, "ERROR: ek tiene %zu bytes, se esperan %zu\n",
                ek_len, kem->length_public_key);
        free(ek);
        return 1;
    }

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    if (!ct || !ss) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        free(ek);
        return 1;
    }

    if (OQS_KEM_encaps(kem, ct, ss, ek) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_encaps falló\n");
        return 1;
    }

    print_hex("C", ct, kem->length_ciphertext);
    print_hex("K", ss, kem->length_shared_secret);

    free(ek);
    free(ct);
    free(ss);
    return 0;
}

/* decaps: decapsula usando la dk y el ciphertext dados (operación determinista). */
static int do_decaps(OQS_KEM *kem, const char *dk_hex, const char *c_hex)
{
    uint8_t *dk = NULL;
    uint8_t *ct = NULL;
    size_t dk_len = hex_to_bytes(dk_hex, &dk);
    size_t c_len  = hex_to_bytes(c_hex, &ct);
    if (!dk || !ct) {
        fprintf(stderr, "ERROR: fallo al convertir dk/c hex\n");
        free(dk); free(ct);
        return 1;
    }
    if (dk_len != kem->length_secret_key) {
        fprintf(stderr, "ERROR: dk tiene %zu bytes, se esperan %zu\n",
                dk_len, kem->length_secret_key);
        free(dk); free(ct);
        return 1;
    }
    if (c_len != kem->length_ciphertext) {
        fprintf(stderr, "ERROR: c tiene %zu bytes, se esperan %zu\n",
                c_len, kem->length_ciphertext);
        free(dk); free(ct);
        return 1;
    }

    uint8_t *ss = malloc(kem->length_shared_secret);
    if (!ss) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        free(dk); free(ct);
        return 1;
    }

    if (OQS_KEM_decaps(kem, ss, ct, dk) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps falló\n");
        return 1;
    }

    print_hex("K", ss, kem->length_shared_secret);

    free(dk);
    free(ct);
    free(ss);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Uso:\n");
    fprintf(stderr, "  %s keygen <alg>\n", prog);
    fprintf(stderr, "  %s encaps <alg> <ek_hex>\n", prog);
    fprintf(stderr, "  %s decaps <alg> <dk_hex> <c_hex>\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    const char *op       = argv[1];
    const char *alg_name = argv[2];

    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        fprintf(stderr, "ERROR: algoritmo '%s' no reconocido por liboqs\n", alg_name);
        return 1;
    }

    int rc;
    if (strcmp(op, "keygen") == 0) {
        rc = do_keygen(kem);
    } else if (strcmp(op, "encaps") == 0) {
        if (argc != 4) { usage(argv[0]); rc = 2; }
        else rc = do_encaps(kem, argv[3]);
    } else if (strcmp(op, "decaps") == 0) {
        if (argc != 5) { usage(argv[0]); rc = 2; }
        else rc = do_decaps(kem, argv[3], argv[4]);
    } else {
        fprintf(stderr, "ERROR: sub-comando '%s' no reconocido\n", op);
        usage(argv[0]);
        rc = 2;
    }

    OQS_KEM_free(kem);
    return rc;
}
