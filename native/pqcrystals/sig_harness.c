#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int SIG_KEYPAIR(uint8_t *pk, uint8_t *sk);

/* Dilithium signature incluye ctx y ctxlen */
extern int SIG_SIGN(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *ctx, size_t ctxlen,
                    const uint8_t *sk);

extern int SIG_VERIFY(const uint8_t *sig, size_t siglen,
                      const uint8_t *m, size_t mlen,
                      const uint8_t *ctx, size_t ctxlen,
                      const uint8_t *pk);

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
    uint8_t pk[SIG_PK_BYTES];
    uint8_t sk[SIG_SK_BYTES];
    if (SIG_KEYPAIR(pk, sk) != 0) {
        fprintf(stderr, "ERROR: keygen falló\n");
        return 1;
    }
    print_hex("PK", pk, SIG_PK_BYTES);
    print_hex("SK", sk, SIG_SK_BYTES);
    return 0;
}

static int do_sign(const char *sk_hex, const char *msg_hex, const char *ctx_hex)
{
    uint8_t *sk = NULL, *msg = NULL;
    size_t sk_len  = hex_to_bytes(sk_hex,  &sk);
    size_t msg_len = hex_to_bytes(msg_hex, &msg);

    if (!sk || sk_len != SIG_SK_BYTES) {
        fprintf(stderr, "ERROR: sk inválida (esperados %d bytes, recibidos %zu)\n",
                SIG_SK_BYTES, sk_len);
        free(sk); free(msg);
        return 1;
    }
    if (!msg) {
        fprintf(stderr, "ERROR: fallo al convertir msg hex\n");
        free(sk);
        return 1;
    }

    /* ctx ignorado — Dilithium no soporta contexto FIPS 204 */
    (void)ctx_hex;

    uint8_t *sig = malloc(SIG_MAX_SIG_BYTES);
    size_t sig_len = 0;
    if (!sig) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        free(sk); free(msg);
        return 1;
    }

    if (SIG_SIGN(sig, &sig_len, msg, msg_len, NULL, 0, sk) != 0) {
        fprintf(stderr, "ERROR: firma falló\n");
        free(sk); free(msg); free(sig);
        return 1;
    }

    print_hex("SIGNATURE", sig, sig_len);
    free(sk); free(msg); free(sig);
    return 0;
}

static int do_verify(const char *pk_hex, const char *msg_hex,
                     const char *sig_hex, const char *ctx_hex)
{
    (void)ctx_hex;

    uint8_t *pk = NULL, *msg = NULL, *sig = NULL;
    size_t pk_len  = hex_to_bytes(pk_hex,  &pk);
    size_t msg_len = hex_to_bytes(msg_hex, &msg);
    size_t sig_len = hex_to_bytes(sig_hex, &sig);

    if (!pk || pk_len != SIG_PK_BYTES) {
        fprintf(stderr, "ERROR: pk inválida (esperados %d bytes)\n", SIG_PK_BYTES);
        free(pk); free(msg); free(sig);
        return 1;
    }
    if (!msg || !sig) {
        fprintf(stderr, "ERROR: fallo al convertir msg/sig hex\n");
        free(pk); free(msg); free(sig);
        return 1;
    }

    int rc = SIG_VERIFY(sig, sig_len, msg, msg_len, NULL, 0, pk);
    printf("VERIFY: %s\n", rc == 0 ? "PASS" : "FAIL");

    free(pk); free(msg); free(sig);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Uso: %s keygen|sign|verify <alg> [args...]\n", argv[0]);
        return 2;
    }
    const char *op = argv[1];

    if (strcmp(op, "keygen") == 0)
        return do_keygen();

    if (strcmp(op, "sign") == 0) {
        if (argc < 5 || argc > 6) {
            fprintf(stderr, "Uso: %s sign <alg> <sk_hex> <msg_hex> [ctx_hex]\n", argv[0]);
            return 2;
        }
        return do_sign(argv[3], argv[4], argc == 6 ? argv[5] : NULL);
    }

    if (strcmp(op, "verify") == 0) {
        if (argc < 6 || argc > 7) {
            fprintf(stderr, "Uso: %s verify <alg> <pk_hex> <msg_hex> <sig_hex> [ctx_hex]\n", argv[0]);
            return 2;
        }
        return do_verify(argv[3], argv[4], argv[5], argc == 7 ? argv[6] : NULL);
    }

    fprintf(stderr, "ERROR: operación desconocida: '%s'\n", op);
    return 2;
}
