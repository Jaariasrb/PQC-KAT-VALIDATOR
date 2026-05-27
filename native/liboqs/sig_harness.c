/*
 * sig_harness.c
 *
 * Ejecuta operaciones de ML-DSA / SLH-DSA con liboqs y escribe el resultado
 * por stdout en formato "CAMPO: hexvalor".
 *
 * Sub-comandos:
 *   sig_harness keygen <alg>
 *       Lee la semilla KAT (vía LD_PRELOAD) y genera el par de claves.
 *       Salida:  PK: <hex>
 *                SK: <hex>
 *
 *   sig_harness sign <alg> <sk_hex> <msg_hex> [ctx_hex]
 *       Firma el mensaje con la sk indicada. ctx_hex es opcional (contexto FIPS).
 *       La aleatoriedad de firma (si la hay) se toma de la semilla KAT.
 *       Salida:  SIGNATURE: <hex>
 *
 *   sig_harness verify <alg> <pk_hex> <msg_hex> <sig_hex> [ctx_hex]
 *       Verifica la firma. Operación determinista, sin semilla.
 *       Salida:  VERIFY: PASS   o   VERIFY: FAIL
 *
 * Nota: en 'verify', un FAIL es un resultado válido y esperado (algunos
 * vectores ACVP traen firmas inválidas a propósito). Por eso 'verify'
 * devuelve código 0 tanto si PASA como si FALLA — solo devuelve error
 * ante un fallo real (hex inválido, longitudes incorrectas, etc.).
 */

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

/*
 * Convierte una cadena hex a bytes. Devuelve la longitud en bytes.
 * Para una cadena vacía reserva 1 byte dummy y devuelve 0 (mensaje vacío válido).
 */
static size_t hex_to_bytes(const char *hex, uint8_t **out)
{
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    *out = malloc(byte_len > 0 ? byte_len : 1);
    if (!*out) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02X", &byte);
        (*out)[i] = (uint8_t)byte;
    }
    return byte_len;
}

/* keygen: genera el par de claves usando la aleatoriedad inyectada. */
static int do_keygen(OQS_SIG *sig)
{
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (!pk || !sk) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        return 1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_keypair falló\n");
        return 1;
    }

    print_hex("PK", pk, sig->length_public_key);
    print_hex("SK", sk, sig->length_secret_key);

    free(pk);
    free(sk);
    return 0;
}

/* sign: firma msg con sk. ctx_hex opcional (NULL → contexto vacío). */
static int do_sign(OQS_SIG *sig, const char *sk_hex, const char *msg_hex,
                   const char *ctx_hex)
{
    uint8_t *sk = NULL, *msg = NULL, *ctx = NULL;
    size_t sk_len  = hex_to_bytes(sk_hex, &sk);
    size_t msg_len = hex_to_bytes(msg_hex, &msg);
    size_t ctx_len = ctx_hex ? hex_to_bytes(ctx_hex, &ctx) : 0;

    if (!sk || !msg) {
        fprintf(stderr, "ERROR: fallo al convertir sk/msg hex\n");
        free(sk); free(msg); free(ctx);
        return 1;
    }
    if (sk_len != sig->length_secret_key) {
        fprintf(stderr, "ERROR: sk tiene %zu bytes, se esperan %zu\n",
                sk_len, sig->length_secret_key);
        free(sk); free(msg); free(ctx);
        return 1;
    }

    uint8_t *signature = malloc(sig->length_signature);
    size_t   sig_len   = 0;
    if (!signature) {
        fprintf(stderr, "ERROR: fallo al reservar memoria\n");
        free(sk); free(msg); free(ctx);
        return 1;
    }

    OQS_STATUS rc;
    if (ctx_len > 0) {
        rc = OQS_SIG_sign_with_ctx_str(sig, signature, &sig_len,
                                       msg, msg_len, ctx, ctx_len, sk);
    } else {
        rc = OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk);
    }

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_sign falló\n");
        free(sk); free(msg); free(ctx); free(signature);
        return 1;
    }

    print_hex("SIGNATURE", signature, sig_len);

    free(sk);
    free(msg);
    free(ctx);
    free(signature);
    return 0;
}

/* verify: verifica una firma. Devuelve 0 tanto si PASA como si FALLA. */
static int do_verify(OQS_SIG *sig, const char *pk_hex, const char *msg_hex,
                     const char *sig_hex, const char *ctx_hex)
{
    uint8_t *pk = NULL, *msg = NULL, *signature = NULL, *ctx = NULL;
    size_t pk_len  = hex_to_bytes(pk_hex, &pk);
    size_t msg_len = hex_to_bytes(msg_hex, &msg);
    size_t sig_len = hex_to_bytes(sig_hex, &signature);
    size_t ctx_len = ctx_hex ? hex_to_bytes(ctx_hex, &ctx) : 0;

    if (!pk || !msg || !signature) {
        fprintf(stderr, "ERROR: fallo al convertir pk/msg/sig hex\n");
        free(pk); free(msg); free(signature); free(ctx);
        return 1;
    }
    if (pk_len != sig->length_public_key) {
        fprintf(stderr, "ERROR: pk tiene %zu bytes, se esperan %zu\n",
                pk_len, sig->length_public_key);
        free(pk); free(msg); free(signature); free(ctx);
        return 1;
    }

    OQS_STATUS rc;
    if (ctx_len > 0) {
        rc = OQS_SIG_verify_with_ctx_str(sig, msg, msg_len, signature, sig_len,
                                         ctx, ctx_len, pk);
    } else {
        rc = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk);
    }

    printf("VERIFY: %s\n", rc == OQS_SUCCESS ? "PASS" : "FAIL");

    free(pk);
    free(msg);
    free(signature);
    free(ctx);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Uso:\n");
    fprintf(stderr, "  %s keygen <alg>\n", prog);
    fprintf(stderr, "  %s sign   <alg> <sk_hex> <msg_hex> [ctx_hex]\n", prog);
    fprintf(stderr, "  %s verify <alg> <pk_hex> <msg_hex> <sig_hex> [ctx_hex]\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    const char *op       = argv[1];
    const char *alg_name = argv[2];

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        fprintf(stderr, "ERROR: algoritmo '%s' no reconocido por liboqs\n", alg_name);
        return 1;
    }

    int rc;
    if (strcmp(op, "keygen") == 0) {
        rc = do_keygen(sig);
    } else if (strcmp(op, "sign") == 0) {
        if (argc != 5 && argc != 6) { usage(argv[0]); rc = 2; }
        else rc = do_sign(sig, argv[3], argv[4], argc == 6 ? argv[5] : NULL);
    } else if (strcmp(op, "verify") == 0) {
        if (argc != 6 && argc != 7) { usage(argv[0]); rc = 2; }
        else rc = do_verify(sig, argv[3], argv[4], argv[5], argc == 7 ? argv[6] : NULL);
    } else {
        fprintf(stderr, "ERROR: sub-comando '%s' no reconocido\n", op);
        usage(argv[0]);
        rc = 2;
    }

    OQS_SIG_free(sig);
    return rc;
}
