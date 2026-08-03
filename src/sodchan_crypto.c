/**
 * @file sodchan_crypto.c
 * @brief libsodium identity key helpers (PR-2).
 *
 * Ed25519 keygen (64-byte sodium sk), SCSK seed blob, SHA256 fingerprints.
 * Session KX / secretstream land in PR-4; suite locked in ADR 014.
 */

#include "sodchan_internal.h"

#include <sodium.h>
#include <string.h>

/* SCSK\x01 + 32-byte seed */
#define SODCHAN_SEED_MAGIC0 'S'
#define SODCHAN_SEED_MAGIC1 'C'
#define SODCHAN_SEED_MAGIC2 'S'
#define SODCHAN_SEED_MAGIC3 'K'
#define SODCHAN_SEED_MAGIC4 0x01

_Static_assert(SODCHAN_PUBKEY_BYTES == crypto_sign_PUBLICKEYBYTES,
               "pubkey size must match crypto_sign");
_Static_assert(SODCHAN_SECKEY_BYTES == crypto_sign_SECRETKEYBYTES,
               "seckey size must match crypto_sign");
_Static_assert(SODCHAN_SEED_BLOB_LEN == 5 + crypto_sign_SEEDBYTES,
               "seed blob size");

int sodchan_crypto_init(void)
{
    if (sodium_init() < 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    return SODCHAN_OK;
}

int sodchan_keygen_device(uint8_t pk[SODCHAN_PUBKEY_BYTES],
                          uint8_t sk[SODCHAN_SECKEY_BYTES])
{
    if (!pk || !sk) {
        return SODCHAN_ERR_PARAM;
    }
    if (sodchan_crypto_init() != SODCHAN_OK) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (crypto_sign_keypair(pk, sk) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    return SODCHAN_OK;
}

int sodchan_keygen_from_seed(const uint8_t seed[32],
                             uint8_t pk[SODCHAN_PUBKEY_BYTES],
                             uint8_t sk[SODCHAN_SECKEY_BYTES])
{
    if (!seed || !pk || !sk) {
        return SODCHAN_ERR_PARAM;
    }
    if (sodchan_crypto_init() != SODCHAN_OK) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    return SODCHAN_OK;
}

int sodchan_seed_encode(const uint8_t seed[32],
                        uint8_t out[SODCHAN_SEED_BLOB_LEN])
{
    if (!seed || !out) {
        return SODCHAN_ERR_PARAM;
    }
    out[0] = (uint8_t)SODCHAN_SEED_MAGIC0;
    out[1] = (uint8_t)SODCHAN_SEED_MAGIC1;
    out[2] = (uint8_t)SODCHAN_SEED_MAGIC2;
    out[3] = (uint8_t)SODCHAN_SEED_MAGIC3;
    out[4] = (uint8_t)SODCHAN_SEED_MAGIC4;
    memcpy(out + 5, seed, 32);
    return SODCHAN_OK;
}

int sodchan_seed_decode(const uint8_t *blob, size_t len,
                        uint8_t seed[32])
{
    if (!blob || !seed) {
        return SODCHAN_ERR_PARAM;
    }
    /* Reject bare 32-byte seeds without magic (design §4.3.3). */
    if (len != SODCHAN_SEED_BLOB_LEN) {
        return SODCHAN_ERR_PARAM;
    }
    if (blob[0] != SODCHAN_SEED_MAGIC0 ||
        blob[1] != SODCHAN_SEED_MAGIC1 ||
        blob[2] != SODCHAN_SEED_MAGIC2 ||
        blob[3] != SODCHAN_SEED_MAGIC3 ||
        blob[4] != SODCHAN_SEED_MAGIC4) {
        return SODCHAN_ERR_PARAM;
    }
    memcpy(seed, blob + 5, 32);
    return SODCHAN_OK;
}

int sodchan_keygen_from_seed_blob(const uint8_t *blob, size_t len,
                                  uint8_t pk[SODCHAN_PUBKEY_BYTES],
                                  uint8_t sk[SODCHAN_SECKEY_BYTES])
{
    uint8_t seed[32];
    int rc;

    rc = sodchan_seed_decode(blob, len, seed);
    if (rc != SODCHAN_OK) {
        return rc;
    }
    rc = sodchan_keygen_from_seed(seed, pk, sk);
    sodium_memzero(seed, sizeof(seed));
    return rc;
}

int sodchan_pubkey_fingerprint_sha256(const uint8_t pk[SODCHAN_PUBKEY_BYTES],
                                      char *out, size_t out_len)
{
    unsigned char digest[crypto_hash_sha256_BYTES];
    char b64[sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES,
                                       sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
    size_t need;

    if (!pk || !out || out_len == 0) {
        return SODCHAN_ERR_PARAM;
    }
    if (sodchan_crypto_init() != SODCHAN_OK) {
        return SODCHAN_ERR_CRYPTO;
    }

    if (crypto_hash_sha256(digest, pk, SODCHAN_PUBKEY_BYTES) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }

    sodium_bin2base64(b64, sizeof(b64), digest, sizeof(digest),
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    /* "SHA256:" + base64 + NUL */
    need = 7 + strlen(b64) + 1;
    if (out_len < need) {
        return SODCHAN_ERR_PARAM;
    }
    memcpy(out, "SHA256:", 7);
    memcpy(out + 7, b64, strlen(b64) + 1);
    return SODCHAN_OK;
}

int sodchan_crypto_ss_key_derive(const uint8_t kx_key[32],
                                 const char *dom,
                                 uint8_t out_key[32])
{
    crypto_generichash_state st;

    if (!kx_key || !dom || !out_key) {
        return SODCHAN_ERR_PARAM;
    }
    if (sodchan_crypto_init() != SODCHAN_OK) {
        return SODCHAN_ERR_CRYPTO;
    }

    /* ss_key = BLAKE2b-32( kx_direction_key || domain ) */
    if (crypto_generichash_init(&st, NULL, 0, 32) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (crypto_generichash_update(&st, kx_key, 32) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (crypto_generichash_update(&st, (const unsigned char *)dom,
                                  strlen(dom)) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (crypto_generichash_final(&st, out_key, 32) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    return SODCHAN_OK;
}
