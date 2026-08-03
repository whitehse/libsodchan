/**
 * @file test_sodchan_crypto.c
 * @brief PR-2: keygen, SCSK seed blobs, fingerprints, labeled SS KDF.
 */

#include "sodchan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Internal KDF helper — same TU link via static lib (not in public header). */
int sodchan_crypto_ss_key_derive(const uint8_t kx_key[32],
                                 const char *dom,
                                 uint8_t out_key[32]);

static void test_keygen_random(void)
{
    uint8_t pk1[SODCHAN_PUBKEY_BYTES], sk1[SODCHAN_SECKEY_BYTES];
    uint8_t pk2[SODCHAN_PUBKEY_BYTES], sk2[SODCHAN_SECKEY_BYTES];

    assert(sodchan_keygen_device(pk1, sk1) == SODCHAN_OK);
    assert(sodchan_keygen_device(pk2, sk2) == SODCHAN_OK);

    /* Distinct pairs with overwhelming probability */
    assert(memcmp(pk1, pk2, SODCHAN_PUBKEY_BYTES) != 0);
    assert(memcmp(sk1, sk2, SODCHAN_SECKEY_BYTES) != 0);

    /* Sodium sk layout: last 32 bytes are the public key */
    assert(memcmp(sk1 + 32, pk1, SODCHAN_PUBKEY_BYTES) == 0);
    assert(memcmp(sk2 + 32, pk2, SODCHAN_PUBKEY_BYTES) == 0);

    printf("  PASS: random keygen\n");
}

static void test_keygen_from_seed_deterministic(void)
{
    uint8_t seed[SODCHAN_SEED_BYTES];
    uint8_t pk1[SODCHAN_PUBKEY_BYTES], sk1[SODCHAN_SECKEY_BYTES];
    uint8_t pk2[SODCHAN_PUBKEY_BYTES], sk2[SODCHAN_SECKEY_BYTES];
    size_t i;

    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0x40 + i);
    }

    assert(sodchan_keygen_from_seed(seed, pk1, sk1) == SODCHAN_OK);
    assert(sodchan_keygen_from_seed(seed, pk2, sk2) == SODCHAN_OK);
    assert(memcmp(pk1, pk2, SODCHAN_PUBKEY_BYTES) == 0);
    assert(memcmp(sk1, sk2, SODCHAN_SECKEY_BYTES) == 0);
    assert(memcmp(sk1 + 32, pk1, SODCHAN_PUBKEY_BYTES) == 0);

    printf("  PASS: seed keygen deterministic\n");
}

static void test_scsk_roundtrip(void)
{
    uint8_t seed[SODCHAN_SEED_BYTES];
    uint8_t blob[SODCHAN_SEED_BLOB_LEN];
    uint8_t seed2[SODCHAN_SEED_BYTES];
    uint8_t pk[SODCHAN_PUBKEY_BYTES], sk[SODCHAN_SECKEY_BYTES];
    uint8_t pk2[SODCHAN_PUBKEY_BYTES], sk2[SODCHAN_SECKEY_BYTES];
    size_t i;

    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0x80 ^ i);
    }

    assert(sodchan_seed_encode(seed, blob) == SODCHAN_OK);
    assert(blob[0] == 'S' && blob[1] == 'C' && blob[2] == 'S' &&
           blob[3] == 'K' && blob[4] == 0x01);
    assert(memcmp(blob + 5, seed, 32) == 0);

    assert(sodchan_seed_decode(blob, SODCHAN_SEED_BLOB_LEN, seed2) ==
           SODCHAN_OK);
    assert(memcmp(seed, seed2, 32) == 0);

    assert(sodchan_keygen_from_seed(seed, pk, sk) == SODCHAN_OK);
    assert(sodchan_keygen_from_seed_blob(blob, SODCHAN_SEED_BLOB_LEN, pk2,
                                         sk2) == SODCHAN_OK);
    assert(memcmp(pk, pk2, SODCHAN_PUBKEY_BYTES) == 0);
    assert(memcmp(sk, sk2, SODCHAN_SECKEY_BYTES) == 0);

    printf("  PASS: SCSK encode/decode + keygen_from_seed_blob\n");
}

static void test_scsk_reject_bare_seed(void)
{
    uint8_t seed[SODCHAN_SEED_BYTES];
    uint8_t out[SODCHAN_SEED_BYTES];
    size_t i;

    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)i;
    }

    /* Bare 32 bytes without magic must fail */
    assert(sodchan_seed_decode(seed, 32, out) == SODCHAN_ERR_PARAM);
    assert(sodchan_seed_decode(seed, 0, out) == SODCHAN_ERR_PARAM);
    assert(sodchan_seed_decode(NULL, SODCHAN_SEED_BLOB_LEN, out) ==
           SODCHAN_ERR_PARAM);

    printf("  PASS: bare seed rejected\n");
}

static void test_fingerprint(void)
{
    uint8_t seed[SODCHAN_SEED_BYTES];
    uint8_t pk[SODCHAN_PUBKEY_BYTES], sk[SODCHAN_SECKEY_BYTES];
    char fp1[SODCHAN_FP_SHA256_MAX];
    char fp2[SODCHAN_FP_SHA256_MAX];
    char tiny[8];
    size_t i;

    memset(seed, 0x11, sizeof(seed));
    assert(sodchan_keygen_from_seed(seed, pk, sk) == SODCHAN_OK);

    assert(sodchan_pubkey_fingerprint_sha256(pk, fp1, sizeof(fp1)) ==
           SODCHAN_OK);
    assert(strncmp(fp1, "SHA256:", 7) == 0);
    assert(strlen(fp1) > 10);
    /* Unpadded base64: no '=' */
    assert(strchr(fp1, '=') == NULL);

    assert(sodchan_pubkey_fingerprint_sha256(pk, fp2, sizeof(fp2)) ==
           SODCHAN_OK);
    assert(strcmp(fp1, fp2) == 0);

    assert(sodchan_pubkey_fingerprint_sha256(pk, tiny, sizeof(tiny)) ==
           SODCHAN_ERR_PARAM);

    for (i = 0; i < sizeof(seed); i++) {
        seed[i] = (uint8_t)(0x22 + i);
    }
    assert(sodchan_keygen_from_seed(seed, pk, sk) == SODCHAN_OK);
    assert(sodchan_pubkey_fingerprint_sha256(pk, fp2, sizeof(fp2)) ==
           SODCHAN_OK);
    assert(strcmp(fp1, fp2) != 0);

    printf("  PASS: fingerprint format + stability\n");
    printf("        example: %s\n", fp1);
}

static void test_ss_kdf_domain_separation(void)
{
    uint8_t kx[32];
    uint8_t k_c2s[32], k_s2c[32], k_again[32];
    size_t i;

    for (i = 0; i < 32; i++) {
        kx[i] = (uint8_t)(0xA0 + i);
    }

    assert(sodchan_crypto_ss_key_derive(kx, SODCHAN_DOM_SS_C2S, k_c2s) ==
           SODCHAN_OK);
    assert(sodchan_crypto_ss_key_derive(kx, SODCHAN_DOM_SS_S2C, k_s2c) ==
           SODCHAN_OK);
    assert(memcmp(k_c2s, k_s2c, 32) != 0);
    assert(memcmp(k_c2s, kx, 32) != 0);

    assert(sodchan_crypto_ss_key_derive(kx, SODCHAN_DOM_SS_C2S, k_again) ==
           SODCHAN_OK);
    assert(memcmp(k_c2s, k_again, 32) == 0);

    printf("  PASS: labeled secretstream KDF domain separation\n");
}

static void test_create_uses_real_keys(void)
{
    uint8_t pk[SODCHAN_PUBKEY_BYTES], sk[SODCHAN_SECKEY_BYTES];
    sodchan_config_t cfg;
    sodchan_ctx_t *s;

    assert(sodchan_keygen_device(pk, sk) == SODCHAN_OK);
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = pk;
    cfg.server_id_sk = sk;
    s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
    assert(s != NULL);
    sodchan_destroy(s);
    printf("  PASS: create with sodium-generated keys\n");
}

int main(void)
{
    printf("libsodchan crypto test (PR-2)...\n");
    test_keygen_random();
    test_keygen_from_seed_deterministic();
    test_scsk_roundtrip();
    test_scsk_reject_bare_seed();
    test_fingerprint();
    test_ss_kdf_domain_separation();
    test_create_uses_real_keys();
    printf("libsodchan crypto test PASSED.\n");
    return 0;
}
