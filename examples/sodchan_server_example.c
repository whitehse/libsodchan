/**
 * Minimal server-side create/destroy example (no sockets).
 * Uses real sodium keygen (PR-2).
 */

#include "sodchan.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *s;
    uint8_t pk[SODCHAN_PUBKEY_BYTES];
    uint8_t sk[SODCHAN_SECKEY_BYTES];
    char fp[SODCHAN_FP_SHA256_MAX];

    if (sodchan_keygen_device(pk, sk) != SODCHAN_OK) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    (void)sodchan_pubkey_fingerprint_sha256(pk, fp, sizeof(fp));

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = pk;
    cfg.server_id_sk = sk;

    s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
    if (!s) {
        fprintf(stderr, "create failed\n");
        return 1;
    }
    printf("server state=%d fingerprint=%s\n",
           (int)sodchan_current_state(s), fp);
    sodchan_destroy(s);
    return 0;
}
