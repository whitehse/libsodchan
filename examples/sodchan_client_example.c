/**
 * Minimal client-side create/destroy example (no sockets).
 * Pins a generated server public key (fail-closed).
 */

#include "sodchan.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *c;
    uint8_t server_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t server_sk[SODCHAN_SECKEY_BYTES];
    uint8_t client_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t client_sk[SODCHAN_SECKEY_BYTES];

    if (sodchan_keygen_device(server_pk, server_sk) != SODCHAN_OK ||
        sodchan_keygen_device(client_pk, client_sk) != SODCHAN_OK) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = server_pk; /* fail-closed pin */
    cfg.client_id_pk = client_pk;
    cfg.client_id_sk = client_sk;

    c = sodchan_create(SODCHAN_ROLE_CLIENT, &cfg);
    if (!c) {
        fprintf(stderr, "create failed\n");
        return 1;
    }
    printf("client state=%d (IDLE=%d)\n",
           (int)sodchan_current_state(c), (int)SODCHAN_STATE_IDLE);
    sodchan_destroy(c);
    return 0;
}
