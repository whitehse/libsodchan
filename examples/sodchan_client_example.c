/**
 * Minimal client-side create/destroy example (no sockets).
 * Full dialectic examples land with handshake PRs.
 */

#include "sodchan.h"

#include <stdio.h>
#include <string.h>

static const uint8_t k_pin[SODCHAN_PUBKEY_BYTES] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

int main(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *c;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = k_pin; /* fail-closed pin */

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
