/**
 * @file fuzz_sodchan.c
 * @brief libFuzzer harness for sodchan (PR-7).
 *
 * Build:
 *   cmake -B build-fuzz -S . -DENABLE_FUZZ=ON \
 *     -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19
 *   cmake --build build-fuzz --target fuzz_sodchan
 *
 * Run:
 *   ./build-fuzz/fuzz_sodchan fuzz/corpus -max_total_time=60
 *
 * Standalone corpus replay (no libFuzzer):
 *   cmake -B build -S . -DENABLE_FUZZ_STANDALONE=ON && cmake --build build
 *   ./build/fuzz_sodchan_standalone fuzz/corpus/empty fuzz/corpus/garbage
 */

#include "sodchan.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void drain_ctx(sodchan_ctx_t *ctx)
{
    uint8_t out[8192];
    sodchan_event_t *ev;

    if (!ctx) {
        return;
    }
    while (sodchan_get_output(ctx, out, sizeof(out)) > 0) {
        /* discard */
    }
    /* Heap-allocate event: payload embeds SODCHAN_DATA_MAX. */
    ev = (sodchan_event_t *)malloc(sizeof(*ev));
    if (!ev) {
        return;
    }
    while (sodchan_next_event(ctx, ev) == 1) {
        if (ev->type == SODCHAN_EVENT_AUTH_DEVICE) {
            (void)sodchan_auth_decide(ctx, (int)(ev->u.auth.sig_ok & 1));
        } else if (ev->type == SODCHAN_EVENT_CHANNEL_OPEN) {
            (void)sodchan_channel_accept(ctx, ev->u.channel.channel_id, 1);
        }
    }
    free(ev);
}

static void fuzz_one_role(sodchan_role_t role, const uint8_t *data, size_t size,
                          const uint8_t *server_pk, const uint8_t *server_sk,
                          const uint8_t *client_pk, const uint8_t *client_sk)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *ctx;
    size_t off = 0;

    memset(&cfg, 0, sizeof(cfg));
    if (role == SODCHAN_ROLE_SERVER) {
        cfg.server_id_pk = server_pk;
        cfg.server_id_sk = server_sk;
        cfg.allowed_channels = "edge-telemetry,edge-control";
    } else {
        cfg.server_id_pk = server_pk;
        cfg.client_id_pk = client_pk;
        cfg.client_id_sk = client_sk;
        cfg.client_username = "fuzz";
        cfg.client_device_id = "f1";
        /* Alternate pin strictness via first bit of input when present */
        if (size > 0 && (data[0] & 1u)) {
            cfg.accept_any_server_pk = 1;
        }
    }

    ctx = sodchan_create(role, &cfg);
    if (!ctx) {
        return;
    }

    /* Chunked feed to exercise partial frames */
    while (off < size) {
        size_t chunk = 1 + (size_t)((off < size) ? (data[off % size] % 64) : 1);
        size_t left = size - off;
        size_t took;

        if (chunk > left) {
            chunk = left;
        }
        took = sodchan_feed_input(ctx, data + off, chunk);
        if (took == 0 && chunk > 0) {
            /* buffer full or closed — try draining then one more feed */
            drain_ctx(ctx);
            took = sodchan_feed_input(ctx, data + off, chunk);
            if (took == 0) {
                break;
            }
        }
        off += took;
        drain_ctx(ctx);
        if (sodchan_current_state(ctx) == SODCHAN_STATE_ERROR ||
            sodchan_current_state(ctx) == SODCHAN_STATE_CLOSED) {
            break;
        }
    }

    /* Opportunistic channel open if READY */
    if (sodchan_current_state(ctx) == SODCHAN_STATE_READY) {
        uint32_t id = 0;
        if (sodchan_channel_open(ctx, "edge-telemetry", &id) == SODCHAN_OK) {
            const uint8_t msg[] = "fuzz";
            (void)sodchan_channel_send(ctx, id, msg, sizeof(msg) - 1);
        }
        drain_ctx(ctx);
    }

    sodchan_destroy(ctx);
}

/**
 * Dual-role: pump client HELLO into server with fuzz suffix, and vice versa.
 * Exercises parser after a real HELLO prefix when possible.
 */
static void fuzz_dialectic_inject(const uint8_t *data, size_t size,
                                  const uint8_t *server_pk,
                                  const uint8_t *server_sk,
                                  const uint8_t *client_pk,
                                  const uint8_t *client_sk)
{
    sodchan_config_t scfg, ccfg;
    sodchan_ctx_t *s, *c;
    uint8_t buf[4096];
    size_t n;
    int rounds;

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = server_pk;
    scfg.server_id_sk = server_sk;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = server_pk;
    ccfg.client_id_pk = client_pk;
    ccfg.client_id_sk = client_sk;
    ccfg.client_username = "d";
    ccfg.client_device_id = "e";

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    if (!s || !c) {
        sodchan_destroy(s);
        sodchan_destroy(c);
        return;
    }

    for (rounds = 0; rounds < 8; rounds++) {
        n = sodchan_get_output(c, buf, sizeof(buf));
        if (n > 0) {
            (void)sodchan_feed_input(s, buf, n);
        }
        n = sodchan_get_output(s, buf, sizeof(buf));
        if (n > 0) {
            (void)sodchan_feed_input(c, buf, n);
        }
        drain_ctx(s);
        drain_ctx(c);
    }

    /* Inject remaining fuzz into both sides */
    if (size > 0) {
        (void)sodchan_feed_input(s, data, size);
        (void)sodchan_feed_input(c, data, size);
        drain_ctx(s);
        drain_ctx(c);
    }

    sodchan_destroy(s);
    sodchan_destroy(c);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t server_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t server_sk[SODCHAN_SECKEY_BYTES];
    uint8_t client_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t client_sk[SODCHAN_SECKEY_BYTES];
    uint8_t mode;

    if (sodchan_keygen_device(server_pk, server_sk) != SODCHAN_OK ||
        sodchan_keygen_device(client_pk, client_sk) != SODCHAN_OK) {
        return 0;
    }

    mode = (size > 0) ? (data[0] % 3u) : 0;
    if (mode == 0) {
        fuzz_one_role(SODCHAN_ROLE_SERVER, data, size, server_pk, server_sk,
                      client_pk, client_sk);
    } else if (mode == 1) {
        fuzz_one_role(SODCHAN_ROLE_CLIENT, data, size, server_pk, server_sk,
                      client_pk, client_sk);
    } else {
        fuzz_dialectic_inject(data, size, server_pk, server_sk, client_pk,
                              client_sk);
    }
    return 0;
}

#ifdef SODCHAN_FUZZ_STANDALONE
static int run_file(const char *path)
{
    FILE *f;
    uint8_t *buf;
    long sz;
    size_t n;

    f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return 1;
    }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int rc = 0;

    if (argc < 2) {
        /* Empty + tiny inputs */
        uint8_t empty[] = {0};
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput(empty, 0);
        LLVMFuzzerTestOneInput(empty, 1);
        return 0;
    }
    for (i = 1; i < argc; i++) {
        if (run_file(argv[i]) != 0) {
            rc = 1;
        }
    }
    return rc;
}
#endif
