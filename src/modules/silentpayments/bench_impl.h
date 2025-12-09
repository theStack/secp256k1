/***********************************************************************
 * Copyright (c) 2024 josibake                                         *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H
#define SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H

#include "../../../include/secp256k1_silentpayments.h"

#define MAX_TX_OUTPUTS 200 /* maximum number of transaction outputs to benchmark scanning for */
#define MAX_LABELS      50 /* maximum number of labels to benchmark scanning for */

typedef struct {
    secp256k1_context *ctx;
    secp256k1_pubkey spend_pubkeys[1];
    unsigned char scan_key[32];
    unsigned char input_pubkey33[33];
    secp256k1_xonly_pubkey tx_outputs[MAX_TX_OUTPUTS];
    unsigned char tx_outputs2[MAX_TX_OUTPUTS][32];
    secp256k1_xonly_pubkey tx_inputs[2];
    secp256k1_silentpayments_found_output found_outputs[MAX_TX_OUTPUTS];
    secp256k1_silentpayments_found_output2 found_outputs2[MAX_TX_OUTPUTS];
    secp256k1_silentpayments_label_entry label_entries[MAX_LABELS];
    unsigned char scalar[32];
    unsigned char smallest_outpoint[36];
    int n_labels, n_outputs;
} bench_silentpayments_data;

/* we need a non-null pointer for the cache */
static int noop;
void* label_cache = &noop;
const unsigned char* label_lookup(const unsigned char* key, const void* cache_ptr) {
    (void)key;
    (void)cache_ptr;
    return NULL;
}

static void bench_silentpayments_scan_setup(void* arg) {
    int i, j;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    const unsigned char static_tx_input[32] = {
        0xf2,0x07,0x16,0x2b,0x1a,0x7a,0xbc,0x51,
        0xc4,0x20,0x17,0xbe,0xf0,0x55,0xe9,0xec,
        0x1e,0xfc,0x3d,0x35,0x67,0xcb,0x72,0x03,
        0x57,0xe2,0xb8,0x43,0x25,0xdb,0x33,0xac
    };
    const unsigned char smallest_outpoint[36] = {
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
        0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
        0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
        0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00,
    };
    const unsigned char spend_pubkey[33] = {
        0x02,0xee,0x97,0xdf,0x83,0xb2,0x54,0x6a,
        0xf5,0xa7,0xd0,0x62,0x15,0xd9,0x8b,0xcb,
        0x63,0x7f,0xe0,0x5d,0xd0,0xfa,0x37,0x3b,
        0xd8,0x20,0xe6,0x64,0xd3,0x72,0xde,0x9a,0x01
    };
    const unsigned char scan_key[32] = {
        0xa8,0x90,0x54,0xc9,0x5b,0xe3,0xc3,0x01,
        0x56,0x65,0x74,0xf2,0xaa,0x93,0xad,0xe0,
        0x51,0x85,0x09,0x03,0xa6,0x9c,0xbd,0xd1,
        0xd4,0x7e,0xae,0x26,0x3d,0x7b,0xc0,0x31
    };
    secp256k1_keypair input_keypair;
    secp256k1_pubkey input_pubkey;
    size_t pubkeylen = 33;

    for (i = 0; i < 32; i++) {
        data->scalar[i] = i + 1;
    }
    for (i = 0; i < MAX_TX_OUTPUTS; i++) {
        unsigned char buf[32] = {0};
        unsigned char raw_xpk[32];
        secp256k1_write_be32(&buf[0], i);
        /* only about ~50% of random x-only pubkeys are valid, so we have to try repeatedly */
        for (j = 0;; j++) {
            secp256k1_write_be32(&buf[4], j);
            CHECK(secp256k1_tagged_sha256(data->ctx, raw_xpk, (const unsigned char*)"sp-bench-outputs", 16, buf, sizeof(buf)));
            if (secp256k1_xonly_pubkey_parse(data->ctx, &data->tx_outputs[i], raw_xpk)) {
                memcpy(&data->tx_outputs2[i][0], raw_xpk, 32);
                break;
            }
        }
    }
    for (i = 0; i < MAX_LABELS; i++) {
        unsigned char buf[32] = {0};
        secp256k1_write_be32(&buf[0], i);
        CHECK(secp256k1_tagged_sha256(data->ctx, data->label_entries[i].label_tweak32, (const unsigned char*)"sp-bench-labels", 15, buf, sizeof(buf)));
        CHECK(secp256k1_ec_pubkey_create(data->ctx, &data->label_entries[i].label, data->label_entries[i].label_tweak32));
    }
    /* Create the first input public key from the scalar.
     * This input is also used to create the serialized prevouts_summary object for the light client
     */
    CHECK(secp256k1_keypair_create(data->ctx, &input_keypair, data->scalar));
    CHECK(secp256k1_keypair_pub(data->ctx, &input_pubkey, &input_keypair));
    CHECK(secp256k1_ec_pubkey_serialize(data->ctx, data->input_pubkey33, &pubkeylen, &input_pubkey, SECP256K1_EC_COMPRESSED));
    /* Create the input public keys for the full scan */
    CHECK(secp256k1_keypair_xonly_pub(data->ctx, &data->tx_inputs[0], NULL, &input_keypair));
    CHECK(secp256k1_xonly_pubkey_parse(data->ctx, &data->tx_inputs[1], static_tx_input));
    CHECK(secp256k1_ec_pubkey_parse(data->ctx, &data->spend_pubkeys[0], spend_pubkey, pubkeylen));
    memcpy(data->scan_key, scan_key, 32);
    memcpy(data->smallest_outpoint, smallest_outpoint, 36);
}

static void bench_silentpayments_full_tx_scan(void* arg, int iters) {
    int i, j;
    size_t n_found = 0;
    secp256k1_silentpayments_found_output *found_output_ptrs[MAX_TX_OUTPUTS];
    const secp256k1_xonly_pubkey *tx_output_ptrs[MAX_TX_OUTPUTS];
    const secp256k1_xonly_pubkey *tx_input_ptrs[2];
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    const secp256k1_silentpayments_label_lookup label_lookup_fn = (data->n_labels > 0) ? label_lookup : NULL;
    const void *label_context = (data->n_labels > 0) ? label_cache : NULL;

    for (i = 0; i < 2; i++) {
        tx_input_ptrs[i] = &data->tx_inputs[i];
    }
    for (i = 0; i < data->n_outputs; i++) {
        found_output_ptrs[i] = &data->found_outputs[i];
        tx_output_ptrs[i] = &data->tx_outputs[i];
    }
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(data->ctx,
            &prevouts_summary,
            data->smallest_outpoint,
            tx_input_ptrs, 2,
            NULL, 0
        ));
        for (j = 0; j < data->n_outputs; j++) {
            CHECK(secp256k1_xonly_pubkey_parse(data->ctx, &data->tx_outputs[j], &data->tx_outputs2[j][0]));
        }
        CHECK(secp256k1_silentpayments_recipient_scan_outputs(data->ctx,
            found_output_ptrs, &n_found,
            tx_output_ptrs, data->n_outputs,
            data->scan_key,
            &prevouts_summary,
            &data->spend_pubkeys[0],
            label_lookup_fn, label_context)
        );
        CHECK(n_found == 0);
    }
}

/* TODO: deduplicate with above */
static void bench_silentpayments_full_tx_scan2(void* arg, int iters) {
    int i;
    size_t n_found = 0;
    secp256k1_silentpayments_found_output2 *found_output_ptrs[MAX_TX_OUTPUTS];
    const unsigned char *tx_output_ptrs[MAX_TX_OUTPUTS];
    const secp256k1_xonly_pubkey *tx_input_ptrs[2];
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_label_set label_set;
    secp256k1_silentpayments_label_set *label_set_ptr = NULL;

    if (data->n_labels > 0) {
        label_set.entries = &data->label_entries[0];
        label_set.n_entries = data->n_labels;
        label_set_ptr = &label_set;
    }
    for (i = 0; i < 2; i++) {
        tx_input_ptrs[i] = &data->tx_inputs[i];
    }
    for (i = 0; i < data->n_outputs; i++) {
        found_output_ptrs[i] = &data->found_outputs2[i];
        tx_output_ptrs[i] = &data->tx_outputs2[i][0];
    }
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(data->ctx,
            &prevouts_summary,
            data->smallest_outpoint,
            tx_input_ptrs, 2,
            NULL, 0
        ));
        CHECK(secp256k1_silentpayments_recipient_scan_outputs2(data->ctx,
            found_output_ptrs, &n_found,
            tx_output_ptrs, data->n_outputs,
            data->scan_key,
            &prevouts_summary,
            &data->spend_pubkeys[0],
            label_set_ptr
        ));
        CHECK(n_found == 0);
    }
}

static void run_silentpayments_bench(int iters, int argc, char** argv) {
    bench_silentpayments_data data;
    int d = argc == 1;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_full_scan")) {
        {
            /* "BIP" scanning approach */
            const size_t n_labels_bench[] = {0, 1};
            const size_t n_outputs_bench[] = {2, 5, 10, 20, 50, 100, 200};
            size_t l, o;
            bench_silentpayments_scan_setup(&data);
            for (l = 0; l < sizeof(n_labels_bench)/sizeof(n_labels_bench[0]); l++) {
                for (o = 0; o < sizeof(n_outputs_bench)/sizeof(n_outputs_bench[0]); o++) {
                    const size_t n_labels = n_labels_bench[l];
                    const size_t n_outputs = n_outputs_bench[o];
                    char str[64];
                    data.n_labels = n_labels;
                    data.n_outputs = n_outputs;
                    sprintf(str, "sp_full_scan_BIP-algo_L=%li_N=%li", n_labels, n_outputs);
                    run_benchmark(str, bench_silentpayments_full_tx_scan, NULL, NULL, &data, 5, iters);
                }
                printf("-----\n");
            }
            printf("\n");
        }
        {
            /* "Label set" scanning approach */
            const size_t n_labels_bench[] = {0, 1, 2, 3, 5, 10, 20, 50};
            const size_t n_outputs_bench[] = {2, 5, 10, 20, 50, 100, 200};
            size_t l, o;
            bench_silentpayments_scan_setup(&data);
            for (l = 0; l < sizeof(n_labels_bench)/sizeof(n_labels_bench[0]); l++) {
                for (o = 0; o < sizeof(n_outputs_bench)/sizeof(n_outputs_bench[0]); o++) {
                    const size_t n_labels = n_labels_bench[l];
                    const size_t n_outputs = n_outputs_bench[o];
                    char str[64];
                    data.n_labels = n_labels;
                    data.n_outputs = n_outputs;
                    sprintf(str, "sp_full_scan_LabelSet-algo_L=%li_N=%li", n_labels, n_outputs);
                    run_benchmark(str, bench_silentpayments_full_tx_scan2, NULL, NULL, &data, 5, iters);
                }
                printf("-----\n");
            }
            printf("\n");
        }
    }

    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H */
