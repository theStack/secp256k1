/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static int64_t gettime_i64(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_usec + (int64_t)tv.tv_sec * 1000000LL;
}

#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

#include "examples_util.h"

#define MAX_N_OUTPUTS 200
#define MAX_LABELS    100

static const int n_labels_bench[] = {1, 2, 3, 5, 10, 20, 50};
static const int n_outputs_bench[] = {2, 5, 10, 20, 50, 100, 200};

static secp256k1_xonly_pubkey tx_outputs[MAX_N_OUTPUTS];
static secp256k1_xonly_pubkey *tx_output_ptrs[MAX_N_OUTPUTS];
static secp256k1_silentpayments_found_output found_outputs[MAX_N_OUTPUTS];
static secp256k1_silentpayments_found_output *found_output_ptrs[MAX_N_OUTPUTS];
static secp256k1_silentpayments_label_entry label_set_entries[MAX_LABELS];

struct label_cache_entry {
    unsigned char label[33];
    unsigned char label_tweak[32];
};

struct labels_cache {
    size_t entries_used;
    struct label_cache_entry entries[MAX_LABELS];
};

const unsigned char* label_lookup(
    const unsigned char* label33,
    const void* cache_ptr
) {
    const struct labels_cache* cache = (const struct labels_cache*)cache_ptr;
    size_t i;
    for (i = 0; i < cache->entries_used; i++) {
        if (memcmp(cache->entries[i].label, label33, 33) == 0) {
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

int main(void) {
    unsigned char randomize[32];
    unsigned char scan_seckey[32];
    unsigned char spend_seckey[32];
    unsigned char random_xpk[32];
    secp256k1_pubkey spend_pubkey;
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    struct labels_cache labels_cache;
    secp256k1_silentpayments_label_set label_set;
    int ret;
    int valid;
    size_t i, j, a, l, o, n_found_outputs;

    /* create secp256k1 context and randomize it */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    ret = fill_random(randomize, sizeof(randomize)); assert(ret);
    ret = secp256k1_context_randomize(ctx, randomize); assert(ret);

    /* prepare data for scanning (scan/spend keys, random outputs, prevouts summary) */
    {
        ret = fill_random(scan_seckey, sizeof(scan_seckey)); assert(ret);
        ret = fill_random(spend_seckey, sizeof(spend_seckey)); assert(ret);
        ret = secp256k1_ec_pubkey_create(ctx, &spend_pubkey, spend_seckey); assert(ret);

        for (i = 0; i < MAX_N_OUTPUTS; i++) {
            valid = 0;
            while (!valid) {
                ret = fill_random(random_xpk, sizeof(random_xpk)); assert(ret);
                valid = secp256k1_xonly_pubkey_parse(ctx, &tx_outputs[i], random_xpk);
            }
            tx_output_ptrs[i] = &tx_outputs[i];
            found_output_ptrs[i] = &found_outputs[i];
        }

        {
            static const unsigned char smallest_outpoint[36] = {0};
            static secp256k1_xonly_pubkey tx_input;
            static const secp256k1_xonly_pubkey *tx_input_ptrs[1];
            valid = 0;
            while (!valid) {
                ret = fill_random(random_xpk, sizeof(random_xpk)); assert(ret);
                valid = secp256k1_xonly_pubkey_parse(ctx, &tx_input, random_xpk);
            }
            tx_input_ptrs[0] = &tx_input;
            ret = secp256k1_silentpayments_recipient_prevouts_summary_create(ctx,
                &prevouts_summary, smallest_outpoint, tx_input_ptrs, 1, NULL, 0);
            assert(ret);
        }

        for (i = 0; i < MAX_LABELS; i++){
            unsigned char label_seckey[32];
            secp256k1_pubkey label_pubkey;

            ret = fill_random(labels_cache.entries[i].label, sizeof(labels_cache.entries[i].label)); assert(ret);
            ret = fill_random(labels_cache.entries[i].label_tweak, sizeof(labels_cache.entries[i].label_tweak)); assert(ret);

            /* fill label set entries (for label-set scanning approach) */
            ret = fill_random(label_seckey, sizeof(label_seckey)); assert(ret);
            ret = secp256k1_ec_pubkey_create(ctx, &label_pubkey, label_seckey); assert(ret);
            label_set_entries[i].label = label_pubkey;
            memcpy(label_set_entries[i].label_tweak32, labels_cache.entries[i].label_tweak, 32);
        }
        labels_cache.entries_used = MAX_LABELS;
        label_set.entries = &label_set_entries[0];
        label_set.n_entries = MAX_LABELS;
    }

    /* execute a few times without benchmarking first */
    for (i = 0; i < 5; i++) {
        labels_cache.entries_used = 1;
        ret = secp256k1_silentpayments_recipient_scan_outputs(ctx,
            found_output_ptrs, &n_found_outputs,
            (const secp256k1_xonly_pubkey**)tx_output_ptrs, 2,
            scan_seckey, &prevouts_summary, &spend_pubkey, label_lookup, &labels_cache
        ); assert(ret);
    }

    printf("Silent Payments (BIP-352) scanning benchmarks\n");
    printf("[common case scenario, i.e. only one k iteration without match]\n\n");
    printf("Legend: L... number of labels, N... number of transaction outputs\n\n");
    for (a = 0; a < 2; a++) {
        if (a == 0)
            printf("===== BIP approach (calculate label candidates for each output, look them up in labels cache) =====\n");
        else
            printf("===== Label-set approach (calculate output candidate for each label, look it up in outputs) =====\n");
        for (l = 0; l < sizeof(n_labels_bench)/sizeof(n_labels_bench[0]); l++) {
            int n_labels = n_labels_bench[l];
            labels_cache.entries_used = n_labels;
            label_set.n_entries = n_labels;
            printf("L=%2d: ", n_labels);
            for (o = 0; o < sizeof(n_outputs_bench)/sizeof(n_outputs_bench[0]); o++) {
                int64_t start, end, elapsed_us;
                int n_outputs = n_outputs_bench[o];
                n_found_outputs = 0;

                /* recreate scan/spend keys in order to have different shared secret every time */
                ret = fill_random(scan_seckey, sizeof(scan_seckey)); assert(ret);
                ret = fill_random(spend_seckey, sizeof(spend_seckey)); assert(ret);
                ret = secp256k1_ec_pubkey_create(ctx, &spend_pubkey, spend_seckey); assert(ret);
                for (j = 0; j < MAX_N_OUTPUTS; j++) {
                    valid = 0;
                    while (!valid) {
                        ret = fill_random(random_xpk, sizeof(random_xpk)); assert(ret);
                        valid = secp256k1_xonly_pubkey_parse(ctx, &tx_outputs[j], random_xpk);
                    }
                }

                start = gettime_i64();
                if (a == 0) {
                    /* BIP scanning approach */
                    ret = secp256k1_silentpayments_recipient_scan_outputs(ctx,
                        found_output_ptrs, &n_found_outputs,
                        (const secp256k1_xonly_pubkey**)tx_output_ptrs, n_outputs,
                        scan_seckey, &prevouts_summary, &spend_pubkey, label_lookup, &labels_cache
                    ); assert(ret);
                } else {
                    /* Label-set scanning approach */
                    ret = secp256k1_silentpayments_recipient_scan_outputs2(ctx,
                        found_output_ptrs, &n_found_outputs,
                        (const secp256k1_xonly_pubkey**)tx_output_ptrs, n_outputs,
                        scan_seckey, &prevouts_summary, &spend_pubkey, &label_set
                    ); assert(ret);
                }
                end = gettime_i64();
                elapsed_us = end - start;
                printf("[N=%d: %3ld us] ", n_outputs, elapsed_us);
                assert(ret);
                assert(n_found_outputs == 0); /* we benchmark the common case scenario, i.e. "no match" */
            }
            printf("\n");
        }
        printf("\n");
    }

    secp256k1_context_destroy(ctx);
    return EXIT_SUCCESS;
}
