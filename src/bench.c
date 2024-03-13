/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../include/secp256k1.h"
#include "../include/secp256k1_silentpayments.h"
#include "hash_impl.h"
#include "testrand_impl.h"
#include "util.h"
#include "bench.h"

static void help(int default_iters) {
    printf("Benchmarks the following algorithms:\n");
    printf("    - ECDSA signing/verification\n");

#ifdef ENABLE_MODULE_ECDH
    printf("    - ECDH key exchange (optional module)\n");
#endif

#ifdef ENABLE_MODULE_RECOVERY
    printf("    - Public key recovery (optional module)\n");
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
    printf("    - Schnorr signatures (optional module)\n");
#endif

    printf("\n");
    printf("The default number of iterations for each benchmark is %d. This can be\n", default_iters);
    printf("customized using the SECP256K1_BENCH_ITERS environment variable.\n");
    printf("\n");
    printf("Usage: ./bench [args]\n");
    printf("By default, all benchmarks will be run.\n");
    printf("args:\n");
    printf("    help              : display this help and exit\n");
    printf("    ecdsa             : all ECDSA algorithms--sign, verify, recovery (if enabled)\n");
    printf("    ecdsa_sign        : ECDSA siging algorithm\n");
    printf("    ecdsa_verify      : ECDSA verification algorithm\n");
    printf("    ec                : all EC public key algorithms (keygen)\n");
    printf("    ec_keygen         : EC public key generation\n");

#ifdef ENABLE_MODULE_RECOVERY
    printf("    ecdsa_recover     : ECDSA public key recovery algorithm\n");
#endif

#ifdef ENABLE_MODULE_ECDH
    printf("    ecdh              : ECDH key exchange algorithm\n");
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
    printf("    schnorrsig        : all Schnorr signature algorithms (sign, verify)\n");
    printf("    schnorrsig_sign   : Schnorr sigining algorithm\n");
    printf("    schnorrsig_verify : Schnorr verification algorithm\n");
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
    printf("    ellswift          : all ElligatorSwift benchmarks (encode, decode, keygen, ecdh)\n");
    printf("    ellswift_encode   : ElligatorSwift encoding\n");
    printf("    ellswift_decode   : ElligatorSwift decoding\n");
    printf("    ellswift_keygen   : ElligatorSwift key generation\n");
    printf("    ellswift_ecdh     : ECDH on ElligatorSwift keys\n");
#endif

    printf("\n");
}

typedef struct {
    secp256k1_context *ctx;
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char sig[72];
    size_t siglen;
    unsigned char pubkey[33];
    size_t pubkeylen;
} bench_data;

static void bench_verify(void* arg, int iters) {
    int i;
    bench_data* data = (bench_data*)arg;

    for (i = 0; i < iters; i++) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
        CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
        CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
    }
}

static void bench_sign_setup(void* arg) {
    int i;
    bench_data *data = (bench_data*)arg;

    for (i = 0; i < 32; i++) {
        data->msg[i] = i + 1;
    }
    for (i = 0; i < 32; i++) {
        data->key[i] = i + 65;
    }
}

static void bench_sign_run(void* arg, int iters) {
    int i;
    bench_data *data = (bench_data*)arg;

    unsigned char sig[74];
    for (i = 0; i < iters; i++) {
        size_t siglen = 74;
        int j;
        secp256k1_ecdsa_signature signature;
        CHECK(secp256k1_ecdsa_sign(data->ctx, &signature, data->msg, data->key, NULL, NULL));
        CHECK(secp256k1_ecdsa_signature_serialize_der(data->ctx, sig, &siglen, &signature));
        for (j = 0; j < 32; j++) {
            data->msg[j] = sig[j];
            data->key[j] = sig[j + 32];
        }
    }
}

static void bench_keygen_setup(void* arg) {
    int i;
    bench_data *data = (bench_data*)arg;

    for (i = 0; i < 32; i++) {
        data->key[i] = i + 65;
    }
}

static void bench_keygen_run(void *arg, int iters) {
    int i;
    bench_data *data = (bench_data*)arg;

    for (i = 0; i < iters; i++) {
        unsigned char pub33[33];
        size_t len = 33;
        secp256k1_pubkey pubkey;
        CHECK(secp256k1_ec_pubkey_create(data->ctx, &pubkey, data->key));
        CHECK(secp256k1_ec_pubkey_serialize(data->ctx, pub33, &len, &pubkey, SECP256K1_EC_COMPRESSED));
        memcpy(data->key, pub33 + 1, 32);
    }
}


#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/bench_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/bench_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "modules/schnorrsig/bench_impl.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
# include "modules/ellswift/bench_impl.h"
#endif

void pubkey_raw_from_seckey(secp256k1_context *ctx, unsigned char *pubkey_raw, const unsigned char *seckey) {
    secp256k1_pubkey pubkey;
    size_t outputlen = 33;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkey_raw, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED));
}

void xonly_pubkey_raw_from_seckey(secp256k1_context *ctx, unsigned char *xonly_pubkey_raw, const unsigned char *seckey) {
    secp256k1_pubkey pubkey;
    secp256k1_xonly_pubkey xonly_pubkey;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, NULL, &pubkey));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, xonly_pubkey_raw, &xonly_pubkey));
}

#define BIP352_BENCH_MAX_INOUT 1000

#ifdef VERIFY
#error ya shall not build benchmarks with VERIFY enabled!
#endif


void run_silentpayments_bench(void) {
    secp256k1_context *ctx = NULL;
    unsigned char plain_pubkeys[BIP352_BENCH_MAX_INOUT][33];
    unsigned char xonly_pubkeys[BIP352_BENCH_MAX_INOUT][32];
    unsigned char outputs[BIP352_BENCH_MAX_INOUT][32];
    unsigned char const *plain_pubkeys_ptrs[BIP352_BENCH_MAX_INOUT];
    unsigned char const *xonly_pubkeys_ptrs[BIP352_BENCH_MAX_INOUT];
    unsigned char outpoint_smallest[36] = {0};
    unsigned char b_scan[32], b_spend[32];
    secp256k1_pubkey B_spend;
    int64_t begin, stage1, stage2, stage3, total;
    int64_t temp;
    int i;

    /* prepare input data material */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_testrand_init("deadcafebeef6666");
    for (i = 0; i < BIP352_BENCH_MAX_INOUT; i++) {
        unsigned char seckey[32];

        secp256k1_testrand256(seckey);
        pubkey_raw_from_seckey(ctx, &plain_pubkeys[i][0], seckey);
        plain_pubkeys_ptrs[i] = plain_pubkeys[i];

        secp256k1_testrand256(seckey);
        xonly_pubkey_raw_from_seckey(ctx, &xonly_pubkeys[i][0], seckey);
        xonly_pubkeys_ptrs[i] = xonly_pubkeys[i];

        secp256k1_testrand256(seckey);
        xonly_pubkey_raw_from_seckey(ctx, outputs[i], seckey);
    }
    secp256k1_testrand256(b_scan);
    secp256k1_testrand256(b_spend);
    CHECK(secp256k1_ec_pubkey_create(ctx, &B_spend, b_spend));

    /* benchmark receiver (public tweak data + shared secret creation, scanning) */
    begin = gettime_i64();
    {
        secp256k1_pubkey A_sum;
        unsigned char input_hash[32];
        unsigned char input_hash2[32];
        unsigned char shared_secret[33];
        secp256k1_xonly_pubkey P_output;
        unsigned char output_ser[32];

        size_t num_plain = 10;
        size_t num_xonly = 10;

        temp = gettime_i64();
        CHECK(secp256k1_silentpayments_create_public_tweak_data(ctx, &A_sum, input_hash,
            num_plain ? plain_pubkeys_ptrs : NULL, num_plain,
            num_xonly ? xonly_pubkeys_ptrs : NULL, num_xonly, outpoint_smallest));
        printf("-> public tweak data creation took %lld usec (MODULE)\n", gettime_i64() - temp);

        temp = gettime_i64();
        CHECK(secp256k1_silentpayments_create_public_tweak_data_ONLYPUBLIC(ctx, &A_sum, input_hash2,
            num_plain ? plain_pubkeys_ptrs : NULL, num_plain,
            num_xonly ? xonly_pubkeys_ptrs : NULL, num_xonly, outpoint_smallest));
        printf("-> public tweak data creation took %lld usec (ONLYPUBLIC)\n", gettime_i64() - temp);

        printf("input hashes equal == %d\n", memcmp(input_hash, input_hash2, 32) == 0);

        stage1 = gettime_i64();

        CHECK(secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &A_sum, b_scan, input_hash));
        stage2 = gettime_i64();

        CHECK(secp256k1_silentpayments_sender_create_output_pubkey(ctx, &P_output, shared_secret, &B_spend, 0));
        stage3 = gettime_i64();

        /*
        for (i = 0; i < 10; i++) {
            int direct_match;
            unsigned char t_k[32];
            secp256k1_silentpayments_label_data label_data;
            CHECK(secp256k1_silentpayments_receiver_scan_output(ctx, &direct_match, t_k, &label_data,
                shared_secret, &B_spend, 0, outputs[i]));
        }
        printf("-> scanning outputs took %lld usec\n", stage3 - stage2);
        */
        printf("-> public tweak data creation took %lld usec\n", stage1 - begin);
        printf("-> shared secret creation took %lld usec\n", stage2 - stage1);
        printf("-> output creation took %lld usec\n", stage3 - stage2);
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, output_ser, &P_output));
        printf("output: %02x %02x %02x %02x %02x ...\n", output_ser[0], output_ser[1],
            output_ser[2], output_ser[3], output_ser[4]);


    }
    total = gettime_i64() - begin;
    printf("silent payments scanning took %lld usec in total.\n", total);
}

int main(int argc, char** argv) {
    int i;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    bench_data data;

    int d = argc == 1;
    int default_iters = 20000;
    int iters = get_iters(default_iters);

    /* Check for invalid user arguments */
    char* valid_args[] = {"ecdsa", "verify", "ecdsa_verify", "sign", "ecdsa_sign", "ecdh", "recover",
                         "ecdsa_recover", "schnorrsig", "schnorrsig_verify", "schnorrsig_sign", "ec",
                         "keygen", "ec_keygen", "ellswift", "encode", "ellswift_encode", "decode",
                         "ellswift_decode", "ellswift_keygen", "ellswift_ecdh"};
    size_t valid_args_size = sizeof(valid_args)/sizeof(valid_args[0]);
    int invalid_args = have_invalid_args(argc, argv, valid_args, valid_args_size);

    if (argc > 1) {
        if (have_flag(argc, argv, "-h")
           || have_flag(argc, argv, "--help")
           || have_flag(argc, argv, "help")) {
            help(default_iters);
            return 0;
        } else if (invalid_args) {
            fprintf(stderr, "./bench: unrecognized argument.\n\n");
            help(default_iters);
            return 1;
        }
    }

    /* run secp256k1-silentpayments benchmarks */
    run_silentpayments_bench();
    return 0;

/* Check if the user tries to benchmark optional module without building it */
#ifndef ENABLE_MODULE_ECDH
    if (have_flag(argc, argv, "ecdh")) {
        fprintf(stderr, "./bench: ECDH module not enabled.\n");
        fprintf(stderr, "Use ./configure --enable-module-ecdh.\n\n");
        return 1;
    }
#endif

#ifndef ENABLE_MODULE_RECOVERY
    if (have_flag(argc, argv, "recover") || have_flag(argc, argv, "ecdsa_recover")) {
        fprintf(stderr, "./bench: Public key recovery module not enabled.\n");
        fprintf(stderr, "Use ./configure --enable-module-recovery.\n\n");
        return 1;
    }
#endif

#ifndef ENABLE_MODULE_SCHNORRSIG
    if (have_flag(argc, argv, "schnorrsig") || have_flag(argc, argv, "schnorrsig_sign") || have_flag(argc, argv, "schnorrsig_verify")) {
        fprintf(stderr, "./bench: Schnorr signatures module not enabled.\n");
        fprintf(stderr, "Use ./configure --enable-module-schnorrsig.\n\n");
        return 1;
    }
#endif

#ifndef ENABLE_MODULE_ELLSWIFT
    if (have_flag(argc, argv, "ellswift") || have_flag(argc, argv, "ellswift_encode") || have_flag(argc, argv, "ellswift_decode") ||
        have_flag(argc, argv, "encode") || have_flag(argc, argv, "decode") || have_flag(argc, argv, "ellswift_keygen") ||
        have_flag(argc, argv, "ellswift_ecdh")) {
        fprintf(stderr, "./bench: ElligatorSwift module not enabled.\n");
        fprintf(stderr, "Use ./configure --enable-module-ellswift.\n\n");
        return 1;
    }
#endif

    /* ECDSA benchmark */
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    for (i = 0; i < 32; i++) {
        data.msg[i] = 1 + i;
    }
    for (i = 0; i < 32; i++) {
        data.key[i] = 33 + i;
    }
    data.siglen = 72;
    CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
    CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
    CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
    data.pubkeylen = 33;
    CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    print_output_table_header_row();
    if (d || have_flag(argc, argv, "ecdsa") || have_flag(argc, argv, "verify") || have_flag(argc, argv, "ecdsa_verify")) run_benchmark("ecdsa_verify", bench_verify, NULL, NULL, &data, 10, iters);

    if (d || have_flag(argc, argv, "ecdsa") || have_flag(argc, argv, "sign") || have_flag(argc, argv, "ecdsa_sign")) run_benchmark("ecdsa_sign", bench_sign_run, bench_sign_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "ec") || have_flag(argc, argv, "keygen") || have_flag(argc, argv, "ec_keygen")) run_benchmark("ec_keygen", bench_keygen_run, bench_keygen_setup, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);

#ifdef ENABLE_MODULE_ECDH
    /* ECDH benchmarks */
    run_ecdh_bench(iters, argc, argv);
#endif

#ifdef ENABLE_MODULE_RECOVERY
    /* ECDSA recovery benchmarks */
    run_recovery_bench(iters, argc, argv);
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
    /* Schnorr signature benchmarks */
    run_schnorrsig_bench(iters, argc, argv);
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
    /* ElligatorSwift benchmarks */
    run_ellswift_bench(iters, argc, argv);
#endif

    return 0;
}
