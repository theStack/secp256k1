/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecdh.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_silentpayments.h"
#include "../../hash.h"

/* secp256k1_ecdh expects a hash function to be passed in or uses its default
 * hashing function. We don't want to hash the ECDH result, so we define a
 * custom function which simply returns the pubkey without hashing.
 */
static int ecdh_return_pubkey(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    secp256k1_pubkey pubkey;
    unsigned char uncompressed_pubkey[65];
    size_t outputlen = 33;
    (void)data;

    uncompressed_pubkey[0] = 0x04;
    memcpy(uncompressed_pubkey + 1, x32, 32);
    memcpy(uncompressed_pubkey + 33, y32, 32);

    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, uncompressed_pubkey, 65)) {
        return 0;
    }

    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, output, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }

    return 1;
}

int secp256k1_silentpayments_send_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *plain_seckeys, size_t n_plain_seckeys, const secp256k1_keypair *xonly_keypairs, size_t n_xonly_keypairs, const unsigned char *outpoints_hash32, const secp256k1_pubkey *receiver_scan_pubkey) {
    size_t i;
    unsigned char a_tweaked[32];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    memset(shared_secret33, 0, 33);
    ARG_CHECK(plain_seckeys == NULL || n_plain_seckeys >= 1);
    ARG_CHECK(xonly_keypairs == NULL || n_xonly_keypairs >= 1);
    ARG_CHECK((plain_seckeys != NULL) || (xonly_keypairs != NULL));
    ARG_CHECK((n_plain_seckeys + n_xonly_keypairs) >= 1);
    ARG_CHECK(outpoints_hash32 != NULL);
    ARG_CHECK(receiver_scan_pubkey != NULL);

    /* Compute input private keys tweak: a_tweaked = (a_0 + a_1 + ... + a_(n-1)) * outpoints_hash */
    for (i = 0; i < n_plain_seckeys; i++) {
        const unsigned char *seckey_to_add = &plain_seckeys[i*32];
        if (i == 0) {
            memcpy(a_tweaked, seckey_to_add, 32);
            continue;
        }
        if (!secp256k1_ec_seckey_tweak_add(ctx, a_tweaked, seckey_to_add)) {
            return 0;
        }
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_xonly_keypairs; i++) {
        unsigned char seckey_to_add[32];
        secp256k1_scalar sk;
        secp256k1_ge pk;
        secp256k1_keypair_load(ctx, &sk, &pk, &xonly_keypairs[i]);
        if (secp256k1_fe_is_odd(&pk.y)) {
            secp256k1_scalar_negate(&sk, &sk);
        }
        secp256k1_scalar_get_b32(seckey_to_add, &sk);
        if (i == 0 && n_plain_seckeys == 0) {
            memcpy(a_tweaked, seckey_to_add, 32);
            continue;
        }
        if (!secp256k1_ec_seckey_tweak_add(ctx, a_tweaked, seckey_to_add)) {
            return 0;
        }
    }

    if (!secp256k1_ec_seckey_tweak_mul(ctx, a_tweaked, outpoints_hash32)) {
        return 0;
    }

    /* Compute shared_secret = a_tweaked * B_scan */
    if (!secp256k1_ecdh(ctx, shared_secret33, receiver_scan_pubkey, a_tweaked, ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
}

int secp256k1_silentpayments_create_public_tweak_data(const secp256k1_context *ctx, unsigned char *tweak_data33, const secp256k1_pubkey *plain_pubkeys, size_t n_plain_pubkeys, const secp256k1_xonly_pubkey *xonly_pubkeys, size_t n_xonly_pubkeys, const unsigned char *outpoints_hash32) {
    size_t i;
    secp256k1_pubkey A_tweaked;
    size_t outputlen = 33;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_data33 != NULL);
    memset(tweak_data33, 0, 33);
    ARG_CHECK(plain_pubkeys == NULL || n_plain_pubkeys >= 1);
    ARG_CHECK(xonly_pubkeys == NULL || n_xonly_pubkeys >= 1);
    ARG_CHECK((plain_pubkeys != NULL) || (xonly_pubkeys != NULL));
    ARG_CHECK((n_plain_pubkeys + n_xonly_pubkeys) >= 1);
    ARG_CHECK(outpoints_hash32 != NULL);

    /* Compute input public keys tweak: A_tweaked = (A_0 + A_1 + ... + A_n) * outpoints_hash */
    for (i = 0; i < n_plain_pubkeys; i++) {
        secp256k1_pubkey combined;
        const secp256k1_pubkey *addends[2];
        if (i == 0) {
            A_tweaked = plain_pubkeys[0];
            continue;
        }
        addends[0] = &A_tweaked;
        addends[1] = &plain_pubkeys[i];
        if (!secp256k1_ec_pubkey_combine(ctx, &combined, addends, 2)) {
            return 0;
        }
        A_tweaked = combined;
    }
    /* X-only public keys have to be converted to regular public keys (assuming even parity) */
    for (i = 0; i < n_xonly_pubkeys; i++) {
        unsigned char pubkey_to_add_ser[33];
        secp256k1_pubkey combined, pubkey_to_add;
        const secp256k1_pubkey *addends[2];

        pubkey_to_add_ser[0] = 0x02;
        if (!secp256k1_xonly_pubkey_serialize(ctx, &pubkey_to_add_ser[1], &xonly_pubkeys[i])) {
            return 0;
        }
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_to_add, pubkey_to_add_ser, 33)) {
            return 0;
        }

        if (i == 0 && n_plain_pubkeys == 0) {
            A_tweaked = pubkey_to_add;
            continue;
        }
        addends[0] = &A_tweaked;
        addends[1] = &pubkey_to_add;
        if (!secp256k1_ec_pubkey_combine(ctx, &combined, addends, 2)) {
            return 0;
        }
        A_tweaked = combined;
    }

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &A_tweaked, outpoints_hash32)) {
        return 0;
    }

    /* Serialize tweak_data */
    if (!secp256k1_ec_pubkey_serialize(ctx, tweak_data33, &outputlen, &A_tweaked, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }

    return 1;
}

int secp256k1_silentpayments_receive_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *tweak_data33, const unsigned char *receiver_scan_seckey) {
    secp256k1_pubkey A_tweaked;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    memset(shared_secret33, 0, 33);
    ARG_CHECK(tweak_data33 != NULL);
    ARG_CHECK(receiver_scan_seckey != NULL);

    /* Parse tweak data into pubkey object */
    if (!secp256k1_ec_pubkey_parse(ctx, &A_tweaked, tweak_data33, 33)) {
        return 0;
    }

    /* Compute shared_secret = A_tweaked * b_scan */
    if (!secp256k1_ecdh(ctx, shared_secret33, &A_tweaked, receiver_scan_seckey, ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
}

static void secp256k1_silentpayments_create_t_k(unsigned char *t_k, const unsigned char *shared_secret33, unsigned int k) {
    secp256k1_sha256 sha;
    unsigned char shared_secret_and_k[33+4];

    /* Compute t_k = sha256(shared_secret || ser_32(k)) */
    memcpy(shared_secret_and_k, shared_secret33, 33);
    secp256k1_write_be32(shared_secret_and_k+33, k);
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, shared_secret_and_k, sizeof(shared_secret_and_k));
    secp256k1_sha256_finalize(&sha, t_k);
}

int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *output_xonly_pubkey, const unsigned char *shared_secret33, const secp256k1_pubkey *receiver_spend_pubkey, unsigned int k, const unsigned char *label_tweak32) {
    secp256k1_pubkey P_output;
    unsigned char t_k[32];

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output_xonly_pubkey != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(receiver_spend_pubkey != NULL);
    ARG_CHECK(label_tweak32 == NULL); /* label tweaks are not supported yet */

    /* Compute and return P_output = B_spend + t_k * G */
    secp256k1_silentpayments_create_t_k(t_k, shared_secret33, k);
    P_output = *receiver_spend_pubkey;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &P_output, t_k)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, output_xonly_pubkey, NULL, &P_output)) {
        return 0;
    }

    return 1;
}

#endif
