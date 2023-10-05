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

/* TODO: implement functions for receiver side. */

#endif
