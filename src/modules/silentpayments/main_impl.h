/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_silentpayments.h"

int secp256k1_silentpayments_create_private_tweak_data(const secp256k1_context *ctx, unsigned char *tweak_data32, const unsigned char *plain_seckeys, size_t n_plain_seckeys, const unsigned char *taproot_seckeys, size_t n_taproot_seckeys, const unsigned char *outpoints_hash32) {
    size_t i;
    unsigned char a_tweaked[32];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_data32 != NULL);
    memset(tweak_data32, 0, 32);
    ARG_CHECK(plain_seckeys == NULL || n_plain_seckeys >= 1);
    ARG_CHECK(taproot_seckeys == NULL || n_taproot_seckeys >= 1);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    ARG_CHECK((n_plain_seckeys + n_taproot_seckeys) >= 1);
    ARG_CHECK(outpoints_hash32 != NULL);

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
    for (i = 0; i < n_taproot_seckeys; i++) {
        unsigned char seckey_to_add[32];
        secp256k1_pubkey pubkey;
        secp256k1_ge ge;

        memcpy(seckey_to_add, &taproot_seckeys[32*i], 32);
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey_to_add)) {
            return 0;
        }
        if (!secp256k1_pubkey_load(ctx, &ge, &pubkey)) {
            return 0;
        }
        if (secp256k1_fe_is_odd(&ge.y)) {
            if (!secp256k1_ec_seckey_negate(ctx, seckey_to_add)) {
                return 0;
            }
        }

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

    memcpy(tweak_data32, a_tweaked, 32);
    return 1;
}

/* TODO: implement functions for receiver side. */

#endif
