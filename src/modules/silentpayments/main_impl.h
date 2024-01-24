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

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Inputs". */
static void secp256k1_silentpayments_sha256_init_inputs(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0xd4143ffcul;
    hash->s[1] = 0x012ea4b5ul;
    hash->s[2] = 0x36e21c8ful;
    hash->s[3] = 0xf7ec7b54ul;
    hash->s[4] = 0x4dd4e2acul;
    hash->s[5] = 0x9bcaa0a4ul;
    hash->s[6] = 0xe244899bul;
    hash->s[7] = 0xcd06903eul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_calculate_input_hash(secp256k1_scalar *input_hash_scalar, const unsigned char *outpoint_lowest36, secp256k1_ge *pubkey_sum) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char pubkey_sum_ser[33];
    size_t ser_size;
    int ser_ret;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_lowest36, 36);
    ser_ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == sizeof(pubkey_sum_ser));
    (void)ser_ret;
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(input_hash_scalar, hash_ser, NULL);
}

int secp256k1_silentpayments_create_private_tweak_data(const secp256k1_context *ctx, unsigned char *tweak_data32, const unsigned char *plain_seckeys, size_t n_plain_seckeys, const unsigned char *taproot_seckeys, size_t n_taproot_seckeys, const unsigned char *outpoint_lowest36) {
    size_t i;
    secp256k1_scalar a_sum;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    secp256k1_scalar input_hash_scalar;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_data32 != NULL);
    memset(tweak_data32, 0, 32);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(plain_seckeys == NULL || n_plain_seckeys >= 1);
    ARG_CHECK(taproot_seckeys == NULL || n_taproot_seckeys >= 1);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    ARG_CHECK((n_plain_seckeys + n_taproot_seckeys) >= 1);
    ARG_CHECK(outpoint_lowest36 != NULL);

    /* Compute input private keys sum: a_sum = a_1 + a_2 + ... + a_n */
    a_sum = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        secp256k1_scalar addend;
        int ret = secp256k1_scalar_set_b32_seckey(&addend, &plain_seckeys[i*32]);
        VERIFY_CHECK(ret);
        (void)ret;

        secp256k1_scalar_add(&a_sum, &a_sum, &addend);
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&a_sum));
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_scalar addend;
        secp256k1_ge addend_point;
        int ret = secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &addend, &addend_point, &taproot_seckeys[i*32]);
        VERIFY_CHECK(ret);
        (void)ret;
        /* declassify addend_point to allow using it as a branch point (this is fine because addend_point is not a secret) */
        secp256k1_declassify(ctx, &addend_point, sizeof(addend_point));
        secp256k1_fe_normalize_var(&addend_point.y);
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }

        secp256k1_scalar_add(&a_sum, &a_sum, &addend);
        VERIFY_CHECK(!secp256k1_scalar_is_zero(&a_sum));
    }

    /* Compute input_hash = hash(outpoint_L || A_sum) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &A_sum_gej, &a_sum);
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    secp256k1_silentpayments_calculate_input_hash(&input_hash_scalar, outpoint_lowest36, &A_sum_ge);

    /* Compute a_tweaked = a_sum * input_hash */
    secp256k1_scalar_mul(&a_sum, &a_sum, &input_hash_scalar);
    secp256k1_scalar_get_b32(tweak_data32, &a_sum);

    return 1;
}

/* secp256k1_ecdh expects a hash function to be passed in or uses its default
 * hashing function. We don't want to hash the ECDH result, so we define a
 * custom function which simply returns the pubkey without hashing.
 */
static int secp256k1_silentpayments_ecdh_return_pubkey(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    secp256k1_ge point;
    secp256k1_fe x, y;
    size_t ser_size;
    int ser_ret;

    (void)data;
    /* Parse point as group element */
    if (!secp256k1_fe_set_b32_limit(&x, x32) || !secp256k1_fe_set_b32_limit(&y, y32)) {
        return 0;
    }
    secp256k1_ge_set_xy(&point, &x, &y);

    /* Serialize as compressed pubkey */
    ser_ret = secp256k1_eckey_pubkey_serialize(&point, output, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == 33);
    (void)ser_ret;

    return 1;
}

int secp256k1_silentpayments_send_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *tweak_data32, const secp256k1_pubkey *receiver_scan_pubkey) {
    /* Sanity check inputs */
    ARG_CHECK(shared_secret33 != NULL);
    memset(shared_secret33, 0, 33);
    ARG_CHECK(receiver_scan_pubkey != NULL);

    /* Compute shared_secret = a_tweaked * B_scan */
    if (!secp256k1_ecdh(ctx, shared_secret33, receiver_scan_pubkey, tweak_data32, secp256k1_silentpayments_ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
}

int secp256k1_silentpayments_create_public_tweak_data(const secp256k1_context *ctx, unsigned char *tweak_data33, const secp256k1_pubkey *plain_pubkeys, size_t n_plain_pubkeys, const secp256k1_xonly_pubkey *xonly_pubkeys, size_t n_xonly_pubkeys, const unsigned char *outpoint_lowest36) {
    size_t i;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    secp256k1_scalar input_hash_scalar;
    size_t ser_size;
    int ser_ret;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(tweak_data33 != NULL);
    memset(tweak_data33, 0, 33);
    ARG_CHECK(plain_pubkeys == NULL || n_plain_pubkeys >= 1);
    ARG_CHECK(xonly_pubkeys == NULL || n_xonly_pubkeys >= 1);
    ARG_CHECK((plain_pubkeys != NULL) || (xonly_pubkeys != NULL));
    ARG_CHECK((n_plain_pubkeys + n_xonly_pubkeys) >= 1);
    ARG_CHECK(outpoint_lowest36 != NULL);

    /* Compute input public keys sum: A_sum = A_1 + A_2 + ... + A_n */
    secp256k1_gej_set_infinity(&A_sum_gej);
    for (i = 0; i < n_plain_pubkeys; i++) {
        secp256k1_ge addend;
        secp256k1_pubkey_load(ctx, &addend, &plain_pubkeys[i]);
        secp256k1_gej_add_ge(&A_sum_gej, &A_sum_gej, &addend);
    }

    /* X-only public keys have to be converted to regular public keys (assuming even parity) */
    for (i = 0; i < n_xonly_pubkeys; i++) {
        secp256k1_ge addend;
        secp256k1_xonly_pubkey_load(ctx, &addend, &xonly_pubkeys[i]);
        if (secp256k1_fe_is_odd(&addend.y)) {
            secp256k1_fe_negate(&addend.y, &addend.y, 1);
        }
        VERIFY_CHECK(!secp256k1_fe_is_odd(&addend.y));
        secp256k1_gej_add_ge(&A_sum_gej, &A_sum_gej, &addend);
    }
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);

    /* Compute input_hash = hash(outpoint_L || A_sum) */
    secp256k1_silentpayments_calculate_input_hash(&input_hash_scalar, outpoint_lowest36, &A_sum_ge);

    /* Compute A_tweaked = A_sum * input_hash */
    if (!secp256k1_eckey_pubkey_tweak_mul(&A_sum_ge, &input_hash_scalar)) {
        return 0;
    }

    /* Serialize tweak_data */
    ser_ret = secp256k1_eckey_pubkey_serialize(&A_sum_ge, tweak_data33, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == 33);
    (void)ser_ret;

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
    if (!secp256k1_ecdh(ctx, shared_secret33, &A_tweaked, receiver_scan_seckey, secp256k1_silentpayments_ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Label". */
static void secp256k1_silentpayments_sha256_init_label(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x26b95d63ul;
    hash->s[1] = 0x8bf1b740ul;
    hash->s[2] = 0x10a5986ful;
    hash->s[3] = 0x06a387a5ul;
    hash->s[4] = 0x2d1c1c30ul;
    hash->s[5] = 0xd035951aul;
    hash->s[6] = 0x2d7f0f96ul;
    hash->s[7] = 0x29e3e0dbul;

    hash->bytes = 64;
}

int secp256k1_silentpayments_create_label_tweak(const secp256k1_context *ctx, unsigned char *label_tweak32, const unsigned char *receiver_scan_seckey, unsigned int m) {
    secp256k1_sha256 hash;
    unsigned char m_serialized[4];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    (void)ctx;
    VERIFY_CHECK(label_tweak32 != NULL);
    VERIFY_CHECK(receiver_scan_seckey != NULL);

    /* Compute label_tweak = hash(ser_256(b_scan) || ser_32(m))  [sha256 with tag "BIP0352/Label"] */
    secp256k1_silentpayments_sha256_init_label(&hash);
    secp256k1_sha256_write(&hash, receiver_scan_seckey, 32);
    secp256k1_write_be32(m_serialized, m);
    secp256k1_sha256_write(&hash, m_serialized, sizeof(m_serialized));
    secp256k1_sha256_finalize(&hash, label_tweak32);

    return 1;
}

int secp256k1_silentpayments_create_address_spend_pubkey(const secp256k1_context *ctx, unsigned char *l_addr_spend_pubkey33, const secp256k1_pubkey *receiver_spend_pubkey, const unsigned char *label_tweak32) {
    secp256k1_ge B_m;
    size_t ser_size;
    int ser_ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    VERIFY_CHECK(l_addr_spend_pubkey33 != NULL);
    VERIFY_CHECK(receiver_spend_pubkey != NULL);
    VERIFY_CHECK(label_tweak32 != NULL);

    /* Calculate B_m = B_spend + label_tweak * G */
    secp256k1_pubkey_load(ctx, &B_m, receiver_spend_pubkey);
    if (!secp256k1_ec_pubkey_tweak_add_helper(&B_m, label_tweak32)) {
        return 0;
    }

    /* Serialize B_m */
    ser_ret = secp256k1_eckey_pubkey_serialize(&B_m, l_addr_spend_pubkey33, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == 33);
    (void)ser_ret;

    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/SharedSecret". */
static void secp256k1_silentpayments_sha256_init_sharedsecret(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x88831537ul;
    hash->s[1] = 0x5127079bul;
    hash->s[2] = 0x69c2137bul;
    hash->s[3] = 0xab0303e6ul;
    hash->s[4] = 0x98fa21faul;
    hash->s[5] = 0x4a888523ul;
    hash->s[6] = 0xbd99daabul;
    hash->s[7] = 0xf25e5e0aul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_create_t_k(secp256k1_scalar *t_k_scalar, const unsigned char *shared_secret33, unsigned int k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];

    /* Compute t_k = hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 33);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(t_k_scalar, hash_ser, NULL);
}

int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *output_xonly_pubkey, const unsigned char *shared_secret33, const secp256k1_pubkey *receiver_spend_pubkey, unsigned int k, const unsigned char *label_tweak32) {
    secp256k1_ge P_output;
    secp256k1_scalar t_k_scalar;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output_xonly_pubkey != NULL);
    ARG_CHECK(receiver_spend_pubkey != NULL);

    /* Apply label tweak if provided: B_m = B_spend + label_tweak * G */
    secp256k1_pubkey_load(ctx, &P_output, receiver_spend_pubkey);
    if (label_tweak32 != NULL) {
        if (!secp256k1_ec_pubkey_tweak_add_helper(&P_output, label_tweak32)) {
            return 0;
        }
    }

    /* Calculate and return P_output = B_m + t_k * G */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    if (!secp256k1_eckey_pubkey_tweak_add(&P_output, &t_k_scalar)) {
        return 0;
    }
    secp256k1_xonly_pubkey_save(output_xonly_pubkey, &P_output);

    return 1;
}

int secp256k1_silentpayments_create_output_seckey(const secp256k1_context *ctx, unsigned char *output_seckey, const unsigned char *shared_secret33, const unsigned char *receiver_spend_seckey, unsigned int k, const unsigned char *label_tweak32) {
    secp256k1_scalar t_k_scalar;
    secp256k1_scalar final_seckey;
    int ret;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output_seckey != NULL);
    memset(output_seckey, 0, 32);
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(receiver_spend_seckey != NULL);

    /* Apply label tweak if provided */
    ret = secp256k1_scalar_set_b32_seckey(&final_seckey, receiver_spend_seckey);
    VERIFY_CHECK(ret);
    (void)ret;
    if (label_tweak32 != NULL) {
        secp256k1_scalar tweak_scalar;
        secp256k1_scalar_set_b32(&tweak_scalar, label_tweak32, NULL);
        secp256k1_eckey_privkey_tweak_add(&final_seckey, &tweak_scalar);
    }

    /* Compute and return d = (b_m + t_k) mod n */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    secp256k1_eckey_privkey_tweak_add(&final_seckey, &t_k_scalar);
    secp256k1_scalar_get_b32(output_seckey, &final_seckey);
    secp256k1_scalar_clear(&final_seckey);

    return 1;
}

#endif
