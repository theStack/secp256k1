#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for the ECC related parts of
 * Silent Payments, as specified in BIP352. This particularly involves the
 * derivation of a shared secret using Elliptic Curve Diffie-Hellman, for
 * determining transaction output public keys. Combined are either:
 *   - spender's private keys and receiver's public key (a * B, sender side)
 *   - spender's public keys and receiver's private key (A * b, receiver side)
 *
 * Note that this module is *not* a full implementation of BIP352, as it
 * inherently doesn't deal with concepts like addresses, transactions or output
 * script types. The intent is to provide cryptographical helpers for low-level
 * calculations that are most error-prone to custom implementations (e.g.
 * tweaking of private and public keys, ECDH calculation etc.). For any wallet
 * already using libsecp256k1, this API should include all the ECC functions
 * needed for a Silent Payments implementation without the need for any further
 * manual cryptographical calculations.
 */

/** Create Silent Payment shared secret for the sender side.
 *
 *  Given a list of n private keys a_0...a_(n-1) (one for each input to spend),
 *  an outpoints_hash, and a recipient's scan public key B_scan, compute the
 *  corresponding shared secret using ECDH:
 *
 *  shared_secret = ((a_0 + a_1 + ... a_(n-1)) * outpoints_hash) * B_scan
 *
 *  Note that the private keys have to be passed in via two different parameter
 *  pairs, depending on whether they were used for creating taproot outputs or not.
 *  The resulting data is needed as input for creating silent payments outputs
 *  belonging to the same receiver scan public key.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:       shared_secret33: pointer to the resulting 33-byte shared secret
 *  In:          plain_seckeys: pointer to an array of 32-byte private keys of non-taproot inputs
 *                              (can be NULL if no private keys of non-taproot inputs are used)
 *             n_plain_seckeys: the number of sender's non-taproot input private keys
 *              xonly_keypairs: pointer to an array of keypairs of taproot inputs
 *                              (can be NULL if no private keys of taproot inputs are used)
 *            n_xonly_keypairs: the number of sender's taproot input keypairs
 *            outpoints_hash32: hash of the sorted serialized outpoints
 *        receiver_scan_pubkey: pointer to the receiver's scan pubkey
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_send_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const unsigned char *plain_seckeys,
    size_t n_plain_seckeys,
    const secp256k1_keypair *xonly_keypairs,
    size_t n_xonly_keypairs,
    const unsigned char *outpoints_hash32,
    const secp256k1_pubkey *receiver_scan_pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/* TODO: add function API for receiver side. */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
