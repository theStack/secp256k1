#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for the ECC related parts of
 * Silent Payments, as specified in BIP352. This particularly involves
 * the creation of input tweak data by summing up private or public keys
 * and the derivation of a shared secret using Elliptic Curve Diffie-Hellman.
 * Combined are either:
 *   - spender's private keys and receiver's public key (a * B, sender side)
 *   - spender's public keys and receiver's private key (A * b, receiver side)
 * With this result, the necessary key material for ultimately creating/scanning
 * or spending Silent Payment outputs can be determined.
 *
 * Note that this module is _not_ a full implementation of BIP352, as it
 * inherently doesn't deal with higher-level concepts like addresses, output
 * script types or transactions. The intent is to provide cryptographical
 * helpers for low-level calculations that are most error-prone to custom
 * implementations (e.g. enforcing the right y-parity for key material, ECDH
 * calculation etc.). For any wallet software already using libsecp256k1, this
 * API should provide all the functions needed for a Silent Payments
 * implementation without the need for any further manual elliptic-curve
 * operations.
 */

/** Create Silent Payment tweak data from input private keys.
 *
 * Given a list of n private keys a_0...a_(n-1) (one for each input to spend)
 * and an outpoints_hash, compute the corresponding input private keys tweak data:
 *
 * a_tweaked = (a_0 + a_1 + ... a_(n-1)) * outpoints_hash
 *
 * If necessary, the private keys are negated to enforce the right y-parity.
 * For that reason, the private keys have to be passed in via two different parameter
 * pairs, depending on whether they were used for creating taproot outputs or not.
 * The resulting data is needed to create a shared secret for the sender side.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:          tweak_data32: pointer to the resulting 32-byte tweak data
 *  In:          plain_seckeys: pointer to an array of 32-byte private keys of non-taproot inputs
 *                              (can be NULL if no private keys of non-taproot inputs are used)
 *             n_plain_seckeys: the number of sender's non-taproot input private keys
 *             taproot_seckeys: pointer to an array of 32-byte private keys of taproot inputs
 *                              (can be NULL if no private keys of taproot inputs are used)
 *           n_taproot_seckeys: the number of sender's taproot input private keys
 *            outpoints_hash32: hash of the sorted serialized outpoints
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_private_tweak_data(
    const secp256k1_context *ctx,
    unsigned char *tweak_data32,
    const unsigned char *plain_seckeys,
    size_t n_plain_seckeys,
    const unsigned char *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char *outpoints_hash32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(7);

/* TODO: add function API for receiver side. */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
