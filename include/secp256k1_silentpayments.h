#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"

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

/* TODO: add function API for sender side. */

/* TODO: add function API for receiver side. */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
