#ifndef MWEB_SCHNORR_H_
#define MWEB_SCHNORR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * MWEB Schnorr signature
 *
 * Differences from BIP340:
 *   - SHA256 for nonce derivation and challenge (not tagged SHA256)
 *   - 33-byte compressed pubkey in challenge hash (not x-only 32-byte)
 *   - Quadratic residue convention for R.y (not even/odd parity)
 *   - s = e * secret_key + k (same math, different normalization)
 *
 * Algorithm:
 *   k = SHA256(secret_key || message)
 *   R = k * G
 *   if R.y is NOT a quadratic residue mod p: negate k
 *   e = SHA256(R.x || compress(secret_key*G) || message)
 *   s = e * secret_key + k
 *   signature = (R.x[32] || s[32])
 */
bool mweb_schnorr_sign(const uint8_t secret_key[32],
                       const uint8_t* msg, size_t msg_len,
                       uint8_t signature[64]);

#endif /* MWEB_SCHNORR_H_ */
