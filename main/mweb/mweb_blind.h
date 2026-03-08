#ifndef MWEB_BLIND_H_
#define MWEB_BLIND_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * BlindSwitch: switches a blinding factor through a commitment hash.
 *
 * Algorithm:
 *   C = Pedersen(blind, value)       → 33 bytes, 0x08/0x09 prefix
 *   J = blind * generator_J          → 33 bytes, 0x02/0x03 prefix
 *   tweak = SHA256(C || J)            → 32 bytes
 *   output = blind + tweak (mod n)
 *
 * The two serialization formats differ intentionally:
 *   C uses Pedersen commitment format (0x08/0x09)
 *   J uses standard compressed pubkey format (0x02/0x03)
 */
bool mweb_blind_switch(const uint8_t blind[32], uint64_t value,
                       uint8_t output_blind[32]);

/*
 * Pedersen commitment: C = blind*G + value*H → 33-byte serialized.
 *
 * Uses secp256k1_pedersen_commit with the standard generator H
 * (secp256k1_generator_h from libsecp256k1-zkp).
 *
 * Output format: [0x08 or 0x09] [32 bytes X coordinate]
 * *** NOT standard 0x02/0x03 compressed pubkey format ***
 */
bool mweb_pedersen_commit(const uint8_t blind[32], uint64_t value,
                          uint8_t commitment[33]);

#endif /* MWEB_BLIND_H_ */
