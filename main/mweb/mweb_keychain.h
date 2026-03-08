#ifndef MWEB_KEYCHAIN_H_
#define MWEB_KEYCHAIN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../utils/network.h"
#include <wally_bip32.h>

/* Standard MWEB derivation paths */
#define MWEB_SCAN_PATH                                                         \
    {                                                                          \
        BIP32_INITIAL_HARDENED_CHILD, BIP32_INITIAL_HARDENED_CHILD + 100,      \
            BIP32_INITIAL_HARDENED_CHILD                                        \
    } /* m/0'/100'/0' */
#define MWEB_SPEND_PATH                                                        \
    {                                                                          \
        BIP32_INITIAL_HARDENED_CHILD, BIP32_INITIAL_HARDENED_CHILD + 100,      \
            BIP32_INITIAL_HARDENED_CHILD + 1                                    \
    } /* m/0'/100'/1' */
#define MWEB_PATH_LEN 3

/*
 * Derive MWEB key from BIP32 path via Jade's master keychain.
 * For standalone RPC: use MWEB_SCAN_PATH or MWEB_SPEND_PATH.
 * For PSBT signing: use the path from 0x9A/0x9B origin fields.
 * Returns 32-byte private key. Caller wraps in SENSITIVE_PUSH/POP.
 */
bool mweb_derive_key_from_path(const uint32_t* path, size_t path_len,
                               uint8_t key_out[32]);

/*
 * Derive scan and spend keys using standard paths m/0'/100'/0' and m/0'/100'/1'.
 * Convenience wrapper for standalone RPC commands.
 */
bool mweb_derive_standard_keys(uint8_t scan_key[32], uint8_t spend_key[32]);

/*
 * Derive MWEB stealth address at subaddress index.
 * Requires scan + spend SECRET keys (32 bytes each).
 *
 * Algorithm:
 *   m_i = BLAKE3('A' || index_le32 || scan_key)
 *   B_i = spend_pubkey + m_i*G
 *   A_i = scan_key * B_i
 *   address = bech32(hrp, version=0, A_i || B_i)
 *
 * Returns bech32 string via address_out. Caller must free with wally_free_string().
 */
bool mweb_derive_address(const uint8_t scan_key[32],
                         const uint8_t spend_key[32],
                         uint32_t index, network_t network,
                         char** address_out);

/* Get MWEB bech32 HRP for a network. Returns NULL for non-Litecoin networks. */
const char* mweb_network_hrp(network_t network);

#endif /* MWEB_KEYCHAIN_H_ */
