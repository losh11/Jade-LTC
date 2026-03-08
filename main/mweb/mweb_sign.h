#ifndef MWEB_SIGN_H_
#define MWEB_SIGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MWEB_INPUT_STEALTH_KEY_BIT 0x01
#define MWEB_INPUT_EXTRA_DATA_BIT  0x02

typedef struct {
    uint8_t signature[64];
    uint8_t input_blind[32];  /* For global offset: MwebTxOffset -= input_blind */
    uint8_t stealth_tweak[32]; /* For global offset: MwebStealthOffset += stealth_tweak */
    uint8_t input_pubkey[33]; /* Ephemeral input pubkey K_i */
    uint8_t output_commit[33]; /* Pedersen(blind, amount), 0x08/0x09 prefix */
} mweb_sign_result_t;

/*
 * Sign an MWEB input with full output key verification.
 *
 * Accepts either key_exchange_pk (33 bytes) OR shared_secret (32 bytes).
 * If key_exchange_pk is provided, Jade derives the shared secret on-device.
 * If shared_secret is provided, it is used directly.
 * Exactly one of key_exchange_pk / shared_secret must be non-NULL.
 *
 * Output key verification is mandatory — the function re-derives the expected
 * output pubkey from address_index and rejects if it doesn't match spent_output_pk.
 */
bool mweb_sign_input(
    const uint8_t scan_key[32],
    const uint8_t spend_key[32],
    uint32_t address_index,
    uint8_t features,
    const uint8_t spent_output_id[32],
    const uint8_t spent_output_pk[33],
    uint64_t amount,
    const uint8_t* extra_data,
    size_t extra_data_len,
    const uint8_t* key_exchange_pk,
    const uint8_t* shared_secret,
    mweb_sign_result_t* result);

#endif /* MWEB_SIGN_H_ */
