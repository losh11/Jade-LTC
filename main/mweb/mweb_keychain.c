#include "mweb_keychain.h"
#include "mweb_hash.h"

#include <string.h>

#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "../keychain.h"
#include "../sensitive.h"

/* ------------------------------------------------------------------ */
/*  Bech32 encoding (Pieter Wuille, MIT license)                      */
/*  Reimplemented here because libwally's bech32_encode/mweb_convert_bits   */
/*  are static and segwit_addr_encode rejects programs > 40 bytes.     */
/* ------------------------------------------------------------------ */

static const char MWEB_BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t mweb_bech32_polymod_step(uint32_t pre)
{
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
           (-((b >> 1) & 1) & 0x26508e6dUL) ^
           (-((b >> 2) & 1) & 0x1ea119faUL) ^
           (-((b >> 3) & 1) & 0x3d4233ddUL) ^
           (-((b >> 4) & 1) & 0x2a1462b3UL);
}

/*
 * Convert between bit groups.
 * out/outlen must be pre-zeroed (*outlen = 0).
 * Returns 1 on success.
 */
static int mweb_convert_bits(uint8_t* out, size_t* outlen, int outbits,
                        const uint8_t* in, size_t inlen, int inbits, int pad)
{
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

/*
 * Bech32 encode.
 * output must be large enough for hrp + "1" + data_len + 6 + NUL.
 */
static int mweb_bech32_encode(char* output, const char* hrp,
                              const uint8_t* data, size_t data_len)
{
    const size_t hrp_len = strlen(hrp);
    uint32_t chk = 1;
    size_t i;

    /* HRP expansion */
    for (i = 0; i < hrp_len; ++i) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126 || (ch >= 'A' && ch <= 'Z')) {
            return 0;
        }
        chk = mweb_bech32_polymod_step(chk) ^ (ch >> 5);
    }
    chk = mweb_bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = mweb_bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);
        *(output++) = hrp[i];
    }
    *(output++) = '1';

    /* Data */
    for (i = 0; i < data_len; ++i) {
        if (data[i] >> 5) {
            return 0;
        }
        chk = mweb_bech32_polymod_step(chk) ^ data[i];
        *(output++) = MWEB_BECH32_CHARSET[data[i]];
    }

    /* Checksum (bech32, constant = 1) */
    for (i = 0; i < 6; ++i) {
        chk = mweb_bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = MWEB_BECH32_CHARSET[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */

bool mweb_derive_key_from_path(const uint32_t* path, size_t path_len,
                               uint8_t key_out[32])
{
    const keychain_t* kc = keychain_get();
    if (!kc) {
        return false;
    }

    struct ext_key derived;
    SENSITIVE_PUSH(&derived, sizeof(derived));

    const int ret = bip32_key_from_parent_path(
        &kc->xpriv, path, path_len,
        BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH, &derived);

    if (ret == WALLY_OK) {
        /* priv_key[0] is 0x00 prefix, actual key is bytes 1-32 */
        memcpy(key_out, derived.priv_key + 1, 32);
    }

    SENSITIVE_POP(&derived);
    return ret == WALLY_OK;
}

bool mweb_derive_standard_keys(uint8_t scan_key[32], uint8_t spend_key[32])
{
    const uint32_t scan_path[] = MWEB_SCAN_PATH;
    const uint32_t spend_path[] = MWEB_SPEND_PATH;
    return mweb_derive_key_from_path(scan_path, MWEB_PATH_LEN, scan_key)
        && mweb_derive_key_from_path(spend_path, MWEB_PATH_LEN, spend_key);
}

/* ------------------------------------------------------------------ */
/*  Network HRP                                                        */
/* ------------------------------------------------------------------ */

const char* mweb_network_hrp(network_t network)
{
    switch (network) {
    case NETWORK_LITECOIN:
        return "ltcmweb";
    case NETWORK_LITECOIN_TESTNET:
    case NETWORK_LITECOIN_REGTEST:
        return "tmweb";
    default:
        return NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  Stealth address derivation                                         */
/* ------------------------------------------------------------------ */

bool mweb_derive_address(const uint8_t scan_key[32],
                         const uint8_t spend_key[32],
                         uint32_t index, network_t network,
                         char** address_out)
{
    if (!address_out) {
        return false;
    }
    *address_out = NULL;

    const char* hrp = mweb_network_hrp(network);
    if (!hrp) {
        return false;
    }

    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx) {
        return false;
    }

    bool ok = false;

    /*
     * m_i = BLAKE3('A' || index_le32 || scan_key)
     */
    uint8_t mi_input[4 + 32];
    mi_input[0] = (uint8_t)(index);
    mi_input[1] = (uint8_t)(index >> 8);
    mi_input[2] = (uint8_t)(index >> 16);
    mi_input[3] = (uint8_t)(index >> 24);
    memcpy(mi_input + 4, scan_key, 32);

    uint8_t m_i[32];
    mweb_hashed(MWEB_TAG_ADDRESS, mi_input, sizeof(mi_input), m_i);

    /*
     * spend_pubkey = spend_key * G  (33 bytes compressed)
     * m_i_pub = m_i * G
     */
    uint8_t spend_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(spend_key, 32,
            spend_pub, sizeof(spend_pub)) != WALLY_OK) {
        goto cleanup;
    }

    uint8_t mi_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(m_i, 32,
            mi_pub, sizeof(mi_pub)) != WALLY_OK) {
        goto cleanup;
    }

    /*
     * B_i = spend_pubkey + m_i*G  (EC point addition)
     */
    secp256k1_pubkey spend_pk, mi_pk, Bi_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &spend_pk, spend_pub, 33)) {
        goto cleanup;
    }
    if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) {
        goto cleanup;
    }
    const secp256k1_pubkey* pts[2] = { &spend_pk, &mi_pk };
    if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) {
        goto cleanup;
    }

    uint8_t Bi_bytes[EC_PUBLIC_KEY_LEN];
    size_t Bi_len = sizeof(Bi_bytes);
    secp256k1_ec_pubkey_serialize(ctx, Bi_bytes, &Bi_len,
                                  &Bi_pk, SECP256K1_EC_COMPRESSED);

    /*
     * A_i = scan_key * B_i  (scalar * point)
     */
    secp256k1_pubkey Ai_pk = Bi_pk;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Ai_pk, scan_key)) {
        goto cleanup;
    }

    uint8_t Ai_bytes[EC_PUBLIC_KEY_LEN];
    size_t Ai_len = sizeof(Ai_bytes);
    secp256k1_ec_pubkey_serialize(ctx, Ai_bytes, &Ai_len,
                                  &Ai_pk, SECP256K1_EC_COMPRESSED);

    /*
     * stealth_address = (A_i || B_i) = 66 bytes
     * Encode: convertbits(8→5) on payload, prepend version 0, bech32 encode
     */
    uint8_t payload[66];
    memcpy(payload, Ai_bytes, 33);
    memcpy(payload + 33, Bi_bytes, 33);

    /* mweb_convert_bits: 66 bytes × 8 bits = 528 bits → ceil(528/5) = 106 five-bit values */
    uint8_t data5[1 + 107]; /* version byte + max converted */
    size_t data5_len = 0;
    data5[0] = 0; /* witness version 0 */
    data5_len = 1;

    size_t converted_len = 0;
    if (!mweb_convert_bits(data5 + 1, &converted_len, 5, payload, 66, 8, 1)) {
        goto cleanup;
    }
    data5_len += converted_len;

    /* Bech32 encode: hrp(7) + "1" + data5(107) + checksum(6) + NUL = max 122 */
    char bech32_buf[128];
    if (!mweb_bech32_encode(bech32_buf, hrp, data5, data5_len)) {
        goto cleanup;
    }

    /* Allocate output string via wally (caller frees with wally_free_string) */
    const size_t addr_len = strlen(bech32_buf);
    char* result = wally_malloc(addr_len + 1);
    if (!result) {
        goto cleanup;
    }
    memcpy(result, bech32_buf, addr_len + 1);
    *address_out = result;
    ok = true;

cleanup:
    wally_bzero(m_i, sizeof(m_i));
    wally_bzero(mi_input, sizeof(mi_input));
    return ok;
}
