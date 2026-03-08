#include "mweb_sign.h"
#include "mweb_blind.h"
#include "mweb_hash.h"
#include "mweb_schnorr.h"

#include <string.h>

#include <blake3.h>
#include <secp256k1.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "../random.h"

/*
 * Write a Bitcoin-style compact varint to buf.
 * Returns the number of bytes written (1, 3, 5, or 9).
 */
static size_t write_varint(uint8_t* buf, uint64_t val)
{
    if (val < 0xfd) {
        buf[0] = (uint8_t)val;
        return 1;
    } else if (val <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = (uint8_t)(val);
        buf[2] = (uint8_t)(val >> 8);
        return 3;
    } else if (val <= 0xffffffff) {
        buf[0] = 0xfe;
        buf[1] = (uint8_t)(val);
        buf[2] = (uint8_t)(val >> 8);
        buf[3] = (uint8_t)(val >> 16);
        buf[4] = (uint8_t)(val >> 24);
        return 5;
    } else {
        buf[0] = 0xff;
        for (int i = 0; i < 8; i++) {
            buf[1 + i] = (uint8_t)(val >> (i * 8));
        }
        return 9;
    }
}

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
    const uint8_t* shared_secret_in,
    mweb_sign_result_t* result)
{
    const secp256k1_context* ctx = wally_get_secp_context();
    if (!ctx || !result) {
        return false;
    }

    /* Exactly one of key_exchange_pk / shared_secret_in must be provided */
    if ((!key_exchange_pk && !shared_secret_in)
        || (key_exchange_pk && shared_secret_in)) {
        return false;
    }

    /* 1. Validate STEALTH_KEY_BIT */
    if (!(features & MWEB_INPUT_STEALTH_KEY_BIT)) {
        return false;
    }

    bool ok = false;
    uint8_t ss[32];           /* shared secret */
    uint8_t pre_blind[32];
    uint8_t out_key_hash[32];
    uint8_t m_i[32];
    uint8_t osk[32];          /* output spend key (scalar) */
    uint8_t blind[32];
    uint8_t ephemeral[32];
    uint8_t key_hash[32];
    uint8_t sig_key[32];
    uint8_t msg_hash[32];

    /* 2. Derive shared secret */
    if (key_exchange_pk) {
        /* ECDH: key_exchange_pk * scan_key → compressed → Hashed('D', ...) */
        secp256k1_pubkey kex;
        if (!secp256k1_ec_pubkey_parse(ctx, &kex, key_exchange_pk, 33)) {
            return false;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &kex, scan_key)) {
            return false;
        }
        uint8_t ecdh_result[EC_PUBLIC_KEY_LEN];
        size_t ecdh_len = sizeof(ecdh_result);
        secp256k1_ec_pubkey_serialize(ctx, ecdh_result, &ecdh_len,
                                      &kex, SECP256K1_EC_COMPRESSED);
        mweb_hashed(MWEB_TAG_DERIVE, ecdh_result, 33, ss);
    } else {
        memcpy(ss, shared_secret_in, 32);
    }

    /* 3. pre_blind = Hashed('B', ss) */
    mweb_hashed(MWEB_TAG_BLIND, ss, 32, pre_blind);

    /* 4. out_key_hash = Hashed('O', ss) */
    mweb_hashed(MWEB_TAG_OUTKEY, ss, 32, out_key_hash);

    /* 5. m_i = Hashed('A', index_le32 || scan_key) */
    {
        uint8_t mi_buf[4 + 32];
        mi_buf[0] = (uint8_t)(address_index);
        mi_buf[1] = (uint8_t)(address_index >> 8);
        mi_buf[2] = (uint8_t)(address_index >> 16);
        mi_buf[3] = (uint8_t)(address_index >> 24);
        memcpy(mi_buf + 4, scan_key, 32);
        mweb_hashed(MWEB_TAG_ADDRESS, mi_buf, sizeof(mi_buf), m_i);
    }

    /* 6. output_spend_key = (spend_key + m_i) * out_key_hash */
    memcpy(osk, spend_key, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, osk, m_i)) {
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_tweak_mul(ctx, osk, out_key_hash)) {
        goto cleanup;
    }

    /* 7. Output key verification (mandatory — no bypass)
     *    B_i = spend_pubkey + m_i*G
     *    expected_Ko = out_key_hash * B_i
     *    ASSERT(expected_Ko == spent_output_pk) */
    {
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

        /* B_i = spend_pub + m_i*G */
        secp256k1_pubkey sp_pk, mi_pk, Bi_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &sp_pk, spend_pub, 33)) {
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_parse(ctx, &mi_pk, mi_pub, 33)) {
            goto cleanup;
        }
        const secp256k1_pubkey* pts[2] = { &sp_pk, &mi_pk };
        if (!secp256k1_ec_pubkey_combine(ctx, &Bi_pk, pts, 2)) {
            goto cleanup;
        }

        /* expected_Ko = out_key_hash * B_i */
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Bi_pk, out_key_hash)) {
            goto cleanup;
        }

        uint8_t expected_Ko[EC_PUBLIC_KEY_LEN];
        size_t ko_len = sizeof(expected_Ko);
        secp256k1_ec_pubkey_serialize(ctx, expected_Ko, &ko_len,
                                      &Bi_pk, SECP256K1_EC_COMPRESSED);

        /* Reject if output key doesn't match */
        if (memcmp(expected_Ko, spent_output_pk, EC_PUBLIC_KEY_LEN) != 0) {
            goto cleanup;
        }
    }

    /* 8. blind = BlindSwitch(pre_blind, amount) */
    if (!mweb_blind_switch(pre_blind, amount, blind)) {
        goto cleanup;
    }

    /* 9. ephemeral_key = get_random(32) — hardware TRNG */
    get_random(ephemeral, sizeof(ephemeral));

    /* 10. input_pubkey = ephemeral * G → serialize compressed */
    if (wally_ec_public_key_from_private_key(ephemeral, 32,
            result->input_pubkey, EC_PUBLIC_KEY_LEN) != WALLY_OK) {
        goto cleanup;
    }

    /* 11. key_hash = BLAKE3(input_pubkey || spent_output_pk) — raw, NO tag */
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, result->input_pubkey, 33);
        blake3_hasher_update(&hasher, spent_output_pk, 33);
        blake3_hasher_finalize(&hasher, key_hash, 32);
    }

    /* 12. sig_key = output_spend_key * key_hash + ephemeral */
    memcpy(sig_key, osk, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, sig_key, key_hash)) {
        goto cleanup;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, sig_key, ephemeral)) {
        goto cleanup;
    }

    /* 13. msg_hash = BLAKE3(features || spent_output_id || [varint+extra_data]) — raw */
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &features, 1);
        blake3_hasher_update(&hasher, spent_output_id, 32);

        if (features & MWEB_INPUT_EXTRA_DATA_BIT) {
            uint8_t vi_buf[9];
            size_t vi_len = write_varint(vi_buf, (uint64_t)extra_data_len);
            blake3_hasher_update(&hasher, vi_buf, vi_len);
            if (extra_data && extra_data_len > 0) {
                blake3_hasher_update(&hasher, extra_data, extra_data_len);
            }
        }

        blake3_hasher_finalize(&hasher, msg_hash, 32);
    }

    /* 14. signature = SchnorrSign(sig_key, msg_hash) */
    if (!mweb_schnorr_sign(sig_key, msg_hash, 32, result->signature)) {
        goto cleanup;
    }

    /* 15. output_commit = Pedersen(blind, amount) — 33 bytes, 0x08/0x09 prefix */
    if (!mweb_pedersen_commit(blind, amount, result->output_commit)) {
        goto cleanup;
    }

    /* 16. stealth_tweak = ephemeral - output_spend_key */
    memcpy(result->stealth_tweak, ephemeral, 32);
    {
        uint8_t neg_osk[32];
        memcpy(neg_osk, osk, 32);
        if (!secp256k1_ec_seckey_negate(ctx, neg_osk)) {
            goto cleanup;
        }
        if (!secp256k1_ec_seckey_tweak_add(ctx, result->stealth_tweak, neg_osk)) {
            goto cleanup;
        }
        wally_bzero(neg_osk, sizeof(neg_osk));
    }

    /* 17. input_blind = blind (for caller's offset bookkeeping) */
    memcpy(result->input_blind, blind, 32);

    ok = true;

cleanup:
    wally_bzero(ss, sizeof(ss));
    wally_bzero(pre_blind, sizeof(pre_blind));
    wally_bzero(out_key_hash, sizeof(out_key_hash));
    wally_bzero(m_i, sizeof(m_i));
    wally_bzero(osk, sizeof(osk));
    wally_bzero(blind, sizeof(blind));
    wally_bzero(ephemeral, sizeof(ephemeral));
    wally_bzero(key_hash, sizeof(key_hash));
    wally_bzero(sig_key, sizeof(sig_key));
    wally_bzero(msg_hash, sizeof(msg_hash));
    return ok;
}
