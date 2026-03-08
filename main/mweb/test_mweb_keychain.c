/*
 * Tests for MWEB key derivation, stealth address generation, and HRP mapping.
 *
 * Fixed-vector tests using known scan/spend keys and expected stealth
 * addresses from ltcsuite waddrmgr/mweb_compat_test.go.
 *
 * Derivation path: m/0'/100'/0' (scan), m/0'/100'/1' (spend)
 * Seed: 2a64df085eefedd8bfdbb33176b5ba2e62e8be8b56c8837795598bb6c440c064
 */
#include "mweb_keychain.h"
#include "../keychain.h"

#include <stdio.h>
#include <string.h>

#include <wally_bip32.h>
#include <wally_core.h>

static int failures = 0;

/* --- Known keys (m/0'/100') --- */

static const uint8_t SCAN_KEY[32] = {
    0xb3,0xc9,0x1b,0x72,0x91,0xc2,0xe1,0xe0,
    0x6d,0x4a,0x93,0xf3,0xdc,0x32,0x40,0x4a,
    0xef,0x99,0x27,0xdb,0x8e,0x79,0x4c,0x01,
    0xa7,0xb4,0xde,0x18,0xa3,0x97,0xc3,0x38,
};

static const uint8_t SPEND_KEY[32] = {
    0x2f,0xe1,0x98,0x2b,0x98,0xc0,0xb6,0x8c,
    0x08,0x39,0x42,0x1c,0x8a,0x0a,0x0a,0x67,
    0xef,0x31,0x98,0xc7,0x46,0xab,0x8e,0x6d,
    0x09,0x10,0x1e,0xb7,0x39,0x6a,0x44,0xd8,
};

/* --- Expected stealth addresses --- */

static const struct {
    uint32_t index;
    const char* encoded;
} EXPECTED_ADDRESSES[] = {
    { 0, "ltcmweb1qqwkdldufg0enxpphwc8rwucc9ru6h43x5uklzm78ektgmufmw3j6k"
         "qu76qqw66w204vn7zddfgmnyq9ujugjvx4t2mhuqkuj5h4tgd8cvs6gg076" },
    { 1, "ltcmweb1qqfgk4yhnh3szt08zjy0xw9qdmmf54s0e8r0szjxfk3uw2aa4q48yy"
         "q6a44z9re8jhl2khvpxdgfdj2h5wjw58fzjgu099fphh8tmhv2hcygfr2nl" },
    { 10, "ltcmweb1qq0uxfh92v7n52shlndddcfad97gqycnt42gnwt56aemn0m87cxxv5"
          "qnjy0cyh9rp0mq46l2uzdwyyfp27e9jz203wzqwdvg826akasgqwvgs2kze" },
};

/* --- Tests --- */

static void test_address(uint32_t index, const char* expected)
{
    char* addr = NULL;
    char name[64];
    snprintf(name, sizeof(name), "derive_address(index=%u)", index);

    if (!mweb_derive_address(SCAN_KEY, SPEND_KEY, index,
                             NETWORK_LITECOIN, &addr)) {
        printf("FAIL: %s — derivation failed\n", name);
        failures++;
        return;
    }

    if (!addr) {
        printf("FAIL: %s — NULL address\n", name);
        failures++;
        return;
    }

    if (strcmp(addr, expected) != 0) {
        printf("FAIL: %s\n  got:  %s\n  want: %s\n", name, addr, expected);
        failures++;
        wally_free_string(addr);
        return;
    }

    printf("PASS: %s\n", name);
    wally_free_string(addr);
}

static void test_network_hrp(void)
{
    const char* hrp;

    hrp = mweb_network_hrp(NETWORK_LITECOIN);
    if (!hrp || strcmp(hrp, "ltcmweb") != 0) {
        printf("FAIL: hrp(LITECOIN) = %s, want ltcmweb\n", hrp ? hrp : "NULL");
        failures++;
    } else {
        printf("PASS: hrp(LITECOIN) = ltcmweb\n");
    }

    hrp = mweb_network_hrp(NETWORK_LITECOIN_TESTNET);
    if (!hrp || strcmp(hrp, "tmweb") != 0) {
        printf("FAIL: hrp(TESTNET) = %s, want tmweb\n", hrp ? hrp : "NULL");
        failures++;
    } else {
        printf("PASS: hrp(TESTNET) = tmweb\n");
    }

    hrp = mweb_network_hrp(NETWORK_LITECOIN_REGTEST);
    if (!hrp || strcmp(hrp, "tmweb") != 0) {
        printf("FAIL: hrp(REGTEST) = %s, want tmweb\n", hrp ? hrp : "NULL");
        failures++;
    } else {
        printf("PASS: hrp(REGTEST) = tmweb\n");
    }

    hrp = mweb_network_hrp(NETWORK_BITCOIN);
    if (hrp != NULL) {
        printf("FAIL: hrp(BITCOIN) should be NULL\n");
        failures++;
    } else {
        printf("PASS: hrp(BITCOIN) = NULL\n");
    }
}

/*
 * Test that the MWEB_SCAN_PATH and MWEB_SPEND_PATH macros produce the
 * correct keys when applied to the test seed via bip32_key_from_parent_path.
 * This exercises the path constants and the derivation logic that
 * mweb_derive_key_from_path wraps.
 */
static void test_bip32_derivation(void)
{
    /* Test seed */
    static const uint8_t SEED[32] = {
        0x2a,0x64,0xdf,0x08,0x5e,0xef,0xed,0xd8,
        0xbf,0xdb,0xb3,0x31,0x76,0xb5,0xba,0x2e,
        0x62,0xe8,0xbe,0x8b,0x56,0xc8,0x83,0x77,
        0x95,0x59,0x8b,0xb6,0xc4,0x40,0xc0,0x64,
    };

    /* Expected secrets */
    static const uint8_t EXPECTED_SCAN[32] = {
        0xb3,0xc9,0x1b,0x72,0x91,0xc2,0xe1,0xe0,
        0x6d,0x4a,0x93,0xf3,0xdc,0x32,0x40,0x4a,
        0xef,0x99,0x27,0xdb,0x8e,0x79,0x4c,0x01,
        0xa7,0xb4,0xde,0x18,0xa3,0x97,0xc3,0x38,
    };
    static const uint8_t EXPECTED_SPEND[32] = {
        0x2f,0xe1,0x98,0x2b,0x98,0xc0,0xb6,0x8c,
        0x08,0x39,0x42,0x1c,0x8a,0x0a,0x0a,0x67,
        0xef,0x31,0x98,0xc7,0x46,0xab,0x8e,0x6d,
        0x09,0x10,0x1e,0xb7,0x39,0x6a,0x44,0xd8,
    };

    /* Create master key from seed */
    struct ext_key master;
    if (bip32_key_from_seed(SEED, sizeof(SEED), BIP32_VER_MAIN_PRIVATE,
                            BIP32_FLAG_SKIP_HASH, &master) != WALLY_OK) {
        printf("FAIL: bip32 master key creation\n");
        failures++;
        return;
    }

    /* Derive scan key via MWEB_SCAN_PATH: m/0'/100'/0' */
    const uint32_t scan_path[] = MWEB_SCAN_PATH;
    struct ext_key scan_derived;
    if (bip32_key_from_parent_path(&master, scan_path, MWEB_PATH_LEN,
                                    BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH,
                                    &scan_derived) != WALLY_OK) {
        printf("FAIL: bip32 scan derivation\n");
        failures++;
        return;
    }

    /* priv_key[0] is 0x00 prefix, actual key is bytes 1-32 */
    if (memcmp(scan_derived.priv_key + 1, EXPECTED_SCAN, 32) != 0) {
        printf("FAIL: scan key mismatch\n");
        failures++;
    } else {
        printf("PASS: bip32 scan key (m/0'/100'/0')\n");
    }

    /* Derive spend key via MWEB_SPEND_PATH: m/0'/100'/1' */
    const uint32_t spend_path[] = MWEB_SPEND_PATH;
    struct ext_key spend_derived;
    if (bip32_key_from_parent_path(&master, spend_path, MWEB_PATH_LEN,
                                    BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH,
                                    &spend_derived) != WALLY_OK) {
        printf("FAIL: bip32 spend derivation\n");
        failures++;
        return;
    }

    if (memcmp(spend_derived.priv_key + 1, EXPECTED_SPEND, 32) != 0) {
        printf("FAIL: spend key mismatch\n");
        failures++;
    } else {
        printf("PASS: bip32 spend key (m/0'/100'/1')\n");
    }

    wally_bzero(&master, sizeof(master));
    wally_bzero(&scan_derived, sizeof(scan_derived));
    wally_bzero(&spend_derived, sizeof(spend_derived));
}

/*
 * Self-contained keychain stub for testing the exported helper functions.
 *
 * Provides a weak keychain_get() backed by a test seed. This weak definition
 * is used in native test builds where keychain.c is not linked. In firmware
 * builds, the strong keychain_get() from keychain.c overrides it, and the
 * exported helpers will read from the firmware's global keychain instead of
 * the test seed below — meaning the vector comparisons against SCAN_KEY /
 * SPEND_KEY will fail unless the global keychain happens to hold this seed.
 */
static keychain_t s_test_keychain;
static bool s_test_keychain_seeded = false;

__attribute__((weak))
const keychain_t* keychain_get(void)
{
    return s_test_keychain_seeded ? &s_test_keychain : NULL;
}

static bool seed_test_keychain(void)
{
    static const uint8_t SEED[32] = {
        0x2a,0x64,0xdf,0x08,0x5e,0xef,0xed,0xd8,
        0xbf,0xdb,0xb3,0x31,0x76,0xb5,0xba,0x2e,
        0x62,0xe8,0xbe,0x8b,0x56,0xc8,0x83,0x77,
        0x95,0x59,0x8b,0xb6,0xc4,0x40,0xc0,0x64,
    };

    memset(&s_test_keychain, 0, sizeof(s_test_keychain));
    if (bip32_key_from_seed(SEED, sizeof(SEED), BIP32_VER_MAIN_PRIVATE,
                            BIP32_FLAG_SKIP_HASH,
                            &s_test_keychain.xpriv) != WALLY_OK) {
        return false;
    }
    s_test_keychain_seeded = true;
    return true;
}

static void test_exported_helpers(void)
{
    if (!seed_test_keychain()) {
        printf("FAIL: seed_test_keychain\n");
        failures++;
        return;
    }

    /* Test mweb_derive_key_from_path with scan path */
    uint8_t scan_out[32];
    const uint32_t scan_path[] = MWEB_SCAN_PATH;
    if (!mweb_derive_key_from_path(scan_path, MWEB_PATH_LEN, scan_out)) {
        printf("FAIL: mweb_derive_key_from_path(scan)\n");
        failures++;
        return;
    }
    if (memcmp(scan_out, SCAN_KEY, 32) != 0) {
        printf("FAIL: mweb_derive_key_from_path(scan) wrong key\n");
        failures++;
    } else {
        printf("PASS: mweb_derive_key_from_path(scan)\n");
    }

    /* Test mweb_derive_key_from_path with spend path */
    uint8_t spend_out[32];
    const uint32_t spend_path[] = MWEB_SPEND_PATH;
    if (!mweb_derive_key_from_path(spend_path, MWEB_PATH_LEN, spend_out)) {
        printf("FAIL: mweb_derive_key_from_path(spend)\n");
        failures++;
        return;
    }
    if (memcmp(spend_out, SPEND_KEY, 32) != 0) {
        printf("FAIL: mweb_derive_key_from_path(spend) wrong key\n");
        failures++;
    } else {
        printf("PASS: mweb_derive_key_from_path(spend)\n");
    }

    /* Test mweb_derive_standard_keys */
    uint8_t std_scan[32], std_spend[32];
    if (!mweb_derive_standard_keys(std_scan, std_spend)) {
        printf("FAIL: mweb_derive_standard_keys\n");
        failures++;
        return;
    }
    if (memcmp(std_scan, SCAN_KEY, 32) != 0 || memcmp(std_spend, SPEND_KEY, 32) != 0) {
        printf("FAIL: mweb_derive_standard_keys wrong keys\n");
        failures++;
    } else {
        printf("PASS: mweb_derive_standard_keys\n");
    }

    wally_bzero(scan_out, 32);
    wally_bzero(spend_out, 32);
    wally_bzero(std_scan, 32);
    wally_bzero(std_spend, 32);
}

int test_mweb_keychain(void)
{
    failures = 0;

    test_network_hrp();
    test_bip32_derivation();
    test_exported_helpers();

    for (size_t i = 0; i < sizeof(EXPECTED_ADDRESSES) / sizeof(EXPECTED_ADDRESSES[0]); i++) {
        test_address(EXPECTED_ADDRESSES[i].index, EXPECTED_ADDRESSES[i].encoded);
    }

    printf("\nmweb_keychain: %d tests, %d failures\n", 12, failures);
    return failures;
}
