#include "mweb_hash.h"
#include <blake3.h>

void mweb_hashed(uint8_t tag, const uint8_t* data, size_t data_len,
                 uint8_t output[32])
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &tag, 1);
    if (data && data_len > 0) {
        blake3_hasher_update(&hasher, data, data_len);
    }
    blake3_hasher_finalize(&hasher, output, 32);
}
