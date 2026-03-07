#ifndef MWEB_HASH_H_
#define MWEB_HASH_H_

#include <stddef.h>
#include <stdint.h>

/* MWEB tagged hash: BLAKE3(tag_byte || data) -> 32 bytes. */
void mweb_hashed(uint8_t tag, const uint8_t* data, size_t data_len,
                 uint8_t output[32]);

/* Tag constants (ASCII character values) */
#define MWEB_TAG_ADDRESS   'A'  /* Subaddress modifier */
#define MWEB_TAG_BLIND     'B'  /* Blinding factor derivation */
#define MWEB_TAG_DERIVE    'D'  /* Shared secret derivation */
#define MWEB_TAG_NONCE     'N'  /* Nonce generation */
#define MWEB_TAG_OUTKEY    'O'  /* Output key hash */
#define MWEB_TAG_SENDKEY   'S'  /* Sending key */
#define MWEB_TAG_TAG       'T'  /* View tag */
#define MWEB_TAG_NONCEMASK 'X'  /* Nonce mask */
#define MWEB_TAG_VALUEMASK 'Y'  /* Value mask */

#endif /* MWEB_HASH_H_ */
