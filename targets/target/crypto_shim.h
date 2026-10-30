#ifndef CRYPTO_SHIM_H
#define CRYPTO_SHIM_H
#include <stddef.h>

/*
 * Declarations for crypto-substitute primitives that compare.py's
 * SUBSTITUTES map may ask VINCENT to introduce (see crs_core/api.py).
 * vuln.c only pre-declares MD5/AES_encrypt at its own top; PRISM only
 * swaps the function BODY, not file-level declarations, so any new
 * primitive a patch calls needs a declaration visible to that
 * translation unit. This header is force-included into every file via
 * the Makefile's -include flag, so it applies to scratch builds too,
 * without touching the tracked vuln.c.
 *
 * Link-only stubs for these live in crypto_stubs.c, same as MD5/AES_encrypt.
 */
void SHA256(const unsigned char *data, size_t length, unsigned char *digest);
void SHA3_256(const unsigned char *data, size_t length, unsigned char *digest);

#endif
