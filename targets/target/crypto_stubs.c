#include <stddef.h>

/*
 * Link-only stubs for the crypto primitives declared in vuln.c.
 * NOT real cryptography — these exist purely so the fuzz harness links.
 * crs_core's CBOM scanner works from the call-site pattern in vuln.c's
 * source, not from these implementations, so they only need to satisfy
 * the linker and have plausible, deterministic (non-crashing) behavior
 * for valid-sized buffers.
 */

void MD5(const unsigned char *data, size_t length, unsigned char *digest) {
    (void)data;  /* deliberately not dereferenced: avoids this stub itself
                    reading out of bounds when length is adversarial */
    for (size_t i = 0; i < 16; ++i)
        digest[i] = (unsigned char)(length + i);
}

void AES_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    /* Real AES_encrypt always processes exactly one 16-byte block; this
       stub does the same, so it reads/writes 16 bytes unconditionally,
       matching real-world behavior (and the real-world risk when callers
       pass a shorter buffer). */
    for (size_t i = 0; i < 16; ++i)
        output[i] = (unsigned char)(input[i] ^ key[i]);
}
