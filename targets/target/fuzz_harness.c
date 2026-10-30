#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern void decrypt_record(const unsigned char *ciphertext, int ciphertext_len);

/*
 * First 4 bytes of the fuzz input are interpreted as a little-endian signed
 * int32 and passed directly as ciphertext_len. This is deliberate: it lets a
 * tiny input (no multi-GB corpus needed) drive ciphertext_len up near
 * INT_MAX, which is exactly what trips the signed-integer-overflow in
 * decrypt_record()'s `allocation_size = ciphertext_len + 32` line.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    int32_t len;
    memcpy(&len, data, sizeof(len));
    decrypt_record(data + 4, (int)len);
    return 0;
}
