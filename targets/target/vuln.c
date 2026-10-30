#include <stdlib.h>
#include <string.h>

void decrypt_record(const unsigned char *ciphertext, int ciphertext_len)
{
    int allocation_size = ciphertext_len + 32; /* signed overflow: vulnerable statement */
    if (allocation_size < 0)
        allocation_size = 0;
    unsigned char *plaintext = malloc((size_t)allocation_size);
    if (plaintext == NULL)
        return;
    memcpy(plaintext, ciphertext, (size_t)ciphertext_len);
    free(plaintext);
}
