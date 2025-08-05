#include <sodium.h>
#include <stdio.h>
#include <string.h>

// Output: private_key (64 bytes) dan public_key (32 bytes)
void password_to_keypair(const char *password, unsigned char *public_key, unsigned char *private_key) {
    unsigned char seed[crypto_generichash_BYTES];
    
    crypto_generichash(seed, sizeof seed, (const unsigned char*)password, strlen(password), NULL, 0);
    
    crypto_sign_seed_keypair(public_key, private_key, seed);
}

int verify_password(const char *password, const unsigned char *stored_public_key) {
    unsigned char test_public_key[32];
    unsigned char test_private_key[64];
    password_to_keypair(password, test_public_key, test_private_key);
    
    return memcmp(stored_public_key, test_public_key, 32) == 0;
}
