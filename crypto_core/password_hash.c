#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define SALT_BYTES crypto_pwhash_SALTBYTES
#define HASH_BYTES crypto_generichash_BYTES
#define OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
#define SIGNATURE_LEN crypto_sign_BYTES
#define CHECKSUM_LEN 16

// Safe memory allocation
void secure_zero(void *ptr, size_t len) {
    if (ptr) {
        sodium_memzero(ptr, len);
    }
}

// Generates a secure random salt
void generate_salt(unsigned char *salt) {
    randombytes_buf(salt, SALT_BYTES);
}

// Generates HMAC checksum for integrity
void generate_checksum(const unsigned char *data, size_t data_len, unsigned char *checksum) {
    crypto_generichash(checksum, CHECKSUM_LEN, data, data_len, NULL, 0);
}

// Password → keypair with hardened KDF and checksum
int password_to_keypair(const char *password, const unsigned char *salt,
                        unsigned char *public_key, unsigned char *private_key,
                        unsigned char *checksum_out) {

    unsigned char derived_seed[crypto_sign_SEEDBYTES];

    if (crypto_pwhash(derived_seed, sizeof derived_seed,
                      password, strlen(password),
                      salt,
                      OPSLIMIT, MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return -1; // out of memory or other fatal error
    }

    // Generate keypair
    if (crypto_sign_seed_keypair(public_key, private_key, derived_seed) != 0) {
        return -2;
    }

    if (checksum_out) {
        generate_checksum(public_key, crypto_sign_PUBLICKEYBYTES, checksum_out);
    }

    secure_zero(derived_seed, sizeof derived_seed);
    return 0;
}

// Verifies if password matches the provided public key and checksum
int verify_password(const char *password,
                    const unsigned char *salt,
                    const unsigned char *stored_public_key,
                    const unsigned char *stored_checksum) {

    unsigned char temp_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char temp_private_key[crypto_sign_SECRETKEYBYTES];
    unsigned char calc_checksum[CHECKSUM_LEN];

    int res = password_to_keypair(password, salt, temp_public_key, temp_private_key, calc_checksum);
    if (res != 0) return 0;

    int match_key = sodium_memcmp(temp_public_key, stored_public_key, crypto_sign_PUBLICKEYBYTES) == 0;
    int match_checksum = sodium_memcmp(calc_checksum, stored_checksum, CHECKSUM_LEN) == 0;

    secure_zero(temp_private_key, sizeof temp_private_key);
    secure_zero(calc_checksum, sizeof calc_checksum);

    return match_key && match_checksum;
}
