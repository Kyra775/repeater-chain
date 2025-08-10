/*
  Purpose: Secure password -> deterministic ed25519 keypair derivation using Argon2id,
           keyed checksum (BLAKE2b) for integrity, secure memory wiping, and simple hex serialization.
  IMPORTANT: Keep server-side pepper secret outside the database (env var / HSM).
*/

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#define SALT_BYTES        crypto_pwhash_SALTBYTES
#define SEED_BYTES        crypto_sign_SEEDBYTES
#define PUBKEY_BYTES      crypto_sign_PUBLICKEYBYTES
#define PRIVKEY_BYTES     crypto_sign_SECRETKEYBYTES
#define CHECKSUM_LEN      16
#define VERSION_BYTE      0x01

/* Default Argon2id params (adjust per environment) */
#define DEFAULT_OPSLIMIT  crypto_pwhash_OPSLIMIT_MODERATE
#define DEFAULT_MEMLIMIT  crypto_pwhash_MEMLIMIT_MODERATE
#define KDF_ALG           crypto_pwhash_ALG_ARGON2ID13

/* Minimal secure zero helper */
static void secure_zero(void *ptr, size_t len) {
    if (ptr) sodium_memzero(ptr, len);
}

/* Random salt generation */
static void generate_salt(unsigned char *salt) {
    randombytes_buf(salt, SALT_BYTES);
}

/* Keyed checksum using crypto_generichash (BLAKE2b). If pepper_len==0, unkeyed hash is produced. */
static int generate_keyed_checksum(const unsigned char *data, size_t data_len,
                                   const unsigned char *pepper, size_t pepper_len,
                                   unsigned char *out_checksum) {
    return crypto_generichash(out_checksum, CHECKSUM_LEN,
                              data, data_len,
                              pepper, (pepper && pepper_len > 0) ? pepper_len : 0) == 0 ? 0 : -1;
}

/* Simple record to store per-user authentication data */
typedef struct {
    uint8_t version;            /* format version */
    uint64_t opslimit;          /* Argon2 opslimit used */
    uint64_t memlimit;          /* Argon2 memlimit used */
    unsigned char salt[SALT_BYTES];
    unsigned char public_key[PUBKEY_BYTES];
    unsigned char checksum[CHECKSUM_LEN];
} pw_record_t;

/*
  create_pw_record:
  - Derive a seed from password || pepper using Argon2id (seed size = SEED_BYTES).
  - Generate deterministic ed25519 keypair from seed.
  - Compute keyed checksum of public key.
  - Fill pw_record_t for storage (private key is wiped and not stored).
  Returns 0 on success, negative on failure.
*/
int create_pw_record(const char *password,
                     const unsigned char *pepper, size_t pepper_len,
                     uint64_t opslimit, uint64_t memlimit,
                     pw_record_t *record_out) {
    if (!password || !record_out) return -1;
    if (opslimit == 0) opslimit = DEFAULT_OPSLIMIT;
    if (memlimit == 0) memlimit = DEFAULT_MEMLIMIT;

    unsigned char seed[SEED_BYTES];
    unsigned char sk[PRIVKEY_BYTES];

    record_out->version = VERSION_BYTE;
    record_out->opslimit = opslimit;
    record_out->memlimit = memlimit;
    generate_salt(record_out->salt);

    /* Combine password || pepper into temporary secure buffer */
    size_t pw_len = strlen(password);
    size_t tmp_len = pw_len + pepper_len;
    unsigned char *tmp = (unsigned char *) sodium_malloc(tmp_len ? tmp_len : 1);
    if (!tmp) return -2;
    if (pw_len) memcpy(tmp, password, pw_len);
    if (pepper && pepper_len) memcpy(tmp + pw_len, pepper, pepper_len);

    if (crypto_pwhash(seed, sizeof seed,
                      (const char *)tmp, tmp_len,
                      record_out->salt,
                      (unsigned long long)opslimit, (size_t)memlimit, KDF_ALG) != 0) {
        secure_zero(seed, sizeof seed);
        sodium_free(tmp);
        return -3; /* KDF failed (likely insufficient resources) */
    }

    sodium_free(tmp);

    /* Deterministic ed25519 keypair from seed */
    if (crypto_sign_seed_keypair(record_out->public_key, sk, seed) != 0) {
        secure_zero(seed, sizeof seed);
        secure_zero(sk, sizeof sk);
        return -4;
    }

    /* Keyed checksum for integrity (use pepper as key if provided) */
    if (generate_keyed_checksum(record_out->public_key, PUBKEY_BYTES, pepper, pepper_len, record_out->checksum) != 0) {
        secure_zero(seed, sizeof seed);
        secure_zero(sk, sizeof sk);
        return -5;
    }

    secure_zero(seed, sizeof seed);
    secure_zero(sk, sizeof sk);
    return 0;
}

/*
  verify_pw_with_record:
  - Re-derive seed from provided password and stored salt using stored ops/mem params.
  - Recreate public key and keyed checksum; compare both in constant time.
  - Return 1 for match, 0 for mismatch.
*/
int verify_pw_with_record(const char *password,
                          const unsigned char *pepper, size_t pepper_len,
                          const pw_record_t *record) {
    if (!password || !record) return 0;

    unsigned char seed[SEED_BYTES];
    unsigned char tmp_pk[PUBKEY_BYTES];
    unsigned char tmp_sk[PRIVKEY_BYTES];
    unsigned char calc_ck[CHECKSUM_LEN];

    uint64_t ops = record->opslimit;
    uint64_t mem = record->memlimit;

    size_t pw_len = strlen(password);
    size_t tmp_len = pw_len + pepper_len;
    unsigned char *tmp = (unsigned char *) sodium_malloc(tmp_len ? tmp_len : 1);
    if (!tmp) return 0;
    if (pw_len) memcpy(tmp, password, pw_len);
    if (pepper && pepper_len) memcpy(tmp + pw_len, pepper, pepper_len);

    if (crypto_pwhash(seed, sizeof seed,
                      (const char *)tmp, tmp_len,
                      record->salt,
                      (unsigned long long)ops, (size_t)mem, KDF_ALG) != 0) {
        sodium_free(tmp);
        secure_zero(seed, sizeof seed);
        return 0;
    }
    sodium_free(tmp);

    if (crypto_sign_seed_keypair(tmp_pk, tmp_sk, seed) != 0) {
        secure_zero(seed, sizeof seed);
        secure_zero(tmp_sk, sizeof tmp_sk);
        return 0;
    }

    if (generate_keyed_checksum(tmp_pk, PUBKEY_BYTES, pepper, pepper_len, calc_ck) != 0) {
        secure_zero(seed, sizeof seed);
        secure_zero(tmp_sk, sizeof tmp_sk);
        return 0;
    }

    int match_pk = sodium_memcmp(tmp_pk, record->public_key, PUBKEY_BYTES) == 0;
    int match_ck = sodium_memcmp(calc_ck, record->checksum, CHECKSUM_LEN) == 0;

    secure_zero(seed, sizeof seed);
    secure_zero(tmp_sk, sizeof tmp_sk);
    secure_zero(calc_ck, sizeof calc_ck);
    secure_zero(tmp_pk, sizeof tmp_pk);

    return (match_pk && match_ck) ? 1 : 0;
}

/* Helpers: hex encode / decode for easy storage/display */
static void to_hex(const unsigned char *in, size_t in_len, char *out_hex, size_t out_hex_len) {
    sodium_bin2hex(out_hex, out_hex_len, in, in_len);
}

/* Very simple serializer (human-readable single-line). Caller must free returned string. */
char *serialize_record_hex(const pw_record_t *rec) {
    if (!rec) return NULL;
    size_t buf_sz = 1024;
    char *buf = (char *) malloc(buf_sz);
    if (!buf) return NULL;
    char hexbuf[1024];

    snprintf(buf, buf_sz, "v=%02x;op=%" PRIu64 ";mem=%" PRIu64 ";salt=", rec->version, rec->opslimit, rec->memlimit);
    to_hex(rec->salt, SALT_BYTES, hexbuf, sizeof hexbuf);
    strncat(buf, hexbuf, buf_sz - strlen(buf) - 1);
    strncat(buf, ";pk=", buf_sz - strlen(buf) - 1);
    to_hex(rec->public_key, PUBKEY_BYTES, hexbuf, sizeof hexbuf);
    strncat(buf, hexbuf, buf_sz - strlen(buf) - 1);
    strncat(buf, ";ck=", buf_sz - strlen(buf) - 1);
    to_hex(rec->checksum, CHECKSUM_LEN, hexbuf, sizeof hexbuf);
    strncat(buf, hexbuf, buf_sz - strlen(buf) - 1);

    return buf;
}

/* Minimal demo: create record and test verification (NOT for production testing of secrets). */
int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    /* Example pepper - IN PRODUCTION get from secure env / HSM */
    const unsigned char *pepper = (const unsigned char *) "example-32-byte-pepper-should-be-secret!";
    size_t pepper_len = strlen((const char *)pepper);

    const char *password = "admin123";

    pw_record_t rec;
    memset(&rec, 0, sizeof rec);

    if (create_pw_record(password, pepper, pepper_len, 0, 0, &rec) != 0) {
        fprintf(stderr, "create_pw_record failed\n");
        return 2;
    }

    char *ser = serialize_record_hex(&rec);
    if (ser) {
        printf("STORED_RECORD: %s\n", ser);
        free(ser);
    }

    printf("Verify correct password: %s\n", verify_pw_with_record("admin123", pepper, pepper_len, &rec) ? "OK" : "FAIL");
    printf("Verify wrong password  : %s\n", verify_pw_with_record("wrongpass", pepper, pepper_len, &rec) ? "OK" : "FAIL");

    /* Wipe record before exit */
    secure_zero(&rec, sizeof rec);
    return 0;
}
