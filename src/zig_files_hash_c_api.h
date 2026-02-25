#ifndef ZIG_FILES_HASH_C_API_H
#define ZIG_FILES_HASH_C_API_H

#include <stddef.h>
#include <stdint.h>

#define ZFH_API_VERSION 2u

#ifdef __cplusplus
extern "C" {
#endif

/* ABI note: enum numeric values are stable and must not be reordered. */
typedef enum zfh_error {
    ZFH_OK = 0,
    ZFH_INVALID_ARGUMENT = 1,
    ZFH_INVALID_ALGORITHM = 2,
    ZFH_BUFFER_TOO_SMALL = 3,
    ZFH_KEY_REQUIRED = 4,
    ZFH_INVALID_KEY_LENGTH = 5,
    ZFH_FILE_NOT_FOUND = 6,
    ZFH_ACCESS_DENIED = 7,
    ZFH_INVALID_PATH = 8,
    ZFH_IO_ERROR = 9,
    ZFH_UNKNOWN_ERROR = 10,
} zfh_error;

/* ABI note: enum numeric values are stable and must not be reordered. */
typedef enum zfh_algorithm {
    ZFH_ALG_SHA_224 = 0,
    ZFH_ALG_SHA_256 = 1,
    ZFH_ALG_SHA_384 = 2,
    ZFH_ALG_SHA_512 = 3,
    ZFH_ALG_SHA_512_224 = 4,
    ZFH_ALG_SHA_512_256 = 5,
    ZFH_ALG_MD5 = 6,
    ZFH_ALG_SHA_1 = 7,
    ZFH_ALG_XXH3_64 = 8,
    ZFH_ALG_BLAKE3 = 9,
    ZFH_ALG_HMAC_SHA_224 = 10,
    ZFH_ALG_HMAC_SHA_256 = 11,
    ZFH_ALG_HMAC_SHA_384 = 12,
    ZFH_ALG_HMAC_SHA_512 = 13,
    ZFH_ALG_HMAC_MD5 = 14,
    ZFH_ALG_HMAC_SHA_1 = 15,
} zfh_algorithm;

typedef struct zfh_options {
    /* Must be set to ZFH_OPTIONS_STRUCT_SIZE (i.e. sizeof(zfh_options)). */
    uint32_t struct_size;
    /* Bitmask of ZFH_OPTION_HAS_* values. */
    uint32_t flags;
    /* Currently used by XXH3 when ZFH_OPTION_HAS_SEED is set. */
    uint64_t seed;
    const uint8_t* key_ptr;
    /* If ZFH_OPTION_HAS_KEY is set and key_len == 0, empty key is used. */
    size_t key_len;
} zfh_options;

#define ZFH_OPTIONS_STRUCT_SIZE ((uint32_t)sizeof(zfh_options))

enum {
    ZFH_OPTION_HAS_SEED = 1u << 0,
    ZFH_OPTION_HAS_KEY = 1u << 1,
};

size_t zfh_max_digest_length(void);
/* Returns the same ABI version value as ZFH_API_VERSION. */
uint32_t zfh_api_version(void);

/* On success, writes digest length to *out_len_ptr and returns ZFH_OK.
 * On error, writes 0 to *out_len_ptr and returns a non-zero zfh_error.
 */
zfh_error zfh_digest_length(zfh_algorithm alg, size_t* out_len_ptr);

/* Returns a static, thread-safe, null-terminated English message.
 * Never returns NULL.
 */
const char* zfh_error_message(zfh_error code);

/* On success, writes digest bytes to out_ptr and length to *written_len_ptr.
 * On error, writes 0 to *written_len_ptr and returns a non-zero zfh_error.
 * options_ptr may be NULL (equivalent to no options).
 * If ZFH_OPTION_HAS_KEY and key_len == 0: HMAC uses empty key;
 * BLAKE3 keyed mode returns ZFH_INVALID_KEY_LENGTH.
 */
zfh_error zfh_string_hash(
    zfh_algorithm alg,
    const uint8_t* data_ptr,
    size_t data_len,
    const zfh_options* options_ptr,
    uint8_t* out_ptr,
    size_t out_len,
    size_t* written_len_ptr
);

/* path_ptr is byte data with explicit path_len; null-termination is not required.
 * On success, writes digest bytes to out_ptr and length to *written_len_ptr.
 * On error, writes 0 to *written_len_ptr and returns a non-zero zfh_error.
 * options_ptr may be NULL (equivalent to no options).
 * If ZFH_OPTION_HAS_KEY and key_len == 0: HMAC uses empty key;
 * BLAKE3 keyed mode returns ZFH_INVALID_KEY_LENGTH.
 */
zfh_error zfh_file_hash(
    zfh_algorithm alg,
    const uint8_t* path_ptr,
    size_t path_len,
    const zfh_options* options_ptr,
    uint8_t* out_ptr,
    size_t out_len,
    size_t* written_len_ptr
);

/* Size/alignment requirements for caller-provided streaming state buffer. */
size_t zfh_hasher_state_size(void);
size_t zfh_hasher_state_align(void);

/* Initializes hasher state in caller-provided memory.
 * state_ptr must be aligned to zfh_hasher_state_align() and state_len must be
 * >= zfh_hasher_state_size().
 */
zfh_error zfh_hasher_init_inplace(
    zfh_algorithm alg,
    const zfh_options* options_ptr,
    void* state_ptr,
    size_t state_len
);

/* Feeds a chunk into the hasher.
 * data_ptr may be NULL only when data_len == 0.
 * Returns ZFH_INVALID_ARGUMENT if state is not initialized or was already finalized.
 */
zfh_error zfh_hasher_update(
    void* state_ptr,
    size_t state_len,
    const uint8_t* data_ptr,
    size_t data_len
);

/* Finalizes digest into out_ptr.
 * On success, writes digest bytes to out_ptr and length to *written_len_ptr.
 * On error, writes 0 to *written_len_ptr and returns a non-zero zfh_error.
 * Must be called at most once for a given initialized state.
 * Repeated calls return ZFH_INVALID_ARGUMENT.
 */
zfh_error zfh_hasher_final(
    void* state_ptr,
    size_t state_len,
    uint8_t* out_ptr,
    size_t out_len,
    size_t* written_len_ptr
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ZIG_FILES_HASH_C_API_H
