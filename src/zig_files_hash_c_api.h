#ifndef ZIG_FILES_HASH_C_API_H
#define ZIG_FILES_HASH_C_API_H

#include <stddef.h>
#include <stdint.h>

#include "zig_files_hash_c_api_generated.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zfh_context zfh_context;

typedef struct zfh_options {
    /* Must be set to ZFH_OPTIONS_STRUCT_SIZE, i.e. sizeof(zfh_options). */
    uint32_t struct_size;
    /* Bitmask of ZFH_OPTION_HAS_* values. Unknown flags are rejected. */
    uint32_t flags;
    /* Currently used by XXH3 when ZFH_OPTION_HAS_SEED is set. */
    uint64_t seed;
    const uint8_t* key_ptr;
    /* If ZFH_OPTION_HAS_KEY is set and key_len == 0, empty key is used. */
    size_t key_len;
} zfh_options;

typedef struct zfh_request {
    /* Must be set to ZFH_REQUEST_STRUCT_SIZE, i.e. sizeof(zfh_request). */
    uint32_t struct_size;
    const zfh_options* options_ptr;
    /* Optional initialized operation state for cooperative cancellation.
     * Pass NULL/0 when cancellation is not needed.
     */
    void* operation_ptr;
    size_t operation_len;
} zfh_request;

#define ZFH_OPTIONS_STRUCT_SIZE ((uint32_t)sizeof(zfh_options))
#define ZFH_REQUEST_STRUCT_SIZE ((uint32_t)sizeof(zfh_request))

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
 * request_ptr may be NULL (equivalent to no options and no operation).
 */
zfh_error zfh_string_hash(
    zfh_algorithm alg,
    const uint8_t* data_ptr,
    size_t data_len,
    const zfh_request* request_ptr,
    uint8_t* out_ptr,
    size_t out_len,
    size_t* written_len_ptr
);

zfh_error zfh_context_create(zfh_context** out_ctx);
zfh_error zfh_context_destroy(zfh_context* ctx);

/* Size/alignment requirements for caller-provided operation state buffer. */
size_t zfh_operation_state_size(void);
size_t zfh_operation_state_align(void);

/* Initializes operation state in caller-provided memory.
 * operation_ptr must be aligned to zfh_operation_state_align() and
 * operation_len must be >= zfh_operation_state_size().
 */
zfh_error zfh_operation_init_inplace(void* operation_ptr, size_t operation_len);

/* Requests cooperative cancellation for an initialized operation state. */
zfh_error zfh_operation_cancel(void* operation_ptr, size_t operation_len);

/* path_ptr is byte data with explicit path_len; null-termination is not required.
 * On success, writes digest bytes to out_ptr and length to *written_len_ptr.
 * On error, writes 0 to *written_len_ptr and returns a non-zero zfh_error.
 * request_ptr may be NULL (equivalent to no options and no operation).
 */
zfh_error zfh_context_file_hash(
    zfh_context* ctx,
    zfh_algorithm alg,
    const uint8_t* path_ptr,
    size_t path_len,
    const zfh_request* request_ptr,
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
 * request_ptr may be NULL (equivalent to no options and no operation).
 */
zfh_error zfh_hasher_init_inplace(
    zfh_algorithm alg,
    const zfh_request* request_ptr,
    void* state_ptr,
    size_t state_len
);

/* Feeds a chunk into the hasher.
 * data_ptr may be NULL only when data_len == 0.
 * Returns ZFH_INVALID_ARGUMENT if state is not initialized or was already finalized.
 * Returns ZFH_OPERATION_CANCELED if the request operation was canceled.
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
 * Returns ZFH_OPERATION_CANCELED if the request operation was canceled.
 */
zfh_error zfh_hasher_final(
    void* state_ptr,
    size_t state_len,
    uint8_t* out_ptr,
    size_t out_len,
    size_t* written_len_ptr
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZIG_FILES_HASH_C_API_H */
