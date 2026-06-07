# Contributing

## Regenerating the C ABI files

The C ABI has a small generated layer. Regenerate it after changing any of:

- `src/algorithms.zig` public `HashAlgorithm` values
- `src/algorithms.zig` public `Error` values
- `tools/c_api/def.zig`
- `tools/c_api/gen.zig`
- `tools/c_api/render_zig.zig`
- `tools/c_api/render_header.zig`
- `tools/c_api/common.zig`

Run:

```sh
zig build gen-c-api
```

This updates:

- `src/c_api_generated.zig`
- `src/zig_files_hash_c_api_generated.h`

The generated header intentionally contains only mechanical declarations:

- `ZFH_API_VERSION`
- `zfh_error`
- `zfh_algorithm`
- `ZFH_OPTION_*` flags

The main C header, `src/zig_files_hash_c_api.h`, is maintained by hand and
includes the generated header. Keep ownership rules, struct definitions,
function prototypes, and ABI comments in the hand-written header.

Before submitting changes that touch the C ABI, run:

```sh
zig build test
zig build c-api
clang -x c -fsyntax-only src/zig_files_hash_c_api.h
```
