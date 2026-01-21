#pragma once

/*
 * PS3 PKG unpacker (manifest parsing + streaming extraction with AES-CTR decryption)
 *
 * This header exposes a function that parses the package TOC/manifest and
 * extracts content entries (streamed) to the output layer (zip or filesystem).
 *
 * The signature matches existing helpers in this repo and uses the same
 * AES key types as other unpackers (aes128_key).
 *
 * Note: full CEK unwrapping and license (RIF/RAP) based derivation are not
 * implemented here and should be added where marked in the implementation.
 */

#include "pkg2zip_aes.h"
#include "pkg2zip_sys.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parse PS3 PKG manifest and extract contents.
// - outdir: user supplied output base (used by produced filenames)
// - key: package master key (derived earlier in main())
// - ps3_key: PS3-specific AES key (if available)
// - iv: package IV
// - pkg: opened sys_file for the package
// - pkg_size: size of the package file
// - enc_offset: offset where encrypted content region begins
// - items_offset: offset (relative to enc_offset) where manifest/TOC starts
// - item_count: number of manifest entries
// - zipped: whether output is currently zipped (passed through to out_* funcs)
// - list_only: if non-zero, do not write files, only list them
void unpack_ps3_pkg(const char* outdir,
                    const aes128_key* key,
                    const aes128_key* ps3_key,
                    const uint8_t* iv,
                    sys_file pkg,
                    uint64_t pkg_size,
                    uint64_t enc_offset,
                    uint64_t items_offset,
                    uint32_t item_count,
                    int zipped,
                    int list_only);

#ifdef __cplusplus
}
#endif