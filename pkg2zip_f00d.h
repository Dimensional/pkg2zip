#pragma once

#include <stdint.h>

#include "pkg2zip_npdrm.h"

typedef struct {
    const char* cache_path;
} f00d_context;

// Placeholder clean-room interface for F00D-like key derivation.
npdrm_status f00d_derive_key(const f00d_context* ctx, const uint8_t* in_key, uint32_t in_key_size, uint8_t* out_key, uint32_t out_key_size);
