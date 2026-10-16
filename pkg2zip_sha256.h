#pragma once

#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t total_size;
    uint8_t buffer[64];
    uint32_t buffer_size;
} sha256_ctx;

void sha256_init(sha256_ctx* ctx);
void sha256_update(sha256_ctx* ctx, const uint8_t* data, uint32_t size);
void sha256_final(sha256_ctx* ctx, uint8_t out[32]);
