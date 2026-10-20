#pragma once

#include <stdint.h>

typedef struct {
    uint32_t state[5];
    uint64_t total_size;
    uint8_t buffer[64];
    uint32_t buffer_size;
} sha1_ctx;

void sha1_init(sha1_ctx* ctx);
void sha1_update(sha1_ctx* ctx, const uint8_t* data, uint32_t size);
void sha1_final(sha1_ctx* ctx, uint8_t out[20]);

void sha1_digest(const uint8_t* data, uint32_t size, uint8_t out[20]);
void hmac_sha1_digest(const uint8_t* key, uint32_t key_size, const uint8_t* data, uint32_t size, uint8_t out[20]);