#include "pkg2zip_sha1.h"

#include <string.h>

typedef struct {
    uint32_t state[5];
    uint64_t total_size;
    uint8_t buffer[64];
    uint32_t buffer_size;
} sha1_ctx;

static uint32_t sha1_rotl32(uint32_t value, uint32_t shift)
{
    return (value << shift) | (value >> (32u - shift));
}

static void sha1_process_block(sha1_ctx* ctx, const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t i;

    for (i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3] << 0);
    }

    for (i = 16; i < 80; i++)
    {
        w[i] = sha1_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++)
    {
        uint32_t f;
        uint32_t k;
        uint32_t temp;

        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        temp = sha1_rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotl32(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(sha1_ctx* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
}

static void sha1_update(sha1_ctx* ctx, const uint8_t* data, uint32_t size)
{
    ctx->total_size += size;

    while (size > 0)
    {
        uint32_t chunk = 64u - ctx->buffer_size;
        if (chunk > size)
        {
            chunk = size;
        }

        memcpy(ctx->buffer + ctx->buffer_size, data, chunk);
        ctx->buffer_size += chunk;
        data += chunk;
        size -= chunk;

        if (ctx->buffer_size == 64u)
        {
            sha1_process_block(ctx, ctx->buffer);
            ctx->buffer_size = 0;
        }
    }
}

static void sha1_final(sha1_ctx* ctx, uint8_t out[20])
{
    uint64_t bit_count = ctx->total_size * 8u;
    uint8_t pad = 0x80u;
    uint8_t zero = 0;
    uint8_t length_block[8];
    uint32_t i;

    for (i = 0; i < 8; i++)
    {
        length_block[7 - i] = (uint8_t)(bit_count >> (i * 8));
    }

    sha1_update(ctx, &pad, 1);
    while (ctx->buffer_size != 56u)
    {
        sha1_update(ctx, &zero, 1);
    }
    sha1_update(ctx, length_block, 8);

    for (i = 0; i < 5; i++)
    {
        out[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 0);
    }
}

void sha1_digest(const uint8_t* data, uint32_t size, uint8_t out[20])
{
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, size);
    sha1_final(&ctx, out);
}

void hmac_sha1_digest(const uint8_t* key, uint32_t key_size, const uint8_t* data, uint32_t size, uint8_t out[20])
{
    uint8_t key_block[64];
    uint8_t inner_hash[20];
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    uint32_t i;
    sha1_ctx ctx;

    memset(key_block, 0, sizeof(key_block));
    if (key_size > sizeof(key_block))
    {
        sha1_digest(key, key_size, key_block);
    }
    else if (key_size > 0)
    {
        memcpy(key_block, key, key_size);
    }

    for (i = 0; i < 64; i++)
    {
        inner_pad[i] = (uint8_t)(key_block[i] ^ 0x36u);
        outer_pad[i] = (uint8_t)(key_block[i] ^ 0x5Cu);
    }

    sha1_init(&ctx);
    sha1_update(&ctx, inner_pad, sizeof(inner_pad));
    sha1_update(&ctx, data, size);
    sha1_final(&ctx, inner_hash);

    sha1_init(&ctx);
    sha1_update(&ctx, outer_pad, sizeof(outer_pad));
    sha1_update(&ctx, inner_hash, sizeof(inner_hash));
    sha1_final(&ctx, out);
}