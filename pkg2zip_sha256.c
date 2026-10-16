#include "pkg2zip_sha256.h"

#include <string.h>

// FIPS 180-4, section 4.2.2
static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t sha256_rotr32(uint32_t value, uint32_t shift)
{
    return (value >> shift) | (value << (32u - shift));
}

static void sha256_process_block(sha256_ctx* ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t i;

    for (i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3] << 0);
    }

    for (i = 16; i < 64; i++)
    {
        uint32_t s0 = sha256_rotr32(w[i - 15], 7) ^ sha256_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_rotr32(w[i - 2], 17) ^ sha256_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++)
    {
        uint32_t s1 = sha256_rotr32(e, 6) ^ sha256_rotr32(e, 11) ^ sha256_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = sha256_rotr32(a, 2) ^ sha256_rotr32(a, 13) ^ sha256_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

void sha256_update(sha256_ctx* ctx, const uint8_t* data, uint32_t size)
{
    ctx->total_size += size;

    // Hash whole blocks straight from the input once any buffered partial block is filled.
    if (ctx->buffer_size != 0)
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

        if (ctx->buffer_size != 64u)
        {
            return;
        }

        sha256_process_block(ctx, ctx->buffer);
        ctx->buffer_size = 0;
    }

    while (size >= 64u)
    {
        sha256_process_block(ctx, data);
        data += 64;
        size -= 64;
    }

    memcpy(ctx->buffer, data, size);
    ctx->buffer_size = size;
}

void sha256_final(sha256_ctx* ctx, uint8_t out[32])
{
    uint64_t bit_count = ctx->total_size * 8u;
    uint8_t pad[72] = { 0x80u };
    uint32_t pad_size = (ctx->buffer_size < 56u) ? (56u - ctx->buffer_size) : (120u - ctx->buffer_size);
    uint32_t i;

    for (i = 0; i < 8; i++)
    {
        pad[pad_size + 7 - i] = (uint8_t)(bit_count >> (i * 8));
    }

    sha256_update(ctx, pad, pad_size + 8);

    for (i = 0; i < 8; i++)
    {
        out[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 0);
    }
}
