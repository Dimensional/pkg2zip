#include "pkg2zip_f00d.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char* in_key;
    const char* out_key;
} f00d_test_vector;

static const f00d_test_vector known_vectors[] = {
    {
        "8e777fa60a2cc51b7ba196a24fd6d0e5",
        "f57c97d294287b22bebe992300326ed1"
    },
};

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static int parse_hex_16(const char* hex, uint8_t out[16])
{
    uint32_t i;

    if (hex == NULL || out == NULL)
    {
        return -1;
    }

    for (i = 0; i < 16; i++)
    {
        int hi = hex_nibble(hex[i * 2 + 0]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return hex[32] == 0 ? 0 : -1;
}

static int lookup_known_vector(const uint8_t* in_key, uint8_t* out_key)
{
    uint32_t i;
    for (i = 0; i < (uint32_t)(sizeof(known_vectors) / sizeof(known_vectors[0])); i++)
    {
        uint8_t key[16];
        uint8_t value[16];

        if (parse_hex_16(known_vectors[i].in_key, key) != 0 || parse_hex_16(known_vectors[i].out_key, value) != 0)
        {
            continue;
        }

        if (memcmp(in_key, key, 16) == 0)
        {
            memcpy(out_key, value, 16);
            return 0;
        }
    }

    return -1;
}

static int parse_cache_line(const char* line, char* key, size_t key_size, char* value, size_t value_size)
{
    char a[129];
    char b[129];
    char c[129];
    int n;

    // Accept either:
    // 1) "<key> <value>"
    // 2) "<titleid> <key> <value>"
    n = sscanf(line, " %128[^, \t\r\n] %128[^, \t\r\n] %128[^, \t\r\n]", a, b, c);
    if (n == 2)
    {
        snprintf(key, key_size, "%s", a);
        snprintf(value, value_size, "%s", b);
        return 0;
    }
    if (n == 3)
    {
        snprintf(key, key_size, "%s", b);
        snprintf(value, value_size, "%s", c);
        return 0;
    }

    return -1;
}

static int lookup_cache_file(const char* cache_path, const uint8_t* in_key, uint8_t* out_key)
{
    FILE* f;
    char line[512];

    if (cache_path == NULL)
    {
        return -1;
    }

    f = fopen(cache_path, "rb");
    if (f == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL)
    {
        char key_hex[129];
        char value_hex[129];
        uint8_t key[16];
        uint8_t value[16];

        if (line[0] == '#')
        {
            continue;
        }

        if (parse_cache_line(line, key_hex, sizeof(key_hex), value_hex, sizeof(value_hex)) != 0)
        {
            continue;
        }

        if (parse_hex_16(key_hex, key) != 0 || parse_hex_16(value_hex, value) != 0)
        {
            continue;
        }

        if (memcmp(in_key, key, 16) == 0)
        {
            memcpy(out_key, value, 16);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

npdrm_status f00d_derive_key(const f00d_context* ctx, const uint8_t* in_key, uint32_t in_key_size, uint8_t* out_key, uint32_t out_key_size)
{
    if (in_key == NULL || out_key == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (in_key_size != 16 || out_key_size < 16)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (ctx != NULL && lookup_cache_file(ctx->cache_path, in_key, out_key) == 0)
    {
        return NPDRM_OK;
    }

    if (lookup_known_vector(in_key, out_key) == 0)
    {
        return NPDRM_OK;
    }

    // Clean-room scaffold: full derivation algorithm is still pending.
    // Current implementation supports explicit cache entries and known vectors.
    (void)memset(out_key, 0, out_key_size);
    return NPDRM_ERR_NOT_IMPLEMENTED;
}
