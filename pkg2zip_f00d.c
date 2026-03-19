#include "pkg2zip_f00d.h"

#include "pkg2zip_aes.h"

#include <string.h>

static const uint8_t f00d_contract_key0[16] = {
    0xE1, 0x22, 0x13, 0xB4, 0x80, 0x16, 0xB0, 0xE9,
    0x9A, 0xB8, 0x1F, 0x8E, 0xC0, 0x2A, 0xD4, 0xA2
};

npdrm_status f00d_derive_key(const uint8_t* in_key, uint32_t in_key_size, uint8_t* out_key, uint32_t out_key_size)
{
    aes128_key aes;

    if (in_key == NULL || out_key == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (in_key_size != 16 || out_key_size < 16)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    aes128_init_dec(&aes, f00d_contract_key0);
    aes128_ecb_decrypt(&aes, in_key, out_key);
    return NPDRM_OK;
}
