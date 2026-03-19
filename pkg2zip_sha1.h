#pragma once

#include <stdint.h>

void sha1_digest(const uint8_t* data, uint32_t size, uint8_t out[20]);
void hmac_sha1_digest(const uint8_t* key, uint32_t key_size, const uint8_t* data, uint32_t size, uint8_t out[20]);