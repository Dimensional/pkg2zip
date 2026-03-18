#pragma once

#include <stdint.h>

#include "pkg2zip_npdrm.h"

typedef struct {
    const char* title_src_dir;
    const char* title_dst_dir;
    const uint8_t* klicensee;
    const uint8_t* content_key;
    uint32_t content_key_size;
} pfs_request;

// Placeholder clean-room interface for PFS metadata parsing + file decryption.
npdrm_status pfs_extract_decrypted_title(const pfs_request* request, char* error_message, uint32_t error_message_size);
