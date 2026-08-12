#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    NPDRM_OK = 0,
    NPDRM_ERR_INVALID_ARG = -1,
    NPDRM_ERR_INVALID_DATA = -2,
    NPDRM_ERR_NOT_IMPLEMENTED = -3,
    NPDRM_ERR_IO = -4,
    NPDRM_ERR_INTERNAL = -5,
} npdrm_status;

struct pfs_source; // see pkg2zip_pfs.h

typedef struct {
    const struct pfs_source* source; // still-PKG-layer-encrypted title content, read directly from the .pkg
    const char* title_dst_dir;
    const char* zrif;
    const uint8_t* rif;
    uint32_t rif_size;
    const uint8_t* klicensee;
    uint32_t klicensee_size;
} npdrm_request;

typedef struct {
    npdrm_status status;
    char error_message[256];
} npdrm_result;

// Resolves klicensee in the following order:
// 1) request.klicensee (if provided)
// 2) request.rif (if provided)
// 3) request.zrif (if provided)
npdrm_status npdrm_resolve_klicensee(const npdrm_request* request, uint8_t out_klicensee[16], char* error_message, size_t error_message_size);

// Entry point for stage-2 NPDRM/PFS decryption (scaffold only for now).
npdrm_result npdrm_extract_title(const npdrm_request* request);
