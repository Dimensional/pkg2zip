#include "pkg2zip_npdrm.h"

#include "pkg2zip_zrif.h"
#include "pkg2zip_f00d.h"
#include "pkg2zip_pfs.h"

#include <string.h>

#define RIF_KEY_OFFSET 0x50
#define RIF_KEY2_OFFSET 0xA0
#define RIF_CONTENT_ID_OFFSET 0x10
#define RIF_CONTENT_ID_SIZE 0x30
#define RIF_MIN_SIZE_FOR_KEY (RIF_KEY_OFFSET + 0x10)
#define RIF_MIN_SIZE_FOR_KEY2 (RIF_KEY2_OFFSET + 0x10)

static void set_error(char* error_message, size_t error_message_size, const char* msg)
{
    if (error_message == NULL || error_message_size == 0)
    {
        return;
    }

    size_t len = strlen(msg);
    if (len >= error_message_size)
    {
        len = error_message_size - 1;
    }
    memcpy(error_message, msg, len);
    error_message[len] = 0;
}

static npdrm_status copy_klicensee(const uint8_t* src, uint32_t src_size, uint8_t out_klicensee[16])
{
    if (src == NULL || out_klicensee == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (src_size < 16)
    {
        return NPDRM_ERR_INVALID_DATA;
    }

    memcpy(out_klicensee, src, 16);
    return NPDRM_OK;
}

static int is_zero_block(const uint8_t* data, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; i++)
    {
        if (data[i] != 0)
        {
            return 0;
        }
    }
    return 1;
}

static int is_ascii_content_id(const uint8_t* data, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; i++)
    {
        uint8_t c = data[i];
        if (c == 0)
        {
            break;
        }

        if (c < 0x20 || c > 0x7e)
        {
            return 0;
        }
    }
    return 1;
}

static npdrm_status extract_klicensee_from_rif(const uint8_t* rif, uint32_t rif_size, uint8_t out_klicensee[16])
{
    const uint8_t* key;

    if (rif == NULL || out_klicensee == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (rif_size < RIF_MIN_SIZE_FOR_KEY)
    {
        return NPDRM_ERR_INVALID_DATA;
    }

    // Basic structure sanity check: content id field is expected to be textual.
    if (!is_ascii_content_id(rif + RIF_CONTENT_ID_OFFSET, RIF_CONTENT_ID_SIZE))
    {
        return NPDRM_ERR_INVALID_DATA;
    }

    key = rif + RIF_KEY_OFFSET;
    if (!is_zero_block(key, 16))
    {
        memcpy(out_klicensee, key, 16);
        return NPDRM_OK;
    }

    // Some license variants expose a secondary key slot.
    if (rif_size >= RIF_MIN_SIZE_FOR_KEY2)
    {
        key = rif + RIF_KEY2_OFFSET;
        if (!is_zero_block(key, 16))
        {
            memcpy(out_klicensee, key, 16);
            return NPDRM_OK;
        }
    }

    return NPDRM_ERR_INVALID_DATA;
}

npdrm_status npdrm_resolve_klicensee(const npdrm_request* request, uint8_t out_klicensee[16], char* error_message, size_t error_message_size)
{
    if (request == NULL || out_klicensee == NULL)
    {
        set_error(error_message, error_message_size, "invalid request");
        return NPDRM_ERR_INVALID_ARG;
    }

    if (request->klicensee != NULL)
    {
        npdrm_status st = copy_klicensee(request->klicensee, request->klicensee_size, out_klicensee);
        if (st != NPDRM_OK)
        {
            set_error(error_message, error_message_size, "provided klicensee is invalid");
            return st;
        }
        return NPDRM_OK;
    }

    if (request->rif != NULL)
    {
        npdrm_status st = extract_klicensee_from_rif(request->rif, request->rif_size, out_klicensee);
        if (st != NPDRM_OK)
        {
            set_error(error_message, error_message_size, "failed to extract klicensee from RIF data");
        }
        return st;
    }

    if (request->zrif != NULL)
    {
        uint8_t rif[1024];
        uint32_t rif_size = 512;

        // pkg2zip currently supports 512-byte licenses for Vita APP/DLC/THEME.
        zrif_decode(request->zrif, rif, rif_size);

        npdrm_status st = extract_klicensee_from_rif(rif, rif_size, out_klicensee);
        if (st != NPDRM_OK)
        {
            set_error(error_message, error_message_size, "zRIF decoded, but no valid klicensee was found");
        }
        return st;
    }

    set_error(error_message, error_message_size, "no klicensee, RIF, or zRIF was provided");
    return NPDRM_ERR_INVALID_ARG;
}

npdrm_result npdrm_extract_title(const npdrm_request* request)
{
    npdrm_result result;
    result.status = NPDRM_OK;
    result.error_message[0] = 0;

    if (request == NULL)
    {
        result.status = NPDRM_ERR_INVALID_ARG;
        set_error(result.error_message, sizeof(result.error_message), "invalid request");
        return result;
    }

    if (request->title_src_dir == NULL || request->title_dst_dir == NULL)
    {
        result.status = NPDRM_ERR_INVALID_ARG;
        set_error(result.error_message, sizeof(result.error_message), "title_src_dir and title_dst_dir are required");
        return result;
    }

    uint8_t klicensee[16];
    result.status = npdrm_resolve_klicensee(request, klicensee, result.error_message, sizeof(result.error_message));
    if (result.status != NPDRM_OK)
    {
        return result;
    }

    // Placeholder for F00D-like transformation stage.
    uint8_t content_key[16];
    result.status = f00d_derive_key(klicensee, sizeof(klicensee), content_key, sizeof(content_key));
    if (result.status != NPDRM_OK)
    {
        set_error(result.error_message, sizeof(result.error_message), "F00D-like key derivation not implemented yet");
        return result;
    }

    // Placeholder for PFS metadata + file decryption stage.
    pfs_request pfs_req;
    pfs_req.title_src_dir = request->title_src_dir;
    pfs_req.title_dst_dir = request->title_dst_dir;
    pfs_req.klicensee = klicensee;
    pfs_req.content_key = content_key;
    pfs_req.content_key_size = sizeof(content_key);

    result.status = pfs_extract_decrypted_title(&pfs_req, result.error_message, (uint32_t)sizeof(result.error_message));
    return result;
}
