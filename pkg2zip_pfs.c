#include "pkg2zip_pfs.h"

#include <string.h>

npdrm_status pfs_extract_decrypted_title(const pfs_request* request, char* error_message, uint32_t error_message_size)
{
    if (request == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (request->title_src_dir == NULL || request->title_dst_dir == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (request->klicensee == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (error_message != NULL && error_message_size > 0)
    {
        const char* msg = "PFS extraction scaffold is present, but implementation is not added yet";
        size_t len = strlen(msg);
        if (len >= error_message_size)
        {
            len = error_message_size - 1;
        }
        memcpy(error_message, msg, len);
        error_message[len] = 0;
    }

    return NPDRM_ERR_NOT_IMPLEMENTED;
}
