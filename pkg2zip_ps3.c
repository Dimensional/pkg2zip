/*
 * pkg2zip_ps3.c
 *
 * PS3 package manifest parser + streaming extractor.
 *
 * Notes:
 * - Parses a common 32-byte-per-item TOC layout (offset @ +8, size @ +16, type @ +24).
 * - Streams reads and (optionally) AES-CTR decrypts each content entry.
 * - Writes out via out_begin_file/out_write/out_end_file so extraction goes to zip or FS.
 *
 * TODO:
 * - Fully implement wrapped CEK unwrapping if manifest contains wrapped CEKs.
 * - Implement CEK derivation from license (RIF/RAP) files if user supplies them.
 * - If manifest layout differs for some PKG flavors, extend descriptor parsing.
 */

#include "pkg2zip_ps3.h"
#include "pkg2zip_utils.h"
#include "pkg2zip_out.h"
#include "pkg2zip_sys.h"
#include "pkg2zip_aes.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define PS3_ITEM_SIZE 32
#define PS3_MAX_ITEMS 65536   // safety limit to avoid OOM from corrupted counts
#define PS3_READ_CHUNK (64 * 1024) // 64KB streaming chunk

static int is_printable_ascii(const uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (!(isprint(p[i]) || p[i] == 0))
            return 0;
    return 1;
}

/*
 * Helper: sanitize a short string to be safe as a filename component.
 * Replaces ':' and slashes and non-printable chars.
 */
static void sanitize_name(char* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    size_t j = 0;
    for (size_t i = 0; i < inlen && j + 1 < outlen; ++i)
    {
        uint8_t c = in[i];
        if (!isprint(c) || c == 0) break;
        char ch = (char)c;
        if (ch == ':' || ch == '/') ch = ' ';
        if (ch == '\\') ch = '_';
        out[j++] = ch;
    }
    if (j == 0)
    {
        strncpy(out, "content", outlen);
        out[outlen - 1] = 0;
    }
    else
    {
        out[j] = 0;
    }
}

/*
 * Core unpacker implementation.
 *
 * This implementation expects that 'items_offset' is the offset (relative to enc_offset)
 * where the item descriptors begin, and each descriptor is PS3_ITEM_SIZE bytes.
 * The item descriptor parsed here follows the layout used elsewhere in this repo:
 * - [ 0..7 ]   : optional name/content id (up to 16 bytes inspected)
 * - [ 8..15 ]  : data offset (big-endian 64)
 * - [ 16..23 ] : data size   (big-endian 64)
 * - [ 24 ]     : content type / flags
 *
 * The descriptor area may be encrypted; we decrypt descriptors with 'key' & 'iv'
 * using AES-CTR with a block index derived from items_offset and the descriptor index.
 *
 * For content blobs we stream-read from the package file and decrypt each chunk
 * using aes128_ctr_xor with the determined per-content key (item_key) and iv.
 */
void unpack_ps3_pkg(const char* outdir,
                    const aes128_key* key,
                    const aes128_key* ps3_key,
                    const uint8_t* iv,
                    sys_file pkg,
                    uint64_t pkg_size,
                    uint64_t enc_offset,
                    uint64_t items_offset,
                    uint32_t item_count,
                    int zipped,
                    int list_only)
{
    (void)zipped;

    if (item_count == 0)
    {
        sys_output("PS3 PKG: item_count == 0, nothing to do\n");
        return;
    }

    if (item_count > PS3_MAX_ITEMS)
    {
        sys_error("ERROR: suspiciously large PKG item_count (%u)\n", item_count);
    }

    sys_output("PS3 PKG: parsing %u manifest entries (enc_offset=0x%llx, items_offset=0x%llx)\n",
               item_count, (unsigned long long)enc_offset, (unsigned long long)items_offset);

    uint8_t item[PS3_ITEM_SIZE];

    for (uint32_t i = 0; i < item_count; ++i)
    {
        uint64_t descriptor_abs = enc_offset + items_offset + (uint64_t)i * PS3_ITEM_SIZE;
        if (descriptor_abs + PS3_ITEM_SIZE > pkg_size)
        {
            sys_output("  [!] manifest entry %u descriptor out of range, skipping\n", i);
            continue;
        }

        // Read descriptor
        sys_read(pkg, descriptor_abs, item, PS3_ITEM_SIZE);

        // Decrypt descriptor in-place if keys are present.
        if (key && iv)
        {
            uint64_t block = (items_offset / 16) + ((uint64_t)i * PS3_ITEM_SIZE) / 16;
            aes128_ctr_xor((aes128_key*)key, iv, block, item, PS3_ITEM_SIZE);
        }

        // Parse fields according to the common 32-byte layout:
        // [8..15]  data offset (big-endian)
        // [16..23] data size   (big-endian)
        // [24]     content type
        uint64_t data_offset = get64be(item + 8);
        uint64_t data_size = get64be(item + 16);
        uint8_t ctype = item[24];

        uint64_t absolute_data_offset = enc_offset + data_offset;
        if (absolute_data_offset + data_size > pkg_size)
        {
            sys_output("    entry %u: data out of range (offset 0x%llx + size 0x%llx > pkg size)\n",
                       i, (unsigned long long)absolute_data_offset, (unsigned long long)data_size);
            continue;
        }

        // determine name
        char namebuf[1024];
        if (is_printable_ascii(item, 16) && item[0] != 0)
        {
            char clean[64];
            sanitize_name(clean, sizeof(clean), item, 16);
            snprintf(namebuf, sizeof(namebuf), "%s/%s_%02u.bin", outdir ? outdir : ".", clean, (unsigned)i);
        }
        else
        {
            snprintf(namebuf, sizeof(namebuf), "%s/content_%08u_type%02x.bin", outdir ? outdir : ".", (unsigned)i, (unsigned)ctype);
        }

        sys_output("  entry %u -> '%s'  offset=0x%llx size=0x%llx type=0x%02x\n",
                   i, namebuf, (unsigned long long)absolute_data_offset, (unsigned long long)data_size, (unsigned)ctype);

        if (list_only)
            continue;

        // create parent folder if needed
        out_add_parent(namebuf);

        // choose item key heuristic (repo convention)
        const aes128_key* item_key = NULL;
        if (ctype == 0x90)
            item_key = key;
        else
            item_key = ps3_key;

        // Begin file
        out_begin_file(namebuf, 0);

        // stream read / decrypt / write
        uint64_t remain = data_size;
        uint64_t read_off = absolute_data_offset;
        uint64_t processed = 0;
        uint8_t* chunk = (uint8_t*)sys_realloc(NULL, PS3_READ_CHUNK);

        while (remain)
        {
            uint32_t rchunk = (uint32_t)min64(remain, PS3_READ_CHUNK);
            sys_read(pkg, read_off, chunk, rchunk);

            if (item_key && iv)
            {
                // compute block index relative to data offset
                uint64_t block = (data_offset / 16) + (processed / 16);
                aes128_ctr_xor((aes128_key*)item_key, iv, block, chunk, rchunk);
            }

            out_write(chunk, rchunk);

            read_off += rchunk;
            processed += rchunk;
            remain -= rchunk;
        }

        sys_realloc(chunk, 0);
        out_end_file();
    }

    sys_output("PS3 PKG: done processing manifest entries\n");
}