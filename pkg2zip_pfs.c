#include "pkg2zip_pfs.h"

#include "pkg2zip_aes.h"
#include "pkg2zip_sha1.h"
#include "pkg2zip_sys.h"
#include "pkg2zip_utils.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define FILES_DB_MAGIC "SCENGPFS"

#define FILES_DB_ENTRY_PAGE_SIZE 0x400
#define FILES_DB_MAX_FILES_IN_BLOCK 9
#define FILES_DB_INVALID_INDEX 0xFFFFFFFFu
#define FILES_DB_ATTR_DIR 0x8000u

#define FILES_DB_INVALID_FLAT_INDEX 0xFFFFFFFFu
#define FILES_DB_ATTR_NENC 0x4000u

#define FILES_DB_BLOCK_HEADER_SIZE 16u
#define FILES_DB_FILE_HEADERS_SIZE 648u
#define FILES_DB_INFOS_OFFSET (FILES_DB_BLOCK_HEADER_SIZE + FILES_DB_FILE_HEADERS_SIZE)
#define FILES_DB_INFO_SIZE 16u
#define FILES_DB_INFO_COUNT 10u

#define UNICV_DB_MAGIC "SCEIRODB"
#define UNICV_TABLE_MAGIC "SCEIFTBL"
#define UNICV_HEADER_SIZE 32u
#define UNICV_TABLE_HEADER_SIZE 72u
#define UNICV_BLOCK_SIZE_DEFAULT 0x400u

#define PFS_CRYPTO_ENGINE_CRYPTO_USE_KEYGEN 0x0002u

static const uint8_t pfs_hmac_key1[20] = {
    0xAF, 0xE6, 0x56, 0xBB, 0x3C, 0x17, 0x25, 0x6A, 0x3C, 0x80,
    0x9F, 0x6E, 0x9B, 0xF1, 0x9F, 0xDD, 0x5A, 0x38, 0x85, 0x43
};

static const uint8_t pfs_hmac_key0[20] = {
    0xE4, 0x62, 0x25, 0x8B, 0x1F, 0x31, 0x21, 0x56, 0x07, 0x45,
    0xDB, 0x62, 0xB1, 0x43, 0x67, 0x23, 0xD2, 0xBF, 0x80, 0xFE
};

static const uint8_t pfs_iv0[16] = {
    0x74, 0xD2, 0x0C, 0xC3, 0x98, 0x81, 0xC2, 0x13,
    0xEE, 0x77, 0x0B, 0x10, 0x10, 0xE4, 0xBE, 0xA7
};

typedef struct {
    const pfs_filesdb_inventory_entry* entry;
    uint8_t* first_bytes;
    uint32_t first_size;
    uint8_t matched;
} pfs_probe_file_candidate;

static uint32_t expected_sectors_for_size(uint32_t file_size, uint32_t sector_size)
{
    if (sector_size == 0u)
    {
        return 0u;
    }
    return (file_size + sector_size - 1u) / sector_size;
}

static void join_path3(char* out, size_t out_size, const char* a, const char* b, const char* c);
static void join_path2(char* out, size_t out_size, const char* a, const char* b);

static void set_error(char* error_message, uint32_t error_message_size, const char* msg)
{
    size_t len;

    if (error_message == NULL || error_message_size == 0 || msg == NULL)
    {
        return;
    }

    len = strlen(msg);
    if (len >= error_message_size)
    {
        len = error_message_size - 1;
    }

    memcpy(error_message, msg, len);
    error_message[len] = 0;
}

static int path_exists_file(const char* path)
{
    struct stat info;
    if (path == NULL)
    {
        return 0;
    }
    if (stat(path, &info) != 0)
    {
        return 0;
    }
    return (info.st_mode & S_IFDIR) ? 0 : 1;
}

static uint64_t file_size_bytes(const char* path)
{
    struct stat info;
    if (path == NULL)
    {
        return 0;
    }
    if (stat(path, &info) != 0)
    {
        return 0;
    }
    return (uint64_t)info.st_size;
}

static int path_exists_dir(const char* path)
{
    return sys_test_dir(path) == 1;
}

static void trim_name_copy(char out[69], const uint8_t* in68)
{
    uint32_t i;
    for (i = 0; i < 68; i++)
    {
        uint8_t c = in68[i];
        if (c == 0)
        {
            break;
        }
        out[i] = (char)c;
    }
    out[i] = 0;
}

static int is_directory_type(uint16_t type)
{
    return (type & FILES_DB_ATTR_DIR) != 0;
}

static int is_unexisting_type(uint16_t type)
{
    return type == 0;
}

static uint16_t crypto_engine_flag_from_image_spec(uint16_t image_spec)
{
    if (image_spec == 1 || image_spec == 4)
    {
        return PFS_CRYPTO_ENGINE_CRYPTO_USE_KEYGEN;
    }
    if (image_spec == 2 || image_spec == 3)
    {
        return 0;
    }
    return 0x0001u;
}

static void sha1_contract(const uint8_t left[20], const uint8_t right[20], uint8_t out[20])
{
    uint8_t combo[40];
    memcpy(combo, left, 20);
    memcpy(combo + 20, right, 20);
    sha1_digest(combo, sizeof(combo), out);
}

static void aes128_cbc_encrypt_cts(const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* src, uint32_t size, uint8_t* dst)
{
    aes128_key aes;
    uint8_t iv[16];
    uint32_t size_block;
    uint32_t size_tail;
    uint32_t offset;

    aes128_init(&aes, key);
    memcpy(iv, iv_in, sizeof(iv));

    size_block = size & ~0xFu;
    size_tail = size & 0xFu;

    for (offset = 0; offset < size_block; offset += 16u)
    {
        uint8_t block[16];
        uint32_t i;
        for (i = 0; i < 16u; i++)
        {
            block[i] = (uint8_t)(src[offset + i] ^ iv[i]);
        }
        aes128_ecb_encrypt(&aes, block, dst + offset);
        memcpy(iv, dst + offset, 16u);
    }

    if (size_tail != 0u)
    {
        uint8_t tweak_enc[16];
        uint32_t i;
        aes128_ecb_encrypt(&aes, iv, tweak_enc);
        for (i = 0; i < size_tail; i++)
        {
            dst[size_block + i] = (uint8_t)(src[size_block + i] ^ tweak_enc[i]);
        }
    }
}

static void aes128_cbc_decrypt_cts(const aes128_key* dec, const aes128_key* enc, const uint8_t iv_in[16], const uint8_t* src, uint32_t size, uint8_t* dst)
{
    uint8_t iv[16];
    uint32_t size_block;
    uint32_t size_tail;
    uint32_t offset;

    memcpy(iv, iv_in, sizeof(iv));
    size_block = size & ~0xFu;
    size_tail = size & 0xFu;

    for (offset = 0; offset < size_block; offset += 16u)
    {
        uint8_t plain[16];
        uint8_t cipher[16];
        uint32_t i;

        memcpy(cipher, src + offset, sizeof(cipher));
        aes128_ecb_decrypt(dec, cipher, plain);
        for (i = 0; i < 16u; i++)
        {
            dst[offset + i] = (uint8_t)(plain[i] ^ iv[i]);
        }
        memcpy(iv, cipher, sizeof(iv));
    }

    if (size_tail != 0u)
    {
        uint8_t tweak_enc[16];
        uint32_t i;
        aes128_ecb_encrypt(enc, iv, tweak_enc);
        for (i = 0; i < size_tail; i++)
        {
            dst[size_block + i] = (uint8_t)(src[size_block + i] ^ tweak_enc[i]);
        }
    }
}

static void ensure_parent_dir(const char* path)
{
    char parent[PFS_MAX_PATH];
    char* last;

    if (path == NULL || path[0] == 0)
    {
        return;
    }

    snprintf(parent, sizeof(parent), "%s", path);
    last = strrchr(parent, '/');
    if (last != NULL)
    {
        *last = 0;
        if (parent[0] != 0)
        {
            sys_mkdir(parent);
        }
    }
}

static npdrm_status create_empty_file_on_disk(const char* path)
{
    sys_file file;

    if (path == NULL || path[0] == 0)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    ensure_parent_dir(path);
    file = sys_create(path);
    sys_close(file);
    return NPDRM_OK;
}

static npdrm_status copy_file_raw(const char* src_path, const char* dst_path)
{
    sys_file src;
    sys_file dst;
    uint64_t src_size;
    uint64_t offset;
    uint8_t buffer[1 << 16];

    if (src_path == NULL || dst_path == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    ensure_parent_dir(dst_path);
    src = sys_open(src_path, &src_size);
    dst = sys_create(dst_path);

    for (offset = 0; offset < src_size; offset += sizeof(buffer))
    {
        uint32_t chunk = (uint32_t)min64((uint64_t)sizeof(buffer), src_size - offset);
        sys_read(src, offset, buffer, chunk);
        sys_write(dst, offset, buffer, chunk);
    }

    sys_close(dst);
    sys_close(src);
    return NPDRM_OK;
}

static const pfs_unicv_file_mapping_entry* find_mapping_by_path(const pfs_unicv_file_mapping* mapping, const char* path)
{
    uint32_t i;

    if (mapping == NULL || path == NULL)
    {
        return NULL;
    }

    for (i = 0; i < mapping->count; i++)
    {
        const pfs_unicv_file_mapping_entry* entry = &mapping->entries[i];
        if (entry->verified_match && strcmp(entry->path, path) == 0)
        {
            return entry;
        }
    }

    return NULL;
}

static void generate_tweak_mask_keygen(uint32_t files_salt, uint32_t icv_salt, uint8_t out_mask[16])
{
    uint8_t drvkey[20];
    uint8_t salt_bytes[8];

    if (files_salt == 0u)
    {
        set32le(salt_bytes, icv_salt);
        hmac_sha1_digest(pfs_hmac_key0, sizeof(pfs_hmac_key0), salt_bytes, 4u, drvkey);
    }
    else
    {
        set32le(salt_bytes + 0, files_salt);
        set32le(salt_bytes + 4, icv_salt);
        hmac_sha1_digest(pfs_hmac_key0, sizeof(pfs_hmac_key0), salt_bytes, sizeof(salt_bytes), drvkey);
    }

    memcpy(out_mask, drvkey, 16u);
}

static void generate_tweak_mask_dbseed(const uint8_t dbseed[20], uint8_t out_mask[16])
{
    uint8_t drvkey[20];
    hmac_sha1_digest(pfs_hmac_key0, sizeof(pfs_hmac_key0), dbseed, 20u, drvkey);
    memcpy(out_mask, drvkey, 16u);
}

static void build_unicv_tweak(const uint8_t tweak_mask[16], uint64_t tweak_key, uint8_t out_tweak[16])
{
    uint32_t i;

    set64le(out_tweak, tweak_key);
    memset(out_tweak + 8, 0, 8u);
    for (i = 0; i < 16u; i++)
    {
        out_tweak[i] ^= tweak_mask[i];
    }
}

static npdrm_status decrypt_unicv_file_to_path(const char* src_path, const char* dst_path, uint32_t files_salt, uint32_t icv_salt, uint32_t sector_size, const uint8_t content_key[16], const uint8_t* dbseed, uint32_t dbseed_size)
{
    sys_file src;
    sys_file dst;
    uint64_t file_size;
    uint64_t offset;
    uint8_t tweak_mask[16];
    uint8_t tweak[16];
    uint8_t* buffer;
    aes128_key enc;
    aes128_key dec;

    if (src_path == NULL || dst_path == NULL || content_key == NULL || sector_size == 0u)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    ensure_parent_dir(dst_path);
    src = sys_open(src_path, &file_size);
    dst = sys_create(dst_path);

    if (dbseed != NULL && dbseed_size >= 20u)
    {
        generate_tweak_mask_dbseed(dbseed, tweak_mask);
    }
    else
    {
        generate_tweak_mask_keygen(files_salt, icv_salt, tweak_mask);
    }
    aes128_init(&enc, content_key);
    aes128_init_dec(&dec, content_key);

    buffer = (uint8_t*)sys_realloc(NULL, sector_size);
    for (offset = 0; offset < file_size; offset += sector_size)
    {
        uint32_t chunk = (uint32_t)min64((uint64_t)sector_size, file_size - offset);
        build_unicv_tweak(tweak_mask, offset, tweak);
        sys_read(src, offset, buffer, chunk);
        aes128_cbc_decrypt_cts(&dec, &enc, tweak, buffer, chunk, buffer);
        sys_write(dst, offset, buffer, chunk);
    }

    sys_realloc(buffer, 0);
    sys_close(dst);
    sys_close(src);
    return NPDRM_OK;
}

static npdrm_status generate_secret_keygen(const uint8_t content_key[16], uint32_t files_salt, uint32_t icv_salt, uint8_t out_secret[20])
{
    uint8_t combo[20];
    uint8_t salt_bytes[8];

    if (content_key == NULL || out_secret == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (files_salt == 0)
    {
        set32le(salt_bytes, icv_salt);
        hmac_sha1_digest(pfs_hmac_key1, sizeof(pfs_hmac_key1), salt_bytes, 4u, combo);
    }
    else
    {
        set32le(salt_bytes + 0, files_salt);
        set32le(salt_bytes + 4, icv_salt);
        hmac_sha1_digest(pfs_hmac_key1, sizeof(pfs_hmac_key1), salt_bytes, sizeof(salt_bytes), combo);
    }

    aes128_cbc_encrypt_cts(content_key, pfs_iv0, combo, sizeof(combo), out_secret);
    return NPDRM_OK;
}

static npdrm_status generate_secret_savedata(const uint8_t klicensee[16], uint32_t icv_salt, uint8_t out_secret[20])
{
    uint8_t base0[20];
    uint8_t base1[20];
    uint8_t salt_bytes[8];

    if (klicensee == NULL || out_secret == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    sha1_digest(klicensee, 16u, base0);
    set32le(salt_bytes + 0, 0x0Au);
    set32le(salt_bytes + 4, icv_salt);
    sha1_digest(salt_bytes, sizeof(salt_bytes), base1);
    sha1_contract(base0, base1, out_secret);
    return NPDRM_OK;
}

static npdrm_status generate_table_secret(const pfs_filesdb_header* header, const uint8_t* klicensee, uint32_t klicensee_size, const uint8_t* content_key, uint32_t content_key_size, uint32_t table_page, uint8_t out_secret[20])
{
    uint16_t flag;

    if (header == NULL || out_secret == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    flag = crypto_engine_flag_from_image_spec(header->image_spec);
    if ((flag & PFS_CRYPTO_ENGINE_CRYPTO_USE_KEYGEN) != 0)
    {
        if (content_key == NULL || content_key_size < 16u)
        {
            return NPDRM_ERR_INVALID_ARG;
        }
        return generate_secret_keygen(content_key, header->files_salt, table_page, out_secret);
    }

    if (klicensee == NULL || klicensee_size < 16u)
    {
        return NPDRM_ERR_INVALID_ARG;
    }
    return generate_secret_savedata(klicensee, table_page, out_secret);
}

static void free_probe_candidates(pfs_probe_file_candidate* files, uint32_t count)
{
    uint32_t i;
    if (files == NULL)
    {
        return;
    }
    for (i = 0; i < count; i++)
    {
        if (files[i].first_bytes != NULL)
        {
            sys_realloc(files[i].first_bytes, 0);
            files[i].first_bytes = NULL;
        }
    }
    sys_realloc(files, 0);
}

static npdrm_status collect_probe_candidates(const char* title_src_dir, const pfs_filesdb_inventory* inventory, const pfs_unicv_table_list* tables, pfs_probe_file_candidate** out_files, uint32_t* out_count, char* error_message, uint32_t error_message_size)
{
    pfs_probe_file_candidate* files = NULL;
    uint32_t count = 0;
    uint32_t max_sector_size = 0;
    uint32_t i;

    if (title_src_dir == NULL || inventory == NULL || tables == NULL || out_files == NULL || out_count == NULL)
    {
        set_error(error_message, error_message_size, "invalid probe candidate request");
        return NPDRM_ERR_INVALID_ARG;
    }

    for (i = 0; i < tables->count; i++)
    {
        if (tables->tables[i].n_sectors > 0 && tables->tables[i].file_sector_size > max_sector_size)
        {
            max_sector_size = tables->tables[i].file_sector_size;
        }
    }

    if (max_sector_size == 0)
    {
        *out_files = NULL;
        *out_count = 0;
        return NPDRM_OK;
    }

    for (i = 0; i < inventory->count; i++)
    {
        const pfs_filesdb_inventory_entry* entry = &inventory->entries[i];
        char full_path[PFS_MAX_PATH];
        uint32_t read_size;
        uint64_t file_size;
        uint64_t opened_size;
        sys_file file;

        if (!entry->is_processable || entry->size == 0 || entry->path[0] == 0)
        {
            continue;
        }

        join_path2(full_path, sizeof(full_path), title_src_dir, entry->path);
        if (full_path[0] == 0 || !path_exists_file(full_path))
        {
            free_probe_candidates(files, count);
            set_error(error_message, error_message_size, "inventory file path not found on disk");
            return NPDRM_ERR_INVALID_DATA;
        }

        files = (pfs_probe_file_candidate*)sys_realloc(files, sizeof(pfs_probe_file_candidate) * (size_t)(count + 1));
        memset(&files[count], 0, sizeof(files[count]));
        files[count].entry = entry;

        file_size = file_size_bytes(full_path);
        read_size = (uint32_t)min64(file_size, max_sector_size);
        if (read_size == 0)
        {
            count++;
            continue;
        }

        files[count].first_bytes = (uint8_t*)sys_realloc(NULL, read_size);
        files[count].first_size = read_size;

        file = sys_open(full_path, &opened_size);
        if (opened_size < read_size)
        {
            sys_close(file);
            free_probe_candidates(files, count + 1);
            set_error(error_message, error_message_size, "failed to read probe file sector");
            return NPDRM_ERR_IO;
        }
        sys_read(file, 0, files[count].first_bytes, read_size);
        sys_close(file);
        count++;
    }

    *out_files = files;
    *out_count = count;
    return NPDRM_OK;
}

npdrm_status pfs_read_filesdb_header(const char* files_db_path, pfs_filesdb_header* out_header, char* error_message, uint32_t error_message_size)
{
    sys_file files_db;
    uint64_t files_db_size;
    uint8_t header[0x38];

    if (files_db_path == NULL || out_header == NULL)
    {
        set_error(error_message, error_message_size, "invalid files.db header request");
        return NPDRM_ERR_INVALID_ARG;
    }

    files_db = sys_open(files_db_path, &files_db_size);
    if (files_db_size < sizeof(header))
    {
        sys_close(files_db);
        set_error(error_message, error_message_size, "files.db is too small for header");
        return NPDRM_ERR_INVALID_DATA;
    }

    sys_read(files_db, 0, header, (uint32_t)sizeof(header));
    sys_close(files_db);

    if (memcmp(header, FILES_DB_MAGIC, 8) != 0)
    {
        set_error(error_message, error_message_size, "files.db has invalid magic");
        return NPDRM_ERR_INVALID_DATA;
    }

    memset(out_header, 0, sizeof(*out_header));
    memcpy(out_header->magic, header + 0x00, 8);
    out_header->magic[8] = 0;
    out_header->version = get32le(header + 0x08);
    out_header->image_spec = get16le(header + 0x0C);
    out_header->key_id = get16le(header + 0x0E);
    out_header->page_size = get32le(header + 0x10);
    out_header->bt_order = get32le(header + 0x14);
    out_header->root_icv_page_number = get32le(header + 0x18);
    out_header->files_salt = get32le(header + 0x1C);
    out_header->unk6 = get64le(header + 0x20);
    out_header->tail_size = get64le(header + 0x28);
    out_header->total_size = get64le(header + 0x30);

    if (error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }

    return NPDRM_OK;
}

static void join_path3(char* out, size_t out_size, const char* a, const char* b, const char* c)
{
    int n;
    if (out == NULL || out_size == 0)
    {
        return;
    }
    n = snprintf(out, out_size, "%s/%s/%s", a, b, c);
    if (n < 0 || (size_t)n >= out_size)
    {
        out[0] = 0;
    }
}

static void join_path2(char* out, size_t out_size, const char* a, const char* b)
{
    int n;
    if (out == NULL || out_size == 0)
    {
        return;
    }
    n = snprintf(out, out_size, "%s/%s", a, b);
    if (n < 0 || (size_t)n >= out_size)
    {
        out[0] = 0;
    }
}

typedef struct {
    uint32_t child;
    uint32_t parent;
} pfs_idx_edge;

static int find_edge_parent(const pfs_idx_edge* edges, uint32_t count, uint32_t child, uint32_t* out_parent)
{
    uint32_t i;
    if (edges == NULL || out_parent == NULL)
    {
        return 0;
    }
    for (i = 0; i < count; i++)
    {
        if (edges[i].child == child)
        {
            *out_parent = edges[i].parent;
            return 1;
        }
    }
    return 0;
}

static int edge_child_exists(const pfs_idx_edge* edges, uint32_t count, uint32_t child)
{
    uint32_t i;
    if (edges == NULL)
    {
        return 0;
    }
    for (i = 0; i < count; i++)
    {
        if (edges[i].child == child)
        {
            return 1;
        }
    }
    return 0;
}

static pfs_filesdb_inventory_entry* find_inventory_entry_by_idx(pfs_filesdb_inventory* inv, uint32_t idx, int required_directory)
{
    uint32_t i;
    if (inv == NULL || inv->entries == NULL)
    {
        return NULL;
    }
    for (i = 0; i < inv->count; i++)
    {
        pfs_filesdb_inventory_entry* e = &inv->entries[i];
        if (e->idx != idx)
        {
            continue;
        }
        if (required_directory == 1 && !e->is_directory)
        {
            continue;
        }
        if (required_directory == 0 && e->is_directory)
        {
            continue;
        }
        return e;
    }
    return NULL;
}

static npdrm_status build_dir_path_from_matrix(
    pfs_filesdb_inventory* inv,
    const pfs_idx_edge* dir_edges,
    uint32_t dir_edge_count,
    uint32_t idx,
    char* out_path,
    uint32_t out_path_size)
{
    const char* names[128];
    uint32_t depth = 0;
    uint32_t cur = idx;

    if (out_path == NULL || out_path_size == 0)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    while (cur != 0 && depth < (uint32_t)(sizeof(names) / sizeof(names[0])))
    {
        pfs_filesdb_inventory_entry* dir = find_inventory_entry_by_idx(inv, cur, 1);
        uint32_t parent = 0;
        if (dir == NULL)
        {
            break;
        }

        names[depth++] = dir->name;

        if (!find_edge_parent(dir_edges, dir_edge_count, cur, &parent))
        {
            break;
        }
        cur = parent;
    }

    out_path[0] = 0;
    while (depth > 0)
    {
        const char* name = names[--depth];
        size_t name_len;
        size_t cur_len;
        if (name == NULL || name[0] == 0)
        {
            continue;
        }
        name_len = strlen(name);
        cur_len = strlen(out_path);
        if (cur_len != 0)
        {
            if (cur_len + 1 >= out_path_size)
            {
                return NPDRM_ERR_INVALID_DATA;
            }
            out_path[cur_len++] = '/';
            out_path[cur_len] = 0;
        }
        if (cur_len + name_len >= out_path_size)
        {
            return NPDRM_ERR_INVALID_DATA;
        }
        memcpy(out_path + cur_len, name, name_len);
        out_path[cur_len + name_len] = 0;
    }

    return NPDRM_OK;
}

npdrm_status pfs_collect_filesdb_inventory(const char* files_db_path, const pfs_filesdb_header* header, pfs_filesdb_inventory* out_inventory, char* error_message, uint32_t error_message_size)
{
    sys_file files_db;
    uint64_t files_db_size;
    uint64_t tail_offset;
    uint64_t tail_size;
    uint64_t page_count;
    uint8_t page[FILES_DB_ENTRY_PAGE_SIZE];
    uint64_t p;
    pfs_idx_edge* dir_edges = NULL;
    pfs_idx_edge* file_edges = NULL;
    uint32_t dir_edge_count = 0;
    uint32_t file_edge_count = 0;

    if (files_db_path == NULL || header == NULL || out_inventory == NULL)
    {
        set_error(error_message, error_message_size, "invalid files.db inventory request");
        return NPDRM_ERR_INVALID_ARG;
    }

    memset(out_inventory, 0, sizeof(*out_inventory));

    if (header->page_size != FILES_DB_ENTRY_PAGE_SIZE)
    {
        set_error(error_message, error_message_size, "unsupported files.db page size");
        return NPDRM_ERR_NOT_IMPLEMENTED;
    }

    files_db = sys_open(files_db_path, &files_db_size);
    if (files_db_size < header->page_size)
    {
        sys_close(files_db);
        set_error(error_message, error_message_size, "files.db is too small");
        return NPDRM_ERR_INVALID_DATA;
    }

    tail_offset = header->page_size;
    tail_size = files_db_size - tail_offset;
    if ((tail_size % header->page_size) != 0)
    {
        sys_close(files_db);
        set_error(error_message, error_message_size, "files.db tail is not page aligned");
        return NPDRM_ERR_INVALID_DATA;
    }

    page_count = tail_size / header->page_size;

    for (p = 0; p < page_count; p++)
    {
        uint32_t n_files;
        uint32_t i;

        sys_read(files_db, tail_offset + (p * header->page_size), page, FILES_DB_ENTRY_PAGE_SIZE);
        n_files = get32le(page + 8);
        if (n_files > FILES_DB_MAX_FILES_IN_BLOCK)
        {
            pfs_free_filesdb_inventory(out_inventory);
            sys_close(files_db);
            set_error(error_message, error_message_size, "files.db block has invalid file count");
            return NPDRM_ERR_INVALID_DATA;
        }

        for (i = 0; i < n_files; i++)
        {
            uint32_t info_off = FILES_DB_INFOS_OFFSET + (i * FILES_DB_INFO_SIZE);
            uint32_t name_off = FILES_DB_BLOCK_HEADER_SIZE + (i * 72u);
            uint32_t idx = get32le(page + info_off);
            uint16_t type = get16le(page + info_off + 4);
            uint32_t size = get32le(page + info_off + 8);
            uint32_t parent_idx = get32le(page + name_off);
            pfs_filesdb_inventory_entry* e;

            if (idx == FILES_DB_INVALID_INDEX)
            {
                continue;
            }

            out_inventory->entries = (pfs_filesdb_inventory_entry*)sys_realloc(
                out_inventory->entries,
                sizeof(pfs_filesdb_inventory_entry) * (size_t)(out_inventory->count + 1));
            e = &out_inventory->entries[out_inventory->count++];
            memset(e, 0, sizeof(*e));

            e->idx = idx;
            e->parent_idx = parent_idx;
            e->type = type;
            e->effective_type = type;
            e->size = size;
            e->block_page = (uint32_t)(p + 1u);
            e->is_directory = (uint8_t)is_directory_type(type);
            e->is_processable = 0;
            e->type_was_fixed = 0;
            trim_name_copy(e->name, page + name_off + 4);

            if (e->is_directory)
            {
                if (edge_child_exists(dir_edges, dir_edge_count, e->idx))
                {
                    pfs_free_filesdb_inventory(out_inventory);
                    if (dir_edges != NULL)
                    {
                        sys_realloc(dir_edges, 0);
                    }
                    if (file_edges != NULL)
                    {
                        sys_realloc(file_edges, 0);
                    }
                    sys_close(files_db);
                    set_error(error_message, error_message_size, "duplicate directory index in files.db");
                    return NPDRM_ERR_INVALID_DATA;
                }
                dir_edges = (pfs_idx_edge*)sys_realloc(dir_edges, sizeof(pfs_idx_edge) * (size_t)(dir_edge_count + 1));
                dir_edges[dir_edge_count].child = e->idx;
                dir_edges[dir_edge_count].parent = e->parent_idx;
                dir_edge_count++;
                out_inventory->directory_count++;
                continue;
            }

            if (is_unexisting_type(type) && size == 0)
            {
                out_inventory->skipped_unexisting_empty_count++;
                continue;
            }

            if (is_unexisting_type(type) && size != 0)
            {
                e->effective_type = 0x0001;
                e->type_was_fixed = 1;
                out_inventory->fixed_unexisting_nonempty_count++;
            }

            if (edge_child_exists(file_edges, file_edge_count, e->idx))
            {
                pfs_free_filesdb_inventory(out_inventory);
                if (dir_edges != NULL)
                {
                    sys_realloc(dir_edges, 0);
                }
                if (file_edges != NULL)
                {
                    sys_realloc(file_edges, 0);
                }
                sys_close(files_db);
                set_error(error_message, error_message_size, "duplicate file index in files.db");
                return NPDRM_ERR_INVALID_DATA;
            }

            file_edges = (pfs_idx_edge*)sys_realloc(file_edges, sizeof(pfs_idx_edge) * (size_t)(file_edge_count + 1));
            file_edges[file_edge_count].child = e->idx;
            file_edges[file_edge_count].parent = e->parent_idx;
            file_edge_count++;

            e->is_processable = 1;
            out_inventory->processable_file_count++;
        }
    }

    sys_close(files_db);

    // Build canonical paths for directories first.
    {
        uint32_t i;
        for (i = 0; i < out_inventory->count; i++)
        {
            pfs_filesdb_inventory_entry* e = &out_inventory->entries[i];
            npdrm_status st;
            if (!e->is_directory)
            {
                continue;
            }
            st = build_dir_path_from_matrix(out_inventory, dir_edges, dir_edge_count, e->idx, e->path, sizeof(e->path));
            if (st != NPDRM_OK)
            {
                pfs_free_filesdb_inventory(out_inventory);
                if (dir_edges != NULL)
                {
                    sys_realloc(dir_edges, 0);
                }
                if (file_edges != NULL)
                {
                    sys_realloc(file_edges, 0);
                }
                set_error(error_message, error_message_size, "failed to build directory paths");
                return st;
            }
        }
    }

    // Build canonical paths for processable files.
    {
        uint32_t i;
        for (i = 0; i < out_inventory->count; i++)
        {
            pfs_filesdb_inventory_entry* e = &out_inventory->entries[i];
            char dir_path[PFS_MAX_PATH];
            size_t dir_len;
            size_t name_len;
            npdrm_status st;

            if (e->is_directory || !e->is_processable)
            {
                continue;
            }

            dir_path[0] = 0;
            if (e->parent_idx != 0)
            {
                st = build_dir_path_from_matrix(out_inventory, dir_edges, dir_edge_count, e->parent_idx, dir_path, sizeof(dir_path));
                if (st != NPDRM_OK)
                {
                    pfs_free_filesdb_inventory(out_inventory);
                    if (dir_edges != NULL)
                    {
                        sys_realloc(dir_edges, 0);
                    }
                    if (file_edges != NULL)
                    {
                        sys_realloc(file_edges, 0);
                    }
                    set_error(error_message, error_message_size, "failed to build file paths");
                    return st;
                }
            }

            dir_len = strlen(dir_path);
            name_len = strlen(e->name);
            if (dir_len == 0)
            {
                if (name_len >= sizeof(e->path))
                {
                    pfs_free_filesdb_inventory(out_inventory);
                    if (dir_edges != NULL)
                    {
                        sys_realloc(dir_edges, 0);
                    }
                    if (file_edges != NULL)
                    {
                        sys_realloc(file_edges, 0);
                    }
                    set_error(error_message, error_message_size, "file path too long");
                    return NPDRM_ERR_INVALID_DATA;
                }
                memcpy(e->path, e->name, name_len + 1);
            }
            else
            {
                if (dir_len + 1 + name_len >= sizeof(e->path))
                {
                    pfs_free_filesdb_inventory(out_inventory);
                    if (dir_edges != NULL)
                    {
                        sys_realloc(dir_edges, 0);
                    }
                    if (file_edges != NULL)
                    {
                        sys_realloc(file_edges, 0);
                    }
                    set_error(error_message, error_message_size, "file path too long");
                    return NPDRM_ERR_INVALID_DATA;
                }
                memcpy(e->path, dir_path, dir_len);
                e->path[dir_len] = '/';
                memcpy(e->path + dir_len + 1, e->name, name_len + 1);
            }
        }
    }

    if (dir_edges != NULL)
    {
        sys_realloc(dir_edges, 0);
    }
    if (file_edges != NULL)
    {
        sys_realloc(file_edges, 0);
    }

    if (error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }
    return NPDRM_OK;
}

void pfs_free_filesdb_inventory(pfs_filesdb_inventory* inventory)
{
    if (inventory == NULL)
    {
        return;
    }
    if (inventory->entries != NULL)
    {
        sys_realloc(inventory->entries, 0);
        inventory->entries = NULL;
    }
    inventory->count = 0;
    inventory->directory_count = 0;
    inventory->processable_file_count = 0;
    inventory->skipped_unexisting_empty_count = 0;
    inventory->fixed_unexisting_nonempty_count = 0;
}

npdrm_status pfs_collect_unicv_tables(const char* unicv_db_path, pfs_unicv_table_list* out_tables, char* error_message, uint32_t error_message_size)
{
    sys_file unicv;
    uint64_t unicv_size;
    uint8_t header[UNICV_HEADER_SIZE];
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t block_size;
    uint64_t block_count;
    uint64_t i;

    if (unicv_db_path == NULL || out_tables == NULL)
    {
        set_error(error_message, error_message_size, "invalid unicv parse request");
        return NPDRM_ERR_INVALID_ARG;
    }

    memset(out_tables, 0, sizeof(*out_tables));

    unicv = sys_open(unicv_db_path, &unicv_size);
    if (unicv_size < UNICV_HEADER_SIZE)
    {
        sys_close(unicv);
        set_error(error_message, error_message_size, "unicv.db is too small");
        return NPDRM_ERR_INVALID_DATA;
    }

    sys_read(unicv, 0, header, UNICV_HEADER_SIZE);
    if (memcmp(header + 0, UNICV_DB_MAGIC, 8) != 0)
    {
        sys_close(unicv);
        set_error(error_message, error_message_size, "unicv.db has invalid magic");
        return NPDRM_ERR_INVALID_DATA;
    }

    block_size = get32le(header + 12);
    data_size = get64le(header + 24);
    data_offset = (uint64_t)block_size;

    if (block_size == 0)
    {
        sys_close(unicv);
        set_error(error_message, error_message_size, "unicv.db has invalid block size");
        return NPDRM_ERR_INVALID_DATA;
    }

    if (data_offset + data_size > unicv_size)
    {
        sys_close(unicv);
        set_error(error_message, error_message_size, "unicv.db data region out of bounds");
        return NPDRM_ERR_INVALID_DATA;
    }

    if ((data_size % block_size) != 0)
    {
        sys_close(unicv);
        set_error(error_message, error_message_size, "unicv.db data region is not block aligned");
        return NPDRM_ERR_INVALID_DATA;
    }

    block_count = data_size / block_size;

    for (i = 0; i < block_count;)
    {
        uint8_t block_header[UNICV_TABLE_HEADER_SIZE];
        uint8_t zero_probe[16];
        uint64_t block_offset = data_offset + (i * block_size);
        uint32_t version;
        uint32_t n_sectors;
        uint32_t bin_max;
        uint32_t file_sector_size;
        uint32_t sig_blocks;
        pfs_unicv_table_info* t;

        sys_read(unicv, block_offset, zero_probe, (uint32_t)sizeof(zero_probe));
        if (memcmp(zero_probe, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0)
        {
            i++;
            continue;
        }

        sys_read(unicv, block_offset, block_header, UNICV_TABLE_HEADER_SIZE);
        if (memcmp(block_header + 0, UNICV_TABLE_MAGIC, 8) != 0)
        {
            sys_close(unicv);
            pfs_free_unicv_table_list(out_tables);
            set_error(error_message, error_message_size, "unexpected table magic in unicv.db");
            return NPDRM_ERR_INVALID_DATA;
        }

        version = get32le(block_header + 8);
        bin_max = get32le(block_header + 16);
        n_sectors = get32le(block_header + 20);
        file_sector_size = get32le(block_header + 24);

        if (bin_max == 0)
        {
            sys_close(unicv);
            pfs_free_unicv_table_list(out_tables);
            set_error(error_message, error_message_size, "unicv.db table has invalid binTreeNumMaxAvail");
            return NPDRM_ERR_INVALID_DATA;
        }

        sig_blocks = (n_sectors + bin_max - 1) / bin_max;

        out_tables->tables = (pfs_unicv_table_info*)sys_realloc(
            out_tables->tables,
            sizeof(pfs_unicv_table_info) * (size_t)(out_tables->count + 1));

        t = &out_tables->tables[out_tables->count++];
        memset(t, 0, sizeof(*t));
        t->table_page = (uint32_t)(i + 1); /* page = 1-based block number within unicv.db (SCEIRODB header = page 0) */
        t->version = version;
        t->n_sectors = n_sectors;
        t->file_sector_size = file_sector_size;
        t->bin_tree_num_max_avail = bin_max;
        t->signature_block_count = sig_blocks;
        t->has_dbseed = (uint8_t)(version > 1u ? 1u : 0u);
        memcpy(t->dbseed, block_header + 52, 20u);

        if (n_sectors > 0)
        {
            uint8_t sig_header[16];
            uint64_t sig_block_offset = block_offset + block_size;
            uint32_t expected_signatures = n_sectors < bin_max ? n_sectors : bin_max;

            if (sig_blocks == 0 || sig_block_offset + 36u > unicv_size)
            {
                sys_close(unicv);
                pfs_free_unicv_table_list(out_tables);
                set_error(error_message, error_message_size, "unicv.db table is missing first signature block");
                return NPDRM_ERR_INVALID_DATA;
            }

            sys_read(unicv, sig_block_offset, sig_header, sizeof(sig_header));
            if (get32le(sig_header + 0) != (16u + (bin_max * 20u)) || get32le(sig_header + 4) != 20u || get32le(sig_header + 12) != 0u)
            {
                sys_close(unicv);
                pfs_free_unicv_table_list(out_tables);
                set_error(error_message, error_message_size, "unicv.db signature block header is invalid");
                return NPDRM_ERR_INVALID_DATA;
            }
            if (get32le(sig_header + 8) == 0 || get32le(sig_header + 8) != expected_signatures)
            {
                sys_close(unicv);
                pfs_free_unicv_table_list(out_tables);
                set_error(error_message, error_message_size, "unicv.db signature count does not match sectors");
                return NPDRM_ERR_INVALID_DATA;
            }

            sys_read(unicv, sig_block_offset + 16u, t->first_signature, 20u);
            t->has_first_signature = 1;
            out_tables->nonempty_count++;
        }

        i += (uint64_t)(1u + sig_blocks);
    }

    sys_close(unicv);

    if (error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }

    return NPDRM_OK;
}

void pfs_free_unicv_table_list(pfs_unicv_table_list* tables)
{
    if (tables == NULL)
    {
        return;
    }
    if (tables->tables != NULL)
    {
        sys_realloc(tables->tables, 0);
        tables->tables = NULL;
    }
    tables->count = 0;
    tables->nonempty_count = 0;
}

npdrm_status pfs_map_unicv_tables_verified(const char* title_src_dir, const pfs_filesdb_header* header, const pfs_filesdb_inventory* inventory, const pfs_unicv_table_list* tables, const uint8_t* klicensee, uint32_t klicensee_size, const uint8_t* content_key, uint32_t content_key_size, pfs_unicv_file_mapping* out_mapping, char* error_message, uint32_t error_message_size)
{
    pfs_probe_file_candidate* files = NULL;
    uint32_t file_count = 0;
    uint32_t i;
    uint32_t processed_tables = 0;
    npdrm_status st;

    if (title_src_dir == NULL || header == NULL || inventory == NULL || tables == NULL || out_mapping == NULL)
    {
        set_error(error_message, error_message_size, "invalid verified unicv mapping request");
        return NPDRM_ERR_INVALID_ARG;
    }

    if (tables->nonempty_count == 0)
    {
        memset(out_mapping, 0, sizeof(*out_mapping));
        return NPDRM_OK;
    }

    st = collect_probe_candidates(title_src_dir, inventory, tables, &files, &file_count, error_message, error_message_size);
    if (st != NPDRM_OK)
    {
        return st;
    }

    memset(out_mapping, 0, sizeof(*out_mapping));
    out_mapping->entries = (pfs_unicv_file_mapping_entry*)sys_realloc(NULL, sizeof(pfs_unicv_file_mapping_entry) * (size_t)tables->nonempty_count);

    for (i = 0; i < tables->count; i++)
    {
        const pfs_unicv_table_info* table = &tables->tables[i];
        pfs_unicv_file_mapping_entry* map;
        uint8_t secret[20];
        uint8_t sector_zero[4];
        uint8_t signature_key[20];
        uint32_t j;
        int found = 0;
        int exact_candidate_seen = 0;

        if (table->n_sectors == 0)
        {
            continue;
        }

        processed_tables++;
        if ((processed_tables == 1u) || ((processed_tables % 64u) == 0u) || (processed_tables == tables->nonempty_count))
        {
            sys_output("\rverified unicv mapping: %u/%u", processed_tables, tables->nonempty_count);
        }

        map = &out_mapping->entries[out_mapping->count++];
        memset(map, 0, sizeof(*map));
        map->table_page = table->table_page;
        map->version = table->version;
        map->n_sectors = table->n_sectors;
        map->file_sector_size = table->file_sector_size;
        map->has_dbseed = table->has_dbseed;
        memcpy(map->dbseed, table->dbseed, sizeof(map->dbseed));

        if (!table->has_first_signature)
        {
            free_probe_candidates(files, file_count);
            pfs_free_unicv_file_mapping(out_mapping);
            set_error(error_message, error_message_size, "unicv table is missing first signature");
            return NPDRM_ERR_INVALID_DATA;
        }

        st = generate_table_secret(header, klicensee, klicensee_size, content_key, content_key_size, table->table_page, secret);
        if (st != NPDRM_OK)
        {
            free_probe_candidates(files, file_count);
            pfs_free_unicv_file_mapping(out_mapping);
            set_error(error_message, error_message_size, "missing key material for verified unicv mapping");
            return st;
        }

        set32le(sector_zero, 0u);
        hmac_sha1_digest(secret, sizeof(secret), sector_zero, sizeof(sector_zero), signature_key);

        for (j = 0; j < file_count; j++)
        {
            const pfs_filesdb_inventory_entry* entry = files[j].entry;
            uint8_t real_signature[20];
            uint32_t expected;
            uint32_t probe_size;

            if (files[j].matched || entry == NULL || files[j].first_size == 0)
            {
                continue;
            }

            expected = expected_sectors_for_size(entry->size, table->file_sector_size);
            if (expected != table->n_sectors)
            {
                continue;
            }
            exact_candidate_seen = 1;

            probe_size = files[j].first_size;
            if (table->file_sector_size < probe_size)
            {
                probe_size = table->file_sector_size;
            }
            if (probe_size == 0)
            {
                continue;
            }

            hmac_sha1_digest(signature_key, sizeof(signature_key), files[j].first_bytes, probe_size, real_signature);
            if (memcmp(real_signature, table->first_signature, sizeof(real_signature)) == 0)
            {
                files[j].matched = 1;
                map->expected_sectors_from_size = expected;
                map->sector_match = (uint8_t)(expected == table->n_sectors);
                map->verified_match = 1;
                snprintf(map->path, sizeof(map->path), "%s", entry->path);
                if (map->sector_match)
                {
                    out_mapping->size_match_count++;
                }
                else
                {
                    out_mapping->size_mismatch_count++;
                }
                out_mapping->verified_match_count++;
                found = 1;
                break;
            }
        }

        if (!found && !exact_candidate_seen)
        {
            for (j = 0; j < file_count; j++)
            {
                const pfs_filesdb_inventory_entry* entry = files[j].entry;
                uint8_t real_signature[20];
                uint32_t expected;
                uint32_t probe_size;

                if (files[j].matched || entry == NULL || files[j].first_size == 0)
                {
                    continue;
                }

                expected = expected_sectors_for_size(entry->size, table->file_sector_size);
                probe_size = files[j].first_size;
                if (table->file_sector_size < probe_size)
                {
                    probe_size = table->file_sector_size;
                }
                if (probe_size == 0)
                {
                    continue;
                }

                hmac_sha1_digest(signature_key, sizeof(signature_key), files[j].first_bytes, probe_size, real_signature);
                if (memcmp(real_signature, table->first_signature, sizeof(real_signature)) == 0)
                {
                    files[j].matched = 1;
                    map->expected_sectors_from_size = expected;
                    map->sector_match = (uint8_t)(expected == table->n_sectors);
                    map->verified_match = 1;
                    snprintf(map->path, sizeof(map->path), "%s", entry->path);
                    if (map->sector_match)
                    {
                        out_mapping->size_match_count++;
                    }
                    else
                    {
                        out_mapping->size_mismatch_count++;
                    }
                    out_mapping->verified_match_count++;
                    found = 1;
                    break;
                }
            }
        }

        if (!found)
        {
            out_mapping->unmatched_count++;
        }
    }

    if (processed_tables != 0u)
    {
        sys_output("\n");
    }

    free_probe_candidates(files, file_count);
    if (error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }
    return NPDRM_OK;
}

void pfs_free_unicv_file_mapping(pfs_unicv_file_mapping* mapping)
{
    if (mapping == NULL)
    {
        return;
    }
    if (mapping->entries != NULL)
    {
        sys_realloc(mapping->entries, 0);
        mapping->entries = NULL;
    }
    mapping->count = 0;
    mapping->size_match_count = 0;
    mapping->size_mismatch_count = 0;
    mapping->verified_match_count = 0;
    mapping->unmatched_count = 0;
}

npdrm_status pfs_probe_title_layout(const char* title_src_dir, pfs_probe_result* out_probe, char* error_message, uint32_t error_message_size)
{
    char sce_pfs_path[PFS_MAX_PATH];
    char files_db_path[PFS_MAX_PATH];
    char unicv_path[PFS_MAX_PATH];
    char icv_dir_path[PFS_MAX_PATH];
    pfs_filesdb_header header;

    if (title_src_dir == NULL || out_probe == NULL)
    {
        set_error(error_message, error_message_size, "invalid pfs probe request");
        return NPDRM_ERR_INVALID_ARG;
    }

    memset(out_probe, 0, sizeof(*out_probe));

    if (!path_exists_dir(title_src_dir))
    {
        set_error(error_message, error_message_size, "title source directory does not exist");
        return NPDRM_ERR_INVALID_DATA;
    }

    join_path2(sce_pfs_path, sizeof(sce_pfs_path), title_src_dir, "sce_pfs");
    if (sce_pfs_path[0] == 0 || !path_exists_dir(sce_pfs_path))
    {
        set_error(error_message, error_message_size, "sce_pfs directory not found");
        return NPDRM_ERR_INVALID_DATA;
    }

    join_path3(files_db_path, sizeof(files_db_path), title_src_dir, "sce_pfs", "files.db");
    if (files_db_path[0] == 0 || !path_exists_file(files_db_path))
    {
        set_error(error_message, error_message_size, "files.db not found in sce_pfs");
        return NPDRM_ERR_INVALID_DATA;
    }

    join_path3(unicv_path, sizeof(unicv_path), title_src_dir, "sce_pfs", "unicv.db");
    join_path3(icv_dir_path, sizeof(icv_dir_path), title_src_dir, "sce_pfs", "icv.db");

    out_probe->has_unicv = path_exists_file(unicv_path) ? 1 : 0;
    out_probe->has_icv_dir = path_exists_dir(icv_dir_path) ? 1 : 0;

    if (!out_probe->has_unicv && !out_probe->has_icv_dir)
    {
        set_error(error_message, error_message_size, "neither unicv.db nor icv.db directory found");
        return NPDRM_ERR_INVALID_DATA;
    }

    if (pfs_read_filesdb_header(files_db_path, &header, error_message, error_message_size) != NPDRM_OK)
    {
        return NPDRM_ERR_INVALID_DATA;
    }

    out_probe->files_db_size = file_size_bytes(files_db_path);
    snprintf(out_probe->files_db_path, sizeof(out_probe->files_db_path), "%s", files_db_path);

    if (error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }

    return NPDRM_OK;
}

npdrm_status pfs_extract_decrypted_title(const pfs_request* request, char* error_message, uint32_t error_message_size)
{
    pfs_probe_result probe;
    pfs_filesdb_header header;
    pfs_filesdb_inventory inventory;
    pfs_unicv_table_list tables;
    pfs_unicv_file_mapping mapping;
    npdrm_status st;
    uint32_t i;

    if (request == NULL || request->title_src_dir == NULL || request->title_dst_dir == NULL)
    {
        return NPDRM_ERR_INVALID_ARG;
    }

    if (request->content_key == NULL || request->content_key_size < 16u)
    {
        set_error(error_message, error_message_size, "content key is required for PFS decryption");
        return NPDRM_ERR_INVALID_ARG;
    }

    memset(&inventory, 0, sizeof(inventory));
    memset(&tables, 0, sizeof(tables));
    memset(&mapping, 0, sizeof(mapping));

    st = pfs_probe_title_layout(request->title_src_dir, &probe, error_message, error_message_size);
    if (st != NPDRM_OK)
    {
        return st;
    }

    if (!probe.has_unicv)
    {
        set_error(error_message, error_message_size, "only unicv PFS titles are implemented right now");
        return NPDRM_ERR_NOT_IMPLEMENTED;
    }

    st = pfs_read_filesdb_header(probe.files_db_path, &header, error_message, error_message_size);
    if (st != NPDRM_OK)
    {
        return st;
    }

    st = pfs_collect_filesdb_inventory(probe.files_db_path, &header, &inventory, error_message, error_message_size);
    if (st != NPDRM_OK)
    {
        return st;
    }

    {
        char unicv_path[PFS_MAX_PATH];
        snprintf(unicv_path, sizeof(unicv_path), "%s/sce_pfs/unicv.db", request->title_src_dir);
        st = pfs_collect_unicv_tables(unicv_path, &tables, error_message, error_message_size);
        if (st != NPDRM_OK)
        {
            pfs_free_filesdb_inventory(&inventory);
            return st;
        }
    }

    st = pfs_map_unicv_tables_verified(
        request->title_src_dir,
        &header,
        &inventory,
        &tables,
        request->klicensee,
        request->klicensee != NULL ? 16u : 0u,
        request->content_key,
        request->content_key_size,
        &mapping,
        error_message,
        error_message_size);
    if (st != NPDRM_OK)
    {
        pfs_free_unicv_table_list(&tables);
        pfs_free_filesdb_inventory(&inventory);
        return st;
    }

    if (mapping.verified_match_count != mapping.count)
    {
        pfs_free_unicv_file_mapping(&mapping);
        pfs_free_unicv_table_list(&tables);
        pfs_free_filesdb_inventory(&inventory);
        set_error(error_message, error_message_size, "verified unicv mapping is incomplete");
        return NPDRM_ERR_INVALID_DATA;
    }

    {
        char dst_root[PFS_MAX_PATH];
        snprintf(dst_root, sizeof(dst_root), "%s", request->title_dst_dir);
        sys_mkdir(dst_root);
    }

    for (i = 0; i < inventory.count; i++)
    {
        const pfs_filesdb_inventory_entry* entry = &inventory.entries[i];
        char src_path[PFS_MAX_PATH];
        char dst_path[PFS_MAX_PATH];

        if (entry->path[0] == 0)
        {
            continue;
        }

        join_path2(dst_path, sizeof(dst_path), request->title_dst_dir, entry->path);

        if (entry->is_directory)
        {
            sys_mkdir(dst_path);
            continue;
        }

        if (!entry->is_processable)
        {
            continue;
        }

        join_path2(src_path, sizeof(src_path), request->title_src_dir, entry->path);
        if (!path_exists_file(src_path))
        {
            st = NPDRM_ERR_INVALID_DATA;
            set_error(error_message, error_message_size, "expected encrypted title file is missing");
            break;
        }

        if (entry->size == 0u)
        {
            st = create_empty_file_on_disk(dst_path);
            if (st != NPDRM_OK)
            {
                set_error(error_message, error_message_size, "failed to create empty decrypted file");
                break;
            }
            continue;
        }

        if ((entry->effective_type & FILES_DB_ATTR_NENC) != 0u)
        {
            st = copy_file_raw(src_path, dst_path);
            if (st != NPDRM_OK)
            {
                set_error(error_message, error_message_size, "failed to copy unencrypted title file");
                break;
            }
            continue;
        }

        {
            const pfs_unicv_file_mapping_entry* map = find_mapping_by_path(&mapping, entry->path);
            if (map == NULL)
            {
                st = NPDRM_ERR_INVALID_DATA;
                set_error(error_message, error_message_size, "missing verified unicv mapping for encrypted file");
                break;
            }

            st = decrypt_unicv_file_to_path(
                src_path,
                dst_path,
                header.files_salt,
                map->table_page,
                map->file_sector_size,
                request->content_key,
                map->has_dbseed ? map->dbseed : NULL,
                map->has_dbseed ? (uint32_t)sizeof(map->dbseed) : 0u);
            if (st != NPDRM_OK)
            {
                set_error(error_message, error_message_size, "failed to decrypt unicv title file");
                break;
            }
        }
    }

    pfs_free_unicv_file_mapping(&mapping);
    pfs_free_unicv_table_list(&tables);
    pfs_free_filesdb_inventory(&inventory);

    if (st == NPDRM_OK && error_message != NULL && error_message_size > 0)
    {
        error_message[0] = 0;
    }
    return st;
}
