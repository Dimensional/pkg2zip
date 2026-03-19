#pragma once

#include <stdint.h>

#define PFS_MAX_PATH 1024

#include "pkg2zip_npdrm.h"

typedef struct {
    const char* title_src_dir;
    const char* title_dst_dir;
    const uint8_t* klicensee;
    const uint8_t* content_key;
    uint32_t content_key_size;
} pfs_request;

typedef struct {
    int has_unicv;
    int has_icv_dir;
    uint64_t files_db_size;
    char files_db_path[PFS_MAX_PATH];
} pfs_probe_result;

typedef struct {
    char magic[9];
    uint32_t version;
    uint16_t image_spec;
    uint16_t key_id;
    uint32_t page_size;
    uint32_t bt_order;
    uint32_t root_icv_page_number;
    uint32_t files_salt;
    uint64_t unk6;
    uint64_t tail_size;
    uint64_t total_size;
} pfs_filesdb_header;

typedef struct {
    uint32_t idx;
    uint32_t parent_idx;
    uint16_t type;
    uint16_t effective_type;
    uint32_t size;
    uint32_t block_page;
    uint8_t is_directory;
    uint8_t is_processable;
    uint8_t type_was_fixed;
    char name[69];
    char path[PFS_MAX_PATH];
} pfs_filesdb_inventory_entry;

typedef struct {
    pfs_filesdb_inventory_entry* entries;
    uint32_t count;
    uint32_t directory_count;
    uint32_t processable_file_count;
    uint32_t skipped_unexisting_empty_count;
    uint32_t fixed_unexisting_nonempty_count;
} pfs_filesdb_inventory;

typedef struct {
    uint32_t table_page;
    uint32_t version;
    uint32_t n_sectors;
    uint32_t file_sector_size;
    uint32_t bin_tree_num_max_avail;
    uint32_t signature_block_count;
    uint8_t has_dbseed;
    uint8_t dbseed[20];
    uint8_t has_first_signature;
    uint8_t first_signature[20];
} pfs_unicv_table_info;

typedef struct {
    pfs_unicv_table_info* tables;
    uint32_t count;
    uint32_t nonempty_count;
} pfs_unicv_table_list;

typedef struct {
    uint32_t table_page;
    uint32_t version;
    uint32_t n_sectors;
    uint32_t file_sector_size;
    uint32_t expected_sectors_from_size;
    uint8_t has_dbseed;
    uint8_t dbseed[20];
    uint8_t sector_match;
    uint8_t verified_match;
    char path[PFS_MAX_PATH];
} pfs_unicv_file_mapping_entry;

typedef struct {
    pfs_unicv_file_mapping_entry* entries;
    uint32_t count;
    uint32_t size_match_count;
    uint32_t size_mismatch_count;
    uint32_t verified_match_count;
    uint32_t unmatched_count;
} pfs_unicv_file_mapping;

// Probes title metadata layout needed for stage-2 decryption.
npdrm_status pfs_probe_title_layout(const char* title_src_dir, pfs_probe_result* out_probe, char* error_message, uint32_t error_message_size);

// Reads and parses the files.db header fields used by the extraction pipeline.
npdrm_status pfs_read_filesdb_header(const char* files_db_path, pfs_filesdb_header* out_header, char* error_message, uint32_t error_message_size);

// Builds canonical files.db inventory using nFiles-mapped records like psvpfsparser.
npdrm_status pfs_collect_filesdb_inventory(const char* files_db_path, const pfs_filesdb_header* header, pfs_filesdb_inventory* out_inventory, char* error_message, uint32_t error_message_size);

// Releases memory allocated by pfs_collect_filesdb_inventory.
void pfs_free_filesdb_inventory(pfs_filesdb_inventory* inventory);

// Parses unicv.db table metadata and exposes table pages (salts) and sector metadata.
npdrm_status pfs_collect_unicv_tables(const char* unicv_db_path, pfs_unicv_table_list* out_tables, char* error_message, uint32_t error_message_size);

// Releases memory allocated by pfs_collect_unicv_tables.
void pfs_free_unicv_table_list(pfs_unicv_table_list* tables);

// Maps non-empty unicv tables to processable files by validating zero-sector HMACs.
npdrm_status pfs_map_unicv_tables_verified(const char* title_src_dir, const pfs_filesdb_header* header, const pfs_filesdb_inventory* inventory, const pfs_unicv_table_list* tables, const uint8_t* klicensee, uint32_t klicensee_size, const uint8_t* content_key, uint32_t content_key_size, pfs_unicv_file_mapping* out_mapping, char* error_message, uint32_t error_message_size);

// Releases memory allocated by pfs_map_unicv_tables_verified.
void pfs_free_unicv_file_mapping(pfs_unicv_file_mapping* mapping);

// Placeholder clean-room interface for PFS metadata parsing + file decryption.
npdrm_status pfs_extract_decrypted_title(const pfs_request* request, char* error_message, uint32_t error_message_size);
