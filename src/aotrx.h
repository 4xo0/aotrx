#ifndef AOTRX_H
#define AOTRX_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct mem mem_t;
typedef struct pe pe_t;
typedef struct sec sec_t;
typedef struct pat pat_t;
typedef struct sym sym_t;
typedef struct sym_db sym_db_t;
typedef struct cfg cfg_t;
typedef struct fn fn_t;
typedef struct fn_db fn_db_t;
typedef struct str str_t;
typedef struct str_db str_db_t;
typedef struct xref xref_t;
typedef struct xref_db xref_db_t;
typedef struct label label_t;
typedef struct label_db label_db_t;
typedef struct import import_t;
typedef struct import_db import_db_t;
typedef struct export export_t;
typedef struct export_db export_db_t;
typedef struct aot_section aot_section_t;
typedef struct aot_section_db aot_section_db_t;
typedef struct accessor accessor_t;
typedef struct accessor_db accessor_db_t;
typedef struct dump dump_t;

struct mem
{
    uint8_t* data;
    size_t size;
};

struct sec
{
    char name[9];
    uint32_t rva;
    uint32_t vsize;
    uint32_t raw;
    uint32_t raw_size;
    uint32_t flags;
};

struct pe
{
    mem_t mem;
    uint64_t image_base;
    uint32_t entry_rva;
    uint16_t machine;
    uint16_t sec_count;
    sec_t* secs;
    uint32_t dir_rva[16];
    uint32_t dir_size[16];
};

struct pat
{
    const char* id;
    const char* name;
    const uint8_t* bytes;
    const char* mask;
    size_t len;
};

struct sym
{
    const char* id;
    const char* name;
    uint64_t va;
    uint32_t rva;
    uint32_t file_off;
    int found;
    const char* why;
};

struct sym_db
{
    sym_t* items;
    size_t len;
    size_t cap;
};

struct fn
{
    uint64_t va;
    uint32_t rva;
    uint32_t end_rva;
    uint32_t file_off;
    uint32_t size;
    uint32_t refs_in;
    uint32_t refs_out;
    const char* name;
    const char* kind;
};

struct fn_db
{
    fn_t* items;
    size_t len;
    size_t cap;
};

struct str
{
    char* text;
    uint64_t va;
    uint32_t rva;
    uint64_t object_va;
    uint32_t object_rva;
    uint32_t file_off;
    uint32_t len;
    uint32_t refs;
    int wide;
    int managed;
};

struct str_db
{
    str_t* items;
    size_t len;
    size_t cap;
};

struct xref
{
    uint64_t from_va;
    uint64_t to_va;
    uint32_t from_rva;
    uint32_t to_rva;
    uint32_t from_func_rva;
    uint32_t to_func_rva;
    const char* kind;
};

struct xref_db
{
    xref_t* items;
    size_t len;
    size_t cap;
};

struct label
{
    char* name;
    const char* kind;
    uint64_t va;
    uint32_t rva;
    uint32_t file_off;
};

struct label_db
{
    label_t* items;
    size_t len;
    size_t cap;
};

struct import
{
    char* dll;
    char* name;
    uint64_t iat_va;
    uint32_t iat_rva;
    uint16_t ordinal;
    int by_ordinal;
};

struct import_db
{
    import_t* items;
    size_t len;
    size_t cap;
};

struct export
{
    char* name;
    char* forwarder;
    uint64_t va;
    uint32_t rva;
    uint32_t file_off;
    uint16_t ordinal;
    int is_forwarder;
};

struct export_db
{
    export_t* items;
    size_t len;
    size_t cap;
};

struct aot_section
{
    const char* name;
    uint32_t type;
    uint32_t rva;
    uint32_t file_off;
    uint32_t size;
    uint64_t va;
};

struct aot_section_db
{
    aot_section_t* items;
    size_t len;
    size_t cap;
};

struct accessor
{
    uint64_t va;
    uint32_t rva;
    uint32_t file_off;
    uint32_t field_offset;
    uint32_t width;
    uint32_t function_size;
    uint32_t refs_in;
    uint32_t refs_out;
    const char* kind;
    const char* value_type;
};

struct accessor_db
{
    accessor_t* items;
    size_t len;
    size_t cap;
};

struct dump
{
    fn_db_t fns;
    str_db_t strs;
    xref_db_t xrefs;
    label_db_t labels;
    import_db_t imports;
    export_db_t exports;
    aot_section_db_t aot_sections;
    accessor_db_t accessors;
};

struct cfg
{
    const char* exe;
    const char* out_dir;
    const char* funcs;
    const char* strings;
    const char* xrefs;
    const char* labels;
    const char* imports;
    const char* exports;
    const char* aot_sections;
    const char* accessors;
    const char* summary;
    const char* ida;
    int check;
};

int mem_load(const char* path, mem_t* mem);
void mem_free(mem_t* mem);
int pe_load(const char* path, pe_t* pe);
void pe_free(pe_t* pe);
const sec_t* pe_sec(const pe_t* pe, const char* name);
int pe_rva_to_off(const pe_t* pe, uint32_t rva, uint32_t* off);
int pe_off_to_rva(const pe_t* pe, uint32_t off, uint32_t* rva);
int pe_is_text(const pe_t* pe, uint32_t off);

void sym_db_init(sym_db_t* db);
void sym_db_free(sym_db_t* db);
int sym_db_add(sym_db_t* db, const sym_t* sym);
const sym_t* sym_db_get(const sym_db_t* db, const char* id);

int sig_find(const pe_t* pe, const pat_t* pat, uint32_t* off, int* count);

void dump_init(dump_t* dump);
void dump_free(dump_t* dump);
int dump_run(const pe_t* pe, dump_t* dump);
int fn_add(fn_db_t* db, const fn_t* fn);
int str_add(str_db_t* db, const str_t* str);
int xref_add(xref_db_t* db, const xref_t* xref);
int label_add(label_db_t* db, const label_t* label);
int import_add(import_db_t* db, const import_t* imp);
int export_add(export_db_t* db, const export_t* exp);
int aot_section_add(aot_section_db_t* db, const aot_section_t* sec);
int accessor_add(accessor_db_t* db, const accessor_t* accessor);
fn_t* fn_by_rva(fn_db_t* db, uint32_t rva);
str_t* str_by_rva(str_db_t* db, uint32_t rva);

int out_summary(const char* path, const pe_t* pe, const dump_t* dump);
int out_funcs(const char* path, const pe_t* pe, const dump_t* dump);
int out_strings(const char* path, const pe_t* pe, const dump_t* dump);
int out_xrefs(const char* path, const pe_t* pe, const dump_t* dump);
int out_labels(const char* path, const pe_t* pe, const dump_t* dump);
int out_imports(const char* path, const pe_t* pe, const dump_t* dump);
int out_exports(const char* path, const pe_t* pe, const dump_t* dump);
int out_aot_sections(const char* path, const pe_t* pe, const dump_t* dump);
int out_accessors(const char* path, const pe_t* pe, const dump_t* dump);
int out_ida(const char* path, const dump_t* dump);
int mk_dir(const char* path);
int path_join(char* dst, size_t cap, const char* dir, const char* file);

#endif
