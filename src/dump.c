#include "aotrx.h"

#include <stdlib.h>
#include <string.h>
#ifdef AOTRX_USE_HDE
#include "hde64.h"
#endif

static uint32_t rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const uint8_t* p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint64_t rd64(const uint8_t* p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static char* dup_cstr(const char* s)
{
    size_t n = strlen(s);
    char* out = (char*)malloc(n + 1);
    if(!out)
    {
        return NULL;
    }
    memcpy(out, s, n + 1);
    return out;
}

static int va_to_rva(const pe_t* pe, uint64_t va, uint32_t* rva)
{
    uint64_t rel;

    if(va < pe->image_base)
    {
        return 0;
    }
    rel = va - pe->image_base;
    if(rel > 0xffffffffu)
    {
        return 0;
    }
    *rva = (uint32_t)rel;
    return 1;
}

static int data_rva_span(const pe_t* pe, uint32_t dir, uint32_t* rva, uint32_t* size)
{
    if(dir >= 16 || pe->dir_rva[dir] == 0 || pe->dir_size[dir] == 0)
    {
        return 0;
    }
    *rva = pe->dir_rva[dir];
    *size = pe->dir_size[dir];
    return 1;
}

static int add_mem(void** ptr, size_t* cap, size_t len, size_t size)
{
    void* next;
    size_t ncap;

    if(len < *cap)
    {
        return 1;
    }
    ncap = *cap ? *cap * 2 : 256;
    next = realloc(*ptr, ncap * size);
    if(!next)
    {
        return 0;
    }
    *ptr = next;
    *cap = ncap;
    return 1;
}

void dump_init(dump_t* dump)
{
    memset(dump, 0, sizeof(*dump));
}

void dump_free(dump_t* dump)
{
    size_t i;

    for(i = 0; i < dump->strs.len; i++)
    {
        free(dump->strs.items[i].text);
    }
    for(i = 0; i < dump->labels.len; i++)
    {
        free(dump->labels.items[i].name);
    }
    for(i = 0; i < dump->imports.len; i++)
    {
        free(dump->imports.items[i].dll);
        free(dump->imports.items[i].name);
    }
    for(i = 0; i < dump->exports.len; i++)
    {
        free(dump->exports.items[i].name);
        free(dump->exports.items[i].forwarder);
    }
    free(dump->fns.items);
    free(dump->strs.items);
    free(dump->xrefs.items);
    free(dump->labels.items);
    free(dump->imports.items);
    free(dump->exports.items);
    free(dump->aot_sections.items);
    free(dump->accessors.items);
    memset(dump, 0, sizeof(*dump));
}

int fn_add(fn_db_t* db, const fn_t* fn)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(fn_t)))
    {
        return 0;
    }
    db->items[db->len++] = *fn;
    return 1;
}

int str_add(str_db_t* db, const str_t* str)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(str_t)))
    {
        return 0;
    }
    db->items[db->len++] = *str;
    return 1;
}

int xref_add(xref_db_t* db, const xref_t* xref)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(xref_t)))
    {
        return 0;
    }
    db->items[db->len++] = *xref;
    return 1;
}

int label_add(label_db_t* db, const label_t* label)
{
    size_t i;

    for(i = 0; i < db->len; i++)
    {
        if(db->items[i].rva == label->rva && strcmp(db->items[i].name, label->name) == 0)
        {
            return 1;
        }
    }
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(label_t)))
    {
        return 0;
    }
    db->items[db->len++] = *label;
    return 1;
}

int import_add(import_db_t* db, const import_t* imp)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(import_t)))
    {
        return 0;
    }
    db->items[db->len++] = *imp;
    return 1;
}

int export_add(export_db_t* db, const export_t* exp)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(export_t)))
    {
        return 0;
    }
    db->items[db->len++] = *exp;
    return 1;
}

int aot_section_add(aot_section_db_t* db, const aot_section_t* sec)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(aot_section_t)))
    {
        return 0;
    }
    db->items[db->len++] = *sec;
    return 1;
}

int accessor_add(accessor_db_t* db, const accessor_t* accessor)
{
    if(!add_mem((void**)&db->items, &db->cap, db->len, sizeof(accessor_t)))
    {
        return 0;
    }
    db->items[db->len++] = *accessor;
    return 1;
}

fn_t* fn_by_rva(fn_db_t* db, uint32_t rva)
{
    size_t lo = 0;
    size_t hi = db->len;

    while(lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        fn_t* fn = &db->items[mid];
        if(rva < fn->rva)
        {
            hi = mid;
        }
        else if(rva >= fn->end_rva)
        {
            lo = mid + 1;
        }
        else
        {
            return fn;
        }
    }
    return NULL;
}

str_t* str_by_rva(str_db_t* db, uint32_t rva)
{
    size_t lo = 0;
    size_t hi = db->len;

    while(lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        str_t* str = &db->items[mid];
        if(rva < str->rva)
        {
            hi = mid;
        }
        else if(rva >= str->rva + str->len)
        {
            lo = mid + 1;
        }
        else
        {
            return str;
        }
    }
    if(lo < db->len && db->items[lo].managed && db->items[lo].object_rva == rva)
    {
        return &db->items[lo];
    }
    return NULL;
}

static int cmp_fn(const void* a, const void* b)
{
    const fn_t* x = (const fn_t*)a;
    const fn_t* y = (const fn_t*)b;
    if(x->rva < y->rva)
    {
        return -1;
    }
    if(x->rva > y->rva)
    {
        return 1;
    }
    return 0;
}

static int cmp_str(const void* a, const void* b)
{
    const str_t* x = (const str_t*)a;
    const str_t* y = (const str_t*)b;
    if(x->rva < y->rva)
    {
        return -1;
    }
    if(x->rva > y->rva)
    {
        return 1;
    }
    return 0;
}

static int cmp_label(const void* a, const void* b)
{
    const label_t* x = (const label_t*)a;
    const label_t* y = (const label_t*)b;
    if(x->rva < y->rva)
    {
        return -1;
    }
    if(x->rva > y->rva)
    {
        return 1;
    }
    return strcmp(x->name, y->name);
}

static int cmp_aot_section(const void* a, const void* b)
{
    const aot_section_t* x = (const aot_section_t*)a;
    const aot_section_t* y = (const aot_section_t*)b;
    if(x->rva < y->rva)
    {
        return -1;
    }
    if(x->rva > y->rva)
    {
        return 1;
    }
    return 0;
}

static int cmp_accessor(const void* a, const void* b)
{
    const accessor_t* x = (const accessor_t*)a;
    const accessor_t* y = (const accessor_t*)b;
    if(x->rva < y->rva)
    {
        return -1;
    }
    if(x->rva > y->rva)
    {
        return 1;
    }
    return 0;
}

static int cmp_xref(const void* a, const void* b)
{
    const xref_t* x = (const xref_t*)a;
    const xref_t* y = (const xref_t*)b;
    if(x->from_rva != y->from_rva) return x->from_rva < y->from_rva ? -1 : 1;
    if(x->to_rva != y->to_rva) return x->to_rva < y->to_rva ? -1 : 1;
    return strcmp(x->kind, y->kind);
}

static int match_ret(const uint8_t* p, uint32_t size, uint32_t used)
{
    return size == used + 1 && p[used] == 0xc3;
}

static int add_accessor(const pe_t* pe, dump_t* dump, const fn_t* fn, uint32_t field_offset,
    uint32_t width, const char* kind, const char* value_type)
{
    accessor_t accessor;

    memset(&accessor, 0, sizeof(accessor));
    accessor.va = fn->va;
    accessor.rva = fn->rva;
    accessor.file_off = fn->file_off;
    accessor.field_offset = field_offset;
    accessor.width = width;
    accessor.function_size = fn->size;
    accessor.refs_in = fn->refs_in;
    accessor.refs_out = fn->refs_out;
    accessor.kind = kind;
    accessor.value_type = value_type;
    (void)pe;
    return accessor_add(&dump->accessors, &accessor);
}

static int scan_accessors(const pe_t* pe, dump_t* dump)
{
    size_t i;

    for(i = 0; i < dump->fns.len; i++)
    {
        const fn_t* fn = &dump->fns.items[i];
        const uint8_t* p;
        uint32_t off;

        if(fn->size < 4 || fn->size > 16 || !pe_rva_to_off(pe, fn->rva, &off) || off + fn->size > pe->mem.size)
        {
            continue;
        }
        p = pe->mem.data + off;

        if(fn->size >= 6 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x41 && match_ret(p, fn->size, 5))
        {
            if(!add_accessor(pe, dump, fn, p[4], 4, "getter", "float")) return 0;
        }
        else if(fn->size >= 9 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x81 && match_ret(p, fn->size, 8))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 4), 4, "getter", "float")) return 0;
        }
        else if(fn->size >= 6 && p[0] == 0xf2 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x41 && match_ret(p, fn->size, 5))
        {
            if(!add_accessor(pe, dump, fn, p[4], 8, "getter", "double")) return 0;
        }
        else if(fn->size >= 9 && p[0] == 0xf2 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x81 && match_ret(p, fn->size, 8))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 4), 8, "getter", "double")) return 0;
        }
        else if(p[0] == 0x8b && p[1] == 0x41 && match_ret(p, fn->size, 3))
        {
            if(!add_accessor(pe, dump, fn, p[2], 4, "getter", "dword")) return 0;
        }
        else if(p[0] == 0x8b && p[1] == 0x81 && match_ret(p, fn->size, 6))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 2), 4, "getter", "dword")) return 0;
        }
        else if(fn->size >= 5 && p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x41 && match_ret(p, fn->size, 4))
        {
            if(!add_accessor(pe, dump, fn, p[3], 8, "getter", "qword")) return 0;
        }
        else if(fn->size >= 8 && p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x81 && match_ret(p, fn->size, 7))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 3), 8, "getter", "qword")) return 0;
        }
        else if(fn->size >= 5 && p[0] == 0x0f && p[1] == 0xb6 && p[2] == 0x41 && match_ret(p, fn->size, 4))
        {
            if(!add_accessor(pe, dump, fn, p[3], 1, "getter", "byte")) return 0;
        }
        else if(fn->size >= 8 && p[0] == 0x0f && p[1] == 0xb6 && p[2] == 0x81 && match_ret(p, fn->size, 7))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 3), 1, "getter", "byte")) return 0;
        }
        else if(fn->size >= 6 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x11 && p[3] == 0x49 && match_ret(p, fn->size, 5))
        {
            if(!add_accessor(pe, dump, fn, p[4], 4, "setter", "float")) return 0;
        }
        else if(fn->size >= 9 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x11 && p[3] == 0x89 && match_ret(p, fn->size, 8))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 4), 4, "setter", "float")) return 0;
        }
        else if(fn->size >= 6 && p[0] == 0xf2 && p[1] == 0x0f && p[2] == 0x11 && p[3] == 0x49 && match_ret(p, fn->size, 5))
        {
            if(!add_accessor(pe, dump, fn, p[4], 8, "setter", "double")) return 0;
        }
        else if(fn->size >= 9 && p[0] == 0xf2 && p[1] == 0x0f && p[2] == 0x11 && p[3] == 0x89 && match_ret(p, fn->size, 8))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 4), 8, "setter", "double")) return 0;
        }
        else if(p[0] == 0x89 && p[1] == 0x51 && match_ret(p, fn->size, 3))
        {
            if(!add_accessor(pe, dump, fn, p[2], 4, "setter", "dword")) return 0;
        }
        else if(p[0] == 0x89 && p[1] == 0x91 && match_ret(p, fn->size, 6))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 2), 4, "setter", "dword")) return 0;
        }
        else if(fn->size >= 5 && p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x51 && match_ret(p, fn->size, 4))
        {
            if(!add_accessor(pe, dump, fn, p[3], 8, "setter", "qword")) return 0;
        }
        else if(fn->size >= 8 && p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x91 && match_ret(p, fn->size, 7))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 3), 8, "setter", "qword")) return 0;
        }
        else if(p[0] == 0x88 && p[1] == 0x51 && match_ret(p, fn->size, 3))
        {
            if(!add_accessor(pe, dump, fn, p[2], 1, "setter", "byte")) return 0;
        }
        else if(p[0] == 0x88 && p[1] == 0x91 && match_ret(p, fn->size, 6))
        {
            if(!add_accessor(pe, dump, fn, rd32(p + 2), 1, "setter", "byte")) return 0;
        }
    }
    qsort(dump->accessors.items, dump->accessors.len, sizeof(accessor_t), cmp_accessor);
    return 1;
}

static const label_t* label_by_rva(const label_db_t* db, uint32_t rva)
{
    size_t lo = 0;
    size_t hi = db->len;

    while(lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        const label_t* label = &db->items[mid];
        if(rva < label->rva)
        {
            hi = mid;
        }
        else if(rva > label->rva)
        {
            lo = mid + 1;
        }
        else
        {
            return label;
        }
    }
    return NULL;
}

static const aot_section_t* aot_section_by_rva(const aot_section_db_t* db, uint32_t rva)
{
    size_t i;

    for(i = 0; i < db->len; i++)
    {
        const aot_section_t* sec = &db->items[i];
        if(rva >= sec->rva && rva < sec->rva + sec->size)
        {
            return sec;
        }
    }
    return NULL;
}

static void clean_name(char* s)
{
    while(*s)
    {
        char c = *s;
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
        {
            *s = '_';
        }
        s++;
    }
}

static int add_label(dump_t* dump, const pe_t* pe, uint32_t rva, const char* kind, const char* name)
{
    uint32_t off;
    label_t label;

    if(!pe_rva_to_off(pe, rva, &off))
    {
        return 1;
    }
    memset(&label, 0, sizeof(label));
    label.name = dup_cstr(name);
    if(!label.name)
    {
        return 0;
    }
    clean_name(label.name);
    label.kind = kind;
    label.rva = rva;
    label.file_off = off;
    label.va = pe->image_base + rva;
    if(!label_add(&dump->labels, &label))
    {
        free(label.name);
        return 0;
    }
    return 1;
}

static void attach_labels(dump_t* dump)
{
    size_t i;

    for(i = 0; i < dump->fns.len; i++)
    {
        fn_t* fn = &dump->fns.items[i];
        const label_t* label = label_by_rva(&dump->labels, fn->rva);
        if(label)
        {
            fn->name = label->name;
            fn->kind = label->kind;
        }
        else
        {
            fn->kind = "pdata";
        }
    }
}

static int is_print(uint8_t c)
{
    return c >= 0x20 && c <= 0x7e;
}

static char* dup_ascii(const uint8_t* p, uint32_t len)
{
    char* s = (char*)malloc((size_t)len + 1);
    if(!s)
    {
        return NULL;
    }
    memcpy(s, p, len);
    s[len] = 0;
    return s;
}

static char* dup_wide(const uint8_t* p, uint32_t len)
{
    uint32_t i;
    char* s = (char*)malloc((size_t)len + 1);
    if(!s)
    {
        return NULL;
    }
    for(i = 0; i < len; i++)
    {
        s[i] = (char)p[i * 2];
    }
    s[len] = 0;
    return s;
}

static int scan_ascii(const pe_t* pe, const sec_t* sec, str_db_t* db)
{
    uint32_t i = sec->raw;
    uint32_t end = sec->raw + sec->raw_size;

    while(i < end)
    {
        uint32_t start = i;
        while(i < end && is_print(pe->mem.data[i]))
        {
            i++;
        }
        if(i - start >= 6 && i < end && pe->mem.data[i] == 0)
        {
            str_t str;
            uint32_t rva;

            if(pe_off_to_rva(pe, start, &rva))
            {
                memset(&str, 0, sizeof(str));
                str.text = dup_ascii(pe->mem.data + start, i - start);
                if(!str.text)
                {
                    return 0;
                }
                str.va = pe->image_base + rva;
                str.rva = rva;
                str.file_off = start;
                str.len = i - start;
                if(!str_add(db, &str))
                {
                    free(str.text);
                    return 0;
                }
            }
        }
        i = start == i ? i + 1 : i + 1;
    }
    return 1;
}

static int scan_wide(const pe_t* pe, const sec_t* sec, str_db_t* db)
{
    uint32_t i = sec->raw;
    uint32_t end = sec->raw + sec->raw_size;

    while(i + 1 < end)
    {
        uint32_t start = i;
        uint32_t n = 0;
        while(i + 1 < end && is_print(pe->mem.data[i]) && pe->mem.data[i + 1] == 0)
        {
            i += 2;
            n++;
        }
        if(n >= 6 && i + 1 < end && pe->mem.data[i] == 0 && pe->mem.data[i + 1] == 0)
        {
            str_t str;
            uint32_t rva;

            if(pe_off_to_rva(pe, start, &rva))
            {
                uint32_t object_rva;
                uint32_t type_rva;
                uint64_t type_va;
                memset(&str, 0, sizeof(str));
                str.text = dup_wide(pe->mem.data + start, n);
                if(!str.text)
                {
                    return 0;
                }
                str.va = pe->image_base + rva;
                str.rva = rva;
                str.file_off = start;
                str.len = n * 2;
                str.wide = 1;
                if(start >= sec->raw + 12 && rd32(pe->mem.data + start - 4) == n)
                {
                    type_va = rd64(pe->mem.data + start - 12);
                    if(va_to_rva(pe, type_va, &type_rva) &&
                       pe_off_to_rva(pe, start - 12, &object_rva))
                    {
                        str.managed = 1;
                        str.object_rva = object_rva;
                        str.object_va = pe->image_base + object_rva;
                    }
                }
                if(!str_add(db, &str))
                {
                    free(str.text);
                    return 0;
                }
            }
        }
        i = start == i ? i + 1 : i + 1;
    }
    return 1;
}

static int scan_fns(const pe_t* pe, fn_db_t* db)
{
    const sec_t* pdata = pe_sec(pe, ".pdata");
    uint32_t i;
    uint32_t end;

    if(!pdata)
    {
        return 1;
    }
    end = pdata->raw + pdata->raw_size;
    for(i = pdata->raw; i + 12 <= end; i += 12)
    {
        uint32_t start = rd32(pe->mem.data + i);
        uint32_t stop = rd32(pe->mem.data + i + 4);
        uint32_t off;
        fn_t fn;

        if(start == 0 || stop <= start)
        {
            continue;
        }
        if(!pe_rva_to_off(pe, start, &off) || !pe_is_text(pe, off))
        {
            continue;
        }
        memset(&fn, 0, sizeof(fn));
        fn.rva = start;
        fn.end_rva = stop;
        fn.file_off = off;
        fn.va = pe->image_base + start;
        fn.size = stop - start;
        if(!fn_add(db, &fn))
        {
            return 0;
        }
    }
    return 1;
}

static int scan_strs(const pe_t* pe, str_db_t* db)
{
    uint16_t i;

    for(i = 0; i < pe->sec_count; i++)
    {
        const sec_t* s = &pe->secs[i];
        if(s->raw == 0 || s->raw + s->raw_size > pe->mem.size)
        {
            continue;
        }
        if((s->flags & 0x40000000) == 0 || (s->flags & 0x20000000) != 0)
        {
            continue;
        }
        if(!scan_ascii(pe, s, db) || !scan_wide(pe, s, db))
        {
            return 0;
        }
    }
    return 1;
}

static size_t bounded_len(const char* s, size_t max)
{
    size_t n = 0;
    while(n < max && s[n])
    {
        n++;
    }
    return n;
}

static char* dup_pe_cstr(const pe_t* pe, uint32_t rva)
{
    uint32_t off;
    size_t n;

    if(!pe_rva_to_off(pe, rva, &off) || off >= pe->mem.size)
    {
        return NULL;
    }
    n = bounded_len((const char*)pe->mem.data + off, pe->mem.size - off);
    if(n == pe->mem.size - off)
    {
        return NULL;
    }
    return dup_cstr((const char*)pe->mem.data + off);
}

static int scan_exports(const pe_t* pe, dump_t* dump)
{
    uint32_t dir_rva;
    uint32_t dir_size;
    uint32_t dir_off;
    uint32_t base;
    uint32_t funcs_rva;
    uint32_t names_rva;
    uint32_t ords_rva;
    uint32_t name_count;
    uint32_t names_off;
    uint32_t ords_off;
    uint32_t i;

    if(!data_rva_span(pe, 0, &dir_rva, &dir_size) || !pe_rva_to_off(pe, dir_rva, &dir_off) || dir_off + 40 > pe->mem.size)
    {
        return 1;
    }
    base = rd32(pe->mem.data + dir_off + 16);
    funcs_rva = rd32(pe->mem.data + dir_off + 28);
    names_rva = rd32(pe->mem.data + dir_off + 32);
    ords_rva = rd32(pe->mem.data + dir_off + 36);
    name_count = rd32(pe->mem.data + dir_off + 24);
    if(!pe_rva_to_off(pe, names_rva, &names_off) || !pe_rva_to_off(pe, ords_rva, &ords_off))
    {
        return 1;
    }
    for(i = 0; i < name_count; i++)
    {
        uint32_t name_rva;
        uint16_t ord_index;
        uint32_t func_rva;
        uint32_t func_off = 0;
        uint32_t funcs_off;
        export_t exp;

        if(names_off + (i + 1) * 4 > pe->mem.size || ords_off + (i + 1) * 2 > pe->mem.size)
        {
            break;
        }
        name_rva = rd32(pe->mem.data + names_off + i * 4);
        ord_index = rd16(pe->mem.data + ords_off + i * 2);
        if(!pe_rva_to_off(pe, funcs_rva + (uint32_t)ord_index * 4, &funcs_off) || funcs_off + 4 > pe->mem.size)
        {
            continue;
        }
        func_rva = rd32(pe->mem.data + funcs_off);
        memset(&exp, 0, sizeof(exp));
        exp.name = dup_pe_cstr(pe, name_rva);
        if(!exp.name)
        {
            return 0;
        }
        exp.rva = func_rva;
        exp.va = pe->image_base + func_rva;
        exp.ordinal = (uint16_t)(base + ord_index);
        exp.is_forwarder = func_rva >= dir_rva && func_rva < dir_rva + dir_size;
        if(exp.is_forwarder)
        {
            exp.forwarder = dup_pe_cstr(pe, func_rva);
        }
        else if(pe_rva_to_off(pe, func_rva, &func_off))
        {
            exp.file_off = func_off;
            if(!add_label(dump, pe, func_rva, "export", exp.name))
            {
                free(exp.name);
                free(exp.forwarder);
                return 0;
            }
        }
        if(!export_add(&dump->exports, &exp))
        {
            free(exp.name);
            free(exp.forwarder);
            return 0;
        }
    }
    return 1;
}

static int scan_imports(const pe_t* pe, dump_t* dump)
{
    uint32_t dir_rva;
    uint32_t dir_size;
    uint32_t desc_off;
    uint32_t i;

    if(!data_rva_span(pe, 1, &dir_rva, &dir_size) || !pe_rva_to_off(pe, dir_rva, &desc_off))
    {
        return 1;
    }
    for(i = 0; desc_off + (i + 1) * 20 <= pe->mem.size && i * 20 < dir_size; i++)
    {
        const uint8_t* d = pe->mem.data + desc_off + i * 20;
        uint32_t oft_rva = rd32(d);
        uint32_t name_rva = rd32(d + 12);
        uint32_t ft_rva = rd32(d + 16);
        uint32_t thunk_rva = oft_rva ? oft_rva : ft_rva;
        uint32_t thunk_off;
        uint32_t t;
        char* dll;

        if(oft_rva == 0 && name_rva == 0 && ft_rva == 0)
        {
            break;
        }
        dll = dup_pe_cstr(pe, name_rva);
        if(!dll)
        {
            continue;
        }
        if(!pe_rva_to_off(pe, thunk_rva, &thunk_off))
        {
            free(dll);
            continue;
        }
        for(t = 0; thunk_off + (t + 1) * 8 <= pe->mem.size; t++)
        {
            uint64_t thunk = rd64(pe->mem.data + thunk_off + t * 8);
            uint32_t iat_rva = ft_rva + t * 8;
            import_t imp;
            char label_name[512];

            if(thunk == 0)
            {
                break;
            }
            memset(&imp, 0, sizeof(imp));
            imp.dll = dup_cstr(dll);
            if(!imp.dll)
            {
                free(dll);
                return 0;
            }
            imp.iat_rva = iat_rva;
            imp.iat_va = pe->image_base + iat_rva;
            if(thunk & 0x8000000000000000ull)
            {
                imp.by_ordinal = 1;
                imp.ordinal = (uint16_t)(thunk & 0xffffu);
                snprintf(label_name, sizeof(label_name), "__imp_%s_ord_%u", dll, imp.ordinal);
            }
            else
            {
                uint32_t by_name_off;
                uint32_t by_name_rva = (uint32_t)thunk;
                if(pe_rva_to_off(pe, by_name_rva, &by_name_off) && by_name_off + 2 < pe->mem.size)
                {
                    imp.name = dup_pe_cstr(pe, by_name_rva + 2);
                }
                snprintf(label_name, sizeof(label_name), "__imp_%s_%s", dll, imp.name ? imp.name : "unknown");
            }
            if(!add_label(dump, pe, iat_rva, "import", label_name))
            {
                free(imp.dll);
                free(imp.name);
                free(dll);
                return 0;
            }
            if(!import_add(&dump->imports, &imp))
            {
                free(imp.dll);
                free(imp.name);
                free(dll);
                return 0;
            }
        }
        free(dll);
    }
    return 1;
}

static int scan_tls(const pe_t* pe, dump_t* dump)
{
    uint32_t dir_rva;
    uint32_t dir_size;
    uint32_t dir_off;
    uint32_t callbacks_rva;
    uint64_t callbacks_va;
    uint32_t callbacks_off;
    uint32_t i;

    if(!data_rva_span(pe, 9, &dir_rva, &dir_size) || !pe_rva_to_off(pe, dir_rva, &dir_off) || dir_off + 32 > pe->mem.size)
    {
        return 1;
    }
    callbacks_va = rd64(pe->mem.data + dir_off + 24);
    if(!va_to_rva(pe, callbacks_va, &callbacks_rva) || !pe_rva_to_off(pe, callbacks_rva, &callbacks_off))
    {
        return 1;
    }
    for(i = 0; callbacks_off + (i + 1) * 8 <= pe->mem.size; i++)
    {
        uint64_t cb_va = rd64(pe->mem.data + callbacks_off + i * 8);
        uint32_t cb_rva;
        char name[64];

        if(cb_va == 0)
        {
            break;
        }
        if(!va_to_rva(pe, cb_va, &cb_rva))
        {
            continue;
        }
        snprintf(name, sizeof(name), "tls_callback_%u", i);
        if(!add_label(dump, pe, cb_rva, "tls_callback", name))
        {
            return 0;
        }
    }
    return 1;
}

static const char* aot_section_name(uint32_t type)
{
    if(type >= 300 && type <= 399)
    {
        return "readonly_blob";
    }
    switch(type)
    {
        case 100: return "compiler_identifier";
        case 101: return "import_sections";
        case 102: return "runtime_functions";
        case 103: return "methoddef_entrypoints";
        case 104: return "exception_info";
        case 105: return "debug_info";
        case 106: return "delay_load_method_call_thunks";
        case 108: return "available_types";
        case 109: return "instance_method_entrypoints";
        case 110: return "inlining_info";
        case 111: return "profile_data_info";
        case 112: return "manifest_metadata";
        case 113: return "attribute_presence";
        case 114: return "inlining_info2";
        case 115: return "component_assemblies";
        case 116: return "owner_composite_executable";
        case 117: return "pgo_instrumentation_data";
        case 118: return "manifest_assembly_mvids";
        case 119: return "cross_module_inline_info";
        case 200: return "string_table";
        case 201: return "gc_static_region";
        case 202: return "thread_static_region";
        case 204: return "type_manager_indirection";
        case 205: return "eager_cctor";
        case 206: return "frozen_object_region";
        case 208: return "thread_static_offset_region";
        case 212: return "import_address_tables";
        default: return "unknown";
    }
}

static int read_aot_entry(const pe_t* pe, const uint8_t* entry, uint8_t entry_size, uint32_t* type, uint32_t* sec_rva, uint32_t* size)
{
    uint64_t start;
    uint64_t end;

    *type = rd32(entry);
    *sec_rva = 0;
    *size = 0;
    if(entry_size >= 24)
    {
        start = rd64(entry + 8);
        end = rd64(entry + 16);
        if(end < start || end - start > 0xffffffffu)
        {
            return 0;
        }
        if(!va_to_rva(pe, start, sec_rva))
        {
            *sec_rva = (uint32_t)start;
        }
        *size = (uint32_t)(end - start);
        return 1;
    }
    if(entry_size >= 16)
    {
        *size = rd32(entry + 4);
        start = rd64(entry + 8);
        if(!va_to_rva(pe, start, sec_rva))
        {
            *sec_rva = (uint32_t)start;
        }
        return 1;
    }
    *size = rd32(entry + 4);
    *sec_rva = rd32(entry + 8);
    return 1;
}

static int scan_aot_header_at(const pe_t* pe, dump_t* dump, uint32_t off, uint32_t* valid_count)
{
    uint16_t count;
    uint8_t entry_size;
    uint32_t rva;
    uint32_t i;
    uint32_t valid = 0;

    *valid_count = 0;
    if(off + 16 > pe->mem.size || memcmp(pe->mem.data + off, "RTR", 3) != 0 || pe->mem.data[off + 3] != 0)
    {
        return 1;
    }
    count = rd16(pe->mem.data + off + 12);
    entry_size = pe->mem.data[off + 14];
    if(count == 0 || count > 2048 || entry_size < 12 || entry_size > 32 || off + 16 + (uint32_t)count * entry_size > pe->mem.size)
    {
        return 1;
    }
    if(!pe_off_to_rva(pe, off, &rva))
    {
        return 1;
    }
    for(i = 0; i < count; i++)
    {
        uint32_t eoff = off + 16 + i * entry_size;
        uint32_t type;
        uint32_t size;
        uint32_t sec_rva;
        uint32_t sec_off;

        if(!read_aot_entry(pe, pe->mem.data + eoff, entry_size, &type, &sec_rva, &size))
        {
            continue;
        }
        if(size == 0)
        {
            continue;
        }
        if(pe_rva_to_off(pe, sec_rva, &sec_off) && sec_off + size <= pe->mem.size)
        {
            valid++;
        }
        else if(pe_rva_to_off(pe, sec_rva, &sec_off))
        {
            valid++;
        }
    }
    if(valid == 0)
    {
        return 1;
    }
    if(!add_label(dump, pe, rva, "native_aot_header", "native_aot_readytorun_header"))
    {
        return 0;
    }
    for(i = 0; i < count; i++)
    {
        uint32_t eoff = off + 16 + i * entry_size;
        uint32_t type;
        uint32_t size;
        uint32_t sec_rva;
        uint32_t sec_off;
        aot_section_t sec;
        char label_name[128];

        if(!read_aot_entry(pe, pe->mem.data + eoff, entry_size, &type, &sec_rva, &size))
        {
            continue;
        }
        if(size == 0)
        {
            continue;
        }
        if(!pe_rva_to_off(pe, sec_rva, &sec_off))
        {
            continue;
        }
        memset(&sec, 0, sizeof(sec));
        sec.name = aot_section_name(type);
        sec.type = type;
        sec.rva = sec_rva;
        sec.file_off = sec_off;
        sec.size = size;
        sec.va = pe->image_base + sec_rva;
        if(!aot_section_add(&dump->aot_sections, &sec))
        {
            return 0;
        }
        snprintf(label_name, sizeof(label_name), "native_aot_%s_%u", sec.name, type);
        if(!add_label(dump, pe, sec_rva, "native_aot_section", label_name))
        {
            return 0;
        }
    }
    *valid_count = valid;
    return 1;
}

static int scan_aot_sections(const pe_t* pe, dump_t* dump)
{
    uint32_t off;
    uint32_t best_off = 0;
    uint32_t best_valid = 0;

    for(off = 0; off + 16 <= pe->mem.size; off++)
    {
        uint32_t valid = 0;
        if(pe->mem.data[off] == 'R' && pe->mem.data[off + 1] == 'T' && pe->mem.data[off + 2] == 'R' && pe->mem.data[off + 3] == 0)
        {
            dump_t tmp;
            dump_init(&tmp);
            if(!scan_aot_header_at(pe, &tmp, off, &valid))
            {
                dump_free(&tmp);
                return 0;
            }
            dump_free(&tmp);
            if(valid > best_valid)
            {
                best_valid = valid;
                best_off = off;
            }
        }
    }
    if(best_valid == 0)
    {
        return 1;
    }
    return scan_aot_header_at(pe, dump, best_off, &best_valid);
}

static void add_ref(dump_t* dump, const pe_t* pe, uint32_t from_rva, uint32_t to_rva, const char* kind)
{
    xref_t xref;
    fn_t* from_fn;
    fn_t* to_fn;
    str_t* str;

    from_fn = fn_by_rva(&dump->fns, from_rva);
    to_fn = fn_by_rva(&dump->fns, to_rva);
    str = str_by_rva(&dump->strs, to_rva);
    if(str)
    {
        to_rva = str->managed ? str->object_rva : str->rva;
    }
    memset(&xref, 0, sizeof(xref));
    xref.from_rva = from_rva;
    xref.to_rva = to_rva;
    xref.from_va = pe->image_base + from_rva;
    xref.to_va = pe->image_base + to_rva;
    xref.from_func_rva = from_fn ? from_fn->rva : 0;
    xref.to_func_rva = to_fn ? to_fn->rva : 0;
    xref.kind = kind;
    xref_add(&dump->xrefs, &xref);
}

static void finalize_xrefs(dump_t* dump)
{
    size_t i;
    size_t out = 0;

    qsort(dump->xrefs.items, dump->xrefs.len, sizeof(xref_t), cmp_xref);
    for(i = 0; i < dump->xrefs.len; i++)
    {
        if(out && cmp_xref(&dump->xrefs.items[out - 1], &dump->xrefs.items[i]) == 0)
        {
            continue;
        }
        dump->xrefs.items[out++] = dump->xrefs.items[i];
    }
    dump->xrefs.len = out;
    for(i = 0; i < dump->fns.len; i++)
    {
        dump->fns.items[i].refs_in = 0;
        dump->fns.items[i].refs_out = 0;
    }
    for(i = 0; i < dump->strs.len; i++) dump->strs.items[i].refs = 0;
    for(i = 0; i < dump->xrefs.len; i++)
    {
        xref_t* x = &dump->xrefs.items[i];
        fn_t* from = x->from_func_rva ? fn_by_rva(&dump->fns, x->from_func_rva) : NULL;
        fn_t* to = x->to_func_rva ? fn_by_rva(&dump->fns, x->to_func_rva) : NULL;
        str_t* str = str_by_rva(&dump->strs, x->to_rva);
        if(from) from->refs_out++;
        if(to && x->to_rva == to->rva) to->refs_in++;
        if(str) str->refs++;
    }
}

static int scan_reloc_xrefs(const pe_t* pe, dump_t* dump)
{
    uint32_t dir_rva;
    uint32_t dir_size;
    uint32_t off;
    uint32_t end;

    if(!data_rva_span(pe, 5, &dir_rva, &dir_size) || !pe_rva_to_off(pe, dir_rva, &off))
    {
        return 1;
    }
    end = off + dir_size;
    if(end > pe->mem.size)
    {
        end = (uint32_t)pe->mem.size;
    }
    while(off + 8 <= end)
    {
        uint32_t page_rva = rd32(pe->mem.data + off);
        uint32_t block_size = rd32(pe->mem.data + off + 4);
        uint32_t count;
        uint32_t i;

        if(page_rva == 0 || block_size < 8 || off + block_size > end)
        {
            break;
        }
        count = (block_size - 8) / 2;
        for(i = 0; i < count; i++)
        {
            uint16_t ent = rd16(pe->mem.data + off + 8 + i * 2);
            uint16_t type = ent >> 12;
            uint16_t ofs = ent & 0x0fffu;
            uint32_t from_rva;
            uint32_t from_off;
            uint64_t target_va;
            uint32_t target_rva;

            if(type != 10)
            {
                continue;
            }
            from_rva = page_rva + ofs;
            if(!pe_rva_to_off(pe, from_rva, &from_off) || from_off + 8 > pe->mem.size)
            {
                continue;
            }
            target_va = rd64(pe->mem.data + from_off);
            if(!va_to_rva(pe, target_va, &target_rva))
            {
                continue;
            }
            if(fn_by_rva(&dump->fns, target_rva))
            {
                add_ref(dump, pe, from_rva, target_rva, "reloc_fn");
            }
            else if(str_by_rva(&dump->strs, target_rva))
            {
                add_ref(dump, pe, from_rva, target_rva, "reloc_str");
            }
            else if(aot_section_by_rva(&dump->aot_sections, target_rva))
            {
                add_ref(dump, pe, from_rva, target_rva, "reloc_aot");
            }
        }
        off += block_size;
    }
    return 1;
}

#ifndef AOTRX_USE_HDE
static int scan_xrefs_legacy(const pe_t* pe, dump_t* dump)
{
    const sec_t* text = pe_sec(pe, ".text");
    uint32_t i;
    uint32_t end;

    if(!text)
    {
        return 1;
    }
    end = text->raw + text->raw_size;
    for(i = text->raw; i + 7 <= end; i++)
    {
        uint32_t from_rva;
        if(!pe_off_to_rva(pe, i, &from_rva))
        {
            continue;
        }
        if(!fn_by_rva(&dump->fns, from_rva))
        {
            continue;
        }
        if(pe->mem.data[i] == 0xe8 || pe->mem.data[i] == 0xe9)
        {
            int32_t rel = (int32_t)rd32(pe->mem.data + i + 1);
            uint32_t to_rva = from_rva + 5 + rel;
            uint32_t to_off;
            if(pe_rva_to_off(pe, to_rva, &to_off) && fn_by_rva(&dump->fns, to_rva))
            {
                add_ref(dump, pe, from_rva, to_rva, pe->mem.data[i] == 0xe8 ? "call" : "jump");
            }
        }
        if(pe->mem.data[i] == 0x0f && (pe->mem.data[i + 1] & 0xf0) == 0x80)
        {
            int32_t rel = (int32_t)rd32(pe->mem.data + i + 2);
            uint32_t to_rva = from_rva + 6 + rel;
            if(fn_by_rva(&dump->fns, to_rva)) add_ref(dump, pe, from_rva, to_rva, "branch");
        }
        if((pe->mem.data[i] == 0x48 || pe->mem.data[i] == 0x4c) && i + 7 <= end)
        {
            uint8_t op = pe->mem.data[i + 1];
            if(op == 0x8d || op == 0x8b)
            {
                int32_t rel = (int32_t)rd32(pe->mem.data + i + 3);
                uint32_t to_rva = from_rva + 7 + rel;
                uint32_t to_off;
                if(pe_rva_to_off(pe, to_rva, &to_off) && str_by_rva(&dump->strs, to_rva))
                {
                    add_ref(dump, pe, from_rva, to_rva, op == 0x8d ? "lea_str" : "mov_str");
                }
                else if(pe_rva_to_off(pe, to_rva, &to_off) && label_by_rva(&dump->labels, to_rva))
                {
                    add_ref(dump, pe, from_rva, to_rva, op == 0x8d ? "lea_label" : "mov_label");
                }
            }
        }
    }
    return 1;
}
#endif

static int scan_xrefs(const pe_t* pe, dump_t* dump);

int dump_run(const pe_t* pe, dump_t* dump)
{
    if(!scan_fns(pe, &dump->fns))
    {
        return 0;
    }
    if(!scan_strs(pe, &dump->strs))
    {
        return 0;
    }
    if(!scan_exports(pe, dump))
    {
        return 0;
    }
    if(!scan_imports(pe, dump))
    {
        return 0;
    }
    if(!scan_tls(pe, dump))
    {
        return 0;
    }
    if(!scan_aot_sections(pe, dump))
    {
        return 0;
    }
    qsort(dump->fns.items, dump->fns.len, sizeof(fn_t), cmp_fn);
    qsort(dump->strs.items, dump->strs.len, sizeof(str_t), cmp_str);
    qsort(dump->labels.items, dump->labels.len, sizeof(label_t), cmp_label);
    qsort(dump->aot_sections.items, dump->aot_sections.len, sizeof(aot_section_t), cmp_aot_section);
    attach_labels(dump);
    if(!scan_xrefs(pe, dump))
    {
        return 0;
    }
    if(!scan_reloc_xrefs(pe, dump))
    {
        return 0;
    }
    finalize_xrefs(dump);
    if(!scan_accessors(pe, dump))
    {
        return 0;
    }
    return 1;
}

#ifdef AOTRX_USE_HDE
static int scan_xrefs(const pe_t* pe, dump_t* dump)
{
    size_t index;

    for(index = 0; index < dump->fns.len; index++)
    {
        const fn_t* fn = &dump->fns.items[index];
        uint32_t cursor = fn->rva;
        while(cursor < fn->end_rva)
        {
            uint32_t off;
            hde64s insn;
            unsigned int length;
            if(!pe_rva_to_off(pe, cursor, &off) || off >= pe->mem.size)
            {
                break;
            }
            length = hde64_disasm(pe->mem.data + off, &insn);
            if(length == 0 || length > fn->end_rva - cursor)
            {
                cursor++;
                continue;
            }
            if(insn.flags & F_ERROR)
            {
                cursor += length;
                continue;
            }
            if((insn.opcode == 0xe8 || insn.opcode == 0xe9) && (insn.flags & F_IMM32))
            {
                uint32_t target = cursor + length + (int32_t)insn.imm.imm32;
                if(fn_by_rva(&dump->fns, target))
                {
                    add_ref(dump, pe, cursor, target, insn.opcode == 0xe8 ? "call" : "jump");
                }
            }
            else if(insn.opcode == 0x0f && (insn.opcode2 & 0xf0) == 0x80 && (insn.flags & F_IMM32))
            {
                uint32_t target = cursor + length + (int32_t)insn.imm.imm32;
                if(fn_by_rva(&dump->fns, target)) add_ref(dump, pe, cursor, target, "branch");
            }
            else if(insn.opcode >= 0x70 && insn.opcode <= 0x7f && (insn.flags & F_IMM8))
            {
                uint32_t target = cursor + length + (int8_t)insn.imm.imm8;
                if(fn_by_rva(&dump->fns, target)) add_ref(dump, pe, cursor, target, "branch");
            }
            else if(insn.opcode == 0xeb && (insn.flags & F_IMM8))
            {
                uint32_t target = cursor + length + (int8_t)insn.imm.imm8;
                if(fn_by_rva(&dump->fns, target)) add_ref(dump, pe, cursor, target, "jump");
            }
            if((insn.flags & (F_MODRM | F_DISP32)) == (F_MODRM | F_DISP32) &&
               insn.modrm_mod == 0 && insn.modrm_rm == 5 && !insn.p_67)
            {
                uint32_t target = cursor + length + (int32_t)insn.disp.disp32;
                str_t* str = str_by_rva(&dump->strs, target);
                const label_t* label = label_by_rva(&dump->labels, target);
                if(str)
                {
                    add_ref(dump, pe, cursor, target, insn.opcode == 0x8d ? "lea_str" : "rip_str");
                }
                else if(label)
                {
                    const char* kind = "rip_label";
                    if(insn.opcode == 0xff && insn.modrm_reg == 2) kind = "indirect_call";
                    else if(insn.opcode == 0xff && insn.modrm_reg == 4) kind = "indirect_jump";
                    add_ref(dump, pe, cursor, target, kind);
                }
                else if(fn_by_rva(&dump->fns, target))
                {
                    add_ref(dump, pe, cursor, target, "rip_fn");
                }
            }
            cursor += length;
        }
    }
    return 1;
}
#else
static int scan_xrefs(const pe_t* pe, dump_t* dump)
{
    return scan_xrefs_legacy(pe, dump);
}
#endif
