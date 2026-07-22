#include "aotrx.h"

#include <stdlib.h>
#include <string.h>

static int hit(const uint8_t* data, const pat_t* pat)
{
    size_t i;

    for(i = 0; i < pat->len; i++)
    {
        if(pat->mask[i] == 'x' && data[i] != pat->bytes[i])
        {
            return 0;
        }
    }
    return 1;
}

int sig_find(const pe_t* pe, const pat_t* pat, uint32_t* off, int* count)
{
    const sec_t* text;
    uint32_t i;
    uint32_t end;
    int n = 0;

    *off = 0;
    *count = 0;
    text = pe_sec(pe, ".text");
    if(!text || pat->len == 0 || text->raw + text->raw_size > pe->mem.size)
    {
        return 0;
    }
    if(text->raw_size < pat->len)
    {
        return 0;
    }
    end = text->raw + text->raw_size - (uint32_t)pat->len;
    for(i = text->raw; i <= end; i++)
    {
        if(hit(pe->mem.data + i, pat))
        {
            if(n == 0)
            {
                *off = i;
            }
            n++;
        }
    }
    *count = n;
    return n > 0;
}

void sym_db_init(sym_db_t* db)
{
    memset(db, 0, sizeof(*db));
}

void sym_db_free(sym_db_t* db)
{
    free(db->items);
    db->items = NULL;
    db->len = 0;
    db->cap = 0;
}

int sym_db_add(sym_db_t* db, const sym_t* sym)
{
    sym_t* next;
    size_t cap;

    if(db->len == db->cap)
    {
        cap = db->cap ? db->cap * 2 : 8;
        next = (sym_t*)realloc(db->items, cap * sizeof(sym_t));
        if(!next)
        {
            return 0;
        }
        db->items = next;
        db->cap = cap;
    }
    db->items[db->len++] = *sym;
    return 1;
}

const sym_t* sym_db_get(const sym_db_t* db, const char* id)
{
    size_t i;

    for(i = 0; i < db->len; i++)
    {
        if(strcmp(db->items[i].id, id) == 0)
        {
            return &db->items[i];
        }
    }
    return NULL;
}
