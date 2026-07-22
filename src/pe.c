#include "aotrx.h"

#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t* p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t* p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

int mem_load(const char* path, mem_t* mem)
{
    FILE* fp;
    long size;

    memset(mem, 0, sizeof(*mem));
    fp = fopen(path, "rb");
    if(!fp)
    {
        return 0;
    }
    if(fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return 0;
    }
    size = ftell(fp);
    if(size <= 0)
    {
        fclose(fp);
        return 0;
    }
    if(fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return 0;
    }
    mem->data = (uint8_t*)malloc((size_t)size);
    if(!mem->data)
    {
        fclose(fp);
        return 0;
    }
    mem->size = (size_t)size;
    if(fread(mem->data, 1, mem->size, fp) != mem->size)
    {
        mem_free(mem);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

void mem_free(mem_t* mem)
{
    free(mem->data);
    mem->data = NULL;
    mem->size = 0;
}

int pe_load(const char* path, pe_t* pe)
{
    uint32_t pe_off;
    uint16_t opt_size;
    uint16_t magic;
    uint32_t dir_count;
    size_t opt_off;
    size_t dir_off;
    size_t sec_off;
    uint16_t i;

    memset(pe, 0, sizeof(*pe));
    if(!mem_load(path, &pe->mem))
    {
        return 0;
    }
    if(pe->mem.size < 0x100 || rd16(pe->mem.data) != 0x5a4d)
    {
        pe_free(pe);
        return 0;
    }
    pe_off = rd32(pe->mem.data + 0x3c);
    if((size_t)pe_off + 0x108 > pe->mem.size || rd32(pe->mem.data + pe_off) != 0x4550)
    {
        pe_free(pe);
        return 0;
    }
    pe->machine = rd16(pe->mem.data + pe_off + 4);
    pe->sec_count = rd16(pe->mem.data + pe_off + 6);
    opt_size = rd16(pe->mem.data + pe_off + 20);
    magic = rd16(pe->mem.data + pe_off + 24);
    if(magic != 0x20b || pe->machine != 0x8664)
    {
        pe_free(pe);
        return 0;
    }
    opt_off = (size_t)pe_off + 24;
    pe->entry_rva = rd32(pe->mem.data + opt_off + 16);
    pe->image_base = rd64(pe->mem.data + opt_off + 24);
    dir_count = rd32(pe->mem.data + opt_off + 108);
    if(dir_count > 16)
    {
        dir_count = 16;
    }
    dir_off = opt_off + 112;
    if(dir_off + (size_t)dir_count * 8 <= pe->mem.size)
    {
        for(i = 0; i < dir_count; i++)
        {
            pe->dir_rva[i] = rd32(pe->mem.data + dir_off + (size_t)i * 8);
            pe->dir_size[i] = rd32(pe->mem.data + dir_off + (size_t)i * 8 + 4);
        }
    }
    sec_off = (size_t)pe_off + 24 + opt_size;
    if(sec_off + (size_t)pe->sec_count * 40 > pe->mem.size)
    {
        pe_free(pe);
        return 0;
    }
    pe->secs = (sec_t*)calloc(pe->sec_count, sizeof(sec_t));
    if(!pe->secs)
    {
        pe_free(pe);
        return 0;
    }
    for(i = 0; i < pe->sec_count; i++)
    {
        const uint8_t* s = pe->mem.data + sec_off + (size_t)i * 40;
        memcpy(pe->secs[i].name, s, 8);
        pe->secs[i].name[8] = 0;
        pe->secs[i].vsize = rd32(s + 8);
        pe->secs[i].rva = rd32(s + 12);
        pe->secs[i].raw_size = rd32(s + 16);
        pe->secs[i].raw = rd32(s + 20);
        pe->secs[i].flags = rd32(s + 36);
    }
    return 1;
}

void pe_free(pe_t* pe)
{
    free(pe->secs);
    pe->secs = NULL;
    pe->sec_count = 0;
    mem_free(&pe->mem);
}

const sec_t* pe_sec(const pe_t* pe, const char* name)
{
    uint16_t i;

    for(i = 0; i < pe->sec_count; i++)
    {
        if(strcmp(pe->secs[i].name, name) == 0)
        {
            return &pe->secs[i];
        }
    }
    return NULL;
}

int pe_rva_to_off(const pe_t* pe, uint32_t rva, uint32_t* off)
{
    uint16_t i;

    for(i = 0; i < pe->sec_count; i++)
    {
        const sec_t* s = &pe->secs[i];
        uint32_t span = s->vsize > s->raw_size ? s->vsize : s->raw_size;
        if(rva >= s->rva && rva < s->rva + span)
        {
            *off = s->raw + (rva - s->rva);
            return *off < pe->mem.size;
        }
    }
    return 0;
}

int pe_off_to_rva(const pe_t* pe, uint32_t off, uint32_t* rva)
{
    uint16_t i;

    for(i = 0; i < pe->sec_count; i++)
    {
        const sec_t* s = &pe->secs[i];
        if(off >= s->raw && off < s->raw + s->raw_size)
        {
            *rva = s->rva + (off - s->raw);
            return 1;
        }
    }
    return 0;
}

int pe_is_text(const pe_t* pe, uint32_t off)
{
    const sec_t* s = pe_sec(pe, ".text");
    if(!s)
    {
        return 0;
    }
    return off >= s->raw && off < s->raw + s->raw_size;
}
