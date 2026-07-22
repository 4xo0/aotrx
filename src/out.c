#include "aotrx.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

static FILE* open_out(const char* path)
{
    if(!path || strcmp(path, "-") == 0)
    {
        return stdout;
    }
    return fopen(path, "wb");
}

static void close_out(FILE* fp)
{
    if(fp && fp != stdout)
    {
        fclose(fp);
    }
}

int mk_dir(const char* path)
{
    if(!path)
    {
        return 1;
    }
#ifdef _WIN32
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
    return 1;
}

int path_join(char* dst, size_t cap, const char* dir, const char* file)
{
    size_t n;
    int r;

    if(!dir || !file)
    {
        return 0;
    }
    n = strlen(dir);
    if(n > 0 && (dir[n - 1] == '/' || dir[n - 1] == '\\'))
    {
        r = snprintf(dst, cap, "%s%s", dir, file);
    }
    else
    {
        r = snprintf(dst, cap, "%s/%s", dir, file);
    }
    return r > 0 && (size_t)r < cap;
}

static void js_str(FILE* fp, const char* s)
{
    fputc('"', fp);
    if(!s)
    {
        fputc('"', fp);
        return;
    }
    while(*s)
    {
        unsigned char c = (unsigned char)*s++;
        if(c == '\\' || c == '"')
        {
            fputc('\\', fp);
            fputc(c, fp);
        }
        else if(c >= 0x20 && c <= 0x7e)
        {
            fputc(c, fp);
        }
        else
        {
            fprintf(fp, "\\u%04x", c);
        }
    }
    fputc('"', fp);
}

int out_summary(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "{\n");
    fprintf(fp, "  \"tool\": \"aotrx\",\n");
    fprintf(fp, "  \"format\": \"native_aot_dump\",\n");
    fprintf(fp, "  \"image_base\": \"0x%llx\",\n", (unsigned long long)pe->image_base);
    fprintf(fp, "  \"entry_rva\": \"0x%x\",\n", pe->entry_rva);
    fprintf(fp, "  \"sections\": %u,\n", pe->sec_count);
    fprintf(fp, "  \"functions\": %llu,\n", (unsigned long long)dump->fns.len);
    fprintf(fp, "  \"strings\": %llu,\n", (unsigned long long)dump->strs.len);
    fprintf(fp, "  \"xrefs\": %llu,\n", (unsigned long long)dump->xrefs.len);
    fprintf(fp, "  \"labels\": %llu,\n", (unsigned long long)dump->labels.len);
    fprintf(fp, "  \"imports\": %llu,\n", (unsigned long long)dump->imports.len);
    fprintf(fp, "  \"exports\": %llu,\n", (unsigned long long)dump->exports.len);
    fprintf(fp, "  \"native_aot_sections\": %llu,\n", (unsigned long long)dump->aot_sections.len);
    fprintf(fp, "  \"accessors\": %llu\n", (unsigned long long)dump->accessors.len);
    fprintf(fp, "}\n");
    close_out(fp);
    return 1;
}

int out_funcs(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->fns.len; i++)
    {
        const fn_t* f = &dump->fns.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"end_rva\":\"0x%x\",\"file_off\":\"0x%x\",\"size\":%u,\"refs_in\":%u,\"refs_out\":%u,\"kind\":",
            (unsigned long long)f->va,
            f->rva,
            f->end_rva,
            f->file_off,
            f->size,
            f->refs_in,
            f->refs_out);
        js_str(fp, f->kind ? f->kind : "pdata");
        fprintf(fp, ",\"name\":");
        if(f->name)
        {
            js_str(fp, f->name);
        }
        else
        {
            fprintf(fp, "null");
        }
        fprintf(fp, "}%s\n", i + 1 == dump->fns.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_strings(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->strs.len; i++)
    {
        const str_t* s = &dump->strs.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"object_va\":\"0x%llx\",\"object_rva\":\"0x%x\",\"file_off\":\"0x%x\",\"len\":%u,\"wide\":%s,\"managed\":%s,\"refs\":%u,\"text\":",
            (unsigned long long)s->va,
            s->rva,
            (unsigned long long)s->object_va,
            s->object_rva,
            s->file_off,
            s->len,
            s->wide ? "true" : "false",
            s->managed ? "true" : "false",
            s->refs);
        js_str(fp, s->text);
        fprintf(fp, "}%s\n", i + 1 == dump->strs.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_xrefs(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->xrefs.len; i++)
    {
        const xref_t* x = &dump->xrefs.items[i];
        fprintf(fp, "  {\"from_va\":\"0x%llx\",\"to_va\":\"0x%llx\",\"from_rva\":\"0x%x\",\"to_rva\":\"0x%x\",\"from_func_rva\":\"0x%x\",\"to_func_rva\":\"0x%x\",\"kind\":\"%s\"}%s\n",
            (unsigned long long)x->from_va,
            (unsigned long long)x->to_va,
            x->from_rva,
            x->to_rva,
            x->from_func_rva,
            x->to_func_rva,
            x->kind,
            i + 1 == dump->xrefs.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_labels(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->labels.len; i++)
    {
        const label_t* l = &dump->labels.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"file_off\":\"0x%x\",\"kind\":",
            (unsigned long long)l->va,
            l->rva,
            l->file_off);
        js_str(fp, l->kind);
        fprintf(fp, ",\"name\":");
        js_str(fp, l->name);
        fprintf(fp, "}%s\n", i + 1 == dump->labels.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_imports(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->imports.len; i++)
    {
        const import_t* imp = &dump->imports.items[i];
        fprintf(fp, "  {\"iat_va\":\"0x%llx\",\"iat_rva\":\"0x%x\",\"dll\":",
            (unsigned long long)imp->iat_va,
            imp->iat_rva);
        js_str(fp, imp->dll);
        if(imp->by_ordinal)
        {
            fprintf(fp, ",\"ordinal\":%u,\"name\":null", imp->ordinal);
        }
        else
        {
            fprintf(fp, ",\"ordinal\":null,\"name\":");
            js_str(fp, imp->name);
        }
        fprintf(fp, "}%s\n", i + 1 == dump->imports.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_exports(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->exports.len; i++)
    {
        const export_t* exp = &dump->exports.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"file_off\":\"0x%x\",\"ordinal\":%u,\"forwarder\":",
            (unsigned long long)exp->va,
            exp->rva,
            exp->file_off,
            exp->ordinal);
        if(exp->is_forwarder)
        {
            js_str(fp, exp->forwarder);
        }
        else
        {
            fprintf(fp, "null");
        }
        fprintf(fp, ",\"name\":");
        js_str(fp, exp->name);
        fprintf(fp, "}%s\n", i + 1 == dump->exports.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_aot_sections(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->aot_sections.len; i++)
    {
        const aot_section_t* s = &dump->aot_sections.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"file_off\":\"0x%x\",\"size\":%u,\"type\":%u,\"name\":",
            (unsigned long long)s->va,
            s->rva,
            s->file_off,
            s->size,
            s->type);
        js_str(fp, s->name);
        fprintf(fp, "}%s\n", i + 1 == dump->aot_sections.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_accessors(const char* path, const pe_t* pe, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;
    (void)pe;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "[\n");
    for(i = 0; i < dump->accessors.len; i++)
    {
        const accessor_t* a = &dump->accessors.items[i];
        fprintf(fp, "  {\"va\":\"0x%llx\",\"rva\":\"0x%x\",\"file_off\":\"0x%x\",\"field_offset\":\"0x%x\",\"width\":%u,\"function_size\":%u,\"refs_in\":%u,\"refs_out\":%u,\"kind\":",
            (unsigned long long)a->va, a->rva, a->file_off, a->field_offset, a->width,
            a->function_size, a->refs_in, a->refs_out);
        js_str(fp, a->kind);
        fprintf(fp, ",\"value_type\":");
        js_str(fp, a->value_type);
        fprintf(fp, "}%s\n", i + 1 == dump->accessors.len ? "" : ",");
    }
    fprintf(fp, "]\n");
    close_out(fp);
    return 1;
}

int out_ida(const char* path, const dump_t* dump)
{
    FILE* fp = open_out(path);
    size_t i;

    if(!fp)
    {
        return 0;
    }
    fprintf(fp, "import ida_bytes\n");
    fprintf(fp, "import ida_name\n\n");
    for(i = 0; i < dump->labels.len; i++)
    {
        const label_t* l = &dump->labels.items[i];
        fprintf(fp, "ida_name.set_name(0x%llx, ", (unsigned long long)l->va);
        js_str(fp, l->name);
        fprintf(fp, ", ida_name.SN_CHECK)\n");
    }
    for(i = 0; i < dump->fns.len; i++)
    {
        const fn_t* f = &dump->fns.items[i];
        if(f->refs_in || f->refs_out)
        {
            fprintf(fp, "ida_bytes.set_cmt(0x%llx, \"aotrx kind=%s refs_in=%u refs_out=%u\", 0)\n",
                (unsigned long long)f->va,
                f->kind ? f->kind : "pdata",
                f->refs_in,
                f->refs_out);
        }
    }
    for(i = 0; i < dump->strs.len; i++)
    {
        const str_t* s = &dump->strs.items[i];
        if(s->refs)
        {
            fprintf(fp, "ida_name.set_name(0x%llx, \"aot_str_%x\", ida_name.SN_CHECK)\n",
                (unsigned long long)s->va,
                s->rva);
        }
    }
    for(i = 0; i < dump->accessors.len; i++)
    {
        const accessor_t* a = &dump->accessors.items[i];
        fprintf(fp, "ida_bytes.set_cmt(0x%llx, \"aotrx %s %s field_offset=0x%x width=%u\", 0)\n",
            (unsigned long long)a->va, a->value_type, a->kind, a->field_offset, a->width);
    }
    close_out(fp);
    return 1;
}
