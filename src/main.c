#include "aotrx.h"

#include <stdio.h>
#include <string.h>

static void usage(void)
{
    printf("aotrx dump <pe> [-o dir] [--summary path] [--funcs path] [--strings path] [--xrefs path] [--labels path] [--imports path] [--exports path] [--aot-sections path] [--accessors path] [--ida path] [--check]\n");
}

static int eq(const char* a, const char* b)
{
    return strcmp(a, b) == 0;
}

static int parse(int argc, char** argv, cfg_t* cfg)
{
    int i;

    memset(cfg, 0, sizeof(*cfg));
    if(argc < 3 || !eq(argv[1], "dump"))
    {
        return 0;
    }
    cfg->exe = argv[2];
    for(i = 3; i < argc; i++)
    {
        if(eq(argv[i], "-o") && i + 1 < argc)
        {
            cfg->out_dir = argv[++i];
        }
        else if(eq(argv[i], "--summary") && i + 1 < argc)
        {
            cfg->summary = argv[++i];
        }
        else if(eq(argv[i], "--funcs") && i + 1 < argc)
        {
            cfg->funcs = argv[++i];
        }
        else if(eq(argv[i], "--strings") && i + 1 < argc)
        {
            cfg->strings = argv[++i];
        }
        else if(eq(argv[i], "--xrefs") && i + 1 < argc)
        {
            cfg->xrefs = argv[++i];
        }
        else if(eq(argv[i], "--labels") && i + 1 < argc)
        {
            cfg->labels = argv[++i];
        }
        else if(eq(argv[i], "--imports") && i + 1 < argc)
        {
            cfg->imports = argv[++i];
        }
        else if(eq(argv[i], "--exports") && i + 1 < argc)
        {
            cfg->exports = argv[++i];
        }
        else if(eq(argv[i], "--aot-sections") && i + 1 < argc)
        {
            cfg->aot_sections = argv[++i];
        }
        else if(eq(argv[i], "--accessors") && i + 1 < argc)
        {
            cfg->accessors = argv[++i];
        }
        else if(eq(argv[i], "--ida") && i + 1 < argc)
        {
            cfg->ida = argv[++i];
        }
        else if(eq(argv[i], "--check"))
        {
            cfg->check = 1;
        }
        else
        {
            fprintf(stderr, "bad arg: %s\n", argv[i]);
            return 0;
        }
    }
    return 1;
}

static int set_out(cfg_t* cfg, char* a, char* b, char* c, char* d, char* e, char* f, char* g, char* h, char* j, char* k, size_t cap)
{
    if(!cfg->out_dir)
    {
        return 1;
    }
    mk_dir(cfg->out_dir);
    if(!cfg->summary && (!path_join(a, cap, cfg->out_dir, "summary.json")))
    {
        return 0;
    }
    if(!cfg->funcs && (!path_join(b, cap, cfg->out_dir, "functions.json")))
    {
        return 0;
    }
    if(!cfg->strings && (!path_join(c, cap, cfg->out_dir, "strings.json")))
    {
        return 0;
    }
    if(!cfg->xrefs && (!path_join(d, cap, cfg->out_dir, "xrefs.json")))
    {
        return 0;
    }
    if(!cfg->labels && (!path_join(e, cap, cfg->out_dir, "labels.json")))
    {
        return 0;
    }
    if(!cfg->imports && (!path_join(f, cap, cfg->out_dir, "imports.json")))
    {
        return 0;
    }
    if(!cfg->exports && (!path_join(g, cap, cfg->out_dir, "exports.json")))
    {
        return 0;
    }
    if(!cfg->aot_sections && (!path_join(h, cap, cfg->out_dir, "native_aot_sections.json")))
    {
        return 0;
    }
    if(!cfg->accessors && (!path_join(j, cap, cfg->out_dir, "accessors.json")))
    {
        return 0;
    }
    if(!cfg->ida && (!path_join(k, cap, cfg->out_dir, "ida.py")))
    {
        return 0;
    }
    if(!cfg->summary)
    {
        cfg->summary = a;
    }
    if(!cfg->funcs)
    {
        cfg->funcs = b;
    }
    if(!cfg->strings)
    {
        cfg->strings = c;
    }
    if(!cfg->xrefs)
    {
        cfg->xrefs = d;
    }
    if(!cfg->labels)
    {
        cfg->labels = e;
    }
    if(!cfg->imports)
    {
        cfg->imports = f;
    }
    if(!cfg->exports)
    {
        cfg->exports = g;
    }
    if(!cfg->aot_sections)
    {
        cfg->aot_sections = h;
    }
    if(!cfg->accessors)
    {
        cfg->accessors = j;
    }
    if(!cfg->ida)
    {
        cfg->ida = k;
    }
    return 1;
}

int main(int argc, char** argv)
{
    cfg_t cfg;
    pe_t pe;
    dump_t dump;
    char a[1024];
    char b[1024];
    char c[1024];
    char d[1024];
    char e[1024];
    char f[1024];
    char g[1024];
    char h[1024];
    char j[1024];
    char k[1024];
    int ok = 1;

    if(!parse(argc, argv, &cfg))
    {
        usage();
        return 1;
    }
    if(!set_out(&cfg, a, b, c, d, e, f, g, h, j, k, sizeof(a)))
    {
        fprintf(stderr, "bad output path\n");
        return 1;
    }
    if(!pe_load(cfg.exe, &pe))
    {
        fprintf(stderr, "failed to load pe64: %s\n", cfg.exe);
        return 1;
    }
    dump_init(&dump);
    if(!dump_run(&pe, &dump))
    {
        fprintf(stderr, "dump failed\n");
        dump_free(&dump);
        pe_free(&pe);
        return 1;
    }
    if(!cfg.summary && !cfg.funcs && !cfg.strings && !cfg.xrefs && !cfg.labels && !cfg.imports && !cfg.exports && !cfg.aot_sections && !cfg.accessors && !cfg.ida)
    {
        ok = out_summary("-", &pe, &dump);
    }
    else
    {
        if(cfg.summary)
        {
            ok = out_summary(cfg.summary, &pe, &dump) && ok;
        }
        if(cfg.funcs)
        {
            ok = out_funcs(cfg.funcs, &pe, &dump) && ok;
        }
        if(cfg.strings)
        {
            ok = out_strings(cfg.strings, &pe, &dump) && ok;
        }
        if(cfg.xrefs)
        {
            ok = out_xrefs(cfg.xrefs, &pe, &dump) && ok;
        }
        if(cfg.labels)
        {
            ok = out_labels(cfg.labels, &pe, &dump) && ok;
        }
        if(cfg.imports)
        {
            ok = out_imports(cfg.imports, &pe, &dump) && ok;
        }
        if(cfg.exports)
        {
            ok = out_exports(cfg.exports, &pe, &dump) && ok;
        }
        if(cfg.aot_sections)
        {
            ok = out_aot_sections(cfg.aot_sections, &pe, &dump) && ok;
        }
        if(cfg.accessors)
        {
            ok = out_accessors(cfg.accessors, &pe, &dump) && ok;
        }
        if(cfg.ida)
        {
            ok = out_ida(cfg.ida, &dump) && ok;
        }
    }
    if(cfg.check && (dump.fns.len == 0 || dump.strs.len == 0))
    {
        ok = 0;
    }
    dump_free(&dump);
    pe_free(&pe);
    return ok ? 0 : 2;
}
