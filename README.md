# aotrx

AOTRX dumps useful information from 64-bit Windows NativeAOT binaries to JSON.
It finds functions, strings, xrefs, imports, exports, NativeAOT sections, and
simple field accessors.

## Build

Set `AOTRX_HDE_DIR` to MinHook's `src/hde` folder and run:

```powershell
$env:AOTRX_HDE_DIR = "C:\path\to\minhook\src\hde"
.\build-msvc.bat
```

Or use CMake:

```powershell
cmake -S . -B build -DAOTRX_HDE_DIR="C:\path\to\minhook\src\hde"
cmake --build build --config Release
```

HDE is optional, but xrefs are more accurate with it.

## Dump

```powershell
.\build\aotrx.exe dump app.exe -o out
```

This writes:

```text
summary.json
functions.json
strings.json
xrefs.json
labels.json
imports.json
exports.json
native_aot_sections.json
accessors.json
ida.py
```

All addresses are RVAs.

## Query

Index the dump:

```powershell
python query.py index out
```

Common queries:

```powershell
python query.py strings gameplay --db out\aotrx.db
python query.py function 0x41e700 --db out\aotrx.db
python query.py accessors 0x138 --type float --db out\aotrx.db
python query.py symbols pitch --db out\aotrx.db
python query.py path 0x1000 0x2000 --db out\aotrx.db
```

Search the executable directly:

```powershell
python query.py signature app.exe 0x41e700 --length 24
python query.py pattern app.exe "48 8B ?? ??"
```

`python query.py -h` shows every command.
