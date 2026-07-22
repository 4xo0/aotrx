#!/usr/bin/env python3

import argparse
import bisect
import json
import mmap
import sqlite3
import struct
import sys
from pathlib import Path


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def load(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def containing_function(starts, ends, rva):
    pos = bisect.bisect_right(starts, rva) - 1
    return starts[pos] if pos >= 0 and rva < ends[pos] else None


def build_index(dump_dir, database):
    functions = load(dump_dir / "functions.json")
    starts = [number(item["rva"]) for item in functions]
    ends = [number(item["end_rva"]) for item in functions]

    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=OFF;
            DROP TABLE IF EXISTS functions;
            DROP TABLE IF EXISTS strings;
            DROP TABLE IF EXISTS xrefs;
            DROP TABLE IF EXISTS accessors;
            DROP TABLE IF EXISTS symbols;
            CREATE TABLE functions (
                rva INTEGER PRIMARY KEY, end_rva INTEGER, size INTEGER,
                refs_in INTEGER, refs_out INTEGER, kind TEXT, name TEXT);
            CREATE TABLE strings (
                rva INTEGER PRIMARY KEY, data_rva INTEGER, text TEXT,
                wide INTEGER, managed INTEGER, refs INTEGER);
            CREATE TABLE xrefs (
                from_rva INTEGER, to_rva INTEGER, kind TEXT,
                from_func INTEGER, to_func INTEGER);
            CREATE TABLE accessors (
                rva INTEGER PRIMARY KEY, field_offset INTEGER, width INTEGER,
                function_size INTEGER, refs_in INTEGER, refs_out INTEGER,
                kind TEXT, value_type TEXT);
            CREATE TABLE symbols (
                rva INTEGER, kind TEXT, name TEXT, detail TEXT);
        """)
        db.executemany(
            "INSERT INTO functions VALUES (?,?,?,?,?,?,?)",
            ((number(x["rva"]), number(x["end_rva"]), x["size"], x["refs_in"],
              x["refs_out"], x["kind"], x["name"]) for x in functions),
        )
        db.executemany(
            "INSERT INTO strings VALUES (?,?,?,?,?,?)",
            (((number(x.get("object_rva", 0)) if x.get("managed") else number(x["rva"])),
              number(x["rva"]), x["text"], int(x["wide"]), int(x.get("managed", False)), x["refs"])
             for x in load(dump_dir / "strings.json")),
        )
        xrefs = load(dump_dir / "xrefs.json")
        db.executemany(
            "INSERT INTO xrefs VALUES (?,?,?,?,?)",
            ((number(x["from_rva"]), number(x["to_rva"]), x["kind"],
              containing_function(starts, ends, number(x["from_rva"])),
              containing_function(starts, ends, number(x["to_rva"]))) for x in xrefs),
        )
        db.executemany(
            "INSERT INTO accessors VALUES (?,?,?,?,?,?,?,?)",
            ((number(x["rva"]), number(x["field_offset"]), x["width"],
              x["function_size"], x["refs_in"], x["refs_out"], x["kind"],
             x["value_type"]) for x in load(dump_dir / "accessors.json")),
        )
        symbols = []
        for x in load(dump_dir / "labels.json"):
            symbols.append((number(x["rva"]), x["kind"], x["name"], ""))
        for x in load(dump_dir / "imports.json"):
            name = x.get("name") or f"ordinal_{x.get('ordinal')}"
            symbols.append((number(x["iat_rva"]), "import", name, x["dll"]))
        for x in load(dump_dir / "exports.json"):
            symbols.append((number(x["rva"]), "export", x["name"], x.get("forwarder") or ""))
        db.executemany("INSERT INTO symbols VALUES (?,?,?,?)", symbols)
        db.executescript("""
            CREATE INDEX xrefs_from ON xrefs(from_func);
            CREATE INDEX xrefs_to ON xrefs(to_rva);
            CREATE INDEX xrefs_to_func ON xrefs(to_func);
            CREATE INDEX accessors_field ON accessors(field_offset, kind, value_type);
            CREATE INDEX strings_text ON strings(text COLLATE NOCASE);
            CREATE INDEX symbols_name ON symbols(name COLLATE NOCASE);
            PRAGMA optimize;
        """)
    print(f"indexed {len(functions):,} functions and {len(xrefs):,} xrefs in {database}")


def hx(value):
    return "-" if value is None else f"0x{value:x}"


def print_rows(rows, columns):
    rows = list(rows)
    if not rows:
        print("no matches")
        return
    rendered = [[hx(v) if name.endswith("rva") or name == "field_offset" else str(v)
                 for name, v in zip(columns, row)] for row in rows]
    widths = [max(len(name), *(len(row[i]) for row in rendered)) for i, name in enumerate(columns)]
    print("  ".join(name.ljust(widths[i]) for i, name in enumerate(columns)))
    for row in rendered:
        print("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))


def query_strings(db, term, limit):
    rows = db.execute("""
        SELECT s.rva, s.refs, s.text, x.from_rva, x.from_func
        FROM strings s LEFT JOIN xrefs x ON x.to_rva=s.rva
        WHERE s.text LIKE ? COLLATE NOCASE
        ORDER BY s.refs DESC, s.rva LIMIT ?
    """, (f"%{term}%", limit))
    print_rows(rows, ("string_rva", "refs", "text", "xref_rva", "function_rva"))


def query_function(db, rva, limit):
    start = db.execute(
        "SELECT rva FROM functions WHERE rva<=? AND end_rva>? ORDER BY rva DESC LIMIT 1",
        (rva, rva)).fetchone()
    if not start:
        print("no containing function")
        return
    start = start[0]
    print_rows(db.execute("SELECT rva,end_rva,size,refs_in,refs_out,kind,coalesce(name,'') FROM functions WHERE rva=?", (start,)),
               ("rva", "end_rva", "size", "refs_in", "refs_out", "kind", "name"))
    print("\ncallers:")
    print_rows(db.execute("""SELECT from_func,from_rva,kind FROM xrefs
        WHERE to_rva=? AND from_func IS NOT NULL AND from_func<>?
          AND kind IN ('call','jump','reloc_fn') ORDER BY from_func LIMIT ?""", (start, start, limit)),
               ("function_rva", "xref_rva", "kind"))
    print("\ncallees/data references:")
    print_rows(db.execute("""
        SELECT x.to_func,x.to_rva,x.kind,coalesce(s.text,'')
        FROM xrefs x LEFT JOIN strings s ON s.rva=x.to_rva
        WHERE x.from_func=? AND x.kind<>'branch'
          AND NOT (x.kind='jump' AND x.to_func=x.from_func)
        ORDER BY x.from_rva LIMIT ?
    """, (start, limit)), ("function_rva", "target_rva", "kind", "text"))


def query_accessors(db, offset, kind, value_type, limit):
    clauses, values = [], []
    if offset is not None:
        clauses.append("field_offset=?")
        values.append(offset)
    if kind:
        clauses.append("kind=?")
        values.append(kind)
    if value_type:
        clauses.append("value_type=?")
        values.append(value_type)
    values.append(limit)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = db.execute(f"""SELECT rva,field_offset,width,kind,value_type,refs_in
        FROM accessors {where} ORDER BY refs_in DESC,rva LIMIT ?""", values)
    print_rows(rows, ("rva", "field_offset", "width", "kind", "value_type", "refs_in"))


def query_symbols(db, term, limit):
    rows = db.execute("""SELECT rva,kind,name,detail FROM symbols
        WHERE name LIKE ? COLLATE NOCASE OR detail LIKE ? COLLATE NOCASE
        ORDER BY kind,name LIMIT ?""", (f"%{term}%", f"%{term}%", limit))
    print_rows(rows, ("rva", "kind", "name", "detail"))


def query_stats(db, limit):
    for title, sql, columns in (
        ("most directly called functions", """SELECT f.rva,count(*),f.refs_in,f.size
            FROM functions f JOIN xrefs x ON x.to_rva=f.rva AND x.kind='call'
            GROUP BY f.rva ORDER BY count(*) DESC LIMIT ?""", ("rva", "calls", "all_refs", "size")),
        ("most referenced strings", "SELECT rva,refs,text FROM strings ORDER BY refs DESC LIMIT ?", ("rva", "refs", "text")),
        ("common accessor fields", "SELECT field_offset,count(*),sum(refs_in) FROM accessors GROUP BY field_offset ORDER BY count(*) DESC LIMIT ?", ("field_offset", "accessors", "refs_in")),
    ):
        print(f"\n{title}:")
        print_rows(db.execute(sql, (limit,)), columns)


def validate_index(db):
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    checks = {
        "functions": db.execute("SELECT count(*) FROM functions").fetchone()[0],
        "strings": db.execute("SELECT count(*) FROM strings").fetchone()[0],
        "xrefs": db.execute("SELECT count(*) FROM xrefs").fetchone()[0],
        "accessors": db.execute("SELECT count(*) FROM accessors").fetchone()[0],
        "bad_xref_sources": db.execute("""SELECT count(*) FROM xrefs x JOIN functions f ON f.rva=x.from_func
            WHERE x.from_rva<f.rva OR x.from_rva>=f.end_rva""").fetchone()[0],
        "bad_xref_targets": db.execute("""SELECT count(*) FROM xrefs x JOIN functions f ON f.rva=x.to_func
            WHERE x.to_rva<f.rva OR x.to_rva>=f.end_rva""").fetchone()[0],
        "orphan_accessors": db.execute("""SELECT count(*) FROM accessors a
            LEFT JOIN functions f ON f.rva=a.rva WHERE f.rva IS NULL""").fetchone()[0],
        "empty_strings": db.execute("SELECT count(*) FROM strings WHERE text='' ").fetchone()[0],
    }
    print(f"sqlite_integrity={integrity}")
    for name, value in checks.items():
        print(f"{name}={value:,}")
    valid = integrity == "ok" and not any(checks[name] for name in (
        "bad_xref_sources", "bad_xref_targets", "orphan_accessors", "empty_strings"))
    print("validation=ok" if valid else "validation=FAILED")
    return valid


def query_path(db, source, target, depth):
    row = db.execute("""
        WITH RECURSIVE walk(node,path,depth) AS (
          SELECT ?, printf('0x%x',?), 0
          UNION ALL
          SELECT x.to_func, path || ' -> ' || printf('0x%x',x.to_func), depth+1
          FROM walk JOIN xrefs x ON x.from_func=walk.node
          WHERE x.to_func IS NOT NULL AND x.kind IN ('call','jump') AND depth < ?
            AND instr(path,printf('0x%x',x.to_func))=0
        ) SELECT path,depth FROM walk WHERE node=? ORDER BY depth LIMIT 1
    """, (source, source, depth, target)).fetchone()
    print(row[0] if row else "no path found")


def pe_sections(image):
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[:2] != b"MZ" or image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    count, optional_size = struct.unpack_from("<H12xH", image, pe + 6)
    optional = pe + 24
    image_base = struct.unpack_from("<Q", image, optional + 24)[0]
    table = optional + optional_size
    sections = []
    for index in range(count):
        off = table + index * 40
        name = bytes(image[off:off + 8]).split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", image, off + 8)
        flags = struct.unpack_from("<I", image, off + 36)[0]
        sections.append((name, rva, virtual_size, raw, raw_size, flags))
    return image_base, sections


def parse_pattern(value):
    tokens = value.replace(",", " ").split()
    values, fixed = [], []
    for token in tokens:
        if token in ("?", "??"):
            values.append(0)
            fixed.append(False)
        else:
            values.append(int(token, 16))
            fixed.append(True)
    if not values:
        raise ValueError("empty pattern")
    return bytes(values), fixed


def scan_pattern(executable, value, limit):
    needle, fixed = parse_pattern(value)
    with executable.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        _, sections = pe_sections(image)
        matches = []
        anchor = next((i for i, item in enumerate(fixed) if item), None)
        if anchor is None:
            raise ValueError("pattern must contain at least one fixed byte")
        for name, rva, _, raw, raw_size, flags in sections:
            if not flags & 0x20000000 or raw_size < len(needle):
                continue
            cursor, end = raw, raw + raw_size - len(needle) + 1
            while cursor < end:
                found = image.find(bytes((needle[anchor],)), cursor + anchor, end + anchor)
                if found < 0:
                    break
                candidate = found - anchor
                if all(not fixed[i] or image[candidate + i] == needle[i] for i in range(len(needle))):
                    matches.append((rva + candidate - raw, name))
                    if len(matches) >= limit:
                        break
                cursor = candidate + 1
            if len(matches) >= limit:
                break
    print_rows(matches, ("rva", "section"))


def make_signature(executable, rva, length):
    with executable.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        _, sections = pe_sections(image)
        for name, section_rva, _, raw, raw_size, _ in sections:
            if section_rva <= rva and rva + length <= section_rva + raw_size:
                offset = raw + rva - section_rva
                data = bytes(image[offset:offset + length])
                pattern = " ".join(f"{byte:02X}" for byte in data)
                print(pattern)
                print(f"section={name} rva=0x{rva:x} length={length}")
                return
    raise ValueError("RVA is not backed by file data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    index = sub.add_parser("index", help="build an index from an aotrx output directory")
    index.add_argument("dump", type=Path)
    index.add_argument("--db", type=Path)
    strings = sub.add_parser("strings", help="find strings and their referencing functions")
    strings.add_argument("term")
    function = sub.add_parser("function", help="show a function's callers and outgoing references")
    function.add_argument("rva", type=lambda x: int(x, 0))
    accessors = sub.add_parser("accessors", help="find exact field accessors by object offset")
    accessors.add_argument("offset", nargs="?", type=lambda x: int(x, 0))
    accessors.add_argument("--kind", choices=("getter", "setter"))
    accessors.add_argument("--type", dest="value_type")
    symbols = sub.add_parser("symbols", help="search imports, exports, and recovered labels")
    symbols.add_argument("term")
    stats = sub.add_parser("stats", help="show high-value analysis statistics")
    validate = sub.add_parser("validate", help="check database integrity and cross-reference invariants")
    path = sub.add_parser("path", help="find a direct-call path between two function RVAs")
    path.add_argument("source", type=lambda x: int(x, 0))
    path.add_argument("target", type=lambda x: int(x, 0))
    path.add_argument("--depth", type=int, default=6)
    pattern = sub.add_parser("pattern", help="scan executable sections for a wildcard byte pattern")
    pattern.add_argument("executable", type=Path)
    pattern.add_argument("pattern", help='hex bytes with ?? wildcards, e.g. "48 8B ?? ??"')
    pattern.add_argument("--limit", type=int, default=50)
    signature = sub.add_parser("signature", help="print exact bytes at an RVA for signature creation")
    signature.add_argument("executable", type=Path)
    signature.add_argument("rva", type=lambda x: int(x, 0))
    signature.add_argument("--length", type=int, default=32)
    for command in (strings, function, accessors, symbols, stats, validate, path):
        command.add_argument("--db", type=Path, default=Path("aotrx.db"))
        command.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    if args.command == "index":
        build_index(args.dump, args.db or args.dump / "aotrx.db")
        return
    if args.command == "pattern":
        scan_pattern(args.executable, args.pattern, args.limit)
        return
    if args.command == "signature":
        make_signature(args.executable, args.rva, args.length)
        return
    with sqlite3.connect(args.db) as db:
        if args.command == "strings":
            query_strings(db, args.term, args.limit)
        elif args.command == "function":
            query_function(db, args.rva, args.limit)
        elif args.command == "accessors":
            query_accessors(db, args.offset, args.kind, args.value_type, args.limit)
        elif args.command == "symbols":
            query_symbols(db, args.term, args.limit)
        elif args.command == "stats":
            query_stats(db, args.limit)
        elif args.command == "validate":
            if not validate_index(db):
                sys.exit(2)
        else:
            query_path(db, args.source, args.target, args.depth)


if __name__ == "__main__":
    main()
