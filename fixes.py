"""Suggested patches for high-risk C/C++ findings.

Each fixer rewrites the flagged line into a bounded equivalent. Bounded calls
need the destination buffer's size, and `sizeof(x)` is only correct when x is
an array (for a pointer it silently gives 4 or 8). So a fix only uses
`sizeof(x)` when it finds `x` declared as an array earlier in the same file,
outside a parameter list. Otherwise it writes a placeholder like
`<size of buf>`, which won't compile until someone fills in the real size.

These are suggestions for a reviewer, not automatic rewrites: behavior
changes (like truncation instead of overflow) are described in each note.
"""

import re

C_LANGS = {"C", "C/C++", "C++", "Objective-C", "Objective-C++"}
STRING_LIT = re.compile(r'^(?:[LuU]|u8)?"')


# ---------- small C parsing helpers ----------

def find_call(line, names, start=0):
    """Find the first call to one of `names`. Returns (name, start, end, args)
    where end is just past the closing paren, or None."""
    pat = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\s*\(")
    m = pat.search(line, start)
    if not m:
        return None
    i, depth, args, cur, quote = m.end(), 1, [], [], None
    while i < len(line):
        c = line[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(line):
                cur.append(line[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return m.group(1), m.start(), i + 1, ([] if args == [""] else args)
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    return None  # call continues on the next line; don't guess


def is_statement(line, start, end):
    """True if the call is the whole statement: only whitespace before, ';' after."""
    return line[:start].strip() == "" and line[end:].strip() == ";"


def array_size(name, lines, before):
    """Return the declared element count expression if `name` is declared as an
    array earlier in the file (and not as a function parameter), else None."""
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    decl = re.compile(r"\b(?:char|wchar_t|TCHAR|u?int8_t|unsigned\s+char|signed\s+char)\s+(?:[^;=()]*,\s*)?\**\s*"
                      + re.escape(name) + r"\s*\[\s*([^\]]+?)\s*\]")
    for i in range(before, -1, -1):
        line = lines[i]
        m = decl.search(line)
        if m:
            head = line[:m.start()]
            if head.count("(") > head.count(")"):
                return None      # parameter: decays to a pointer
            return m.group(1)
        # A pointer declaration of the same name closer to the use wins.
        if re.search(r"\*\s*" + re.escape(name) + r"\s*[;=,)]", line):
            return None
    return None


def size_expr(name, lines, before):
    if array_size(name, lines, before) is not None:
        return f"sizeof({name})", True
    return f"<size of {name}>", False


def indent_of(line):
    return line[: len(line) - len(line.lstrip())]


# ---------- fixers: each returns (new_lines, note, confirmed) or None ----------

def fix_gets(line, lines, i):
    call = find_call(line, ["gets"])
    if not call or len(call[3]) != 1:
        return None
    _, s, e, (dst,) = call
    size, ok = size_expr(dst, lines, i)
    new = line[:s] + f"fgets({dst}, {size}, stdin)" + line[e:]
    out = [new]
    note = "fgets stops at the buffer size. Unlike gets it keeps the trailing newline"
    if is_statement(line, s, e):
        out.append(f"{indent_of(line)}{dst}[strcspn({dst}, \"\\n\")] = '\\0';")
        note += ", so the added line strips it (needs <string.h>)."
    else:
        note += "; strip it with strcspn if the code expects none."
    return out, note, ok


def fix_strcpy(line, lines, i):
    call = find_call(line, ["strcpy"])
    if not call or len(call[3]) != 2 or not is_statement(line, call[1], call[2]):
        return None
    _, s, e, (dst, src) = call
    size, ok = size_expr(dst, lines, i)
    new = line[:s] + f'snprintf({dst}, {size}, "%s", {src})' + line[e:]
    return [new], "snprintf never writes past the size and always NUL-terminates. Long input is truncated instead of overflowing.", ok


def fix_strcat(line, lines, i):
    call = find_call(line, ["strcat"])
    if not call or len(call[3]) != 2:
        return None
    _, s, e, (dst, src) = call
    size, ok = size_expr(dst, lines, i)
    new = line[:s] + f"strncat({dst}, {src}, {size} - strlen({dst}) - 1)" + line[e:]
    return [new], "The third argument is the room left in the buffer, minus one for the NUL. Long input is truncated.", ok


def fix_sprintf(line, lines, i):
    call = find_call(line, ["sprintf", "vsprintf"])
    if not call or len(call[3]) < 2:
        return None
    name, s, e, args = call
    dst, fmt, rest = args[0], args[1], args[2:]
    size, ok = size_expr(dst, lines, i)
    bounded = "snprintf" if name == "sprintf" else "vsnprintf"
    note = f"{bounded} stops at the size and NUL-terminates; its return value is the length it wanted, so compare it to the size to detect truncation."
    if name == "sprintf" and not rest and not STRING_LIT.match(fmt):
        new_args = [dst, size, '"%s"', fmt]
        note += " The variable format string is also passed through \"%s\"."
    else:
        new_args = [dst, size, fmt] + rest
    return [line[:s] + f"{bounded}({', '.join(new_args)})" + line[e:]], note, ok


def fix_format_string(line, lines, i):
    # Position of the format argument for each function.
    fmt_pos = {"printf": 0, "vprintf": 0, "fprintf": 1, "syslog": 1, "snprintf": 2}
    call = find_call(line, list(fmt_pos))
    if not call:
        return fix_sprintf(line, lines, i)   # sprintf(buf, var) is fixed there
    name, s, e, args = call
    k = fmt_pos[name]
    if len(args) != k + 1 or STRING_LIT.match(args[k]):
        return None
    if name == "vprintf":
        return None
    new_args = args[:k] + ['"%s"', args[k]]
    return ([line[:s] + f"{name}({', '.join(new_args)})" + line[e:]],
            "Passing the text as an argument to a literal \"%s\" means % characters in it are printed, not interpreted.", True)


_SPEC = re.compile(r"%(?!%)(\*?)(\d*)(hh|h|ll|l|L|z|j|t)?([a-zA-Z\[])")


def fix_scanf(line, lines, i):
    call = find_call(line, ["scanf", "sscanf", "fscanf"])
    if not call:
        return None
    name, s, e, args = call
    k = 0 if name == "scanf" else 1
    if len(args) <= k or not STRING_LIT.match(args[k]):
        return None
    fmt, dests = args[k], args[k + 1:]
    out, pos, arg_i, ok_all, changed = [], 0, 0, True, False
    for m in _SPEC.finditer(fmt):
        suppress, width, _, conv = m.groups()
        out.append(fmt[pos:m.start()])
        spec = m.group(0)
        if not suppress:
            if conv == "s" and not width and arg_i < len(dests):
                dst = dests[arg_i].lstrip("&").strip()
                n = array_size(dst, lines, i)
                if n is not None and n.isdigit() and int(n) > 1:
                    spec = f"%{int(n) - 1}{m.group(3) or ''}s"
                else:
                    spec = f"%<width for {dst}>s"
                    ok_all = False
                changed = True
            arg_i += 1
        out.append(spec)
        pos = m.end()
    out.append(fmt[pos:])
    if not changed:
        return None
    new_args = args[:k] + ["".join(out)] + dests
    return ([line[:s] + f"{name}({', '.join(new_args)})" + line[e:]],
            "The width caps how many characters are read: one less than the buffer size, leaving room for the NUL.", ok_all)


FIXERS = {
    "c-gets": fix_gets,
    "c-strcpy": fix_strcpy,
    "c-strcat": fix_strcat,
    "c-sprintf": fix_sprintf,
    "c-format-string": fix_format_string,
    "c-scanf-s": fix_scanf,
}


def suggest(rule_id, lang, lines, i):
    """Return a fix dict for finding at line index i, or None."""
    fixer = FIXERS.get(rule_id)
    if not fixer or lang not in C_LANGS:
        return None
    line = lines[i].rstrip("\r")
    if "__VA_ARGS__" in line or "..." in line:
        return None   # forwarding macros: the format comes from the caller
    try:
        res = fixer(line, lines, i)
    except Exception:
        return None
    if not res:
        return None
    new_lines, note, confirmed = res
    if new_lines == [line]:
        return None
    if not confirmed:
        note += " Replace the <…> placeholder with the real buffer size: the buffer isn't declared as an array in this file, so sizeof would be wrong."
    return {"before": line, "after": new_lines, "note": note, "confirmed": confirmed}
