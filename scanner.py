"""Static scanner that flags memory-unsafe code patterns in a GitHub repository.

The repository is downloaded as a zip archive and read entirely in memory.
Nothing from the archive is extracted to disk or executed.

This is a pattern-based (regex) scanner, not a compiler-grade analyzer: it
points a human reviewer at code worth reading, and it will have both false
positives and misses.
"""

import bisect
import io
import json
import os
import re
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass

import fixes

MAX_ARCHIVE_BYTES = 60 * 1024 * 1024    # refuse repos whose zip is bigger than this
MAX_FILE_BYTES = 1024 * 1024            # skip individual source files bigger than this
MAX_TOTAL_SCANNED_BYTES = 150 * 1024 * 1024
MAX_FINDINGS = 2000
CONTEXT_LINES = 2

REPO_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)
SHORT_RE = re.compile(r"^([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})$")

LANG_BY_EXT = {
    ".c": "C", ".h": "C/C++",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".m": "Objective-C", ".mm": "Objective-C++",
    ".rs": "Rust",
    ".go": "Go",
    ".cs": "C#",
    ".py": "Python", ".pyx": "Cython",
    ".zig": "Zig",
}
C_FAMILY = {"C", "C/C++", "C++", "Objective-C", "Objective-C++", "Cython"}

SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "thirdparty", "external", "deps", "test", "tests"}


class ScanError(Exception):
    """A problem the user can act on (bad URL, repo not found, too large)."""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str        # critical | high | medium | low
    languages: frozenset
    pattern: re.Pattern
    title: str
    why: str
    instead: str


def _r(id, severity, langs, pattern, title, why, instead):
    return Rule(id, severity, frozenset(langs), re.compile(pattern), title, why, instead)


RULES = [
    # ---------- C / C++ ----------
    _r("c-gets", "critical", C_FAMILY, r"\bgets\s*\(",
       "gets() reads unbounded input",
       "gets() has no way to know the buffer size, so any input longer than the buffer overflows it. It was removed from the C standard for this reason.",
       "fgets(buf, sizeof buf, stdin)"),
    _r("c-strcpy", "high", C_FAMILY, r"\b(?:strcpy|wcscpy|stpcpy|lstrcpy[AW]?|_tcscpy|_mbscpy)\s*\(",
       "Unbounded string copy",
       "Copies until it finds a terminating NUL, regardless of the destination size. A long or untrusted source overflows the buffer.",
       "strlcpy, snprintf(dst, sizeof dst, \"%s\", src), or strcpy_s"),
    _r("c-strcat", "high", C_FAMILY, r"\b(?:strcat|wcscat|lstrcat[AW]?|_tcscat|_mbscat)\s*\(",
       "Unbounded string append",
       "Appends without checking how much room is left in the destination, a classic buffer overflow.",
       "strlcat or strcat_s, or build the string with snprintf"),
    _r("c-sprintf", "high", C_FAMILY, r"\b(?:sprintf|vsprintf|swprintf|_stprintf|wsprintf[AW]?)\s*\(",
       "Unbounded formatted write",
       "Writes formatted output with no destination size limit, so long arguments overflow the buffer.",
       "snprintf / vsnprintf with sizeof(dst)"),
    _r("c-scanf-s", "high", C_FAMILY, r"\b(?:scanf|sscanf|fscanf|vscanf|vsscanf|vfscanf)\s*\([^;]*\"[^\"]*%s",
       "scanf %s without a width",
       "%s with no field width reads as many characters as the input contains, overflowing the destination buffer.",
       "Give a width (\"%63s\" for a 64-byte buffer) or use fgets and parse"),
    _r("c-format-string", "high", C_FAMILY,
       r"\b(?:printf|vprintf)\s*\(\s*[A-Za-z_][\w\->\.\[\]]*\s*\)"
       r"|\b(?:fprintf|syslog|sprintf)\s*\([^,()\"]+,\s*[A-Za-z_][\w\->\.\[\]]*\s*\)"
       r"|\bsnprintf\s*\([^,()\"]+,[^,()\"]+,\s*[A-Za-z_][\w\->\.\[\]]*\s*\)",
       "Format string from a variable",
       "If the format argument can contain user data, %n and %s specifiers let an attacker read or write memory.",
       "Pass a literal format: printf(\"%s\", msg)"),
    _r("c-memcpy", "medium", C_FAMILY, r"\b(?:memcpy|memmove|wmemcpy|CopyMemory|RtlCopyMemory|bcopy)\s*\(",
       "Raw memory copy",
       "Safe only if the length is checked against both buffers. A length taken from input or computed with arithmetic is a common overflow source.",
       "Verify len <= sizeof(dst) right before the call, or use memcpy_s"),
    _r("c-strncpy", "medium", C_FAMILY, r"\b(?:strncpy|wcsncpy|strncat|wcsncat)\s*\(",
       "strncpy / strncat size pitfalls",
       "strncpy does not NUL-terminate when the source is too long, and strncat's size argument is the space left, not the buffer size. Both are frequently misused.",
       "strlcpy / strlcat, or snprintf"),
    _r("c-alloca", "medium", C_FAMILY, r"\b(?:alloca|_alloca|_malloca)\s*\(",
       "Stack allocation with a variable size",
       "alloca never fails gracefully: a large or attacker-controlled size silently overruns the stack.",
       "malloc with a size check, or a fixed-size array with a bounds check"),
    _r("c-vla", "low", C_FAMILY, r"^\s*(?:unsigned\s+|signed\s+|const\s+)?(?:char|int|short|long|float|double|uint\d+_t|int\d+_t|size_t|u?int)\s+\w+\s*\[\s*[a-z_]\w*\s*\]\s*;",
       "Variable-length array",
       "An array sized by a runtime variable lives on the stack; a large value overflows the stack with no error.",
       "Heap-allocate with an explicit size check"),
    _r("c-realloc-self", "medium", C_FAMILY, r"\b(\w+)\s*=\s*realloc\s*\(\s*\1\b",
       "realloc result assigned to the same pointer",
       "If realloc fails it returns NULL and the original block leaks; code that then uses the pointer dereferences NULL.",
       "Assign to a temporary, check it, then replace the original"),
    _r("c-malloc-mul", "medium", C_FAMILY, r"\bmalloc\s*\(\s*[^)]*\w\s*\*\s*\w[^)]*\)",
       "Multiplication inside malloc size",
       "n * size can overflow and wrap to a small number, so the buffer ends up much smaller than the code later writes into.",
       "calloc(n, size), or check for overflow before multiplying"),
    _r("c-free", "low", C_FAMILY, r"\bfree\s*\(\s*[A-Za-z_][\w\->\.]*\s*\)\s*;(?![^\n]*=\s*NULL)",
       "free() without clearing the pointer",
       "A pointer left dangling after free() can be used again (use-after-free) or freed twice. Worth checking ownership on this path.",
       "Set the pointer to NULL after freeing, or use RAII / smart pointers in C++"),
    _r("cpp-reinterpret", "low", {"C++", "C/C++", "Objective-C++"}, r"\breinterpret_cast\s*<",
       "reinterpret_cast",
       "Reinterprets memory as an unrelated type; size or alignment mismatches cause out-of-bounds reads or undefined behavior.",
       "static_cast, std::bit_cast, or memcpy into the target type"),

    # ---------- Rust ----------
    _r("rs-unsafe", "medium", {"Rust"}, r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)",
       "unsafe Rust",
       "Inside unsafe the compiler stops enforcing memory safety; correctness depends on the author's reasoning.",
       "Check for a SAFETY comment that justifies the invariants, or replace with a safe API"),
    _r("rs-transmute", "high", {"Rust"}, r"\b(?:mem::)?transmute(?:_copy)?\s*(?:::<[^>]*>)?\s*\(",
       "mem::transmute",
       "Reinterprets bits as another type with no checks, an easy route to invalid values and undefined behavior.",
       "from_ne_bytes / to_ne_bytes, as casts, or the bytemuck crate"),
    _r("rs-raw-parts", "medium", {"Rust"}, r"\bfrom_raw_parts(?:_mut)?\s*\(",
       "Slice from raw pointer and length",
       "The length is trusted completely; a wrong value reads or writes outside the allocation.",
       "Keep the original slice, or verify the pointer and length invariants"),
    _r("rs-unchecked", "medium", {"Rust"}, r"\.(?:get_unchecked(?:_mut)?|unwrap_unchecked)\s*\(|\bset_len\s*\(",
       "Unchecked indexing or length",
       "Skips the bounds or validity check that makes Rust memory-safe; an out-of-range value is undefined behavior.",
       "Use get() / indexing with bounds checks unless profiling proves the need"),

    # ---------- Go ----------
    _r("go-unsafe", "medium", {"Go"}, r"\bunsafe\.(?:Pointer|Slice|String|StringData|SliceData|Add)\b",
       "Go unsafe package",
       "Bypasses Go's type and bounds safety; mistakes cause memory corruption that the garbage collector can't protect against.",
       "Use encoding/binary or typed conversions instead"),
    _r("go-cgo", "low", {"Go"}, r"^\s*import\s+\"C\"",
       "cgo boundary",
       "Code reached through cgo is C, with none of Go's memory safety, and pointers crossing the boundary have strict rules.",
       "Review the C side with the same care as C code"),

    # ---------- C# ----------
    _r("cs-unsafe", "medium", {"C#"}, r"\bunsafe\b|\bstackalloc\b|\bfixed\s*\(",
       "C# unsafe code",
       "Pointer code in unsafe blocks is not bounds-checked by the runtime.",
       "Span<T> and Memory<T> give the same performance with bounds checks"),
    _r("cs-marshal", "low", {"C#"}, r"\bMarshal\.(?:Copy|PtrToStructure|WriteInt\d*|ReadInt\d*|AllocHGlobal)\b",
       "Manual marshaling",
       "Copies to and from native memory using caller-supplied sizes and offsets.",
       "Check sizes against the native buffer, or use SafeHandle wrappers"),

    # ---------- Python ----------
    _r("py-ctypes", "low", {"Python"}, r"\bctypes\.(?:memmove|memset|cast|string_at|create_string_buffer|c_char_p|addressof|pointer|POINTER)\b",
       "ctypes raw memory access",
       "ctypes calls into native memory with no bounds checks, so a wrong size or pointer crashes or corrupts the process.",
       "Prefer a typed binding (cffi with declared sizes) and validate lengths"),

    # ---------- Zig ----------
    _r("zig-ptrcast", "medium", {"Zig"}, r"@(?:ptrCast|intToPtr|ptrFromInt|alignCast)\b",
       "Zig pointer cast",
       "Unchecked pointer casts can create misaligned or dangling pointers.",
       "Use slices and std.mem helpers where possible"),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_repo(text):
    """Return (owner, repo) from a GitHub URL or 'owner/repo', or raise ScanError."""
    text = (text or "").strip()
    m = REPO_RE.match(text) or SHORT_RE.match(text)
    if not m:
        raise ScanError("Enter a GitHub repository as https://github.com/owner/repo or owner/repo.")
    return m.group(1), m.group(2)


def _get(url, accept=None, limit=None, on_bytes=None):
    headers = {"User-Agent": "repo-memory-scanner"}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if limit is None:
                return resp.read()
            try:
                length = int(resp.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if on_bytes:
                on_bytes(0, length)
            chunks, size = [], 0
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ScanError(f"This repository is larger than {limit // (1024 * 1024)} MB, which is the scan limit.")
                chunks.append(chunk)
                if on_bytes:
                    on_bytes(size, length)
            return b"".join(chunks)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ScanError("Repository not found. Check the name, or note that private repos need a GITHUB_TOKEN on the server.")
        if e.code == 429 or (e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0"):
            raise ScanError("GitHub's rate limit was hit. Wait a few minutes, or set GITHUB_TOKEN on the server to raise the limit.")
        if e.code == 403:
            raise ScanError("GitHub refused the request (403). If the repo is private, the server needs a GITHUB_TOKEN with access to it.")
        raise ScanError(f"GitHub returned an error ({e.code}).")
    except urllib.error.URLError:
        raise ScanError("Couldn't reach GitHub. Try again in a moment.")


def fetch_repo(owner, repo, report=None):
    report = report or (lambda **kw: None)
    report(phase="looking_up")
    meta = json.loads(_get(f"https://api.github.com/repos/{owner}/{repo}", accept="application/vnd.github+json"))
    branch = meta.get("default_branch") or "main"
    if meta.get("size", 0) == 0 and not meta.get("pushed_at"):
        raise ScanError("This repository is empty.")

    # GitHub usually streams the zip without a Content-Length, so fall back to
    # the repo's reported size (KB, including history) as a rough estimate.
    # The page treats an estimate as "about" and never lets the bar reach the
    # end of the download step on an estimate alone.
    guess = min(int(meta.get("size") or 0) * 1024, MAX_ARCHIVE_BYTES)
    report(phase="downloading", bytes=0, expected=guess, exact=False)

    def on_bytes(n, length):
        if length:
            report(bytes=n, expected=length, exact=True)
        else:
            report(bytes=n)

    archive = _get(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}",
                   limit=MAX_ARCHIVE_BYTES, on_bytes=on_bytes)
    return branch, archive


def _is_comment(line):
    s = line.lstrip()
    return s.startswith(("//", "/*", "*", "#")) and not s.startswith(("#include", "#define", "#if"))


# ---------------------------------------------------------------------------
# Fast path: each rule has keywords that must appear on any line it can
# match. Each keyword is searched across the whole file in C (a plain
# substring search, the fastest thing Python's regex engine does), and the
# full rule patterns then run only on the lines with a hit. Keywords are a
# loose superset on purpose: an extra hit costs a little time, a missing one
# would hide a finding.
# ---------------------------------------------------------------------------
TRIGGERS = {
    "c-gets": ["gets"],
    "c-strcpy": ["cpy"],
    "c-strcat": ["cat"],
    "c-sprintf": ["printf"],
    "c-scanf-s": ["scanf"],
    "c-format-string": ["printf", "syslog"],
    "c-memcpy": ["memcpy", "memmove", "CopyMemory", "bcopy"],
    "c-strncpy": ["cpy", "cat"],
    "c-alloca": ["alloca"],
    "c-vla": [re.compile(r"\][ \t]*;")],
    "c-realloc-self": ["realloc"],
    "c-malloc-mul": ["malloc"],
    "c-free": ["free"],
    "cpp-reinterpret": ["reinterpret_cast"],
    "rs-unsafe": ["unsafe"],
    "rs-transmute": ["transmute"],
    "rs-raw-parts": ["from_raw_parts"],
    "rs-unchecked": ["_unchecked", "set_len"],
    "go-unsafe": ["unsafe."],
    "go-cgo": ['"C"'],
    "cs-unsafe": ["unsafe", "stackalloc", "fixed"],
    "cs-marshal": ["Marshal."],
    "py-ctypes": ["ctypes."],
    "zig-ptrcast": ["@ptrCast", "@intToPtr", "@ptrFromInt", "@alignCast"],
}
assert set(TRIGGERS) == {r.id for r in RULES}, "every rule needs a trigger"

_LANG_PLAN = {}  # lang -> ([trigger regexes], [rules])
_NL = re.compile("\n")


def _plan(lang):
    if lang not in _LANG_PLAN:
        rules = [r for r in RULES if lang in r.languages]
        trigs = {}
        for r in rules:
            for t in TRIGGERS[r.id]:
                pat = t if isinstance(t, re.Pattern) else re.compile(re.escape(t))
                trigs[pat.pattern] = pat
        _LANG_PLAN[lang] = (list(trigs.values()), rules)
    return _LANG_PLAN[lang]


def scan_file(path, lang, text, owner, repo, branch):
    """Scan one file's text. Returns (line_count, findings)."""
    lines = text.split("\n")
    trigs, rules = _plan(lang)
    if not rules:
        return len(lines), []

    # Map trigger hits to line indexes via a sorted list of newline offsets.
    hits = sorted({m.start() for t in trigs for m in t.finditer(text)})
    if not hits:
        return len(lines), []
    newlines = [m.start() for m in _NL.finditer(text)]
    candidates = {bisect.bisect_left(newlines, pos) for pos in hits}

    findings = []
    for i in sorted(candidates):
        line = lines[i].rstrip("\r")
        if len(line) > 1000 or _is_comment(line):
            continue
        for rule in rules:
            if rule.pattern.search(line):
                start = max(0, i - CONTEXT_LINES)
                end = min(len(lines), i + CONTEXT_LINES + 1)
                findings.append({
                    "rule": rule.id,
                    "severity": rule.severity,
                    "title": rule.title,
                    "why": rule.why,
                    "instead": rule.instead,
                    "language": lang,
                    "path": path,
                    "line": i + 1,
                    "snippet": [{"n": n + 1, "text": lines[n].rstrip("\r")[:300]} for n in range(start, end)],
                    "url": f"https://github.com/{owner}/{repo}/blob/{branch}/{path}#L{i + 1}",
                    "fix": fixes.suggest(rule.id, lang, lines, i) if rule.severity in ("critical", "high") else None,
                })
    return len(lines), findings


def _scan_batch(batch, owner, repo, branch):
    """Worker entry point for a process pool: scan several files."""
    return [(path, lang) + scan_file(path, lang, text, owner, repo, branch) for path, lang, text in batch]


def _worker_count():
    try:
        return max(1, int(os.environ.get("SCAN_WORKERS", "1")))
    except ValueError:
        return 1


def list_source_files(zf, include_tests=False):
    """Pick the scannable files out of a repo archive."""
    skip = SKIP_DIRS if not include_tests else SKIP_DIRS - {"test", "tests"}
    picked, total_bytes, truncated = [], 0, False
    for info in zf.infolist():
        if info.is_dir() or info.file_size > MAX_FILE_BYTES:
            continue
        # Archive paths look like "repo-branch/src/x.c"; drop the top folder.
        parts = info.filename.split("/", 1)
        if len(parts) < 2:
            continue
        path = parts[1]
        if {d.lower() for d in path.split("/")[:-1]} & skip:
            continue
        lang = LANG_BY_EXT.get(os.path.splitext(path)[1].lower())
        if not lang:
            continue
        total_bytes += info.file_size
        if total_bytes > MAX_TOTAL_SCANNED_BYTES:
            truncated = True
            break
        picked.append((info, path, lang))
    return picked, truncated


def scan_archive(archive_bytes, owner, repo, branch, include_tests=False, progress=None, workers=None,
                 on_finishing=None):
    """Scan a zip archive. progress(done, total, last_path) is called as files
    finish; on_finishing(n_findings) when scanning ends and results are built."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile:
        raise ScanError("GitHub returned an archive that couldn't be read.")

    files, truncated = list_source_files(zf, include_tests)
    total = len(files)
    workers = workers or _worker_count()
    findings, lines_scanned, lang_counts, done = [], 0, {}, 0
    if progress:
        progress(0, total, None)

    def read(item):
        info, path, lang = item
        return path, lang, zf.read(info).decode("utf-8", errors="replace")

    def collect(results):
        nonlocal lines_scanned, done
        path = None
        for path, lang, n_lines, found in results:
            lines_scanned += n_lines
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
            findings.extend(found)
            done += 1
        if progress:
            progress(done, total, path)

    if workers <= 1 or total < 200:
        for k in range(0, total, 50):
            collect(_scan_batch([read(f) for f in files[k:k + 50]], owner, repo, branch))
    else:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        batch_size = max(20, min(200, total // (workers * 8) or 1))
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_scan_batch, [read(f) for f in files[k:k + batch_size]], owner, repo, branch)
                for k in range(0, total, batch_size)
            ]
            for fut in as_completed(futures):
                collect(fut.result())

    if on_finishing:
        on_finishing(len(findings))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["path"], f["line"]))
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]   # keeps the most severe, since it's sorted
        truncated = True
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    return {
        "repo": f"{owner}/{repo}",
        "branch": branch,
        "files_scanned": done,
        "lines_scanned": lines_scanned,
        "languages": lang_counts,
        "counts": counts,
        "truncated": truncated,
        "findings": findings,
    }


def scan(repo_text, include_tests=False, report=None):
    """Download and scan a repo. report(**fields) receives progress updates."""
    report = report or (lambda **kw: None)
    owner, repo = parse_repo(repo_text)
    branch, archive = fetch_repo(owner, repo, report=report)
    report(phase="unpacking", bytes=len(archive))
    return scan_archive(
        archive, owner, repo, branch, include_tests=include_tests,
        progress=lambda d, t, path: report(phase="scanning", done=d, total=t, current=path),
        on_finishing=lambda n: report(phase="finishing", findings=n),
    )
