import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import COMPILED_PATTERNS, Pattern, SEVERITY_ORDER

# Extensions that are never worth scanning (binary / media / archives)
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".pyc", ".pyo", ".class",
    ".ttf", ".woff", ".woff2", ".eot",
    ".db", ".sqlite", ".sqlite3",
    ".lock",  # package lock files are huge and almost never contain secrets
}

# Directories to always skip
SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".tox", "venv", ".venv", "env", ".env_dir",
    "dist", "build", ".next", ".nuxt",
    ".idea", ".vscode",
}

# Max file size to scan (5 MB)
MAX_FILE_BYTES = 5 * 1024 * 1024


@dataclass
class Finding:
    file: str
    line_number: int
    line: str
    pattern: Pattern
    match: str
    context_before: list = field(default_factory=list)
    context_after: list = field(default_factory=list)


@dataclass
class ScanResult:
    findings: list
    files_scanned: int
    files_skipped: int
    errors: list  # list of (path, reason) tuples


def _load_gitignore_patterns(root):
    """Load gitignore patterns from the root directory."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    patterns = []
    with open(gitignore, errors="replace") as f:
        for raw in f.readlines():
            line = raw.strip()
            if line == "" or line.startswith("#"):
                continue
            # Convert basic glob to regex
            escaped = re.escape(line.lstrip("/"))
            escaped = escaped.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
            try:
                patterns.append(re.compile(escaped))
            except re.error:
                pass
    return patterns


def _is_gitignored(path, root, gi_patterns):
    rel = str(path.relative_to(root))
    # Check if any pattern matches the relative path
    for p in gi_patterns:
        if p.search(rel):
            return True
    return False


def _is_binary(path):
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    # Sniff first 8 KB for null bytes
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _iter_files(root, include_exts, exclude_exts, respect_gitignore, gi_patterns):
    """Get all files to scan and return them as a list."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune unwanted directories in-place
        dirs_to_keep = []
        for d in dirnames:
            if d not in SKIP_DIRS and not d.startswith("."):
                dirs_to_keep.append(d)
        dirnames[:] = dirs_to_keep

        for fname in filenames:
            fpath = Path(os.path.join(dirpath, fname))
            ext = fpath.suffix.lower()

            if ext in BINARY_EXTENSIONS or ext in exclude_exts:
                continue
            if include_exts != None and ext not in include_exts:
                continue
            if respect_gitignore and _is_gitignored(fpath, root, gi_patterns):
                continue

            files.append(fpath)
    return files


def _mask(value):
    """Show first 4 chars then mask the rest."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 4)


def scan_file(path, context_lines=2):
    if path.stat().st_size > MAX_FILE_BYTES or _is_binary(path):
        return []

    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError:
        return []

    lines = text.splitlines()
    findings = []
    seen = set()  # deduplicate

    for pattern, compiled in COMPILED_PATTERNS:
        for m in compiled.finditer(text):
            # Map character offset to line number
            line_number = text.count("\n", 0, m.start()) + 1
            if line_number <= len(lines):
                line = lines[line_number - 1]
            else:
                line = ""

            # Use the first capture group as the secret value (if any), else full match
            if m.lastindex != None and m.lastindex >= 1:
                secret_val = m.group(1)
            else:
                secret_val = m.group(0)

            dedup_key = (pattern.name, line_number, secret_val[:8])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            ctx_start = max(0, line_number - 1 - context_lines)
            ctx_end = min(len(lines), line_number + context_lines)

            finding = Finding(
                file=str(path),
                line_number=line_number,
                line=line.rstrip(),
                pattern=pattern,
                match=_mask(secret_val),
                context_before=lines[ctx_start : line_number - 1],
                context_after=lines[line_number:ctx_end],
            )
            findings.append(finding)

    return findings


def scan(path, include_exts=None, exclude_exts=None, min_severity="low", respect_gitignore=True, context_lines=2):
    root = Path(path).resolve()

    if exclude_exts == None:
        exclude_exts = set()

    if respect_gitignore:
        gi_patterns = _load_gitignore_patterns(root)
    else:
        gi_patterns = []

    min_sev_rank = SEVERITY_ORDER.get(min_severity, 3)

    findings = []
    files_scanned = 0
    files_skipped = 0
    errors = []

    if root.is_file():
        file_list = [root]
    else:
        file_list = _iter_files(root, include_exts, exclude_exts, respect_gitignore, gi_patterns)

    for fpath in file_list:
        try:
            if _is_binary(fpath):
                files_skipped += 1
                continue
            file_findings = scan_file(fpath, context_lines=context_lines)
            files_scanned += 1
            # Only add findings that meet the minimum severity
            for f in file_findings:
                if SEVERITY_ORDER.get(f.pattern.severity, 3) <= min_sev_rank:
                    findings.append(f)
        except Exception as exc:
            errors.append((str(fpath), str(exc)))
            files_skipped += 1

    # Sort: critical first, then by file + line
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.pattern.severity, 3), f.file, f.line_number)
    )

    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        errors=errors,
    )
