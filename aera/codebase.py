"""Source-code ingestion for AERA.

Walks a LOCAL directory you own or are authorized to test, detects languages
by extension, and streams file contents. Binary files, oversized files, and
dependency directories are skipped.
"""
from __future__ import annotations

import os
from pathlib import Path

LANGUAGE_BY_EXT = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".py": "python",
    ".js": "javascript", ".ts": "javascript", ".mjs": "javascript",
    ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
}
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".cache",
    "build", "dist", ".idea", ".vscode", "target", "vendor",
}
MAX_FILE_BYTES = 512 * 1024


class CodebaseTarget:
    """A local source tree authorized for testing."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.root = Path(path).resolve()
        if not self.root.is_dir():
            raise ValueError(f"Not a directory: {path}")

    def iter_files(self):
        """Yield {'path', 'language', 'text'} for each source file."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                full = Path(dirpath) / filename
                language = LANGUAGE_BY_EXT.get(full.suffix.lower())
                if not language:
                    continue
                try:
                    if full.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = full.read_text(encoding="utf-8", errors="strict")
                except (OSError, UnicodeDecodeError):
                    continue
                yield {
                    "path": str(full.relative_to(self.root)),
                    "language": language,
                    "text": text,
                }

    def stats(self) -> dict:
        by_language: dict[str, int] = {}
        total_lines = 0
        n_files = 0
        for f in self.iter_files():
            by_language[f["language"]] = by_language.get(f["language"], 0) + 1
            total_lines += f["text"].count("\n") + 1
            n_files += 1
        return {
            "root": str(self.root),
            "files": n_files,
            "lines": total_lines,
            "by_language": by_language,
        }
