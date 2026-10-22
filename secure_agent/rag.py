"""Document RAG for the SECURE agent: chunking, TF-IDF retrieval, citations,
tenant-scoped retrieval and quarantine of instruction-like chunks.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import config
from guardrails import is_untrusted_instruction

CHUNK_WORDS = 80
OVERLAP_WORDS = 20


@dataclass
class Chunk:
    citation: str
    tenant_id: str
    source: str
    heading: str
    text: str
    quarantined: bool = False


def chunk_markdown(text: str, size: int = CHUNK_WORDS, overlap: int = OVERLAP_WORDS) -> list[tuple[str, str]]:
    sections, heading, buf = [], "", []
    for line in text.splitlines():
        if line.startswith("#"):
            if buf:
                sections.append((heading, " ".join(buf)))
            heading, buf = line.lstrip("# ").strip(), []
        elif line.strip():
            buf.append(line.strip())
    if buf:
        sections.append((heading, " ".join(buf)))
    out = []
    for head, body in sections:
        words, start = body.split(), 0
        while start < len(words):
            out.append((head, " ".join(words[start:start + size])))
            if start + size >= len(words):
                break
            start += size - overlap
    return out


class TenantDocIndex:
    """One TF-IDF index per tenant, so a query can never score another tenant's chunks."""

    def __init__(self, docs_dir: Path | None = None):
        docs_dir = docs_dir or config.DOCS_DIR
        self.by_tenant: dict[str, tuple[list[Chunk], TfidfVectorizer, object]] = {}
        for tenant_dir in sorted(p for p in docs_dir.iterdir() if p.is_dir()):
            chunks = []
            for path in sorted(tenant_dir.glob("*.md")):
                for i, (head, text) in enumerate(chunk_markdown(path.read_text(encoding="utf-8"))):
                    chunks.append(Chunk(f"{tenant_dir.name}/{path.name}#c{i}", tenant_dir.name, path.name, head, text,
                                        quarantined=is_untrusted_instruction(f"{head} {text}")))
            vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
            matrix = vec.fit_transform([f"{c.heading} {c.text}" for c in chunks])
            self.by_tenant[tenant_dir.name] = (chunks, vec, matrix)

    def search(self, tenant_id: str, query: str, k: int = 3) -> tuple[list[tuple[Chunk, float]], list[Chunk]]:
        """Returns (safe results, quarantined chunks that matched and were withheld)."""
        if tenant_id not in self.by_tenant:
            return [], []
        chunks, vec, matrix = self.by_tenant[tenant_id]
        scores = cosine_similarity(vec.transform([query]), matrix)[0]
        ranked = [(c, float(s)) for c, s in sorted(zip(chunks, scores), key=lambda x: x[1], reverse=True) if s > 0]
        safe = [(c, s) for c, s in ranked if not c.quarantined][:k]
        withheld = [c for c, s in ranked[: k + 3] if c.quarantined]
        return safe, withheld


_INDEX: TenantDocIndex | None = None


def get_index() -> TenantDocIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = TenantDocIndex()
    return _INDEX


def format_results(results: list[tuple[Chunk, float]]) -> str:
    if not results:
        return "No matching documents for your hospital."
    return "\n".join(
        f'<untrusted_document citation="{c.citation}" heading="{c.heading}">{c.text}</untrusted_document>'
        for c, _ in results
    )
