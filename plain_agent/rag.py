"""Document RAG for the PLAIN agent: chunking, TF-IDF retrieval and citations.

Weaknesses kept on purpose:
  * every tenant's documents are indexed together (no tenant filter);
  * retrieved text is returned raw, so instructions hidden in a document reach the LLM
    with the same authority as everything else (indirect prompt injection).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import config

CHUNK_WORDS = 80
OVERLAP_WORDS = 20


@dataclass
class Chunk:
    citation: str  # e.g. hosp_a/ventilator_pm_sop.md#c2
    tenant_id: str
    source: str
    heading: str
    text: str


def chunk_markdown(text: str, size: int = CHUNK_WORDS, overlap: int = OVERLAP_WORDS) -> list[tuple[str, str]]:
    """Split by markdown headings, then into overlapping word windows. Returns (heading, text)."""
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
        words = body.split()
        start = 0
        while start < len(words):
            out.append((head, " ".join(words[start:start + size])))
            if start + size >= len(words):
                break
            start += size - overlap
    return out


class DocIndex:
    def __init__(self, docs_dir: Path | None = None):
        self.chunks: list[Chunk] = []
        docs_dir = docs_dir or config.DOCS_DIR
        for path in sorted(docs_dir.glob("*/*.md")):
            tenant = path.parent.name
            for i, (head, text) in enumerate(chunk_markdown(path.read_text(encoding="utf-8"))):
                self.chunks.append(Chunk(f"{tenant}/{path.name}#c{i}", tenant, path.name, head, text))
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self.matrix = self.vectorizer.fit_transform([f"{c.heading} {c.text}" for c in self.chunks])

    def search(self, query: str, k: int = 3) -> list[tuple[Chunk, float]]:
        scores = cosine_similarity(self.vectorizer.transform([query]), self.matrix)[0]
        ranked = sorted(zip(self.chunks, scores), key=lambda x: x[1], reverse=True)
        return [(c, float(s)) for c, s in ranked[:k] if s > 0]


_INDEX: DocIndex | None = None


def get_index() -> DocIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = DocIndex()
    return _INDEX


def format_results(results: list[tuple[Chunk, float]]) -> str:
    if not results:
        return "No matching documents."
    return "\n\n".join(f"[{c.citation}] ({c.heading}) {c.text}" for c, _ in results)
