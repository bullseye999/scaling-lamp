#!/usr/bin/env python3
# book_engine.py - Ingest, search, and reason from books (PDF / text)

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

class BookEngine:
    """
    Personal knowledge base from books.
    Reads PDFs, chunks them intelligently, stores them searchable.
    The assistant can query any book by topic, chapter, or situation.
    """

    CHUNK_SIZE = 800       # words per chunk
    CHUNK_OVERLAP = 100    # overlap between chunks for context continuity
    MAX_SEARCH_RESULTS = 3

    def __init__(self, vault: CipherVault):
        self.vault     = vault
        self.library   = {}   # title -> metadata
        self.books_dir = "system_books"   # renamed from ciph_books
        os.makedirs(self.books_dir, exist_ok=True)
        self._load_library_index()

    # ─────────────────────────────────────────────
    # INGEST
    # ─────────────────────────────────────────────

    def ingest_pdf(self, filepath: str, title: str = None, author: str = None, category: str = 'general') -> str:
        """
        Read a PDF and store it in the knowledge base.
        Chunks intelligently, stores in vault, indexes for search.
        """
        if not os.path.exists(filepath):
            return f"File not found: {filepath}"

        try:
            import fitz  # pymupdf
        except ImportError:
            return "pymupdf not installed. Run: pip install pymupdf"

        print(f"Reading {filepath}...")

        try:
            doc   = fitz.open(filepath)
            title = title or os.path.basename(filepath).replace('.pdf', '').replace('_', ' ').title()
            author = author or 'Unknown'

            # Extract full text
            full_text = ""
            for page_num, page in enumerate(doc):
                text = page.get_text()
                if text.strip():
                    full_text += f"\n[Page {page_num + 1}]\n{text}"

            doc.close()

            if not full_text.strip():
                return f"No text extracted from {filepath}. May be a scanned image PDF."

            # Generate book ID
            book_id = hashlib.md5(title.encode()).hexdigest()[:8]

            # Chunk the text
            chunks = self._chunk_text(full_text)
            print(f"  {len(chunks)} chunks created from {len(full_text)} characters")

            # Store each chunk in vault
            stored = 0
            for i, chunk in enumerate(chunks):
                key = f"book_{book_id}_chunk_{i:04d}"
                entry = {
                    'book_id':   book_id,
                    'title':     title,
                    'author':    author,
                    'category':  category,
                    'chunk_idx': i,
                    'total':     len(chunks),
                    'text':      chunk,
                    'keywords':  self._extract_keywords(chunk)
                }
                self.vault.set_config(key, json.dumps(entry))
                stored += 1

            # Update library index
            self.library[book_id] = {
                'title':       title,
                'author':      author,
                'category':    category,
                'chunks':      len(chunks),
                'ingested_at': datetime.now().isoformat(),
                'filepath':    filepath,
                'book_id':     book_id,
                'word_count':  len(full_text.split())
            }
            self._save_library_index()

            return (
                f"Book ingested: {title} by {author}. "
                f"{len(chunks)} chunks stored. "
                f"{len(full_text.split())} words indexed. "
                f"The system can now reason from this book."
            )

        except Exception as e:
            return f"Ingestion failed: {str(e)[:80]}"

    def ingest_text(self, text: str, title: str, author: str = 'Unknown', category: str = 'general') -> str:
        """
        Ingest raw text directly — for pasting summaries or excerpts.
        """
        book_id = hashlib.md5(title.encode()).hexdigest()[:8]
        chunks  = self._chunk_text(text)

        for i, chunk in enumerate(chunks):
            key   = f"book_{book_id}_chunk_{i:04d}"
            entry = {
                'book_id':   book_id,
                'title':     title,
                'author':    author,
                'category':  category,
                'chunk_idx': i,
                'total':     len(chunks),
                'text':      chunk,
                'keywords':  self._extract_keywords(chunk)
            }
            self.vault.set_config(key, json.dumps(entry))

        self.library[book_id] = {
            'title':       title,
            'author':      author,
            'category':    category,
            'chunks':      len(chunks),
            'ingested_at': datetime.now().isoformat(),
            'book_id':     book_id,
            'word_count':  len(text.split())
        }
        self._save_library_index()

        return f"Text ingested: {title}. {len(chunks)} chunks stored."

    # ─────────────────────────────────────────────
    # SEARCH
    # ─────────────────────────────────────────────

    def search(self, query: str, book_title: str = None, limit: int = None) -> List[Dict]:
        """
        Search across all books or a specific book.
        Returns relevant chunks ranked by relevance.
        """
        limit       = limit or self.MAX_SEARCH_RESULTS
        query_words = set(query.lower().split())
        results     = []

        # Get all book IDs to search
        if book_title:
            book_ids = [
                bid for bid, meta in self.library.items()
                if book_title.lower() in meta['title'].lower()
            ]
        else:
            book_ids = list(self.library.keys())

        for book_id in book_ids:
            meta   = self.library[book_id]
            chunks = meta['chunks']

            for i in range(chunks):
                key = f"book_{book_id}_chunk_{i:04d}"
                raw = self.vault.get_config(key)
                if not raw:
                    continue

                try:
                    entry = json.loads(raw)
                except Exception:
                    continue

                # Score by keyword overlap
                chunk_words = set(entry['text'].lower().split())
                keywords    = set(entry.get('keywords', []))
                overlap     = len(query_words & (chunk_words | keywords))

                if overlap > 0:
                    results.append({
                        'score':    overlap,
                        'title':    entry['title'],
                        'author':   entry['author'],
                        'chunk':    entry['chunk_idx'],
                        'total':    entry['total'],
                        'text':     entry['text'],
                        'category': entry['category']
                    })

        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:limit]

    def ask_book(self, question: str, book_title: str = None) -> str:
        """
        Ask a question and get an answer grounded in book knowledge.
        Returns relevant passages with source attribution.
        """
        results = self.search(question, book_title=book_title, limit=3)

        if not results:
            if book_title:
                return f"No relevant passages found in '{book_title}' for: {question}"
            return "No relevant passages found in library. Add books with /add-book."

        response_parts = []
        for r in results:
            source  = f"{r['title']} by {r['author']}"
            passage = r['text'][:400].strip()
            response_parts.append(f"From {source}:\n{passage}...")

        return "\n\n".join(response_parts)

    def get_situational_advice(self, situation: str) -> str:
        """
        Given a situation the user is facing, pull relevant wisdom
        from all books in the library.
        """
        results = self.search(situation, limit=3)

        if not results:
            return "Library empty. Add books first with /add-book <path>."

        advice = [f"Relevant knowledge for: {situation}\n"]
        for r in results:
            advice.append(
                f"{r['title']} (relevance: {r['score']}):\n"
                f"{r['text'][:300].strip()}...\n"
            )

        return "\n".join(advice)

    # ─────────────────────────────────────────────
    # LIBRARY MANAGEMENT
    # ─────────────────────────────────────────────

    def list_books(self) -> str:
        if not self.library:
            return "Library empty. Add books with /add-book <filepath>"

        lines = [f"Library — {len(self.library)} books:\n"]
        for book_id, meta in self.library.items():
            lines.append(
                f"  [{meta['category'].upper()}] {meta['title']} — {meta['author']} "
                f"({meta['chunks']} chunks, {meta['word_count']} words)"
            )
        return '\n'.join(lines)

    def remove_book(self, book_title: str) -> str:
        """Remove a book from the library"""
        book_id = None
        for bid, meta in self.library.items():
            if book_title.lower() in meta['title'].lower():
                book_id = bid
                break

        if not book_id:
            return f"Book not found: {book_title}"

        meta   = self.library[book_id]
        chunks = meta['chunks']

        for i in range(chunks):
            key = f"book_{book_id}_chunk_{i:04d}"
            self.vault.set_config(key, '')

        del self.library[book_id]
        self._save_library_index()
        return f"Removed: {meta['title']}"

    def get_book_summary(self, book_title: str) -> str:
        """Get metadata about a specific book"""
        for bid, meta in self.library.items():
            if book_title.lower() in meta['title'].lower():
                return (
                    f"{meta['title']} by {meta['author']} | "
                    f"Category: {meta['category']} | "
                    f"{meta['chunks']} chunks | "
                    f"{meta['word_count']} words | "
                    f"Ingested: {meta['ingested_at'][:10]}"
                )
        return f"Book not found: {book_title}"

    # ─────────────────────────────────────────────
    # MEMORY CONTEXT INJECTION
    # ─────────────────────────────────────────────

    def build_book_context(self, user_input: str) -> str:
        """
        Build book context to inject into the system prompt.
        Automatically surfaces relevant passages when the user talks
        about strategy, power, decisions, or situations.
        """
        if not self.library:
            return ""

        # Only inject if query seems strategic/philosophical
        trigger_words = [
            'how', 'should', 'strategy', 'plan', 'move', 'deal',
            'handle', 'approach', 'power', 'enemy', 'ally', 'trust',
            'money', 'win', 'lose', 'fight', 'negotiate', 'decide',
            'situation', 'problem', 'opportunity', 'risk', 'someone',
            'people', 'person', 'they', 'him', 'her', 'undermine',
            'betray', 'friend', 'partner', 'help', 'need', 'want',
            'think', 'feel', 'believe', 'life', 'work', 'build'
        ]

        input_lower = user_input.lower()
        if not any(w in input_lower for w in trigger_words):
            return ""

        results = self.search(user_input, limit=2)
        if not results:
            return ""

        parts = ["\nBOOK KNOWLEDGE (use this to inform your response):"]
        for r in results:
            parts.append(
                f"- {r['title']}: {r['text'][:200].strip()}..."
            )

        return '\n'.join(parts)

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _chunk_text(self, text: str) -> List[str]:
        """Split text into overlapping chunks"""
        words  = text.split()
        chunks = []
        i      = 0

        while i < len(words):
            chunk_words = words[i:i + self.CHUNK_SIZE]
            chunks.append(' '.join(chunk_words))
            i += self.CHUNK_SIZE - self.CHUNK_OVERLAP

        return chunks

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from a chunk"""
        stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at',
            'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was',
            'are', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
            'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'may', 'might', 'must', 'shall', 'that', 'this', 'these',
            'those', 'it', 'its', 'they', 'their', 'them', 'we', 'our',
            'you', 'your', 'he', 'she', 'his', 'her', 'page', 'chapter'
        }

        words    = text.lower().split()
        keywords = [
            w.strip('.,!?;:()[]"\'') for w in words
            if len(w) > 4 and w not in stopwords and w.isalpha()
        ]

        # Return most frequent meaningful words
        from collections import Counter
        counts = Counter(keywords)
        return [w for w, _ in counts.most_common(15)]

    def _load_library_index(self):
        raw = self.vault.get_config('book_library_index')
        if raw:
            try:
                self.library = json.loads(raw)
            except Exception:
                self.library = {}

    def _save_library_index(self):
        self.vault.set_config('book_library_index', json.dumps(self.library))

    def get_status(self) -> Dict[str, Any]:
        total_chunks = sum(m['chunks'] for m in self.library.values())
        total_words  = sum(m['word_count'] for m in self.library.values())
        return {
            'books_in_library': len(self.library),
            'total_chunks':     total_chunks,
            'total_words':      total_words,
            'categories':       list(set(m['category'] for m in self.library.values())),
            'books_dir':        self.books_dir
        }


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault  = CipherVault()
    engine = BookEngine(vault)

    print("Book Engine ready.")
    print(engine.list_books())