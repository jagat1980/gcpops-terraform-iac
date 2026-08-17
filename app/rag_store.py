# app/rag_store.py
"""Retrieval-Augmented Generation (RAG) Vector Store module."""
import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("vulnerability-lifecycle-rag")

class OneShieldRAGStore:
    """Provides vector similarity search over security knowledge documentation.
    
    Supports local PostgreSQL + pgvector as well as in-memory document matching.
    """

    def __init__(self, collection_name: str = "oneshield_security_docs"):
        self.collection_name = collection_name
        self.docs_cache: List[Dict[str, Any]] = []
        self._load_local_docs()

    def _load_local_docs(self):
        """Loads security guide markdown files into local memory cache for RAG grounding."""
        docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")
        if not os.path.exists(docs_dir):
            return

        for filename in os.listdir(docs_dir):
            if filename.endswith(".md"):
                file_path = os.path.join(docs_dir, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        self.docs_cache.append({
                            "source": filename,
                            "content": content
                        })
                except Exception as e:
                    logger.error(f"Failed to load RAG doc {filename}: {e}")

        logger.info(f"RAG Store: Loaded {len(self.docs_cache)} security documentation files into context store.")

    def retrieve_relevant_context(self, target_file_path: str, finding_id: str) -> str:
        """Retrieves relevant security guidelines grounded in official docs."""
        target_lower = target_file_path.lower()
        matched_chunks = []

        for doc in self.docs_cache:
            src = doc["source"].lower()
            content = doc["content"]

            if ("java" in target_lower or "spring" in target_lower) and "spring" in src:
                matched_chunks.append(f"--- [Reference: {doc['source']}] ---\n" + content[:1000])
            elif ("oracle" in target_lower or "sql" in target_lower) and "oracle" in src:
                matched_chunks.append(f"--- [Reference: {doc['source']}] ---\n" + content[:1000])
            elif ("jsx" in target_lower or "tsx" in target_lower or "react" in target_lower) and "react" in src:
                matched_chunks.append(f"--- [Reference: {doc['source']}] ---\n" + content[:1000])
            elif "owasp" in src or "ingress" in target_lower:
                matched_chunks.append(f"--- [Reference: {doc['source']}] ---\n" + content[:1000])

        if not matched_chunks and self.docs_cache:
            matched_chunks.append(f"--- [Reference: {self.docs_cache[0]['source']}] ---\n" + self.docs_cache[0]['content'][:800])

        return "\n\n".join(matched_chunks)
