# scripts/ingest_rag_docs.py
"""Ingestion script parsing docs/*.md, generating text chunks, and populating RAG store."""
import os
import logging
from app.rag_store import OneShieldRAGStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ingest-rag-docs")

def main():
    logger.info("🚀 Starting OneShield Security Knowledge Base Document Ingestion...")
    store = OneShieldRAGStore()
    logger.info(f"✅ Ingestion complete. Total security guides loaded: {len(store.docs_cache)}")
    for doc in store.docs_cache:
        logger.info(f"  └─> Ingested: {doc['source']} ({len(doc['content'])} bytes)")

if __name__ == "__main__":
    main()
