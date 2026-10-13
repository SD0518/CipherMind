"""
MITRE ATT&CK Cyber Knowledge Base

This knowledge base processes MITRE ATT&CK techniques from techniques.json and provides:
- Semantic search using google/embeddinggemma-300m embeddings
- Cross-encoder reranking using cross-encoder/ms-marco-MiniLM-L6-v2
- Hybrid search combining ChromaDB (semantic) and BM25 (keyword)
- Multi-query search with Reciprocal Rank Fusion (RRF)
- Metadata filtering by tactics, platforms, and other technique attributes
"""

import os
import json
import pickle
from typing import List, Dict, Optional, Any
from pathlib import Path
from collections import defaultdict

from langchain.schema import Document
from langchain.retrievers import EnsembleRetriever
from langchain_community.retrievers import BM25Retriever
from langchain_core.runnables import ConfigurableField
from langchain.retrievers.document_compressors import CrossEncoderReranker
from langchain_community.cross_encoders import HuggingFaceCrossEncoder

import torch

from nltk.tokenize import word_tokenize
import nltk

nltk.download("punkt_tab")

# Use newest import paths for langchain
try:
    from langchain_chroma import Chroma
except ImportError:
    from langchain_community.vectorstores import Chroma

# Use HuggingFaceEmbeddings for google/embeddinggemma-300m
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings


class CyberKnowledgeBase:
    """MITRE ATT&CK knowledge base with semantic search and reranking"""

    def __init__(self, embedding_model: str = "google/embeddinggemma-300m"):
        """
        Initialize the cyber knowledge base

        Args:
            embedding_model: Embedding model to use for semantic search
        """
        print(f"[INFO] Initializing CyberKnowledgeBase with {embedding_model}")

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        # self.device = "cpu"
        print(f"[INFO] Using device: {self.device}")

        # Initialize embeddings with GPU support and trust_remote_code
        model_kwargs = {"device": self.device}

        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model, model_kwargs=model_kwargs
        )

        # Initialize retrievers as None
        self.chroma_retriever = None
        self.bm25_retriever = None
        self.ensemble_retriever = None

        # Initialize reranker
        self.cross_encoder = HuggingFaceCrossEncoder(
            model_name="cross-encoder/ms-marco-MiniLM-L12-v2",
            model_kwargs=model_kwargs,
        )

        # Store original techniques data for filtering
        self.techniques_data = None

    def build_knowledge_base(
        self,
        techniques_json_path: str,
        persist_dir: str = "./knowledge_base",
        reset: bool = True,
    ) -> None:
        """
        Build knowledge base from techniques.json

        Args:
            techniques_json_path: Path to the techniques.json file
            persist_dir: Directory to persist the knowledge base
            reset: Whether to reset existing knowledge base
        """
        print("[INFO] Building MITRE ATT&CK knowledge base...")

        # Load techniques data
        self.techniques_data = self._load_techniques(techniques_json_path)
        print(f"[INFO] Loaded {len(self.techniques_data)} techniques")

        # Convert to documents
        documents = self._create_documents(self.techniques_data)
        print(f"[INFO] Created {len(documents)} documents")

        # Create directories
        os.makedirs(persist_dir, exist_ok=True)
        chroma_dir = os.path.join(persist_dir, "chroma")
        bm25_path = os.path.join(persist_dir, "bm25_retriever.pkl")

        # Build ChromaDB retriever
        print("[INFO] Building ChromaDB retriever...")
        self.chroma_retriever = self._build_chroma_retriever(
            documents, chroma_dir, reset
        )

        # Build BM25 retriever
        print("[INFO] Building BM25 retriever...")
        self.bm25_retriever = self._build_bm25_retriever(documents, bm25_path, reset)

        # Create ensemble retriever
        print("[INFO] Creating ensemble retriever...")
        self.ensemble_retriever = self._build_ensemble_retriever(
            self.bm25_retriever, self.chroma_retriever
        )

        # Reranking will be done at search time with dynamic top_k
        print("[INFO] Reranker initialized and ready for search...")

        print("[SUCCESS] Knowledge base built successfully!")
        print("[INFO] Use kb.search(query, top_k) to perform searches.")
        print(
            "[INFO] Use kb.search_multi_query(queries, top_k) for multi-query RRF search."
        )

    def load_knowledge_base(self, persist_dir: str = "./knowledge_base") -> bool:
        """
        Load existing knowledge base from disk

        Args:
            persist_dir: Directory where the knowledge base is stored

        Returns:
            bool: True if loaded successfully, False otherwise
        """
        print("[INFO] Loading knowledge base from disk...")

        chroma_dir = os.path.join(persist_dir, "chroma")
        bm25_path = os.path.join(persist_dir, "bm25_retriever.pkl")

        try:
            # Load ChromaDB
            if os.path.exists(chroma_dir):
                vectorstore = Chroma(
                    persist_directory=chroma_dir, embedding_function=self.embeddings
                )
                self.chroma_retriever = vectorstore.as_retriever(
                    search_kwargs={"k": 20}
                ).configurable_fields(
                    search_kwargs=ConfigurableField(
                        id="chroma_search_kwargs",
                        name="Chroma Search Kwargs",
                        description="Search kwargs for Chroma DB retriever",
                    )
                )
                print("[SUCCESS] ChromaDB loaded")
            else:
                print("[ERROR] ChromaDB not found")
                return False

            # Load BM25 retriever
            if os.path.exists(bm25_path):
                with open(bm25_path, "rb") as f:
                    self.bm25_retriever = pickle.load(f)
                print("[SUCCESS] BM25 retriever loaded")
            else:
                # Rebuild BM25 from ChromaDB if pickle not found
                print("[INFO] BM25 pickle not found, rebuilding from ChromaDB...")
                all_docs = vectorstore.get(include=["documents", "metadatas"])
                documents = all_docs["documents"]
                metadatas = all_docs["metadatas"]

                doc_objects = []
                for doc_content, metadata in zip(documents, metadatas):
                    if metadata is None:
                        metadata = {}
                    doc_obj = Document(page_content=doc_content, metadata=metadata)
                    doc_objects.append(doc_obj)

                self.bm25_retriever = self._build_bm25_retriever(
                    doc_objects, bm25_path, reset=False
                )

            # Create ensemble retriever
            self.ensemble_retriever = self._build_ensemble_retriever(
                self.bm25_retriever, self.chroma_retriever
            )

            # Reranking will be done at search time with dynamic top_k
            print("[INFO] Reranker ready for search...")

            print("[SUCCESS] Knowledge base loaded successfully!")
            return True

        except Exception as e:
            print(f"[ERROR] Error loading knowledge base: {e}")
            return False

    def search(
        self,
        query: str,
        top_k: int = 10,
        filter_tactics: Optional[List[str]] = None,
        filter_platforms: Optional[List[str]] = None,
    ) -> List[Document]:
        """
        Search for techniques using hybrid retrieval and reranking

        Args:
            query: Search query
            top_k: Number of results to return
            filter_tactics: Filter by specific tactics (e.g., ['defense-evasion'])
            filter_platforms: Filter by platforms (e.g., ['Windows'])

        Returns:
            List of retrieved and reranked documents
        """
        if not self.ensemble_retriever:
            raise ValueError(
                "Knowledge base not loaded. Call build_knowledge_base() or load_knowledge_base() first."
            )

        # Build config for retrievers
        config = {
            "configurable": {
                "bm25_k": top_k * 10,  # Get more from BM25 for diversity
                "chroma_search_kwargs": {"k": top_k * 10},
            }
        }

        # Get initial results from ensemble retriever
        initial_results = self.ensemble_retriever.invoke(query, config=config)

        # Create a reranker with the specified top_k for this search
        temp_reranker = CrossEncoderReranker(model=self.cross_encoder, top_n=top_k)

        # Apply reranking to the initial results
        results = temp_reranker.compress_documents(initial_results, query)

        # Manually add relevance scores to metadata since CrossEncoderReranker doesn't preserve them
        scores = self.cross_encoder.score(
            [(query, doc.page_content) for doc in results]
        )
        for doc, score in zip(results, scores):
            doc.metadata["relevance_score"] = float(score)

        # Apply metadata filters if specified
        if filter_tactics or filter_platforms:
            filtered_results = []
            for doc in results:
                # Check tactics filter
                if filter_tactics:
                    doc_tactics = doc.metadata.get("tactics", "").split(",")
                    doc_tactics = [
                        t.strip() for t in doc_tactics if t.strip()
                    ]  # Clean empty strings
                    if not any(tactic in doc_tactics for tactic in filter_tactics):
                        continue

                # Check platforms filter
                if filter_platforms:
                    doc_platforms = doc.metadata.get("platforms", "").split(",")
                    doc_platforms = [
                        p.strip() for p in doc_platforms if p.strip()
                    ]  # Clean empty strings
                    if not any(
                        platform in doc_platforms for platform in filter_platforms
                    ):
                        continue

                filtered_results.append(doc)

            results = filtered_results[:top_k]

        return results

    def search_multi_query(
        self,
        queries: List[str],
        top_k: int = 10,
        rerank_query: Optional[str] = None,
        filter_tactics: Optional[List[str]] = None,
        filter_platforms: Optional[List[str]] = None,
        rrf_k: int = 60,
    ) -> List[Document]:
        """
        Search for techniques using multiple queries with Reciprocal Rank Fusion (RRF)

        This method performs retrieval for each query separately, then combines the results
        using RRF before applying cross-encoder reranking.

        Args:
            queries: List of search queries
            top_k: Number of final results to return after reranking
            rerank_query: Rerank query to use for cross-encoder reranking
            filter_tactics: Filter by specific tactics
            filter_platforms: Filter by platforms
            rrf_k: RRF constant (default: 60, standard value from literature)

        Returns:
            List of retrieved, RRF-fused, and reranked documents
        """
        if not self.ensemble_retriever:
            raise ValueError(
                "Knowledge base not loaded. Call build_knowledge_base() or load_knowledge_base() first."
            )

        if not queries:
            return []

        # If only one query, use regular search
        if len(queries) == 1:
            return self.search(queries[0], top_k, filter_tactics, filter_platforms)

        print(f"[INFO] Performing multi-query search with {len(queries)} queries")

        # Retrieve documents for each query
        all_query_results = []

        config = {
            "configurable": {
                "bm25_k": top_k * 15,  # Get more documents for RRF fusion
                "chroma_search_kwargs": {"k": top_k * 15},
            }
        }

        for i, query in enumerate(queries, 1):
            print(f"[INFO] Query {i}/{len(queries)}: '{query}'")
            results = self.ensemble_retriever.invoke(query, config=config)
            all_query_results.append(results)

        # Apply Reciprocal Rank Fusion (RRF)
        print(f"[INFO] Applying Reciprocal Rank Fusion (k={rrf_k})")
        fused_results = self._reciprocal_rank_fusion(all_query_results, k=rrf_k)

        # Get top candidates before reranking (more than final top_k for better reranking)
        candidates = fused_results[: top_k * 5]

        print(f"[INFO] Reranking {len(candidates)} candidates with cross-encoder")

        reference_query = rerank_query or queries[0]

        # Create a reranker with the specified top_k
        temp_reranker = CrossEncoderReranker(model=self.cross_encoder, top_n=top_k)

        # Apply reranking
        results = temp_reranker.compress_documents(candidates, reference_query)

        # Manually add relevance scores to metadata since CrossEncoderReranker doesn't preserve them
        scores = self.cross_encoder.score(
            [(reference_query, doc.page_content) for doc in results]
        )
        for doc, score in zip(results, scores):
            doc.metadata["relevance_score"] = float(score)

        # Apply metadata filters if specified
        if filter_tactics or filter_platforms:
            filtered_results = []
            for doc in results:
                # Check tactics filter
                if filter_tactics:
                    doc_tactics = doc.metadata.get("tactics", "").split(",")
                    doc_tactics = [t.strip() for t in doc_tactics if t.strip()]
                    if not any(tactic in doc_tactics for tactic in filter_tactics):
                        continue

                # Check platforms filter
                if filter_platforms:
                    doc_platforms = doc.metadata.get("platforms", "").split(",")
                    doc_platforms = [p.strip() for p in doc_platforms if p.strip()]
                    if not any(
                        platform in doc_platforms for platform in filter_platforms
                    ):
                        continue

                filtered_results.append(doc)

            results = filtered_results[:top_k]

        print(f"[INFO] Returning {len(results)} final results")
        return results

    def _reciprocal_rank_fusion(
        self, doc_lists: List[List[Document]], k: int = 60
    ) -> List[Document]:
        """
        Apply Reciprocal Rank Fusion to combine multiple ranked lists

        RRF score for document d: sum over all rankings r of (1 / (k + rank(d, r)))
        where k is a constant (typically 60) and rank is the position in ranking r

        Args:
            doc_lists: List of document lists from different queries
            k: RRF constant (default: 60)

        Returns:
            Fused list of documents sorted by RRF score
        """
        # Create a mapping from document ID to document and its RRF score
        doc_scores = defaultdict(float)
        doc_map = {}

        # Process each ranking
        for doc_list in doc_lists:
            for rank, doc in enumerate(doc_list, start=1):
                # Use attack_id as unique identifier
                doc_id = doc.metadata.get("attack_id", "")
                if not doc_id:
                    # Fallback to content hash if no attack_id
                    doc_id = hash(doc.page_content)

                # Calculate RRF score: 1 / (k + rank)
                rrf_score = 1.0 / (k + rank)
                doc_scores[doc_id] += rrf_score

                # Store document object (keep first occurrence)
                if doc_id not in doc_map:
                    doc_map[doc_id] = doc

        # Sort documents by RRF score (descending)
        sorted_doc_ids = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)

        # Create sorted document list with RRF scores in metadata
        fused_docs = []
        for doc_id, score in sorted_doc_ids:
            doc = doc_map[doc_id]
            # Add RRF score to metadata
            doc.metadata["rrf_score"] = score
            fused_docs.append(doc)

        return fused_docs

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique data by attack ID"""
        if not self.techniques_data:
            return None

        for technique in self.techniques_data:
            if technique.get("attack_id") == technique_id:
                return technique
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        stats = {}

        if self.chroma_retriever:
            try:
                vectorstore = self.chroma_retriever.vectorstore
                collection = vectorstore._collection
                stats["chroma_documents"] = collection.count()
            except:
                stats["chroma_documents"] = "Unknown"

        if self.bm25_retriever:
            try:
                stats["bm25_documents"] = len(self.bm25_retriever.docs)
            except:
                stats["bm25_documents"] = "Unknown"

        stats["ensemble_available"] = self.ensemble_retriever is not None
        stats["reranker_available"] = self.cross_encoder is not None
        stats["reranker_model"] = self.cross_encoder.model_name
        stats["embedding_model"] = self.embeddings.model_name

        if self.techniques_data:
            stats["total_techniques"] = len(self.techniques_data)

            # Count by tactics
            tactics_count = {}
            for technique in self.techniques_data:
                for tactic in technique.get("tactics", []):
                    tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
            stats["techniques_by_tactic"] = tactics_count

            # Count by platforms
            platforms_count = {}
            for technique in self.techniques_data:
                for platform in technique.get("platforms", []):
                    platforms_count[platform] = platforms_count.get(platform, 0) + 1
            stats["techniques_by_platform"] = platforms_count

        return stats

    def _load_techniques(self, json_path: str) -> List[Dict[str, Any]]:
        """Load techniques from JSON file"""
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Techniques file not found: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            techniques = json.load(f)

        return techniques

    def _create_documents(self, techniques: List[Dict[str, Any]]) -> List[Document]:
        """Convert technique data to LangChain documents"""
        documents = []

        for technique in techniques:
            # Main content for embedding: name + description
            page_content = f"Technique: {technique.get('name', 'Unknown')}\n\n"
            page_content += f"Description: {technique.get('description', 'No description available')}"

            # Create metadata - ChromaDB requires simple data types
            metadata = {
                "attack_id": technique.get("attack_id", ""),
                "name": technique.get("name", ""),
                "is_subtechnique": technique.get("is_subtechnique", False),
                "platforms": ",".join(
                    technique.get("platforms", [])
                ),  # Convert list to comma-separated string
                "tactics": ",".join(
                    technique.get("tactics", [])
                ),  # Convert list to comma-separated string
                "doc_type": "mitre_technique",
            }

            # Add mitigation count to metadata
            mitigations = technique.get("mitigations", [])
            metadata["mitigation_count"] = len(mitigations)

            metadata["mitigations"] = "; ".join(mitigations)

            doc = Document(page_content=page_content, metadata=metadata)
            documents.append(doc)

        return documents

    def _build_chroma_retriever(
        self, documents: List[Document], chroma_dir: str, reset: bool
    ):
        """Build ChromaDB retriever"""
        if reset and os.path.exists(chroma_dir):
            import shutil

            shutil.rmtree(chroma_dir)
            print("[INFO] Removed existing ChromaDB for rebuild")

        # Create Chroma vectorstore
        vectorstore = Chroma.from_documents(
            documents=documents, embedding=self.embeddings, persist_directory=chroma_dir
        )

        # Create configurable retriever
        retriever = vectorstore.as_retriever(
            search_kwargs={"k": 20}  # default value
        ).configurable_fields(
            search_kwargs=ConfigurableField(
                id="chroma_search_kwargs",
                name="Chroma Search Kwargs",
                description="Search kwargs for Chroma DB retriever",
            )
        )

        print(f"[SUCCESS] ChromaDB created with {len(documents)} documents")
        return retriever

    def _build_bm25_retriever(
        self, documents: List[Document], bm25_path: str, reset: bool
    ):
        """Build BM25 retriever"""
        # Create BM25 retriever
        retriever = BM25Retriever.from_documents(
            documents=documents,
            k=20,  # default value
            preprocess_func=word_tokenize,
        ).configurable_fields(
            k=ConfigurableField(
                id="bm25_k",
                name="BM25 Top K",
                description="Number of documents to return from BM25",
            )
        )

        # Save BM25 retriever
        try:
            with open(bm25_path, "wb") as f:
                pickle.dump(retriever, f)
            print(f"[SUCCESS] BM25 retriever saved to {bm25_path}")
        except Exception as e:
            print(f"[WARNING] Could not save BM25 retriever: {e}")

        print(f"[SUCCESS] BM25 retriever created with {len(documents)} documents")
        return retriever

    def _build_ensemble_retriever(self, bm25_retriever, chroma_retriever):
        """Build ensemble retriever combining BM25 and ChromaDB"""
        return EnsembleRetriever(
            retrievers=[bm25_retriever, chroma_retriever],
            weights=[0.3, 0.7],  # Favor semantic search slightly
        )


def test_cyber_kb(kb: CyberKnowledgeBase, test_queries: List[str]):
    """Test function for the cyber knowledge base"""

    print("\n[INFO] Testing Cyber Knowledge Base")
    print("=" * 60)

    for i, query in enumerate(test_queries, 1):
        print(f"\n#{i} Query: '{query}'")
        print("-" * 40)

        try:
            # Test search
            results = kb.search(query, top_k=3)

            if results:
                for j, doc in enumerate(results, 1):
                    attack_id = doc.metadata.get("attack_id", "Unknown")
                    name = doc.metadata.get("name", "Unknown")
                    tactics_str = doc.metadata.get("tactics", "")
                    platforms_str = doc.metadata.get("platforms", "")

                    content_preview = doc.page_content[:200].replace("\n", " ")

                    print(f"  {j}. {attack_id} - {name}")
                    print(f"     Tactics: {tactics_str}")
                    print(f"     Platforms: {platforms_str}")
                    print(f"     Preview: {content_preview}...")
                    print()
            else:
                print("  No results found")

        except Exception as e:
            print(f"  [ERROR] Error: {e}")


def test_multi_query_search(kb: CyberKnowledgeBase):
    """Test multi-query search with RRF"""
    print("\n[INFO] Testing Multi-Query Search with RRF")
    print("=" * 60)

    # Test case 1: Credential dumping with different query angles
    print("\n### Test Case 1: Credential Dumping ###")
    queries_1 = [
        "credential dumping LSASS memory",
        "stealing authentication secrets",
        "SAM database access ntds.dit",
    ]

    print(f"Queries: {queries_1}")
    results = kb.search_multi_query(queries_1, top_k=5)

    print("\nTop 5 Results:")
    for i, doc in enumerate(results, 1):
        attack_id = doc.metadata.get("attack_id", "Unknown")
        name = doc.metadata.get("name", "Unknown")
        rrf_score = doc.metadata.get("rrf_score", "N/A")
        print(f"  {i}. {attack_id} - {name} (RRF Score: {rrf_score:.4f})")

    # Test case 2: Process injection with different perspectives
    print("\n\n### Test Case 2: Process Injection ###")
    queries_2 = [
        "process injection defense evasion",
        "code injection into running processes",
        "DLL injection CreateRemoteThread",
    ]

    print(f"Queries: {queries_2}")
    results = kb.search_multi_query(queries_2, top_k=5)

    print("\nTop 5 Results:")
    for i, doc in enumerate(results, 1):
        attack_id = doc.metadata.get("attack_id", "Unknown")
        name = doc.metadata.get("name", "Unknown")
        rrf_score = doc.metadata.get("rrf_score", "N/A")
        print(f"  {i}. {attack_id} - {name} (RRF Score: {rrf_score:.4f})")


# Example usage
if __name__ == "__main__":
    # Initialize knowledge base
    kb = CyberKnowledgeBase()

    # Path to techniques.json
    techniques_path = "../../processed_data/cti/techniques.json"

    try:
        # Build knowledge base
        kb.build_knowledge_base(
            techniques_json_path=techniques_path, persist_dir="./mitre_kb", reset=True
        )

        # Test queries
        test_queries = [
            "process injection techniques",
            "privilege escalation Windows",
            "scheduled task persistence",
            "credential dumping LSASS",
            "lateral movement SMB",
            "defense evasion DLL hijacking",
        ]

        # Test the knowledge base
        test_cyber_kb(kb, test_queries)

        # Test multi-query search with RRF
        test_multi_query_search(kb)

        # Show stats
        print(f"\n[INFO] Knowledge Base Stats:")
        stats = kb.get_stats()
        for key, value in stats.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for subkey, subvalue in value.items():
                    print(f"    {subkey}: {subvalue}")
            else:
                print(f"  {key}: {value}")

    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback

        traceback.print_exc()
