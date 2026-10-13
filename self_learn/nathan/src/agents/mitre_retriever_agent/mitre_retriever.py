import json
import os
from typing import List, Dict, Optional, Any
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.schema import Document
from langchain.retrievers import ContextualCompressionRetriever, EnsembleRetriever
from langchain.retrievers.document_compressors.embeddings_filter import EmbeddingsFilter
from langchain_community.retrievers import BM25Retriever
import numpy as np

class MitreRetriever:

    def __init__(self, techniques_json_path: str = None):
        if techniques_json_path is None:
            # Get absolute path to raw_data directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.join(current_dir, "..", "..", "..")
            techniques_json_path = os.path.join(project_root, "raw_data", "techniques.json")
        self.techniques_json_path = techniques_json_path
        self.techniques_data = None
        self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        self.vectorstore = None
        self.retriever = None
        self.compressed_retriever = None
        self.bm25_retriever = None
        self.ensemble_retriever = None
        self.documents = None
        self._initialize()

    def _initialize(self):
        """Initialize the vector store and retrievers."""
        self._load_techniques_data()
        self.documents = self._create_documents()
        self._setup_vectorstore(self.documents)
        self._setup_retrievers()

    def _load_techniques_data(self):
        """Load techniques from JSON file."""
        try:
            with open(self.techniques_json_path, "r", encoding="utf-8") as f:
                self.techniques_data = json.load(f)
            print(f"[INFO] Loaded {len(self.techniques_data)} techniques from techniques.json")
        except FileNotFoundError:
            print(f"[ERROR] {self.techniques_json_path} not found. Run extract_mitre_techniques.py first.")
            raise

    def _create_documents(self) -> List[Document]:
        """Create LangChain documents from techniques data."""
        documents = []

        for technique in self.techniques_data:
            # Create rich document content for better semantic search
            content_parts = [
                f"Technique: {technique['name']}",
                f"ID: {technique['attack_id']}",
                f"Description: {technique['description']}",
                f"Tactics: {', '.join(technique['tactics'])}",
                f"Platforms: {', '.join(technique['platforms'])}"
            ]

            # Add mitigation information
            if technique['mitigations']:
                mitigation_names = []
                mitigation_descriptions = []

                for mitigation in technique['mitigations'][:5]:  # Top 5 mitigations
                    if ':' in mitigation:
                        name, desc = mitigation.split(':', 1)
                        mitigation_names.append(name.strip())
                        mitigation_descriptions.append(desc.strip())
                    else:
                        mitigation_names.append(mitigation)

                content_parts.append(f"Mitigations: {'; '.join(mitigation_names)}")
                content_parts.append(f"Mitigation Details: {' '.join(mitigation_descriptions)}")

            # Combine all content
            page_content = "\n".join(content_parts)

            # Create metadata for filtering and retrieval
            metadata = {
                'attack_id': technique['attack_id'],
                'name': technique['name'],
                'tactics': ', '.join(technique['tactics']),
                'platforms': ', '.join(technique['platforms']),
                'is_subtechnique': technique['is_subtechnique'],
                'mitigation_count': len(technique['mitigations']),
                'source': 'techniques_json'
            }

            documents.append(Document(
                page_content=page_content,
                metadata=metadata
            ))

        return documents

    def _setup_vectorstore(self, documents: List[Document]):
        """Setup the vector store with persistence."""
        persist_directory = "./chroma_db"

        # Check if vector store already exists
        if os.path.exists(persist_directory) and os.listdir(persist_directory):
            try:
                self.vectorstore = Chroma(
                    persist_directory=persist_directory,
                    embedding_function=self.embeddings
                )
                print("[INFO] Loaded existing vector database")
                return
            except Exception as e:
                print(f"[ERROR] Error loading existing database: {e}")
                print("[INFO] Creating new vector database...")

        # Create new vector store
        self.vectorstore = Chroma.from_documents(
            documents=documents,
            embedding=self.embeddings,
            persist_directory=persist_directory
        )
        print(f"[INFO] Created new vector database with {len(documents)} techniques")

    def _setup_retrievers(self):
        """Setup different types of retrievers including BM25 and ensemble."""
        # Semantic retriever (MMR)
        self.retriever = self.vectorstore.as_retriever(
            search_type="mmr",
            search_kwargs={
                "k": 15,
                "fetch_k": 30,
                "lambda_mult": 0.7
            }
        )

        # Compressed retriever for better semantic results
        embeddings_filter = EmbeddingsFilter(
            embeddings=self.embeddings
        )

        self.compressed_retriever = ContextualCompressionRetriever(
            base_compressor=embeddings_filter,
            base_retriever=self.retriever
        )

        # BM25 retriever for keyword/exact matching
        self.bm25_retriever = BM25Retriever.from_documents(
            self.documents,
            k=15
        )
        print("[DEBUG] BM25 retriever initialized")

        # Ensemble retriever with RRF for hybrid search
        self.ensemble_retriever = EnsembleRetriever(
            retrievers=[self.bm25_retriever, self.compressed_retriever],
            weights=[0.3, 0.7]
        )
        print("[DEBUG] Ensemble retriever initialized with RRF")

    def semantic_search(self, query: str, use_compression: bool = True, k: int = 10) -> List[Dict]:
        """Standard semantic search."""
        print(f"[INFO] Semantic search for: '{query}' with compression={use_compression}")

        retriever = self.compressed_retriever if use_compression else self.retriever

        try:
            docs = retriever.invoke(query)
            print(f"[DEBUG] Semantic retriever found {len(docs)} documents")
        except Exception as e:
            print(f"[ERROR] Error in retriever.invoke: {e}")
            docs = self.vectorstore.similarity_search(query, k=k)

        return self._format_results(docs[:k])

    def bm25_search(self, query: str, k: int = 10, debug: bool = False) -> List[Dict]:
        """BM25-based keyword search for exact matching."""
        print(f"[INFO] BM25 search for: '{query}'")

        try:
            docs = self.bm25_retriever.invoke(query)
            print(f"[DEBUG] BM25 retriever found {len(docs)} documents")
            if debug:
                # Show BM25 rankings
                print(f"[DEBUG] BM25 top {min(5, len(docs))} results:")
                for i, doc in enumerate(docs[:5]):
                    attack_id = doc.metadata.get('attack_id', 'Unknown')
                    name = doc.metadata.get('name', 'Unknown')
                    print(f"[DEBUG]   {i+1}. {attack_id}: {name}")

            return self._format_results(docs[:k])
        except Exception as e:
            print(f"[ERROR] Error in BM25 search: {e}")
            return []

    def hybrid_search(self, query: str, k: int = 10, debug: bool = False) -> List[Dict]:
        """Hybrid search using RRF to combine BM25 and semantic search."""
        print(f"[INFO] Hybrid RRF search for: '{query}'")

        # First get individual results for comparison
        if debug:
            print("[DEBUG] Getting individual retriever results for comparison...")

            # Get BM25 results
            bm25_docs = self.bm25_retriever.invoke(query)
            print(f"[DEBUG] BM25 found {len(bm25_docs)} documents")
            print("[DEBUG] BM25 top 5:")
            for i, doc in enumerate(bm25_docs[:5]):
                attack_id = doc.metadata.get('attack_id', 'Unknown')
                name = doc.metadata.get('name', 'Unknown')
                print(f"[DEBUG]   BM25-{i+1}. {attack_id}: {name}")

            # Get semantic results
            semantic_docs = self.retriever.invoke(query)
            print(f"[DEBUG] Semantic found {len(semantic_docs)} documents")
            print("[DEBUG] Semantic top 5:")
            for i, doc in enumerate(semantic_docs[:5]):
                attack_id = doc.metadata.get('attack_id', 'Unknown')
                name = doc.metadata.get('name', 'Unknown')
                print(f"[DEBUG]   SEM-{i+1}. {attack_id}: {name}")

        docs = self.ensemble_retriever.invoke(query)
        # print(f"[DEBUG] Ensemble retriever found {len(docs)} documents using RRF")

        if debug:
            print("[DEBUG] RRF Final ranking:")
            for i, doc in enumerate(docs[:10]):
                attack_id = doc.metadata.get('attack_id', 'Unknown')
                name = doc.metadata.get('name', 'Unknown')
                print(f"[DEBUG]   RRF-{i+1}. {attack_id}: {name}")

        return self._format_results(docs[:k])

    def _format_results(self, docs: List[Document]) -> List[Dict]:
        """Format documents into standardized result format."""
        results = []
        for doc in docs:
            tactics_str = doc.metadata.get('tactics', '')
            platforms_str = doc.metadata.get('platforms', '')

            tactics_list = [t.strip() for t in tactics_str.split(',') if t.strip()] if tactics_str else []
            platforms_list = [p.strip() for p in platforms_str.split(',') if p.strip()] if platforms_str else []

            result = {
                'attack_id': doc.metadata.get('attack_id'),
                'name': doc.metadata.get('name'),
                'tactics': tactics_list,
                'platforms': platforms_list,
                'is_subtechnique': doc.metadata.get('is_subtechnique', False),
                'mitigation_count': doc.metadata.get('mitigation_count', 0),
                'content': doc.page_content,
                'metadata': doc.metadata
            }
            results.append(result)
        return results

    def search_by_tactic(self, tactic: str, k: int = 10) -> List[Dict]:
        """Search techniques by specific tactic using BM25."""
        query = f"tactic {tactic}"
        print(f"[INFO] Searching by tactic: {tactic}")
        return self.bm25_search(query, k)

    def search_by_platform(self, platform: str, k: int = 10) -> List[Dict]:
        """Search techniques by platform using BM25."""
        query = f"platform {platform}"
        print(f"[INFO] Searching by platform: {platform}")
        return self.bm25_search(query, k)

    def get_technique_details(self, attack_id: str) -> Optional[Dict]:
        """Get full details for a specific technique."""
        for technique in self.techniques_data:
            if technique['attack_id'] == attack_id:
                return technique
        return None

    def get_retriever(self, retriever_type: str = "ensemble"):
        """Get the specified LangChain retriever for use in chains."""
        print(f"[DEBUG] Getting retriever type: {retriever_type}")
        if retriever_type == "ensemble":
            return self.ensemble_retriever
        elif retriever_type == "bm25":
            return self.bm25_retriever
        elif retriever_type == "semantic":
            return self.compressed_retriever
        else:
            return self.ensemble_retriever

    def add_to_vectorstore(self, new_techniques: List[Dict]):
        """Add new techniques to both vector store and BM25 retriever."""
        new_documents = []

        for technique in new_techniques:
            content_parts = [
                f"Technique: {technique['name']}",
                f"ID: {technique['attack_id']}",
                f"Description: {technique.get('description', '')}",
                f"Tactics: {', '.join(technique.get('tactics', []))}",
                f"Platforms: {', '.join(technique.get('platforms', []))}"
            ]

            new_documents.append(Document(
                page_content="\n".join(content_parts),
                metadata={
                    'attack_id': technique['attack_id'],
                    'name': technique['name'],
                    'tactics': ', '.join(technique.get('tactics', [])),
                    'platforms': ', '.join(technique.get('platforms', [])),
                    'source': 'manual_addition'
                }
            ))

        # Add to vector store
        self.vectorstore.add_documents(new_documents)

        # Recreate BM25 retriever with updated documents
        all_documents = self.documents + new_documents
        self.bm25_retriever = BM25Retriever.from_documents(all_documents, k=15)

        # Recreate ensemble retriever
        self.ensemble_retriever = EnsembleRetriever(
            retrievers=[self.bm25_retriever, self.compressed_retriever],
            weights=[0.3, 0.7]
        )

        print(f"[INFO] Added {len(new_documents)} new techniques to both retrievers")

if __name__ == "__main__":
    # Initialize retriever
    retriever = MitreRetriever()

    # Test different search methods
    print("\n" + "="*50)
    print("=== BM25 Search ===")
    bm25_results = retriever.bm25_search("network socket backdoor", k=3)
    for i, result in enumerate(bm25_results):
        print(f"  {i+1}. {result['attack_id']}: {result['name']}")

    print("\n" + "="*50)
    print("=== Semantic Search ===")
    semantic_results = retriever.semantic_search("adversaries may attach filters to network socket", k=3)
    for i, result in enumerate(semantic_results):
        print(f"  {i+1}. {result['attack_id']}: {result['name']}")

    print("\n" + "="*50)
    print("=== Hybrid RRF Search ===")
    hybrid_results = retriever.hybrid_search("T1205 network socket filter", k=3, debug=False)
    for i, result in enumerate(hybrid_results):
        sources = result.get('rrf_sources', [])
        sources_str = f" [{', '.join(sources)}]" if sources else ""
        print(f"  {i+1}. {result['attack_id']}: {result['name']} {sources_str}")

    print("\n" + "="*50)
    print("=== Tactic Search (BM25) ===")
    tactic_results = retriever.search_by_tactic("persistence", k=3)
    for i, result in enumerate(tactic_results):
        print(f"  {i+1}. {result['attack_id']}: {result['name']}")