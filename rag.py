"""
RAG (Retrieval-Augmented Generation) Demo for Business Logic Vulnerability Analysis

This module implements a RAG system that:
1. Uses FAISS for vector similarity search
2. Loads knowledge base from markdown files
3. Optionally adds parsed HAR files as additional context
4. Uses LLM to analyze HTTP traffic for BLV (Business Logic Vulnerability) potentials
"""

import os
import json
import argparse
from typing import List, Optional, Tuple
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer

from utils import call_llm
from schema import ReasoningOutput


def safe_print(text: str) -> None:
    """Print text safely, handling Unicode encoding errors on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fall back to ASCII-safe printing on Windows cp932
        print(text.encode('ascii', errors='replace').decode('ascii'))

# ============================================================================
# Configuration
# ============================================================================

KB_PATHS = [
    "knowledge_base/top10bla.md",
    "knowledge_base/wstg_wsa.md"
]

PARSED_HARS_DIR = "parsed_hars"
EMBEDDING_MODEL_NAME = 'all-MiniLM-L6-v2'
CHUNK_SIZE = 500  # Character limit per chunk
CHUNK_OVERLAP = 50  # Overlap between chunks
TOP_K = 5  # Number of chunks to retrieve

PROMPTS_DIR = "prompts"

def load_prompt(prompt_name: str) -> str:
    """Load a prompt from the prompts directory."""
    prompt_path = os.path.join(PROMPTS_DIR, f"{prompt_name}.txt")
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read().strip()


# ============================================================================
# Text Chunking Functions
# ============================================================================

def read_file(file_path: str) -> str:
    """Read file content."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """
    Split text into overlapping chunks.

    Args:
        text: Input text to chunk
        chunk_size: Maximum characters per chunk
        overlap: Number of characters to overlap between chunks

    Returns:
        List of text chunks
    """
    chunks = []
    start = 0
    text_len = len(text)

    while start < text_len:
        end = start + chunk_size

        # Try to break at a reasonable point (newline or period)
        if end < text_len:
            # Look for newline in the last 100 chars
            newline_pos = text.rfind('\n', start + chunk_size - 100, end)
            if newline_pos != -1 and newline_pos > start:
                end = newline_pos + 1
            else:
                # Look for period in the last 100 chars
                period_pos = text.rfind('.', start + chunk_size - 100, end)
                if period_pos != -1 and period_pos > start:
                    end = period_pos + 1

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        start = end - overlap

    return chunks


def chunk_markdown_by_section(text: str) -> List[str]:
    """
    Chunk markdown by sections (headers) for better context preservation.

    Args:
        text: Markdown text

    Returns:
        List of chunks (each chunk is a section with its header)
    """
    chunks = []
    lines = text.split('\n')
    current_chunk = []
    current_size = 0

    for line in lines:
        line_size = len(line)

        # If this line is a header (starts with #)
        if line.strip().startswith('#'):
            # Save current chunk if it exists
            if current_chunk:
                chunk_text = '\n'.join(current_chunk).strip()
                if chunk_text:
                    chunks.append(chunk_text)

            # Start new chunk with this header
            current_chunk = [line]
            current_size = line_size
        else:
            # Add line to current chunk if it doesn't exceed size
            if current_size + line_size <= CHUNK_SIZE:
                current_chunk.append(line)
                current_size += line_size
            else:
                # Save current chunk and start a new one
                if current_chunk:
                    chunk_text = '\n'.join(current_chunk).strip()
                    if chunk_text:
                        chunks.append(chunk_text)
                current_chunk = [line]
                current_size = line_size

    # Don't forget the last chunk
    if current_chunk:
        chunk_text = '\n'.join(current_chunk).strip()
        if chunk_text:
            chunks.append(chunk_text)

    return chunks


def load_knowledge_base(file_paths: List[str]) -> List[Tuple[str, str]]:
    """
    Load and chunk knowledge base documents.

    Args:
        file_paths: List of file paths to load

    Returns:
        List of (source, chunk) tuples
    """
    documents = []

    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}")
            continue

        print(f"Loading: {file_path}")
        text = read_file(file_path)

        # Use section-based chunking for markdown
        chunks = chunk_markdown_by_section(text)

        for chunk in chunks:
            documents.append((file_path, chunk))

    return documents

def load_har_as_context(har_path: str, chunk_size: int = CHUNK_SIZE) -> List[str]:
    """
    Load HAR file and convert to text context chunks.
    Enhanced to include ALL entries with chunking for complete ingestion.

    Args:
        har_path: Path to HAR file
        chunk_size: Maximum characters per chunk

    Returns:
        List of text chunks containing all HAR content
    """
    with open(har_path, "r", encoding="utf-8") as f:
        har_data = json.load(f)

    if isinstance(har_data, dict):
        entries = har_data.get("log", {}).get("entries", [])
    elif isinstance(har_data, list):
        entries = har_data
    else:
        return ["Invalid HAR format"]

    # Build full text content with ALL entries (no limit)
    context_parts = [f"HTTP Traffic Analysis ({len(entries)} entries)\n"]
    context_parts.append("=" * 60)

    for idx, entry in enumerate(entries):
        request = entry.get("request", {})
        response = entry.get("response", {})

        method = request.get("method", "")
        url = request.get("url", "")
        status = response.get("status", 0)

        # Capture critical headers for PoC context
        headers = request.get("headers", [])
        important_headers = ["Authorization", "Content-Type", "Cookie", "X-XSRF-TOKEN", "x-csrf-token", "xsrf-token"]
        header_list = [f"{h['name']}: {h['value']}" for h in headers if h['name'].lower() in [h.lower() for h in important_headers]]
        header_str = "\n    ".join(header_list)

        # Capture FULL body for mutation reference (no truncation)
        body = ""
        if request.get("postData"):
            post_data = request.get("postData", {})
            body = post_data.get("text", "") if isinstance(post_data, dict) else str(post_data)
            # Don't truncate - keep full content for analysis

        entry_text = f"\n[Entry #{idx}] {method} {url}\n"
        entry_text += f"  Response Status: {status}\n"
        if header_str:
            entry_text += f"  Key Headers:\n    {header_str}\n"
        if body:
            entry_text += f"  Request Body: {body}\n"
        entry_text += "-" * 30

        context_parts.append(entry_text)

    # Join all parts and chunk the result
    full_text = "\n".join(context_parts)

    # Use chunking to split into manageable pieces
    chunks = chunk_text(full_text, chunk_size=chunk_size, overlap=CHUNK_OVERLAP)

    print(f"  HAR file processed: {len(entries)} entries -> {len(chunks)} chunks")
    return chunks

# ============================================================================
# FAISS Vector Database
# ============================================================================

class VectorStore:
    """FAISS-based vector store for semantic search."""

    def __init__(self, embedding_model_name: str = EMBEDDING_MODEL_NAME):
        """Initialize the vector store with an embedding model."""
        print(f"Loading embedding model: {embedding_model_name}")
        self.model = SentenceTransformer(embedding_model_name)
        self.index = None
        self.chunks = []
        self.sources = []

    def build_index(self, documents: List[Tuple[str, str]]) -> None:
        """
        Build FAISS index from documents.

        Args:
            documents: List of (source, chunk) tuples
        """
        self.sources = [doc[0] for doc in documents]
        self.chunks = [doc[1] for doc in documents]

        print(f"Creating embeddings for {len(self.chunks)} chunks...")
        embeddings = self.model.encode(
            self.chunks,
            show_progress_bar=True,
            convert_to_numpy=True
        )

        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(embeddings)

        # Create FAISS index (Inner Product = Cosine Similarity for normalized vectors)
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(embeddings)

        print(f"Index built with {self.index.ntotal} vectors")

    def search(self, query: str, top_k: int = TOP_K) -> List[Tuple[str, str, float]]:
        """
        Search for relevant chunks.

        Args:
            query: Search query
            top_k: Number of results to return

        Returns:
            List of (source, chunk, score) tuples
        """
        if self.index is None:
            raise ValueError("Index not built. Call build_index() first.")

        # Create query embedding
        query_embedding = self.model.encode([query], convert_to_numpy=True)

        # Normalize for cosine similarity
        faiss.normalize_L2(query_embedding)

        # Search - FAISS returns (distances, indices)
        distances, indices = self.index.search(query_embedding, top_k)

        results = []
        for score, idx in zip(distances[0], indices[0]):
            if idx >= 0:  # FAISS returns -1 for empty results
                results.append((
                    self.sources[idx],
                    self.chunks[idx],
                    float(score)
                ))

        return results

    def save(self, index_path: str = "faiss_index.bin") -> None:
        """Save FAISS index to disk."""
        if self.index is None:
            raise ValueError("No index to save")

        faiss.write_index(self.index, index_path)

        # Save metadata
        metadata = {
            "sources": self.sources,
            "chunks": self.chunks
        }
        metadata_path = index_path.replace(".bin", "_metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

        print(f"Index saved to {index_path}")

    def load(self, index_path: str = "faiss_index.bin") -> None:
        """Load FAISS index from disk."""
        self.index = faiss.read_index(index_path)

        # Load metadata
        metadata_path = index_path.replace(".bin", "_metadata.json")
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        self.sources = metadata["sources"]
        self.chunks = metadata["chunks"]

        print(f"Index loaded from {index_path} ({self.index.ntotal} vectors)")


# ============================================================================
# RAG Query Functions
# ============================================================================

def format_retrieved_context(results: List[Tuple[str, str, float]]) -> str:
    """Format retrieved chunks into context for LLM."""
    context_parts = ["Relevant Knowledge Base Entries:\n"]

    for source, chunk, score in results:
        source_name = Path(source).name
        context_parts.append(f"\n--- Source: {source_name} (Relevance: {score:.3f}) ---")
        context_parts.append(chunk)

    return "\n".join(context_parts)

def construct_rag_prompt(retrieved_context: str, har_context: Optional[List[str]] = None) -> List[dict]:
    har_text = "\n".join(har_context) if har_context else "No traffic provided."

    # Load prompts from files
    system_prompt = load_prompt("system_prompt")
    user_message_template = load_prompt("user_message")

    # Format user message with context
    user_message = user_message_template.format(
        retrieved_context=retrieved_context,
        har_text=har_text
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message}
    ]

# ============================================================================
# HAR File Selection
# ============================================================================

def list_har_files(directory: str) -> List[str]:
    """List all HAR JSON files in directory."""
    path = Path(directory)
    if not path.exists():
        print(f"Directory not found: {directory}")
        return []

    return [str(f) for f in path.glob("*.json")]


def resolve_har_path(har_input: Optional[str], directory: str) -> Optional[str]:
    """
    Resolve HAR file path from input (filename or full path).

    Args:
        har_input: User input (filename, full path, or None)
        directory: Default directory to search

    Returns:
        Resolved file path or None
    """
    if not har_input:
        return None

    # If it's a full path that exists, use it
    if Path(har_input).exists() and Path(har_input).is_file():
        return har_input

    # Try to find in the default directory
    har_path = Path(directory) / har_input
    if har_path.exists() and har_path.is_file():
        return str(har_path)

    # Try with .json extension if not provided
    if not har_input.endswith('.json'):
        har_path = Path(directory) / f"{har_input}.json"
        if har_path.exists() and har_path.is_file():
            return str(har_path)

    print(f"Error: HAR file not found: {har_input}")
    print(f"       Searched in: {directory}")
    return None


# ============================================================================
# Main RAG Pipeline
# ============================================================================

def run_rag_analysis(
    query: str,
    vector_store: VectorStore,
    har_file: Optional[str] = None,
    top_k: int = TOP_K
) -> ReasoningOutput:
    """
    Run the complete RAG analysis pipeline.

    Args:
        query: User query for retrieval
        vector_store: Initialized VectorStore
        har_file: Optional path to HAR file
        top_k: Number of chunks to retrieve

    Returns:
        ReasoningOutput with analysis results
    """
    # Step 1: Retrieve relevant knowledge
    print(f"\n[1/4] Retrieving relevant knowledge (top {top_k})...")
    results = vector_store.search(query, top_k=top_k)

    print(f"  Retrieved {len(results)} chunks:")
    for source, _, score in results:
        source_name = Path(source).name
        print(f"    - {source_name}: {score:.3f}")

    # Step 2: Load HAR context if provided
    har_context = None
    if har_file:
        print(f"\n[2/4] Loading HAR file: {Path(har_file).name}")
        har_context = load_har_as_context(har_file)
    else:
        print("\n[2/4] No HAR file provided.")

    # Step 3: Construct RAG prompt
    print("\n[3/4] Constructing RAG prompt...")
    retrieved_context = format_retrieved_context(results)
    messages = construct_rag_prompt(retrieved_context, har_context)

    # Step 4: Call LLM
    print("\n[4/4] Calling LLM for analysis...")
    result: ReasoningOutput = call_llm(
        messages=messages,
        response_format=ReasoningOutput
    )

    return result


# ============================================================================
# Demo / Main Function
# ============================================================================

def main():
    """Main demonstration function."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="RAG Demo: Business Logic Vulnerability Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with specific HAR file
  python rag.py juice_shop.json

  # Run with HAR file from parsed_hars/ directory
  python rag.py juice_shop

  # List available HAR files
  python rag.py --list

  # Run without HAR file
  python rag.py --no-har
        """
    )
    parser.add_argument(
        "har_file",
        nargs="?",
        help="HAR file to analyze (filename or full path)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available HAR files in parsed_hars/ directory"
    )
    parser.add_argument(
        "--no-har",
        action="store_true",
        help="Run analysis without HAR file"
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=TOP_K,
        help=f"Number of knowledge chunks to retrieve (default: {TOP_K})"
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Force rebuild of FAISS index"
    )
    parser.add_argument(
        "--query",
        type=str,
        default="you are a security researcher. find BLV potentials in these HTTP traffic request sequences",
        help="Custom query for retrieval"
    )

    args = parser.parse_args()

    # List available HAR files if requested
    if args.list:
        print("=" * 70)
        print("Available HAR files in parsed_hars/:")
        print("=" * 70)
        har_files = list_har_files(PARSED_HARS_DIR)
        if har_files:
            for i, f in enumerate(har_files, 1):
                print(f"  [{i}] {Path(f).name}")
        else:
            print("  No HAR files found.")
        print("=" * 70)
        return

    # Validate HAR file argument
    har_file = None
    if not args.no_har and args.har_file:
        har_file = resolve_har_path(args.har_file, PARSED_HARS_DIR)
        if not har_file:
            return
    elif args.no_har:
        print("Running without HAR file...")
    elif not args.har_file:
        print("Error: Please provide a HAR file or use --no-har flag")
        print("Use --list to see available HAR files")
        print("Use --help for more information")
        return

    print("=" * 70)
    print("RAG Demo: Business Logic Vulnerability Analysis")
    print("=" * 70)

    # Step 1: Load knowledge base
    print("\n[Step 1] Loading knowledge base...")
    documents = load_knowledge_base(KB_PATHS)
    print(f"  Loaded {len(documents)} chunks from {len(KB_PATHS)} files")

    # Step 2: Build or load FAISS index
    print("\n[Step 2] Building vector index...")
    vector_store = VectorStore()

    # Try to load existing index
    index_path = "faiss_index.bin"
    if os.path.exists(index_path) and not args.rebuild_index:
        print(f"  Found existing index. Loading from {index_path}...")
        try:
            vector_store.load(index_path)
        except Exception as e:
            print(f"  Failed to load index: {e}")
            print("  Building new index...")
            vector_store.build_index(documents)
            vector_store.save(index_path)
    else:
        if args.rebuild_index:
            print("  Rebuilding index (--rebuild-index flag set)...")
        else:
            print("  Building new index...")
        vector_store.build_index(documents)
        vector_store.save(index_path)

    # Step 3: Confirm HAR file
    if har_file:
        print(f"\n[Step 3] Using HAR file: {Path(har_file).name}")
    else:
        print("\n[Step 3] No HAR file provided")

    # Step 4: Define query
    query = args.query

    # Step 5: Run RAG analysis
    print("\n[Step 4] Running RAG analysis...")
    print("-" * 70)

    result = run_rag_analysis(
        query=query,
        vector_store=vector_store,
        har_file=har_file,
        top_k=args.top_k
    )

    # Step 6: Display results
    safe_print("\n" + "=" * 70)
    safe_print("ANALYSIS RESULTS")
    safe_print("=" * 70)

    safe_print("\n[Business Flow]")
    safe_print(result.business_flow)

    safe_print("\n[Thought Process]")
    for i, thought in enumerate(result.thought_process, 1):
        safe_print(f"  {i}. {thought}")

    safe_print(f"\n[Potential Vulnerabilities] ({len(result.potential_vulnerabilities)} found)")
    for i, vuln in enumerate(result.potential_vulnerabilities, 1):
        safe_print(f"\n  [{i}] {vuln.category} - {vuln.severity}")
        safe_print(f"      Description: {vuln.description}")
        safe_print(f"      Evidence IDs: {vuln.evidence_entry_ids}")

        # Display PoC Payload
        if hasattr(vuln, 'reproduction_guide') and vuln.reproduction_guide:
            poc = vuln.reproduction_guide
            safe_print(f"      --- Reproduction Guide ---")
            safe_print(f"      Mutation: {poc.payload_mutation}")
            safe_print(f"      cURL PoC: {poc.curl_command}")

    # Step 7: Save results
    output_dir = Path("without_rag_results")
    output_dir.mkdir(exist_ok=True)

    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    har_name = Path(har_file).stem if har_file else "no_har"
    output_file = output_dir / f"{timestamp}_{har_name}_rag_result.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            result.model_dump(),
            f,
            ensure_ascii=False,
            indent=2
        )

    safe_print(f"\n[OK] Results saved to: {output_file}")
    safe_print("=" * 70)


if __name__ == "__main__":
    main()
