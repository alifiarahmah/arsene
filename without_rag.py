"""
Non-RAG (Direct LLM) Business Logic Vulnerability Analysis

This module implements a direct LLM analysis system that:
1. Loads knowledge base from markdown files with chunking
2. Loads HAR files with chunking for context management
3. Uses the same prompts as the RAG version
4. Calls LLM directly with full knowledge base included in prompt
"""

import os
import json
import argparse
from typing import List, Optional, Tuple
from pathlib import Path

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
CHUNK_SIZE = 500  # Character limit per chunk
CHUNK_OVERLAP = 50  # Overlap between chunks
MAX_KB_CHUNKS = 20  # Maximum number of KB chunks to include (to manage context)

PROMPTS_DIR = "prompts"


def load_prompt(prompt_name: str) -> str:
    """Load a prompt from the prompts directory."""
    prompt_path = os.path.join(PROMPTS_DIR, f"{prompt_name}.txt")
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def read_file(file_path: str) -> str:
    """Read file content."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


# ============================================================================
# Text Chunking Functions
# ============================================================================

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


def load_knowledge_base(file_paths: List[str], max_chunks: int = MAX_KB_CHUNKS) -> str:
    """
    Load and chunk knowledge base documents, concatenating into a single context string.

    Args:
        file_paths: List of file paths to load
        max_chunks: Maximum number of chunks to include (to manage context window)

    Returns:
        Concatenated knowledge base text
    """
    all_chunks = []

    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}")
            continue

        print(f"Loading: {file_path}")
        text = read_file(file_path)

        # Use section-based chunking for markdown
        chunks = chunk_markdown_by_section(text)
        all_chunks.extend(chunks)

    # Limit chunks to avoid exceeding context window
    selected_chunks = all_chunks[:max_chunks] if len(all_chunks) > max_chunks else all_chunks

    if len(all_chunks) > max_chunks:
        print(f"  Knowledge base truncated: {len(all_chunks)} chunks -> {len(selected_chunks)} chunks (max: {max_chunks})")
    else:
        print(f"  Loaded {len(selected_chunks)} chunks from {len(file_paths)} files")

    # Concatenate chunks with separator
    return "\n\n---\n\n".join(selected_chunks)


# ============================================================================
# HAR File Loading
# ============================================================================

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
# Prompt Construction
# ============================================================================

def construct_direct_prompt(
    har_context: Optional[List[str]] = None,
    kb_context: Optional[str] = None
) -> List[dict]:
    """
    Construct prompt for direct LLM call with knowledge base included.

    Args:
        har_context: List of HAR text chunks
        kb_context: Knowledge base context text (if None, loads from files)

    Returns:
        List of messages for LLM
    """
    har_text = "\n".join(har_context) if har_context else "No traffic provided."

    # Load knowledge base if not provided
    if kb_context is None:
        kb_context = load_knowledge_base(KB_PATHS)

    # Load prompts from files
    system_prompt = load_prompt("system_prompt")
    user_message_template = load_prompt("user_message")

    # Format user message with knowledge base as context
    user_message = user_message_template.format(
        retrieved_context=kb_context,
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
# Main Direct LLM Pipeline
# ============================================================================

def run_direct_analysis(
    har_file: Optional[str] = None,
    kb_context: Optional[str] = None,
    max_kb_chunks: int = MAX_KB_CHUNKS
) -> ReasoningOutput:
    """
    Run the direct LLM analysis pipeline with knowledge base included.

    Args:
        har_file: Optional path to HAR file
        kb_context: Pre-loaded knowledge base context (if None, loads from files)
        max_kb_chunks: Maximum number of KB chunks to include

    Returns:
        ReasoningOutput with analysis results
    """
    # Step 1: Load knowledge base
    print(f"\n[1/4] Loading knowledge base (max {max_kb_chunks} chunks)...")
    if kb_context is None:
        kb_context = load_knowledge_base(KB_PATHS, max_chunks=max_kb_chunks)
    else:
        print(f"  Using provided knowledge base ({len(kb_context)} chars)")

    # Step 2: Load HAR context if provided
    har_context = None
    if har_file:
        print(f"\n[2/4] Loading HAR file: {Path(har_file).name}")
        har_context = load_har_as_context(har_file)
    else:
        print("\n[2/4] No HAR file provided.")

    # Step 3: Construct prompt
    print("\n[3/4] Constructing prompt...")
    messages = construct_direct_prompt(har_context, kb_context)

    # Step 4: Call LLM
    print("\n[4/4] Calling LLM for analysis...")
    result: ReasoningOutput = call_llm(
        messages=messages,
        response_format=ReasoningOutput
    )

    return result


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main demonstration function."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Non-RAG Demo: Direct LLM Business Logic Vulnerability Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with specific HAR file
  python without_rag.py juice_shop.json

  # Run with HAR file from parsed_hars/ directory
  python without_rag.py juice_shop

  # List available HAR files
  python without_rag.py --list

  # Run without HAR file
  python without_rag.py --no-har

  # Run with limited knowledge base chunks (for smaller context window)
  python without_rag.py juice_shop --max-kb-chunks 10

  # Run with knowledge base (outputs to without_rag_with_kb_results/)
  python without_rag.py juice_shop --with-kb

  # Run without knowledge base (outputs to without_rag_results/)
  python without_rag.py juice_shop --no-kb
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
        "--max-kb-chunks",
        type=int,
        default=MAX_KB_CHUNKS,
        help=f"Maximum number of knowledge base chunks to include (default: {MAX_KB_CHUNKS})"
    )
    parser.add_argument(
        "--with-kb",
        action="store_true",
        help="Include knowledge base context in analysis"
    )
    parser.add_argument(
        "--no-kb",
        action="store_true",
        help="Exclude knowledge base context from analysis"
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
    print("Non-RAG Demo: Direct LLM Business Logic Vulnerability Analysis")
    print("=" * 70)

    # Determine if knowledge base should be used
    use_kb = args.with_kb and not args.no_kb

    # Prepare knowledge base context
    kb_context = None
    if use_kb:
        print(f"\nUsing knowledge base with max {args.max_kb_chunks} chunks...")
    else:
        print("\nRunning without knowledge base context (--no-kb flag set)...")
        kb_context = "No knowledge base provided - analyzing based solely on HTTP traffic patterns."

    # Run analysis
    print("\n[Step 2] Running direct LLM analysis...")
    print("-" * 70)

    result = run_direct_analysis(
        har_file=har_file,
        kb_context=kb_context,
        max_kb_chunks=args.max_kb_chunks
    )

    # Display results
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

    # Save results - different folder based on whether KB was used
    if use_kb:
        output_dir = Path("without_rag_with_kb_results")
    else:
        output_dir = Path("without_rag_results")
    output_dir.mkdir(exist_ok=True)

    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    har_name = Path(har_file).stem if har_file else "no_har"
    output_file = output_dir / f"{timestamp}_{har_name}_without_rag_result.json"

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
