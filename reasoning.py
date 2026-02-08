"""
Simple RAG (Retrieval-Augmented Generation) System
Uses knowledge_base folder (markdown) and parsed_hars folder (JSON) with call_llm from utils.py
"""

from openai import OpenAI
from typing import List, Dict, Optional
import os
import json
import argparse
from config import config
from utils import call_llm

# Initialize OpenAI client for embeddings
client = OpenAI(api_key=config['OPENAI_KEY'])

# Configuration
KNOWLEDGE_BASE_DIR = "knowledge_base"
PARSED_HARS_DIR = "parsed_hars"
EMBEDDING_MODEL = "text-embedding-3-small"

# Prompt
PROMPT=""""You are a security analyst. Analyze the following HAR file step-by-step:

Step 1: Describe the business flow
Step 2: Identify any missing state validations
Step 3: Check if any object properties can be manipulated
Step 4: Classify the vulnerability using OWASP BLA taxonomy

<PARSED_HARS>
"""

def load_documents(kb_dir: str = KNOWLEDGE_BASE_DIR) -> List[Dict]:
    """
    Load all markdown documents from knowledge base folder.

    Returns:
        List of dicts with 'content', 'source', and 'metadata'
    """
    documents = []

    for filename in os.listdir(kb_dir):
        if filename.endswith('.md'):
            filepath = os.path.join(kb_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Split into sections based on headers
            sections = split_into_sections(content, filename)

            for section in sections:
                documents.append({
                    'content': section['content'],
                    'source': filename,
                    'section': section['title']
                })

    return documents


def get_parsed_har_files(hars_dir: str = PARSED_HARS_DIR) -> List[str]:
    """
    Get list of JSON files in parsed_hars directory.

    Returns:
        List of filenames
    """
    if not os.path.exists(hars_dir):
        return []

    return [f for f in os.listdir(hars_dir) if f.endswith('.json')]


def load_har_file(filepath: str, source: str) -> List[Dict]:
    """
    Load HAR file and convert entries to text documents.

    Returns:
        List of dicts with 'content', 'source', and 'metadata'
    """
    documents = []

    with open(filepath, 'r', encoding='utf-8') as f:
        har_data = json.load(f)

    target_domain = har_data.get('target_domain', 'unknown')
    entries = har_data.get('entries', [])

    for i, entry in enumerate(entries):
        # Convert entry to text format
        content = har_entry_to_text(entry, i, target_domain)

        documents.append({
            'content': content,
            'source': source,
            'section': f"Entry {i + 1}",
            'type': 'har'
        })

    return documents


def har_entry_to_text(entry: Dict, index: int, target_domain: str) -> str:
    """
    Convert a HAR entry to readable text format.

    Returns:
        Formatted text string
    """
    request = entry.get('request', {})
    response = entry.get('response', {})

    # Extract request info
    method = request.get('method', '')
    url = request.get('url', '')
    normalized_path = entry.get('_normalized_path', '')

    # Extract headers (summarized)
    headers = request.get('headers', [])
    header_summary = summarize_headers(headers)

    # Extract post data
    post_data = request.get('postData', {})
    post_text = post_data.get('text', '')
    post_params = post_data.get('params', [])

    # Extract response info
    status = response.get('status', 0)
    content_size = response.get('content', {}).get('size', 0)

    # Build text representation
    text_parts = [
        f"HTTP Request #{index + 1} from {target_domain}",
        f"Method: {method}",
        f"URL: {url}",
        f"Normalized Path: {normalized_path}",
        f"Response Status: {status}",
        f"Content Size: {content_size} bytes",
    ]

    if header_summary:
        text_parts.append(f"Key Headers: {header_summary}")

    if post_params:
        text_parts.append(f"POST Params: {json.dumps(post_params, indent=2)}")

    if post_text:
        text_parts.append(f"POST Body: {post_text[:500]}")  # Limit body size

    return "\n".join(text_parts)


def summarize_headers(headers: List[Dict]) -> str:
    """
    Summarize important headers.

    Returns:
        Comma-separated string of important header names
    """
    important_headers = ['authorization', 'cookie', 'content-type', 'x-api-key', 'referer']
    found = []

    for header in headers:
        name = header.get('name', '').lower()
        if any(imp in name for imp in important_headers):
            found.append(header.get('name', ''))

    return ', '.join(found) if found else ''


def split_into_sections(content: str, source: str) -> List[Dict]:
    """
    Split markdown content into sections based on headers.

    Returns:
        List of dicts with 'title' and 'content'
    """
    sections = []
    lines = content.split('\n')
    current_section = {'title': 'Introduction', 'content': []}

    for line in lines:
        # Check for markdown headers (### or ####)
        if line.startswith('###'):
            # Save previous section
            if current_section['content']:
                sections.append({
                    'title': current_section['title'],
                    'content': '\n'.join(current_section['content']).strip()
                })

            # Start new section
            current_section = {
                'title': line.strip('#').strip(),
                'content': []
            }
        else:
            current_section['content'].append(line)

    # Add last section
    if current_section['content']:
        sections.append({
            'title': current_section['title'],
            'content': '\n'.join(current_section['content']).strip()
        })

    return sections


def get_embedding(text: str) -> List[float]:
    """
    Get embedding for a text string using OpenAI.

    Args:
        text: Text to embed

    Returns:
        List of embedding values
    """
    # Truncate if too long (embedding model has limit)
    text = text[:8191]

    response = client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=text
    )

    return response.data[0].embedding


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """
    Calculate cosine similarity between two vectors.
    """
    dot_product = sum(x * y for x, y in zip(a, b))
    magnitude_a = sum(x * x for x in a) ** 0.5
    magnitude_b = sum(y * y for y in b) ** 0.5

    if magnitude_a == 0 or magnitude_b == 0:
        return 0

    return dot_product / (magnitude_a * magnitude_b)


class SimpleRAG:
    """
    Simple RAG system for querying knowledge base.
    """

    def __init__(self, kb_dir: str = KNOWLEDGE_BASE_DIR, har_files: Optional[List[str]] = None):
        """
        Initialize RAG system.

        Args:
            kb_dir: Path to knowledge base directory
            har_files: List of HAR filenames to include (from parsed_hars)
        """
        self.documents = load_documents(kb_dir)
        self.embeddings = None

        # Load HAR files if specified
        if har_files:
            for filename in har_files:
                filepath = os.path.join(PARSED_HARS_DIR, filename)
                if os.path.exists(filepath):
                    print(f"Loading HAR file: {filename}")
                    har_docs = load_har_file(filepath, filename)
                    self.documents.extend(har_docs)
                    print(f"  Added {len(har_docs)} entries from {filename}")

    def add_har_file(self, filename: str):
        """
        Add a HAR file to the existing index.

        Args:
            filename: Name of HAR file in parsed_hars directory
        """
        filepath = os.path.join(PARSED_HARS_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File not found: {filename}")
            return 0

        print(f"Loading HAR file: {filename}")
        har_docs = load_har_file(filepath, filename)
        self.documents.extend(har_docs)
        print(f"Added {len(har_docs)} entries from {filename}")

        # Rebuild index if it exists
        if self.embeddings is not None:
            print("Rebuilding index...")
            self.build_index()

        return len(har_docs)

    def build_index(self):
        """
        Build embeddings index for all documents.
        """
        print(f"Building index for {len(self.documents)} sections...")
        self.embeddings = []

        for i, doc in enumerate(self.documents):
            if i % 10 == 0:
                print(f"  Processing {i}/{len(self.documents)}...")

            embedding = get_embedding(doc['content'])
            self.embeddings.append({
                'embedding': embedding,
                'doc_index': i
            })

        print(f"Index built successfully!")

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict]:
        """
        Retrieve most relevant documents for a query.

        Args:
            query: Query string
            top_k: Number of top results to return

        Returns:
            List of relevant documents with metadata
        """
        if self.embeddings is None:
            raise RuntimeError("Index not built. Call build_index() first.")

        # Get query embedding
        query_embedding = get_embedding(query)

        # Calculate similarities
        results = []
        for item in self.embeddings:
            doc = self.documents[item['doc_index']]
            similarity = cosine_similarity(query_embedding, item['embedding'])

            results.append({
                'content': doc['content'],
                'source': doc['source'],
                'section': doc['section'],
                'score': similarity
            })

        # Sort by similarity and return top_k
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def query(
        self,
        question: str,
        model: str = config['MODEL'],
        top_k: int = 3,
        temperature: float = 0.2
    ) -> str:
        """
        Query the RAG system.

        Args:
            question: User's question
            model: Model to use for generation
            top_k: Number of context chunks to retrieve
            temperature: LLM temperature

        Returns:
            Generated answer
        """
        # Retrieve relevant context
        context_docs = self.retrieve(question, top_k=top_k)

        # Build context string
        context = "\n\n---\n\n".join([
            f"From {doc['source']} - {doc['section']}:\n{doc['content']}"
            for doc in context_docs
        ])

        # Build prompt
        prompt = f"""You are a security expert specializing in business logic vulnerabilities and OWASP testing guidelines.

Use the following context from the knowledge base to answer the user's question.

Context:
{context}

Question: {question}

Provide a comprehensive answer based on the context above. If the context doesn't contain relevant information, say so explicitly."""

        # Call LLM
        messages = [
            {"role": "system", "content": "You are a security expert assistant."},
            {"role": "user", "content": prompt}
        ]

        response = call_llm(
            model=model,
            messages=messages,
            response_format=None,
            temperature=temperature
        )

        # Add sources info
        sources = [f"- {doc['source']} ({doc['section']})" for doc in context_docs]
        sources_text = "\n".join(sources)

        return f"{response}\n\n---\n**Sources:**\n{sources_text}"


def interactive_menu(har_files: Optional[List[str]] = None):
    """
    Interactive CLI menu for building and querying RAG system.

    Args:
        har_files: List of HAR filenames to include (from command line)
    """
    print("=" * 60)
    print("RAG System - Interactive Mode")
    print("=" * 60)

    print(f"\n📁 Knowledge Base: {KNOWLEDGE_BASE_DIR} (auto-loaded)")

    if har_files:
        print(f"📁 HAR files: {', '.join(har_files)}")
    else:
        print(f"📁 HAR files: None (use --har argument to include)")

    # Show available HAR files if none specified
    if not har_files:
        available_hars = get_parsed_har_files()
        if available_hars:
            print(f"\n💡 Tip: Available HAR files in {PARSED_HARS_DIR}:")
            for filename in available_hars:
                print(f"   - {filename}")
            print("\n💡 Use: python rag.py --har <filename> to include a HAR file")

    # Create RAG instance
    print("\n🔧 Initializing RAG system...")
    rag = SimpleRAG(har_files=har_files)

    # Build index
    print("\n📊 Building embedding index...")
    rag.build_index()

    # Query loop
    print("\n" + "=" * 60)
    print("✅ Ready! Enter your questions (or 'quit' to exit)")
    print("=" * 60)

    while True:
        print("\n❓ Your question:")
        question = input("> ").strip()

        if not question:
            continue

        if question.lower() in ['quit', 'exit', 'q']:
            print("Goodbye! 👋")
            break

        print("\n🤖 Thinking...")
        try:
            answer = rag.query(question)
            print(f"\n💡 Answer:\n{answer}")
        except Exception as e:
            print(f"\n❌ Error: {e}")


def demo():
    """
    Demo function showing how to use the RAG system.
    """
    print("Initializing RAG system...")

    # Create RAG instance without HAR files
    rag = SimpleRAG()

    # Build index (only need to do this once)
    rag.build_index()

    # Example queries
    questions = [
        "What are Object State Manipulations?",
        "How can I detect Missing Transition Validation in HTTP traffic?",
        "What is Shadow Function Abuse?"
    ]

    for question in questions:
        print(f"\n{'='*60}")
        print(f"Question: {question}")
        print(f"{'='*60}")

        answer = rag.query(question)
        print(answer)


def parse_args():
    """
    Parse command line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="RAG System - Query knowledge base and HAR files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rag.py                      # Run with knowledge base only
  python rag.py --har pixi.json      # Include specific HAR file
  python rag.py --har juice_shop.json ginandjuice-shop.json  # Multiple HAR files
  python rag.py --demo               # Run demo mode
        """
    )

    parser.add_argument(
        '--har',
        nargs='+',
        help='HAR file(s) to include from parsed_hars folder'
    )

    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demo mode with sample questions'
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.demo:
        demo()
    else:
        interactive_menu(har_files=args.har)