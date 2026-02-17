# Usage Documentation

This document provides comprehensive usage instructions for the three main Python scripts in this project: `parser.py`, `rag.py`, and `without_rag.py`.

## Table of Contents

1. [Overview](#overview)
2. [parser.py - HAR File Parser](#parserpy---har-file-parser)
3. [rag.py - RAG-based Analysis](#ragpy---rag-based-analysis)
4. [without_rag.py - Direct LLM Analysis](#without_ragpy---direct-llm-analysis)
5. [Workflow Example](#workflow-example)
6. [Requirements](#requirements)

---

## Overview

This project provides tools for analyzing Business Logic Vulnerabilities (BLV) in web applications using HTTP traffic captured in HAR (HTTP Archive) files. The analysis can be performed using two approaches:

1. **RAG (Retrieval-Augmented Generation)**: Uses FAISS vector similarity search to retrieve relevant knowledge from a security knowledge base
2. **Direct LLM**: Sends full knowledge base context directly to the LLM

Both approaches use `parser.py` to preprocess HAR files before analysis.

---

## parser.py - HAR File Parser

### Purpose

[parser.py](parser.py) parses and filters raw HAR files to extract security-relevant information. It removes noise like static assets, third-party requests, and irrelevant data while preserving sensitive fields and business logic indicators.

### Features

- **Static Asset Filtering**: Removes `.css`, `.js`, images, fonts, and other static files
- **Third-party Filtering**: Excludes requests to analytics, CDNs, and third-party services
- **Header Filtering**: Keeps only relevant headers (Authorization, Cookie, Content-Type, X-\*)
- **Content Filtering**: Smart filtering based on content type (JSON, HTML, XML, text)
- **Base64 Decoding**: Handles ZAP's base64-encoded response content
- **Sensitive Field Preservation**: Always keeps fields like `id`, `user_id`, `token`, `password`, etc.

### Usage

```bash
# Parse a single HAR file
python parser.py <path_to_har_file>

# Parse a single HAR file with custom output directory
python parser.py <path_to_har_file> <output_directory>

# Parse all HAR files in a directory
python parser.py <directory_with_har_files>

# Parse all HAR files with custom output directory
python parser.py <directory_with_har_files> <output_directory>
```

### Examples

```bash
# Parse a single HAR file (outputs to parsed_hars/ by default)
python parser.py hars/juice_shop.har

# Parse with custom output directory
python parser.py hars/juice_shop.har my_parsed_hars/

# Parse all HAR files in the hars/ directory
python parser.py hars/

# Parse all HAR files with custom output
python parser.py hars/ custom_output/
```

### Output

The parser generates filtered JSON files in the output directory (default: `parsed_hars/`). Each output file:

- Contains only security-relevant HTTP entries
- Has filtered headers (keeps Authorization, Cookie, X-\*, etc.)
- Preserves sensitive fields in JSON/HTML content
- Truncates large responses intelligently
- Decodes base64 content from ZAP recordings

### Statistics

After parsing, the script displays statistics:

```
Statistics:
  Total entries: 245
  Static assets: 89
  Third-party requests: 45
  Relevant requests: 111
  Base64 encoded responses: 23
  Unique domains: 8
```

---

## rag.py - RAG-based Analysis

### Purpose

[rag.py](rag.py) implements a Retrieval-Augmented Generation system that:

1. Builds a vector index from security knowledge base documents
2. Retrieves relevant knowledge chunks using semantic search
3. Augments HAR context with retrieved knowledge
4. Uses LLM to analyze for Business Logic Vulnerabilities

### Features

- **FAISS Vector Store**: Fast similarity search with normalized embeddings
- **Semantic Retrieval**: Finds relevant KB sections based on query meaning
- **Chunked Context**: Handles large HAR files through intelligent chunking
- **Configurable Retrieval**: Adjust number of chunks to retrieve
- **Index Persistence**: Saves/loads FAISS index to avoid rebuilding

### Usage

```bash
# Run RAG analysis with a specific HAR file
python rag.py <har_file>

# List available HAR files
python rag.py --list

# Run without HAR file (knowledge-only analysis)
python rag.py --no-har

# Run without knowledge base (HAR-only analysis)
python rag.py <har_file> --no-kb

# Force rebuild of FAISS index
python rag.py <har_file> --rebuild-index

# Customize number of chunks to retrieve
python rag.py <har_file> --top-k 10

# Use custom retrieval query
python rag.py <har_file> --query "analyze authentication bypass vulnerabilities"
```

### Examples

```bash
# Analyze juice_shop HAR with RAG
python rag.py juice_shop.json

# List available parsed HAR files
python rag.py --list

# Run with HAR file from parsed_hars directory (filename only)
python rag.py juice_shop

# Force rebuild index and analyze
python rag.py juice_shop.json --rebuild-index

# Retrieve top 10 chunks instead of default 5
python rag.py juice_shop.json --top-k 10

# Analyze without knowledge base (HAR patterns only)
python rag.py juice_shop.json --no-kb

# Run without HAR file (test knowledge retrieval)
python rag.py --no-har

# Custom query for specific vulnerability type
python rag.py juice_shop.json --query "find privilege escalation vulnerabilities"
```

### Command-line Arguments

| Argument          | Type       | Description                                                              |
| ----------------- | ---------- | ------------------------------------------------------------------------ |
| `har_file`        | positional | HAR file to analyze (filename or full path)                              |
| `--list`          | flag       | List available HAR files in parsed_hars/                                 |
| `--no-har`        | flag       | Run analysis without HAR file                                            |
| `--no-kb`         | flag       | Run without knowledge base context                                       |
| `--top-k`         | int        | Number of knowledge chunks to retrieve (default: 5)                      |
| `--rebuild-index` | flag       | Force rebuild of FAISS index                                             |
| `--query`         | string     | Custom query for retrieval (default: "you are a security researcher...") |

### Output

Results are saved to `rag_results/` with timestamp:

```
rag_results/20260212_070933_juice_shop_rag_result.json
```

Each result contains:

- `business_flow`: Description of the application's business logic flow
- `thought_process`: Step-by-step reasoning
- `potential_vulnerabilities`: Array of vulnerability findings with:
  - `category`: Vulnerability type
  - `severity`: Critical/High/Medium/Low
  - `description`: Vulnerability description
  - `evidence_entry_ids`: HAR entry IDs as evidence
  - `reproduction_guide`: PoC with payload mutation and cURL command

---

## without_rag.py - Direct LLM Analysis

### Purpose

[without_rag.py](without_rag.py) implements direct LLM analysis that:

1. Loads and chunks the full knowledge base
2. Concatenates chunks into prompt context
3. Sends complete context + HAR to LLM
4. Used for comparison with RAG approach

### Features

- **No Vector Store**: Simpler pipeline without FAISS
- **Full KB Context**: All knowledge base chunks included (up to limit)
- **Chunking Strategy**: Same intelligent chunking as RAG version
- **Configurable Context**: Adjust maximum KB chunks to fit context window
- **Optional KB**: Can run without knowledge base for comparison

### Usage

```bash
# Run analysis without knowledge base (default behavior)
python without_rag.py <har_file>

# Run with knowledge base included
python without_rag.py <har_file> --with-kb

# List available HAR files
python without_rag.py --list

# Run without HAR file
python without_rag.py --no-har

# Customize maximum KB chunks (default: 20)
python without_rag.py <har_file> --max-kb-chunks 10 --with-kb
```

### Examples

```bash
# Analyze juice_shop HAR without knowledge base
python without_rag.py juice_shop.json

# Analyze WITH knowledge base
python without_rag.py juice_shop.json --with-kb

# List available parsed HAR files
python without_rag.py --list

# Run with smaller KB context (10 chunks instead of 20)
python without_rag.py juice_shop.json --with-kb --max-kb-chunks 10

# Run without HAR file (knowledge base only)
python without_rag.py --no-har --with-kb
```

### Command-line Arguments

| Argument          | Type       | Description                                        |
| ----------------- | ---------- | -------------------------------------------------- |
| `har_file`        | positional | HAR file to analyze (filename or full path)        |
| `--list`          | flag       | List available HAR files in parsed_hars/           |
| `--no-har`        | flag       | Run analysis without HAR file                      |
| `--with-kb`       | flag       | Include knowledge base context (default: disabled) |
| `--max-kb-chunks` | int        | Maximum KB chunks to include (default: 20)         |

### Output

Results are saved to `without_rag_results/` with timestamp:

```
without_rag_results/20260212_071002_juice_shop_without_rag_result.json
```

Output format is identical to RAG version for easy comparison.

---

## Workflow Example

### Complete Analysis Workflow

```bash
# Step 1: Parse raw HAR files
python parser.py hars/juice_shop.har

# Step 2: Run RAG-based analysis
python rag.py juice_shop.json

# Step 3: Run direct LLM analysis (for comparison)
python without_rag.py juice_shop.json --with-kb

# Step 4: Compare results in the output directories
# - rag_results/
# - without_rag_results/
```

### Batch Processing Multiple HAR Files

```bash
# Step 1: Parse all HAR files in a directory
python parser.py hars/

# Step 2: Analyze each parsed file with RAG
python rag.py 1_excessive_trust_in_client-side_controls.json
python rag.py 2_2fa_broken_logic.json
python rag.py juice_shop.json

# Step 3: Analyze each with direct LLM
python without_rag.py 1_excessive_trust_in_client-side_controls.json --with-kb
python without_rag.py 2_2fa_broken_logic.json --with-kb
python without_rag.py juice_shop.json --with-kb
```

---

## Requirements

### Python Dependencies

```bash
pip install haralyzer faiss-cpu sentence-transformers
```

Or with GPU support for FAISS:

```bash
pip install faiss-gpu
```

### Full Requirements

See `requirements.txt` for complete dependency list:

- `haralyzer`: HAR file parsing
- `faiss-cpu` or `faiss-gpu`: Vector similarity search
- `sentence-transformers`: Text embeddings for RAG
- `openai`: LLM API calls (for utils.py)

### Directory Structure

```
project/
├── hars/                      # Raw HAR files (.har)
├── parsed_hars/               # Filtered JSON outputs from parser.py
├── rag_results/               # RAG analysis results
├── without_rag_results/       # Direct LLM analysis results
├── knowledge_base/            # Security knowledge base markdown files
│   ├── top10bla.md
│   └── wstg_wsa.md
├── prompts/                   # Prompt templates
│   ├── system_prompt.txt
│   └── user_message.txt
├── parser.py                  # HAR file parser
├── rag.py                     # RAG-based analysis
├── without_rag.py             # Direct LLM analysis
├── schema.py                  # Pydantic models for output
└── utils.py                   # LLM API utilities
```

---

## Tips and Best Practices

1. **Always parse HAR files first**: Raw HAR files from tools like ZAP or Burp Suite contain lots of noise. Use `parser.py` to filter them.

2. **Start with RAG**: The RAG approach is more efficient and typically provides better results by retrieving only relevant knowledge.

3. **Adjust `--top-k` for RAG**: Default is 5 chunks. Increase for broader context, decrease for focused analysis.

4. **Manage context window**: If using `without_rag.py`, adjust `--max-kb-chunks` to fit your LLM's context window.

5. **Use `--no-kb` for baseline**: Run analysis without knowledge base to establish a baseline of HAR-only analysis.

6. **Compare approaches**: Run both RAG and direct LLM on the same HAR to compare effectiveness.

7. **Check statistics**: After parsing, review statistics to ensure relevant requests were captured.

8. **Custom queries**: Tailor the `--query` parameter in RAG to focus on specific vulnerability types.

---

## Troubleshooting

### Common Issues

**Issue**: `FileNotFoundError: knowledge_base/top10bla.md not found`

- **Solution**: Ensure knowledge base files exist in the `knowledge_base/` directory

**Issue**: `Error: HAR file not found`

- **Solution**: Use `--list` to see available files, or provide full path to HAR file

**Issue**: Context length exceeded errors

- **Solution**: Reduce `--max-kb-chunks` in `without_rag.py` or `--top-k` in `rag.py`

**Issue**: FAISS index load errors

- **Solution**: Run with `--rebuild-index` to rebuild the index

---

## Additional Resources

- [HAR File Format Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
- [OWASP Top 10 Business Logic Vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/)
- [FAISS Documentation](https://faiss.ai/)
- [Sentence Transformers](https://www.sbert.net/)
