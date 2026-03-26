import os
import tiktoken
from pathlib import Path


def count_tokens_in_file(file_path: str, encoding: tiktoken.Encoding) -> int:
    """Count tokens in a file using tiktoken."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        tokens = encoding.encode(content)
        return len(tokens)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return 0


def scan_directory(directory: str, encoding: tiktoken.Encoding) -> dict:
    """Scan directory and count tokens for each file, returning base_name -> token_count."""
    results = {}
    path = Path(directory)

    if not path.exists():
        print(f"Directory not found: {directory}")
        return results

    for file_path in path.iterdir():
        if file_path.is_file():
            # Get base name without extension
            base_name = file_path.stem
            token_count = count_tokens_in_file(str(file_path), encoding)
            results[base_name] = token_count

    return results


def print_table(hars_results: dict, parsed_hars_results: dict):
    """Print results in a formatted table."""
    # Get all unique base names
    all_files = set(hars_results.keys()) | set(parsed_hars_results.keys())
    sorted_files = sorted(all_files)

    # Print header
    print("\n" + "=" * 100)
    print(f"{'File Name':<50} {'Before (hars/)':>20} {'After (parsed_hars/)':>25}")
    print("=" * 100)

    # Print rows
    total_before = 0
    total_after = 0

    for file_name in sorted_files:
        before_count = hars_results.get(file_name, 0)
        after_count = parsed_hars_results.get(file_name, 0)
        reduction = before_count - after_count
        reduction_pct = (reduction / before_count * 100) if before_count > 0 else 0

        print(f"{file_name:<50} {before_count:>20,} {after_count:>25,} ({reduction_pct:>5.1f}% reduction)")

        total_before += before_count
        total_after += after_count

    # Print totals
    print("-" * 100)
    total_reduction = total_before - total_after
    total_reduction_pct = (total_reduction / total_before * 100) if total_before > 0 else 0
    print(f"{'TOTAL':<50} {total_before:>20,} {total_after:>25,} ({total_reduction_pct:>5.1f}% reduction)")
    print("=" * 100)
    print(f"\nGrand Total: {total_before + total_after:,} tokens | Saved: {total_reduction:,} tokens ({total_reduction_pct:.1f}%)")
    print("=" * 100)


def main():
    # Initialize tiktoken encoding (using o200k_base for GPT-4o/GPT-5-mini)
    try:
        encoding = tiktoken.encoding_for_model("gpt-4o")
    except KeyError:
        # Fallback to direct encoding name
        encoding = tiktoken.get_encoding("cl100k_base")

    # Directories to scan
    hars_dir = "hars"
    parsed_hars_dir = "parsed_hars"

    print("Counting tokens using tiktoken (o200k_base encoding for GPT-4o/GPT-5-mini)...\n")

    # Scan directories
    hars_results = scan_directory(hars_dir, encoding)
    parsed_hars_results = scan_directory(parsed_hars_dir, encoding)

    # Print results as table
    print_table(hars_results, parsed_hars_results)


if __name__ == "__main__":
    main()
