"""
Main Pipeline Script

Orchestrates the complete analysis pipeline:
1. Parse HAR file from hars/<filename>.har to parsed_hars/<filename>.json
2. Run RAG analysis with index rebuild
3. Run without_rag.py with knowledge base
4. Run RAG analysis without knowledge base
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from parser import parse_har_file


def run_command(cmd: list[str], description: str) -> int:
    """
    Run a command and print its output.

    Args:
        cmd: Command list to execute
        description: Description of what the command does

    Returns:
        Exit code from the command
    """
    print(f"\n{'=' * 70}")
    print(f"[STEP] {description}")
    print(f"{'=' * 70}")
    print(f"Command: {' '.join(cmd)}")
    print('-' * 70)

    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}")

    return result.returncode


def main():
    """Main pipeline function."""
    parser = argparse.ArgumentParser(
        description="Complete HAR Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline on a HAR file
  python main.py juice_shop.har

  # Run on a HAR file (without .har extension)
  python main.py juice_shop
        """
    )
    parser.add_argument(
        "har_file",
        help="HAR file to analyze (path or filename from hars/ directory)"
    )

    args = parser.parse_args()

    # Resolve HAR file path
    har_input = args.har_file
    har_path = Path(har_input)

    # If not a full path, look in hars/ directory
    if not har_path.exists():
        har_path = Path("hars") / har_input
        if not har_path.exists():
            # Try with .har extension
            if not har_input.endswith('.har'):
                har_path = Path("hars") / f"{har_input}.har"
                if not har_path.exists():
                    print(f"Error: HAR file not found: {args.har_file}")
                    print(f"       Searched in: hars/")
                    sys.exit(1)
            else:
                print(f"Error: HAR file not found: {args.har_file}")
                print(f"       Searched in: hars/")
                sys.exit(1)

    har_path = har_path.resolve()

    # Get filename without extension
    har_name = har_path.stem

    print("=" * 70)
    print("COMPLETE HAR ANALYSIS PIPELINE")
    print("=" * 70)
    print(f"HAR File: {har_path}")
    print(f"Filename: {har_name}")
    print("=" * 70)

    # Step 1: Parse HAR file
    print(f"\n{'=' * 70}")
    print(f"[STEP 1/4] Parsing HAR file")
    print(f"{'=' * 70}")
    print(f"Input: {har_path}")
    print(f"Output: parsed_hars/{har_name}.json")

    try:
        output_path = parse_har_file(str(har_path), "parsed_hars")
        print(f"[OK] Parsed HAR file: {output_path}")
    except Exception as e:
        print(f"[ERROR] Failed to parse HAR file: {e}")
        sys.exit(1)

    # Path to parsed JSON file
    parsed_json = Path("parsed_hars") / f"{har_name}.json"

    # Verify the parsed file exists
    if not parsed_json.exists():
        print(f"[ERROR] Parsed file not found: {parsed_json}")
        sys.exit(1)

    # Step 2: Run RAG with index rebuild
    exit_code = run_command(
        [sys.executable, "rag.py", str(parsed_json), "--rebuild-index"],
        "RAG Analysis (with KB index rebuild)"
    )

    if exit_code != 0:
        print(f"\n[WARNING] RAG with rebuild-index failed, continuing pipeline...")

    # Step 3: Run without_rag.py with knowledge base
    exit_code = run_command(
        [sys.executable, "without_rag.py", str(parsed_json), "--with-kb"],
        "Without RAG Analysis (with KB)"
    )

    if exit_code != 0:
        print(f"\n[WARNING] without_rag with --with-kb failed, continuing pipeline...")

    # Step 4: Run RAG without knowledge base
    exit_code = run_command(
        [sys.executable, "rag.py", str(parsed_json), "--no-kb"],
        "RAG Analysis (without KB)"
    )

    if exit_code != 0:
        print(f"\n[WARNING] RAG with --no-kb failed.")

    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)
    print(f"Analyzed HAR file: {har_name}")
    print(f"\nResults saved to:")
    print(f"  - rag_results/")
    print(f"  - without_rag_with_kb_results/")
    print(f"  - rag_results/ (with --no-kb)")
    print("=" * 70)


if __name__ == "__main__":
    main()
