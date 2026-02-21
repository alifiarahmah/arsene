#!/bin/bash
# Batch HAR Analysis Pipeline

run_on_files() {
    local label="$1"
    shift
    echo "[$label]"
    for file in "$@"; do
        echo "  Processing: $(basename "$file")"
        "$0" "$file"
    done
}

# Parse HAR files
echo "[1/4] Parsing HAR files..."
for har in hars/*.har; do
    [ -f "$har" ] && python parser.py "$har" parsed_hars
done

# Run analysis scripts
echo "[2/4] Running without_rag.py --no-kb..."
for json in parsed_hars/*.json; do
    [ -f "$json" ] && python without_rag.py --no-kb "$json"
done

echo "[3/4] Running without_rag.py --with-kb..."
for json in parsed_hars/*.json; do
    [ -f "$json" ] && python without_rag.py --with-kb "$json"
done

echo "[4/4] Running rag.py --rebuild-index..."
for json in parsed_hars/*.json; do
    [ -f "$json" ] && python rag.py --rebuild-index "$json"
done

echo "Pipeline complete"
