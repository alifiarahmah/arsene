# Batch HAR Analysis Pipeline

# Parse HAR files
Write-Host "[1/4] Parsing HAR files..."
Get-ChildItem -Path "hars" -Filter "*.har" -File | ForEach-Object {
    python parser.py $_.FullName parsed_hars
}

# Run analysis scripts
Write-Host "[2/4] Running without_rag.py --no-kb..."
Get-ChildItem -Path "parsed_hars" -Filter "*.json" -File | ForEach-Object {
    python without_rag.py --no-kb $_.FullName
}

Write-Host "[3/4] Running without_rag.py --with-kb..."
Get-ChildItem -Path "parsed_hars" -Filter "*.json" -File | ForEach-Object {
    python without_rag.py --with-kb $_.FullName
}

Write-Host "[4/4] Running rag.py --rebuild-index..."
Get-ChildItem -Path "parsed_hars" -Filter "*.json" -File | ForEach-Object {
    python rag.py --rebuild-index $_.FullName
}

Write-Host "Pipeline complete"
