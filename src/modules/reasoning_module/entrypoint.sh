#!/bin/sh

set -e

echo "========================================"
echo "🚀 Starting Ollama server..."
echo "========================================"

# Start ollama server in background, wait for server to be ready
/bin/ollama serve &
sleep 5

# model_name="deepseek-r1:1.5b"
model_name="phi3:mini" # for rapid prototyping

echo "========================================"
echo "⬇️ DOWNLOADING $model_name model ⬇️"
echo "========================================"

ollama pull $model_name

echo "========================================"
echo "✅ $model_name model ready!"
echo "🚀 Ollama server running on port 11434"
echo "========================================"

# Keep container alive
tail -f /dev/null