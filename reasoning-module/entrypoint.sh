#!/bin/sh

/bin/ollama serve &
pid=$!

echo "========================================"
echo "⬇️ DOWNLOADING deepseek-r1:1.5b model ⬇️"
echo "========================================"

ollama pull deepseek-r1:1.5b

echo "========================================"
echo "✅  DOWNLOADED deepseek-r1:1.5b model ✅"
echo "🚀   RUNNING deepseek-r1:1.5b model   🚀"
echo "========================================"

ollama run deepseek-r1:1.5b

echo "========================================"
echo "✅   deepseek-r1:1.5b model RUNNING   ✅"
echo "========================================"

wait $pid