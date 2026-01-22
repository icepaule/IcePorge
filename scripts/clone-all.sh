#!/bin/bash
# IcePorge - Clone All Repositories
CLONE_METHOD="${1:---ssh}"
BASE_DIR="${2:-$(pwd)}"

if [ "$CLONE_METHOD" = "--https" ]; then
    BASE_URL="https://github.com/icepaule"
else
    BASE_URL="git@github.com:icepaule"
fi

REPOS=(
    "IcePorge-MWDB-Stack"
    "IcePorge-MWDB-Feeder"
    "IcePorge-CAPE-Feed"
    "IcePorge-CAPE-Mailer"
    "IcePorge-Cockpit"
    "IcePorge-Ghidra-Orchestrator"
    "IcePorge-Malware-RAG"
)

echo "IcePorge - Cloning repositories..."
mkdir -p "$BASE_DIR/components"
cd "$BASE_DIR/components"

for repo in "${REPOS[@]}"; do
    if [ -d "$repo" ]; then
        echo "[$repo] Updating..."
        (cd "$repo" && git pull origin main 2>/dev/null) || echo "  Pull failed"
    else
        echo "[$repo] Cloning..."
        git clone "${BASE_URL}/${repo}.git" 2>/dev/null || git clone "${BASE_URL}:${repo}.git"
    fi
done

echo "Done! Repos in: $BASE_DIR/components/"
