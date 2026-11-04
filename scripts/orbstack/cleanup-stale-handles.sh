#!/bin/bash
# Cleanup OrbStack file handles and restart Rowanholt
# Usage: ./scripts/cleanup-orbstack-handles.sh [--force]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROWANHOLT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$ROWANHOLT_ROOT"

FORCE=false
if [ "$1" = "--force" ]; then
    FORCE=true
fi

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   OrbStack File Handle Cleanup                            ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Check current handle count
HANDLE_COUNT=$(lsof 2>/dev/null | grep -c "/Volumes/Media5TB/rowanholt_imgs" || echo "0")
echo "Current file handles on test volume: $HANDLE_COUNT"

if [ "$HANDLE_COUNT" -gt 1000 ] || [ "$FORCE" = true ]; then
    if [ "$FORCE" = true ]; then
        echo "🔧 Force cleanup requested..."
    else
        echo "⚠️  High file handle count detected - cleaning up..."
    fi

    # Stop Rowanholt containers
    echo ""
    echo "1/4 Stopping Rowanholt containers..."
    docker-compose -f docker-compose.yml -f tests/docker-compose.testing.yml down

    # Restart OrbStack
    echo ""
    echo "2/4 Restarting OrbStack..."
    orbctl stop
    sleep 5
    orbctl start
    sleep 10

    # Verify cleanup
    NEW_COUNT=$(lsof 2>/dev/null | grep -c "/Volumes/Media5TB/rowanholt_imgs" || echo "0")
    echo ""
    echo "3/4 Cleanup verification:"
    echo "    Before: $HANDLE_COUNT handles"
    echo "    After:  $NEW_COUNT handles"

    if [ "$NEW_COUNT" -gt 100 ]; then
        echo "    ⚠️  Warning: Some handles still remain"
    else
        echo "    ✓ Cleanup successful"
    fi

    # Restart Rowanholt
    echo ""
    echo "4/4 Restarting Rowanholt..."
    ./scripts/start-testing-mode.sh

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║   Cleanup Complete - Ready for Testing                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
else
    echo "✓ File handle count is acceptable (< 1000)"
    echo ""
    echo "To force cleanup anyway, run: $0 --force"
fi
