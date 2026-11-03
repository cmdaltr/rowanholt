#!/bin/bash

# Dernvale Architecture Diagram Generator
# Generates PNG, SVG, and PDF versions of all Graphviz DOT diagrams

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Dernvale DFIR Suite - Diagram Generator${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check if Graphviz is installed
if ! command -v dot &> /dev/null; then
    echo -e "${RED}Error: Graphviz is not installed.${NC}\n"
    echo "Please install Graphviz:"
    echo "  macOS:    brew install graphviz"
    echo "  Ubuntu:   sudo apt-get install graphviz"
    echo "  Windows:  Download from https://graphviz.org/download/"
    exit 1
fi

echo -e "${GREEN}✓ Graphviz found: $(dot -V 2>&1)${NC}\n"

# Create output directory
OUTPUT_DIR="output"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}✓ Output directory: $OUTPUT_DIR${NC}\n"

# Count total diagrams
TOTAL_DIAGRAMS=$(ls -1 *.dot 2>/dev/null | wc -l)
if [ "$TOTAL_DIAGRAMS" -eq 0 ]; then
    echo -e "${YELLOW}No .dot files found in current directory.${NC}"
    exit 0
fi

echo -e "${BLUE}Found $TOTAL_DIAGRAMS diagram(s) to process${NC}\n"

# Generate diagrams
CURRENT=0
for dotfile in *.dot; do
    CURRENT=$((CURRENT + 1))
    base="${dotfile%.dot}"

    echo -e "${GREEN}[$CURRENT/$TOTAL_DIAGRAMS] Processing: ${YELLOW}$dotfile${NC}"

    # PNG (for web/presentations)
    echo -n "  → Generating PNG... "
    if dot -Tpng "$dotfile" -o "$OUTPUT_DIR/${base}.png" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi

    # PNG (High Resolution)
    echo -n "  → Generating PNG (High-Res)... "
    if dot -Tpng -Gdpi=300 "$dotfile" -o "$OUTPUT_DIR/${base}_hires.png" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi

    # SVG (scalable for documentation)
    echo -n "  → Generating SVG... "
    if dot -Tsvg "$dotfile" -o "$OUTPUT_DIR/${base}.svg" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi

    # PDF (for printing/reports)
    echo -n "  → Generating PDF... "
    if dot -Tpdf "$dotfile" -o "$OUTPUT_DIR/${base}.pdf" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi

    echo
done

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ All diagrams generated successfully!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

echo "Output files:"
ls -lh "$OUTPUT_DIR" | grep -v "^total" | awk '{print "  " $9 " (" $5 ")"}'

echo -e "\n${YELLOW}Tip:${NC} View diagrams with:"
echo "  • PNG:  open $OUTPUT_DIR/<diagram>.png"
echo "  • SVG:  open $OUTPUT_DIR/<diagram>.svg"
echo "  • PDF:  open $OUTPUT_DIR/<diagram>.pdf"
