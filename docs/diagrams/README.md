# Rowanholt Architecture Diagrams

This directory contains Graphviz DOT files for generating professional architecture diagrams.

## Available Diagrams

1. **system_architecture.dot** - Complete system architecture with all layers
2. **database_erd.dot** - Database entity-relationship diagram
3. **job_state_machine.dot** - Job lifecycle state machine

## Rendering Diagrams

### Prerequisites

Install Graphviz:

**macOS:**
```bash
brew install graphviz
```

**Ubuntu/Debian:**
```bash
sudo apt-get install graphviz
```

**Windows:**
Download from https://graphviz.org/download/

### Generate PNG Images

```bash
# System Architecture
dot -Tpng system_architecture.dot -o system_architecture.png

# Database ERD
dot -Tpng database_erd.dot -o database_erd.png

# Job State Machine
dot -Tpng job_state_machine.dot -o job_state_machine.png
```

### Generate SVG (Scalable)

```bash
# System Architecture
dot -Tsvg system_architecture.dot -o system_architecture.svg

# Database ERD
dot -Tsvg database_erd.dot -o database_erd.svg

# Job State Machine
dot -Tsvg job_state_machine.dot -o job_state_machine.svg
```

### Generate PDF

```bash
# System Architecture
dot -Tpdf system_architecture.dot -o system_architecture.pdf

# All diagrams
for file in *.dot; do
    dot -Tpdf "$file" -o "${file%.dot}.pdf"
done
```

### Batch Generation Script

**File:** `generate_diagrams.sh`

```bash
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Generating Rowanholt Architecture Diagrams...${NC}\n"

# Create output directory
mkdir -p output

# Generate PNG, SVG, and PDF for each diagram
for dotfile in *.dot; do
    base="${dotfile%.dot}"
    echo -e "${GREEN}Processing: $dotfile${NC}"

    # PNG (for web/presentations)
    dot -Tpng "$dotfile" -o "output/${base}.png"
    echo "  ✓ Generated output/${base}.png"

    # SVG (scalable for documentation)
    dot -Tsvg "$dotfile" -o "output/${base}.svg"
    echo "  ✓ Generated output/${base}.svg"

    # PDF (for printing/reports)
    dot -Tpdf "$dotfile" -o "output/${base}.pdf"
    echo "  ✓ Generated output/${base}.pdf"

    echo
done

echo -e "${GREEN}All diagrams generated successfully!${NC}"
echo "Output directory: $(pwd)/output"
```

Make it executable and run:
```bash
chmod +x generate_diagrams.sh
./generate_diagrams.sh
```

## Embedding in Markdown

### PNG
```markdown
![System Architecture](diagrams/output/system_architecture.png)
```

### SVG
```markdown
![Database ERD](diagrams/output/database_erd.svg)
```

## Customization

### Color Scheme

The diagrams use the Rowanholt theme colors:
- Background: `#0f0f23` (dark blue)
- Nodes: `#2d2d44` (slate)
- Text: `#f0dba5` (gold)
- Borders: `#3f4b2a` (olive green)
- Edges: `#66d9ef` (cyan)
- Labels: `#a7db6c` (lime green)

### Modifying Diagrams

Edit the `.dot` files directly. Common modifications:

**Add a new node:**
```dot
new_component [label="New Component", fillcolor="#custom_color"];
```

**Add a connection:**
```dot
component_a -> component_b [label="Connection", color="#66d9ef"];
```

**Change layout:**
```dot
rankdir=TB;  // Top to Bottom
rankdir=LR;  // Left to Right
```

## Integration with CI/CD

### GitHub Actions

**File:** `.github/workflows/generate-diagrams.yml`

```yaml
name: Generate Architecture Diagrams

on:
  push:
    paths:
      - 'docs/diagrams/*.dot'

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Graphviz
        run: sudo apt-get install -y graphviz

      - name: Generate Diagrams
        run: |
          cd docs/diagrams
          ./generate_diagrams.sh

      - name: Commit Generated Images
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add docs/diagrams/output/*.{png,svg,pdf}
          git commit -m "Auto-generate architecture diagrams" || true
          git push || true
```

## Viewing Online

### VS Code
Install the "Graphviz Preview" extension to view `.dot` files directly in VS Code.

### Online Editors
- http://www.webgraphviz.com/
- https://dreampuf.github.io/GraphvizOnline/
- https://edotor.net/

Just paste the contents of any `.dot` file.

## Advanced Rendering Options

### High-Resolution PNGs
```bash
dot -Tpng -Gdpi=300 system_architecture.dot -o system_architecture_hires.png
```

### Specific Layout Engine
```bash
# Use neato for undirected graphs
neato -Tpng database_erd.dot -o database_erd.png

# Use fdp for large graphs
fdp -Tpng system_architecture.dot -o system_architecture.png

# Use circo for circular layouts
circo -Tpng job_state_machine.dot -o job_state_machine.png
```

### Interactive SVG
```bash
dot -Tsvg -Gsize="10,10" -Gdpi=72 system_architecture.dot -o interactive.svg
```

## Troubleshooting

### Diagram Not Rendering
- Check DOT syntax with: `dot -v diagram.dot`
- Validate with online editor first
- Check for unclosed quotes or missing semicolons

### Missing Fonts
```bash
# Install font packages
sudo apt-get install fonts-liberation
```

### Performance Issues
For large diagrams, use a simpler layout engine:
```bash
sfdp -Tpng large_diagram.dot -o large_diagram.png
```

## Resources

- Graphviz Documentation: https://graphviz.org/documentation/
- DOT Language Guide: https://graphviz.org/doc/info/lang.html
- Node Shapes: https://graphviz.org/doc/info/shapes.html
- Color Names: https://graphviz.org/doc/info/colors.html

---

**Note:** Generated diagram files are gitignored by default. Run the generation script locally or set up CI/CD to auto-generate them.
