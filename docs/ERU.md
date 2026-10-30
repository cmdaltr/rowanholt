# Eru - the AI Analyst

Eru answers questions about a case. In the web app it's **Ask Eru**; from a shell it's `python3 -m src.analysis.rivendell.ai.cli` ([CLI.md](CLI.md#eru-ai-analyst)); the endpoints are in [API.md](API.md#eru-ai-analyst).

## With Ollama

Free-text answers, case summaries and investigation suggestions come from a local model through Ollama. The backend finds it at `OLLAMA_HOST` (default `http://host.docker.internal:11434`, so Ollama on the Docker host) and uses `RIVENDELL_MODEL_NAME` (default `llama3.2:3b`). Nothing leaves the machine.

## Without Ollama

If Ollama isn't running, or the model isn't pulled, Ask Eru says which and how to fix it, turns off free text, and offers fixed questions answered exactly from Elrond's output for the selected case: which hosts are in it, which ATT&CK techniques were tagged, what persistence was flagged, who logged in (and failed to), which IOCs were extracted, which shell commands look suspicious, what matched threat intelligence (when the case was run with it), what's rare across the hosts (stacking's top rows, persistence first, each a lead rather than a verdict), and what analysts have confirmed in the case browser. With a model, confirmed findings go into its context first. A few general questions (persistence locations per OS, what Gandalf collects) need no case. These answers are read from the files and the findings, not generated, so they are the same every time.

## Eru Models

The Ollama Modelfiles in `src/models/` build Eru variants: a forensic system prompt over different base models.

## Available Models

| Model | Base Model | Size | Best For |
|-------|------------|------|----------|
| `eru-llama` | llama3.2:3b | 2GB | Fast responses, low resource usage |
| `eru-llama-large` | llama3.1:8b | 4.7GB | Complex analysis, better reasoning |
| `eru-mistral` | mistral:7b | 4.1GB | Balanced performance |
| `eru-qwen` | qwen2.5:7b | 4.4GB | Strong reasoning, multilingual |
| `eru-gemma` | gemma2:9b | 5.4GB | Efficient, well-rounded |
| `eru-phi` | phi3.5:3.8b | 2.2GB | Small but capable |
| `eru-deepseek` | deepseek-coder-v2:16b | 8.9GB | Code/script analysis |
| `eru-codellama` | codellama:7b | 3.8GB | Malware script analysis |

## Quick Start

1. Install Ollama: https://ollama.ai

2. Create a model:
   ```bash
   ollama create eru-llama -f src/models/Modelfile.eru-llama
   ```

3. Configure Rivendell to use it:
   ```bash
   export RIVENDELL_MODEL_NAME=eru-llama
   ```

## Creating All Models

```bash
cd /path/to/rivendell

# Lightweight (recommended for most systems)
ollama create eru-llama -f src/models/Modelfile.eru-llama
ollama create eru-phi -f src/models/Modelfile.eru-phi

# Medium (8GB+ VRAM)
ollama create eru-mistral -f src/models/Modelfile.eru-mistral
ollama create eru-qwen -f src/models/Modelfile.eru-qwen
ollama create eru-llama-large -f src/models/Modelfile.eru-llama-large
ollama create eru-codellama -f src/models/Modelfile.eru-codellama

# Large (16GB+ VRAM)
ollama create eru-gemma -f src/models/Modelfile.eru-gemma
ollama create eru-deepseek -f src/models/Modelfile.eru-deepseek
```

## Testing a Model

```bash
ollama run eru-llama "What Windows artifacts show evidence of lateral movement?"
```

## Recommendations

- **Limited resources**: Use `eru-llama` or `eru-phi`
- **General use**: Use `eru-mistral` or `eru-qwen`
- **Complex investigations**: Use `eru-llama-large` or `eru-gemma`
- **Script/malware analysis**: Use `eru-codellama` or `eru-deepseek`
