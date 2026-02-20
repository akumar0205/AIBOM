# AIBOM
Automatic AI Bill of Materials (AIBOM) generator for Python codebases that use LangChain and related AI/ML tooling.

## What this project does

`aibom_generator.py` performs **static analysis** of a target Python repository and produces a JSON report (`AI_BOM.json`) that inventories AI components found in source code.

It scans all `.py` files recursively and extracts:

- **models**
  - LangChain LLM/chat model class usage (for example `OpenAI`, `ChatOpenAI`, `HuggingFaceHub`, `Ollama`)
  - best-effort model identifiers from constructor args like `model`, `model_name`, `model_id`, `checkpoint`
- **datasets**
  - vector store related usage (for example `FAISS`, `Chroma`, `Pinecone`)
  - best-effort dataset/index references such as `path`, `persist_directory`, `index_name`, `collection_name`
- **tools**
  - LangChain tool/agent-related calls (for example `initialize_agent`, `load_tools`, `Tool`, `AgentExecutor`)
- **frameworks**
  - imported AI frameworks (for example `langchain`, `transformers`, `torch`)
  - installed package version when available via `importlib.metadata`

## How it works (high level)

1. Recursively find Python files in the target directory.
2. Parse each file into a Python AST (`ast.parse`).
3. Visit imports and function/class calls with an AST visitor.
4. Match known LangChain/model/vectorstore/tool patterns.
5. Build a consolidated dictionary with top-level keys:
   - `models`
   - `datasets`
   - `tools`
   - `frameworks`
6. De-duplicate entries and write to JSON.
7. Print a short terminal summary.

## Requirements

- Python 3.8+
- No external dependencies required for core functionality.

## Run locally with a Python virtual environment

Using a virtual environment keeps your local Python packages isolated from system/global installs.

### macOS/Linux

```bash
git clone <your-fork-or-this-repo-url>
cd AIBOM
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
git clone <your-fork-or-this-repo-url>
cd AIBOM
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

When done, leave the virtual environment with:

```bash
deactivate
```

## Usage

### Basic

```bash
python aibom_generator.py /path/to/project
```

This writes `AI_BOM.json` in your current working directory.

### Specify output location

```bash
python aibom_generator.py /path/to/project -o /path/to/output/AI_BOM.json
```

### Scan current directory

```bash
python aibom_generator.py .
```

## Example output structure

```json
{
  "models": [
    {
      "type": "ChatOpenAI",
      "model": "gpt-4",
      "source_file": "app/pipeline.py",
      "details": {
        "call": "ChatOpenAI",
        "params": {
          "model": "gpt-4"
        }
      }
    }
  ],
  "datasets": [
    {
      "name": "FAISS",
      "type": "FAISS.from_documents",
      "used_for": "Vector store / dataset ingestion",
      "source_file": "app/retrieval.py",
      "details": {
        "persist_directory": "./faiss_index"
      }
    }
  ],
  "tools": [
    {
      "name": "initialize_agent",
      "purpose": "Agent/tool usage detected",
      "source_file": "app/agent.py",
      "details": {
        "call": "initialize_agent",
        "params": {}
      }
    }
  ],
  "frameworks": [
    {
      "name": "langchain",
      "version": "0.2.0"
    }
  ]
}
```

## How to use the output

`AI_BOM.json` is intended to support inventory, review, and compliance workflows.

### 1) Governance and risk review

- Identify what models are in use and where (`source_file`).
- Review external dependencies/framework versions for patch and compatibility planning.
- Flag unknown model identifiers (`"model": "unknown"`) for manual follow-up.

### 2) Dependency and upgrade planning

- Use `frameworks` to quickly check what AI libraries are present and which versions are installed.
- Cross-check for deprecated APIs or vulnerable versions.

### 3) Data flow and retrieval visibility

- Inspect `datasets` entries for vector store/index paths and collection names.
- Confirm which files implement ingestion/indexing logic.

### 4) Agent/tool auditing

- Review `tools` entries to understand where autonomous/tool-enabled logic exists.
- Combine with code review in `source_file` paths for deeper behavior analysis.

## Notes and limitations

- This is **static analysis**, so results are best-effort.
- Dynamic patterns (runtime imports, indirect wrappers, values built in many steps) may not resolve fully.
- Some fields can be `unknown` when model names or dataset paths are not literal strings.
- Version reporting depends on packages being installed in the environment where the script runs.

## Quick validation

```bash
python aibom_generator.py . -o AI_BOM.json
python -m py_compile aibom_generator.py
```

## License

See [LICENSE](LICENSE).
