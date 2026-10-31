# SYNTAXIS — Automated Multi-Agent Codebase Vulnerability and Dependency Graph Auditor

**Problem Statement:** PS05  
**Hackathon:** Achithon 2026  
**Version:** 0.1.0

SYNTAXIS is a fully offline-capable, multi-agent security analysis pipeline for Python and JavaScript codebases. It integrates AST-based SAST, dependency advisory correlation, code relationship graphing, multi-agent reasoning, automated remediation patch generation, and a reproducible benchmarking framework.

---

## Architecture

```
auditor/
  core/          # Shared models (Finding, ScanResult), config, safety utilities
  ingestion/     # Local and Git repository ingestion (safe sandboxed staging)
  scanner/       # File discovery, language detection, manifest detection
  parser/        # AST parsing (Python via ast, JS via regex-augmented)
  graph/         # Code relationship graph (NetworkX)
  sast/          # Deterministic SAST rules (CWE-78, 89, 22, 502, 79)
  dependencies/  # Manifest parsing (requirements.txt, package.json, pyproject.toml)
  advisories/    # OSV advisory client with caching, batching, retries
  agents/        # Multi-agent orchestration (5 specialized agents)
  remediation/   # Patch generation, isolated workspace, validation, reports
  evaluation/    # Phase F benchmarking framework
  cli.py         # Entry point: scan | remediate | evaluate
```

---

## Supported Languages & CWEs

| Language | Parsing | SAST | Dependency Manifests |
|----------|---------|------|----------------------|
| Python   | ✅ `ast` module | ✅ Full | `requirements.txt`, `pyproject.toml`, `setup.cfg` |
| JavaScript/TypeScript | ✅ Regex-augmented | ✅ Partial | `package.json`, `package-lock.json` |

| CWE | Description | Severity |
|-----|-------------|----------|
| CWE-78 | OS Command Injection | CRITICAL |
| CWE-89 | SQL Injection | HIGH |
| CWE-22 | Path Traversal | HIGH |
| CWE-502 | Insecure Deserialization | CRITICAL |
| CWE-79 | Cross-Site Scripting (XSS) | MEDIUM |

---

## CLI Commands

### `auditor scan`

Scan a local directory or Git URL for security vulnerabilities.

```bash
python -m auditor.cli scan <target> [options]

Options:
  --format terminal,json,markdown,sarif   Output format(s)
  -o / --output <path>                    Output file path
  --offline                               Offline mode (no network calls)
  --no-sast                               Skip SAST analysis
  --no-deps                               Skip dependency scanning
  --no-agents                             Skip multi-agent analysis
  --no-llm                                Use deterministic agent fallback only
  --llm-provider auto|openai|offline      LLM provider (default: auto)
  --agent-timeout <seconds>               Per-agent timeout (default: 15)
  -v / --verbose                          Verbose output
```

**Example:**
```bash
python -m auditor.cli scan ./myproject --offline --no-llm --format json,markdown
```

### `auditor remediate`

Generate and optionally validate remediation patches for detected findings.

```bash
python -m auditor.cli remediate <target> [options]

Options:
  --finding-id <id>     Remediate only a specific finding
  --output-dir <dir>    Output directory for patches and reports
  --format json,markdown
  --offline             Offline mode
  --no-llm              Deterministic patch strategies only
  --validate            Run validation on generated patches
  --run-tests           Run existing tests in isolated workspace
  -v / --verbose
```

**Example:**
```bash
python -m auditor.cli remediate ./myproject --validate --no-llm
```

### `auditor evaluate`

Run the benchmark evaluation suite against ground-truth test cases.

```bash
python -m auditor.cli evaluate [options]

Options:
  --dataset <path>      Manifest JSON file (default: benchmarks/manifest.json)
  --output-dir <dir>    Report output directory (default: reports/evaluation)
  --format json,markdown
  --offline             Offline mode (recommended for reproducibility)
  --no-llm              Deterministic mode
  --category <name>     Filter to a single category (sql, cmd, path, deser, xss, deps, graph, remediation)
  --case-id <id>        Filter to a single case ID (e.g., SQL-001)
  -v / --verbose        Show per-case status during run
```

**Example:**
```bash
python -m auditor.cli evaluate --offline --no-llm --verbose
```

---

## Multi-Agent Architecture

Five specialized agents are coordinated by an **Orchestrator**:

| Agent | Role |
|-------|------|
| **Orchestrator** | Coordinates workflow; combines and deduplicates findings |
| **Code Analysis Agent** | Reviews AST, call graph, and deterministic SAST evidence |
| **Dependency Security Agent** | Examines manifest declarations and OSV advisory matches |
| **Data-Flow Analysis Agent** | Traces taint flows from recognized sources to sinks |
| **Contextual Reasoning Agent** | Evaluates plausibility of findings given code context |
| **Remediation Agent** | Proposes evidence-grounded remediation advice |

In offline or no-LLM mode, agents run in **OFFLINE_DETERMINISTIC** mode — no LLM API calls are made. All agents complete and contribute deterministic evidence summaries.

---

## Offline Guarantees

SYNTAXIS is fully functional without network access when `--offline` and `--no-llm` are passed:

- **SAST analysis**: Fully offline (AST-based, deterministic rules)
- **Dependency parsing**: Fully offline (manifest file parsing only)
- **OSV advisory lookup**: Uses local cache; skips network in offline mode
- **Agent analysis**: OFFLINE_DETERMINISTIC mode — no LLM calls
- **Remediation**: Deterministic patch strategies only
- **Evaluation**: All benchmark fixtures are local files; no network needed

No API keys, tokens, or credentials are required.

---

## Remediation Workflow

1. **Scan** the target to produce findings.
2. **Patch generation**: Each finding is matched to a deterministic strategy:
   - `SQL_PARAMETERIZATION` — rewrites f-string/format SQL to parameterized form
   - `PATH_TRAVERSAL_GUARD` — inserts `is_safe_subpath` validation before `open()`
   - `SAFE_DESERIALIZATION` — replaces `yaml.load` with `yaml.safe_load`
   - `DEPENDENCY_VERSION_UPGRADE` — updates pinned version in requirements files
   - `REQUIRES_REVIEW` / `UNSUPPORTED` — when auto-patch is not safe/possible
3. **Isolated workspace**: Each patch is applied in a temporary copy of the repository; the original is never modified.
4. **Validation**: Syntax check, regression check (line count diff), optional SAST re-analysis.
5. **Report**: JSON and Markdown reports with diff, explanation, and validation status.

---

## Benchmark Format

Benchmark cases are defined in `benchmarks/manifest.json`:

```json
{
  "version": "1.0.0",
  "dataset_id": "syntaxis-benchmark-v1",
  "cases": [
    {
      "id": "SQL-001",
      "category": "sql",
      "label": "vulnerable",
      "expected_cwe": "CWE-89",
      "fixture": "benchmarks/fixtures/sql/sql_vuln_fstring.py",
      "description": "F-string SQL injection with request.args taint source",
      "rationale": "uid flows from request.args into cursor.execute f-string"
    }
  ]
}
```

**Labels:** `vulnerable` | `safe` | `ambiguous`

- `vulnerable` → scanner must detect a matching CWE → **TP/FN**
- `safe` → scanner must report no finding → **TN/FP**
- `ambiguous` → excluded from binary metrics; reported separately

**Categories:** `sql`, `cmd`, `path`, `deser`, `xss`, `deps`, `graph`, `remediation`

---

## Running Tests

```powershell
# Run the full test suite (190 tests)
python -m unittest discover -s tests -v

# Run a specific test module
python -m unittest tests.test_evaluation -v
python -m unittest tests.test_e2e_scenarios -v
```

**Requirements:** Python 3.11+, packages in `requirements.txt`.  
**No pytest required.** All tests use `unittest` from the standard library.

---

## Running the Benchmark Evaluation

```powershell
# Full benchmark (offline, no LLM)
python -m auditor.cli evaluate --offline --no-llm --verbose

# Single category
python -m auditor.cli evaluate --offline --no-llm --category sql

# Single case
python -m auditor.cli evaluate --offline --no-llm --case-id SQL-001
```

Reports are saved to `reports/evaluation/evaluation_<run_id>.json` and `.md`.

---

## Phase F Benchmark Results (Offline, No-LLM)

| Metric | Value |
|--------|-------|
| Total cases | 24 |
| True Positives | 11 |
| True Negatives | 10 |
| False Positives | 0 |
| False Negatives | 3 |
| **Precision** | **1.0000** |
| **Recall** | **0.7857** |
| **F1 Score** | **0.8800** |
| **Accuracy** | **0.8750** |

> FN cases: dep cases in offline mode (OSV not queried) and graph cases where multi-file taint is not traced across function boundaries. These are documented limitations.

---

## End-to-End Demo

```powershell
# 1. Scan a vulnerable project
python -m auditor.cli scan ./myproject --offline --no-llm --format json,markdown

# 2. Generate remediation patches
python -m auditor.cli remediate ./myproject --validate --no-llm

# 3. Run the benchmark evaluation
python -m auditor.cli evaluate --offline --no-llm --verbose
```

---

## Known Limitations

| Limitation | Scope |
|-----------|-------|
| Transitive dependency resolution | Manifests without lock files only show direct dependencies |
| Cross-file taint tracking | SAST taint is tracked within a single file; multi-file flows require the code graph |
| JavaScript AST depth | JS parsing uses regex-augmented analysis; not as deep as Python `ast` module |
| OSV offline mode | Advisory lookup returns no results when the local cache is empty and `--offline` is set |
| Deserialization ambiguity | `pickle.loads` on non-tainted data is flagged as CONFIRMED (conservative) |
| LLM agents | Without `--no-llm`, LLM calls require a configured API key |

---

## Project Structure

```
achithon-2026-syntaxis/
  auditor/          # Main package
  benchmarks/       # Ground-truth benchmark fixtures and manifest
  tests/            # All test modules (190 tests)
  reports/          # Scan, remediation, and evaluation reports (generated)
  AGENTS.md         # Agent workflow instructions
  PS05.md           # Official problem statement
  CLAUDE.md         # Project coding instructions
  README.md         # This file
  log.txt           # Session and turn log (AGENTS.md §5)
  pyproject.toml    # Project metadata and dependencies
  requirements.txt  # Python dependencies
```

---

## Submission

See `PS05.md` for the official submission URL and instructions.

---

*SYNTAXIS — Built for Achithon 2026 | PS05 | Python 3.13 | Windows/Linux/macOS*



