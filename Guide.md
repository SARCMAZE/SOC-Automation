Guide for L1, L2, and Frontend
===============================

Overview
--------
This repository contains a local SOC pipeline with three main parts:

1. `L1.balanced.py` — deterministic L1 scoring and filtering of raw network flow records.
2. `L2_processor.py` — L2 analysis that enriches flagged flows with local LLM/heuristic risk classification.
3. `frontend/` + `api_server.py` — a React dashboard and API layer for exploring L1/L2 results.

The pipeline is orchestrated by `run_pipeline.py`, which runs L1, then L2, then starts the API and dashboard.

L1: Fast Deterministic Filter
----------------------------

File: `L1.balanced.py`

Purpose
- Quickly identify suspicious flows from large JSON/JSONL network flow datasets.
- Convert raw flow data into a filtered JSONL feed for L2 review.

Inputs
- Accepts JSON array or JSONL flow records.
- Common fields used include `src_ip`, `dst_ip`, `dst_port`, `protocol`, `flow bytes/s`, `flow packets/s`, `syn flag count`, `rst flag count`, `packet length std`, `flow iat mean`, `total fwd packets`, `total backward packets`, `active mean`, `idle mean`, and others.

Output
- Writes flagged flow records as JSONL.
- Each output record includes `l1_score`, `severity`, and `status: "flagged"`.
- The default output filename can be overridden with `--output`.

How it works
- `calculate_score()` computes a score from signals like byte rate, packet rate, SYN counts, flag counts, packet-size statistics, timing behavior, and port sensitivity.
- `severity_from_score()` maps score ranges to `LOW`, `MEDIUM`, or `HIGH`.
- The script only writes records with `l1_score >= --min-score`.

Important CLI options
- `--input` / `-i`: input file path.
- `--output` / `-o`: output JSONL file path.
- `--min-score`: score threshold for flagging; the current relaxed default is `8`.
- `--sample-every`: sampling behaviour used when collecting stats.
- `--verbose`: periodic progress reporting.

Example
```bash
python L1.balanced.py --input Combined_CIC_Data.json --output l1_runtime_output.jsonl --min-score 8 --verbose
```

L2: Local LLM + Heuristic Analysis
----------------------------------

File: `L2_processor.py`

Purpose
- Enrich L1-flagged records with higher-level analysis.
- Provide a normalized risk classification, confidence score, explanation, and recommendation.
- Keep output deterministic and safe even if local LLM analysis fails.

Inputs
- Consumes L1 output JSONL, such as `l1_runtime_output.jsonl`.
- Requires each record to contain `severity` and `l1_score` so the script can apply severity filtering.

Output
- Enriched JSONL where each record contains an appended `l2_analysis` object.
- `l2_analysis` follows the strict schema:
  - `attack_type`
  - `risk_score`
  - `confidence_score`
  - `explanation`
  - `recommendation`

How it works
1. Reads the input file using reservoir sampling if the file is large.
2. Filters records by `--min-severity` (default `MEDIUM`).
3. Attempts to call Ollama via `ollama.chat()` with a strict prompt that asks for one JSON object.
4. Validates the returned JSON using `validate_output()`.
5. If Ollama is unavailable or the output is invalid, it falls back to `heuristic_analysis()`.

Heuristic fallback rules
- Detects likely SYN floods, DDoS, brute-force, and web attack patterns based on SYN counts, packet rates, byte rates, destination ports, and L1 score.
- Returns a consistent fallback JSON analysis object when LLM parsing fails.

Database support
- `init_db_stub()` creates a local SQLite database file (`l2_context.db`) as a placeholder for enriched context storage.
- It is currently a stub and does not alter processing logic.

Important CLI options
- `--input` / `-i`: L1 JSONL input file.
- `--output` / `-o`: L2 output JSONL file.
- `--sample-size`: reservoir sample size from the input file (default `20000`).
- `--min-severity`: lowest severity to process.
- `--target-alerts`: stop after producing this many L2 alerts.
- `--max-workers`: thread pool size when no early stop is requested.
- `--verbose`: progress and ETA printing.

Example
```bash
python L2_processor.py --input l1_runtime_output.jsonl --output l2_output1-6PP.JSONL --sample-size 20000 --min-severity MEDIUM --target-alerts 30 --verbose
```

Frontend and API
----------------

Files
- `frontend/`: React + Vite dashboard with the UI components.
- `api_server.py`: local HTTP API exposing `/api/l1`, `/api/l2`, and `/api/alerts`.

How the dashboard works
- The frontend fetches data from the API endpoints.
- `/api/l1` returns normalized L1 records.
- `/api/l2` returns normalized L2 records with `l2_analysis` fields.
- The API normalizes field names and computes summary metadata such as risk bands, counts, and top sources.

File discovery
- `api_server.py` prefers the runtime output files if they exist:
  - `l1_runtime_output.jsonl` for L1
  - `l2_output1-6PP.JSONL` (or `l2_output1-6PP.jsonl`) for L2
- If those files are not present, it falls back to the latest `l1_*.jsonl` and `l2_*.jsonl` files by modification time.

Starting the dashboard
1. Install frontend dependencies if needed:
```bash
cd frontend
npm install
```
2. Start the React app:
```bash
npm run dev -- --host 127.0.0.1 --port 5173
```
3. Start the API server in the repo root:
```bash
python api_server.py
```
4. Open the dashboard at `http://127.0.0.1:5173`.

Full pipeline
-------------

`run_pipeline.py` orchestrates the full workflow:
- Run L1 and generate `l1_runtime_output.jsonl`.
- Run L2 against that L1 output and generate `l2_output1-6PP.JSONL`.
- Start the API server and React dashboard.

Run the full pipeline:
```bash
python run_pipeline.py
```

If the dashboard shows stale data:
- Confirm `l1_runtime_output.jsonl` and `l2_output1-6PP.JSONL` were created.
- Restart `api_server.py` so it re-reads the latest files.
- Check the frontend browser cache or reload the page.

Tips
----
- Tune `--min-score` in `L1.balanced.py` to balance volume vs signal.
- Use `--target-alerts` in `L2_processor.py` to stop after a manageable number of analyst-ready records.
- Keep the frontend and API running together for interactive review of summaries and alerts.
