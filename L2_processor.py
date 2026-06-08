"""L2 Processor - improved

Improvements:
- CLI args
- Ollama LLM parsing with validation and deterministic heuristic fallback
- Local sqlite DB stub (shown but unused)
- Streaming concurrency with ThreadPoolExecutor
- Strict JSON output (validated)
"""

import argparse
import json
import re
import sqlite3
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import ollama
except Exception:
    ollama = None


DEFAULT_INPUT = "l1_runtime_output.jsonl"
DEFAULT_OUTPUT = "l2_output1-6PP.jsonl"
DEFAULT_DB = "l2_context.db"


def parse_args():
    p = argparse.ArgumentParser(description="L2 Processor - Ollama-backed local L2 analysis")
    p.add_argument("--input", "-i", default=DEFAULT_INPUT)
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--model", default="llama3")
    p.add_argument("--sample-size", type=int, default=20000, help="Number of records to process (reservoir sampled)")
    p.add_argument("--max-workers", type=int, default=8)
    p.add_argument("--min-severity", default="MEDIUM")
    p.add_argument("--target-alerts", type=int, default=30, help="Stop after this many L2 alerts are produced (0 = no limit)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def init_db_stub(db_path):
    # Demonstrate a local DB connection (not used further)
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS l2_context(id INTEGER PRIMARY KEY, meta TEXT)")
        conn.commit()
        return conn
    except Exception:
        return None


def strip_code_blocks(s):
    if not isinstance(s, str):
        return s
    # Remove markdown fences
    s = re.sub(r"```[\s\S]*?```", "", s)
    return s.strip()


def extract_json_text(s):
    s = strip_code_blocks(s)
    idx1 = s.find('{')
    idx2 = s.rfind('}')
    if idx1 == -1 or idx2 == -1 or idx2 <= idx1:
        return None
    return s[idx1:idx2+1]


def validate_output(obj):
    # Ensure schema and sanitize
    required = ["attack_type", "risk_score", "confidence_score", "explanation", "recommendation"]
    if not isinstance(obj, dict):
        return False
    for k in required:
        if k not in obj:
            return False

    # enforce types and ranges
    try:
        obj["attack_type"] = str(obj["attack_type"])[:64]
        obj["risk_score"] = int(max(0, min(10, int(obj["risk_score"]))))
        obj["confidence_score"] = float(max(0.0, min(1.0, float(obj["confidence_score"]))))
        obj["explanation"] = str(obj["explanation"])[:300]
        obj["recommendation"] = str(obj["recommendation"])[:200]
    except Exception:
        return False

    return True


# Severity utilities
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_meets(record_sev, min_sev):
    try:
        if not record_sev:
            return False
        r = str(record_sev).upper()
        return SEVERITY_ORDER.index(r) >= SEVERITY_ORDER.index(str(min_sev).upper())
    except Exception:
        return False


def heuristic_analysis(log):
    # Deterministic rule-based fallback
    syn = float(log.get("syn_flag", log.get("syn flag", 0) or 0))
    flow_pkts = float(log.get("flow_packets_s", log.get("flow_packets_s", log.get("flow packets/s", 0) or 0)) or 0)
    flow_bytes = float(log.get("flow_bytes_s", log.get("flow_bytes_s", log.get("flow bytes/s", 0) or 0)) or 0)
    dst_port = int(log.get("dst_port", log.get("dst_port", log.get("dst_port", 0) or 0)) or 0)
    l1score = int(log.get("l1_score", log.get("l1_score", 0) or 0))

    out = {
        "attack_type": "Unknown Anomaly",
        "risk_score": 3,
        "confidence_score": 0.25,
        "explanation": "Insufficient signals; falls outside deterministic rules.",
        "recommendation": "Monitor traffic; capture packets for deeper analysis"
    }

    # Looser rules to surface more candidates for analyst review
    if syn >= 3 and flow_pkts > 300:
        out.update({"attack_type": "SYN Flood", "risk_score": 8, "confidence_score": 0.75,
                    "explanation": "Elevated SYN count and sustained packet rates—possible SYN-style flood.",
                    "recommendation": "Rate-limit; monitor connection table; block if confirmed"})
        return out

    if flow_pkts > 500 and flow_bytes > 50_000:
        out.update({"attack_type": "DDoS", "risk_score": 8, "confidence_score": 0.7,
                    "explanation": "High packet and byte rates indicate potential volumetric activity.",
                    "recommendation": "Enable mitigation; capture samples; escalate"})
        return out

    if dst_port in (22, 23, 3389) and flow_pkts > 30:
        out.update({"attack_type": "Brute Force", "risk_score": 6, "confidence_score": 0.6,
                    "explanation": "Multiple packets to remote-access ports—possible brute force attempts.",
                    "recommendation": "Check auth logs; block source if suspicious"})
        return out

    if dst_port in (80, 443) and flow_bytes > 100_000 and l1score >= 6:
        out.update({"attack_type": "Web Attack", "risk_score": 7, "confidence_score": 0.6,
                    "explanation": "Elevated bytes to web ports with non-trivial L1 score; investigate further.",
                    "recommendation": "Capture HTTP(s); correlate with app logs; consider WAF rules"})
        return out

    return out


def analyze_with_llm(log, model="llama3", temperature=0.0, max_predict=200):
    prompt = (
        "You are a SOC analyst.\n"
        "STRICT: Output ONLY a single JSON object exactly matching this schema:"
        "{\"attack_type\":\"\",\"risk_score\":0,\"confidence_score\":0.0,\"explanation\":\"\",\"recommendation\":\"\"}\n"
        "Provide concise technical output (max 2 sentences explanation).\n"
        "Log: " + json.dumps(log)
    )

    if ollama is None:
        # Ollama not available in environment; fallback immediately
        return None, "OllamaUnavailable"

    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "system", "content": "Return ONLY JSON."}, {"role": "user", "content": prompt}],
            options={"temperature": temperature, "num_predict": max_predict}
        )

        text = response.get("message", {}).get("content", "")
        jtxt = extract_json_text(text) or text
        try:
            parsed = json.loads(jtxt)
            if validate_output(parsed):
                return parsed, "OK"
        except Exception:
            return None, text

        return None, text

    except Exception as e:
        return None, str(e)


def process_line(line, min_severity):
    try:
        log = json.loads(line)
    except Exception:
        return None, "error"

    # Only process records that meet the requested minimum severity (or CRITICAL)
    if not severity_meets(log.get("severity"), min_severity):
        return None, "skipped"

    # Try LLM analysis
    parsed, meta = analyze_with_llm(log)
    if parsed is None:
        # fallback to heuristic
        parsed = heuristic_analysis(log)

    enriched = {**log, "l2_analysis": parsed}
    return enriched, "processed"


def pretty_progress(done, total, processed, skipped, errors):
    percent = (done / total) * 100 if total else 100
    print(f"\rProcessed {done}/{total} ({percent:.1f}%) | P:{processed} S:{skipped} E:{errors}", end="")


def format_seconds(s):
    s = int(max(0, s))
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    return f"{h:02d}:{m:02d}:{sec:02d}"


def process_l2(input_path, output_path, db_path, model, max_workers, min_severity, sample_size=20000, target_alerts=30, verbose=False):
    db_conn = init_db_stub(db_path)
    processed = skipped = errors = done = 0

    # Reservoir sample the input so we can show we scanned the full file
    sample = []
    total = 0
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f_in:
        for idx, line in enumerate(f_in, start=1):
            total = idx
            if idx <= sample_size:
                sample.append(line)
            else:
                j = random.randint(1, idx)
                if j <= sample_size:
                    sample[j - 1] = line

    print(f"Scanned total input lines: {total:,}. Selected sample size: {len(sample):,} (requested {sample_size}).")
    start_time = time.time()

    sample_total = len(sample)
    # If target_alerts provided, process sequentially and stop when we've produced enough alerts
    with open(output_path, "w", encoding="utf-8") as f_out:
        processed = skipped = errors = done = 0
        if target_alerts and target_alerts > 0:
            flagged_count = 0
            for i, line in enumerate(sample, start=1):
                done += 1
                try:
                    result, status = process_line(line, min_severity)
                except Exception:
                    result = None
                    status = "error"

                if status == "processed":
                    f_out.write(json.dumps(result, ensure_ascii=False) + "\n")
                    processed += 1
                    flagged_count += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    errors += 1

                # progress/ETA
                elapsed = time.time() - start_time
                avg = (elapsed / done) if done > 0 else 0
                remaining = sample_total - done
                eta = avg * remaining if done > 0 else 0
                if verbose and (done % 50 == 0 or flagged_count >= target_alerts or done == sample_total):
                    print(f"Processed {done}/{sample_total} | Flags:{processed} Skipped:{skipped} Errors:{errors} | Elapsed: {format_seconds(elapsed)} ETA: {format_seconds(eta)}")

                if flagged_count >= target_alerts:
                    if verbose:
                        print(f"Reached target alerts: {target_alerts} -- stopping early.")
                    break

        else:
            # concurrent processing path (unchanged)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(process_line, line, min_severity): i for i, line in enumerate(sample)}
                for fut in as_completed(futures):
                    try:
                        result, status = fut.result()
                    except Exception:
                        result = None
                        status = "error"

                    done += 1
                    if status == "processed":
                        f_out.write(json.dumps(result, ensure_ascii=False) + "\n")
                        processed += 1
                    elif status == "skipped":
                        skipped += 1
                    else:
                        errors += 1

                    # ETA calculation
                    elapsed = time.time() - start_time
                    avg = (elapsed / done) if done > 0 else 0
                    remaining = sample_total - done
                    eta = avg * remaining if done > 0 else 0

                    if verbose and (done % 20 == 0 or done == sample_total):
                        print(f"Processed {done}/{sample_total} | Flags:{processed} Skipped:{skipped} Errors:{errors} | Elapsed: {format_seconds(elapsed)} ETA: {format_seconds(eta)}")

    elapsed = time.time() - start_time
    print(f"L2 processing complete. Output records: {processed:,}, skipped: {skipped:,}, errors: {errors:,}. Total elapsed: {format_seconds(elapsed)}")

    if db_conn:
        try:
            db_conn.close()
        except Exception:
            pass

    total_elapsed = time.time() - start_time
    print(f"\nCompleted sample processing: {processed} flagged, {skipped} skipped, {errors} errors")
    print(f"Sample size: {sample_total} | Total input scanned: {total:,}")
    print(f"Total elapsed: {format_seconds(total_elapsed)}")


if __name__ == "__main__":
    args = parse_args()
    start = time.time()
    process_l2(
        args.input,
        args.output,
        args.db,
        args.model,
        args.max_workers,
        args.min_severity,
        sample_size=args.sample_size,
        target_alerts=args.target_alerts,
        verbose=args.verbose,
    )
    if args.verbose:
        print("Elapsed:", time.time() - start)