"""L3 Agent

Purpose:
- Ingest L2-processed JSONL and maintain a persistent context per IP/case.
- Build a hybrid L3 model using IsolationForest anomaly detection + sequence-aware LSTM neural networks.
- Generate interconnected incident reports and maintain a synthetic L3 context dataset for cross-checking.
- Persist model artifacts and contexts to disk (SQLite + joblib + h5).

Usage (examples):
  python L3_agent.py ingest --input l2_output1-6PP.JSONL --db l3_context.db
  python L3_agent.py train --db l3_context.db --model-out l3_hybrid.joblib
  python L3_agent.py predict --input l2_output1-6PP.JSONL --model l3_hybrid.joblib --out preds.jsonl
  python L3_agent.py report --db l3_context.db

Notes:
- Hybrid model: IsolationForest (unsupervised anomaly detection) + LSTM (sequence learning).
- No RandomForest; focuses on unsupervised anomaly detection combined with temporal pattern learning.
- Requires scikit-learn, tensorflow/keras, and joblib. The script will print instructions if missing.
"""

import argparse
import json
import os
import sqlite3
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
    try:
        from tensorflow.keras.models import Sequential
        from tensorflow.keras.layers import LSTM, Dense, Masking
        from tensorflow.keras.callbacks import EarlyStopping
        TENSORFLOW_AVAILABLE = True
    except Exception:
        TENSORFLOW_AVAILABLE = False
except Exception:
    SKLEARN_AVAILABLE = False
    TENSORFLOW_AVAILABLE = False

DEFAULT_DB = "l3_context.db"
DEFAULT_MODEL = "l3_hybrid.joblib"
DEFAULT_LSTM_MODEL = "l3_model_lstm.h5"
DEFAULT_DATASET = "dataset_context_l3agent.json"

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    # contexts: track per-ip summary/context
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contexts(
            ip TEXT PRIMARY KEY,
            last_seen REAL,
            seen_count INTEGER,
            meta_json TEXT
        )
        """
    )
    # events: history of processed L2 records
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            raw_json TEXT,
            label INTEGER
        )
        """
    )
    conn.commit()
    return conn


def normalize_report_to_dataset(record: Dict[str, Any]) -> dict:
    return {
        "ip": record.get("primary_ip"),
        "mac_address": record.get("details", {}).get("src_mac"),
        "hostname": record.get("details", {}).get("hostname"),
        "account": record.get("details", {}).get("account_name"),
        "account_type": "unknown",
        "geolocation": record.get("details", {}).get("geolocation", {}),
        "first_seen": record.get("time_created") or record.get("generated_at"),
        "last_seen": record.get("time_created") or record.get("generated_at"),
        "tcp_ports": [],
        "udp_ports": [],
        "tags": record.get("common_pattern", []),
        "risk_score": 9 if record.get("severity", "").lower() == "critical" else 8,
        "status": "blacklisted" if record.get("severity", "").lower() == "critical" else "warning",
        "related_ips": record.get("details", {}).get("related_ips", []),
        "notes": record.get("summary"),
    }


def load_context_dataset(path: str):
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        records = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    continue
        return records

    if isinstance(data, dict):
        if isinstance(data.get("incidents"), list):
            return [normalize_report_to_dataset(item) for item in data.get("incidents", [])]
        if isinstance(data.get("records"), list):
            return data.get("records", [])
        return []

    if isinstance(data, list):
        return data

    return []


def save_context_dataset(path: str, records):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def merge_dataset_record(existing: dict, new_record: dict) -> dict:
    merged = {**existing, **new_record}
    merged["tags"] = sorted(set((existing.get("tags") or []) + (new_record.get("tags") or [])))
    if existing.get("first_seen") and new_record.get("first_seen"):
        merged["first_seen"] = min(existing["first_seen"], new_record["first_seen"])
    merged["last_seen"] = max(existing.get("last_seen") or new_record.get("last_seen"), new_record.get("last_seen"))
    merged["risk_score"] = max(existing.get("risk_score") or 0, new_record.get("risk_score") or 0)
    return merged


def upsert_dataset_context(path: str, new_record: dict):
    records = load_context_dataset(path)
    match_index = next((i for i, r in enumerate(records) if r.get("ip") == new_record.get("ip")), None)
    if match_index is None:
        records.append(new_record)
    else:
        records[match_index] = merge_dataset_record(records[match_index], new_record)
    save_context_dataset(path, records)


def sync_events_to_dataset(db_path: str, dataset_path: str = DEFAULT_DATASET, min_label: int = 1) -> int:
    conn = init_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT raw_json, label FROM events WHERE label >= ? ORDER BY timestamp DESC", (min_label,))
    new_records = 0
    for raw_json, label in cur.fetchall():
        try:
            event = json.loads(raw_json)
        except Exception:
            continue

        src = event.get("srcIp") or event.get("src_ip") or event.get("source ip")
        if not src:
            continue

        l2 = event.get("l2_analysis") or {}
        if isinstance(l2, str):
            try:
                l2 = json.loads(l2)
            except Exception:
                l2 = {}

        new_record = {
            "ip": src,
            "mac_address": event.get("srcMac") or event.get("mac") or "unknown",
            "hostname": event.get("hostname") or event.get("host") or "unknown",
            "account": event.get("account") or event.get("user") or "unknown",
            "account_type": event.get("account_type") or event.get("role") or "unknown",
            "geolocation": l2.get("geolocation") or event.get("geo") or {},
            "first_seen": event.get("timestamp") or datetime.utcnow().isoformat() + "Z",
            "last_seen": event.get("timestamp") or datetime.utcnow().isoformat() + "Z",
            "tcp_ports": [int(event.get("dstPort") or event.get("dst_port") or 0)] if event.get("dstPort") or event.get("dst_port") else [],
            "udp_ports": [int(event.get("srcPort") or event.get("src_port") or 0)] if event.get("srcPort") or event.get("src_port") else [],
            "tags": [t for t in ([l2.get("attack_type")] if l2.get("attack_type") else []) if t],
            "risk_score": int(l2.get("risk_score") or event.get("riskScore") or event.get("risk_score") or 0),
            "status": "blacklisted" if label >= 1 else "warning",
            "related_ips": [event.get("dstIp") or event.get("dst_ip") or event.get("destination ip")],
            "notes": "Auto-synced flagged L2 event into L3 context dataset."
        }
        upsert_dataset_context(dataset_path, new_record)
        new_records += 1

    conn.close()
    logging.info("Synced %d flagged events into dataset context %s", new_records, dataset_path)
    return new_records


def extract_features_from_record(rec: dict) -> list:
    def num_field(keys):
        for key in keys:
            value = rec.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except Exception:
                continue
        return 0.0

    return [
        num_field(["l1Score", "l1_score"]),
        num_field(["flowBytesPerSec", "flow bytes/s", "flow_bytes_s"]),
        num_field(["flowPacketsPerSec", "flow packets/s", "flow_packets_s"]),
        num_field(["synFlagCount", "syn flag", "syn_flag"]),
        int(rec.get("dstPort") or rec.get("dst_port") or 0),
        int(rec.get("protocol") or 0),
    ]


def build_sequence_score(df: pd.DataFrame) -> None:
    if not TF_AVAILABLE:
        return None

    try:
        groups = []
        for _, group in df.groupby("src_ip"):
            if len(group) < 3:
                continue
            groups.append(group["l1_score"].values[-10:])
        if not groups:
            return None
    except Exception:
        return None

    return None


def train_model(db_path: str, model_out: str = DEFAULT_MODEL, dataset_path: str = DEFAULT_DATASET) -> Tuple[Optional[dict], Optional[float]]:
    if not SKLEARN_AVAILABLE:
        logging.error("scikit-learn or joblib not available. Install via `pip install scikit-learn joblib pandas numpy`. ")
        return None, None

    conn = init_db(db_path)
    df = build_feature_dataframe(conn)
    if df is None or df.shape[0] < 10:
        logging.error("Not enough data to train (need >=10 events).")
        conn.close()
        return None, None

    features = ["l1_score", "flow_bytes_s", "flow_packets_s", "syn_flag", "dst_port", "protocol"]
    X = df[features]

    # Stage 1: IsolationForest - Unsupervised anomaly detection
    if_model = IsolationForest(n_estimators=200, contamination=0.03, random_state=42)
    if_model.fit(X)
    if_scores = if_model.decision_function(X)
    if_anomaly_rate = np.mean(if_scores < -0.1)
    logging.info("IsolationForest trained: anomaly rate=%.2f%%", if_anomaly_rate * 100)

    # Stage 2: LSTM - Temporal sequence learning
    lstm_path = None
    lstm_loss = None
    if TENSORFLOW_AVAILABLE:
        try:
            raw_seq = []
            for _, group in df.groupby("src_ip"):
                if len(group) < 3:
                    continue
                raw_seq.append(group[features].values[-10:])
            if len(raw_seq) >= 10:
                maxlen = max(seq.shape[0] for seq in raw_seq)
                X_seq = np.zeros((len(raw_seq), maxlen, len(features)), dtype=float)
                y_seq = []
                for idx, seq in enumerate(raw_seq):
                    X_seq[idx, -seq.shape[0]:, :] = seq
                    # Label based on anomaly detection result
                    anomaly_flag = np.mean(if_model.decision_function(seq) < -0.1) > 0.5
                    y_seq.append(int(anomaly_flag))
                y_seq = np.array(y_seq)
                
                # Build LSTM model
                lstm_model = Sequential()
                lstm_model.add(LSTM(64, return_sequences=True, input_shape=(maxlen, len(features))))
                lstm_model.add(LSTM(32))
                lstm_model.add(Dense(16, activation="relu"))
                lstm_model.add(Dense(1, activation="sigmoid"))
                lstm_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
                
                # Train with early stopping
                history = lstm_model.fit(X_seq, y_seq, epochs=15, batch_size=8, validation_split=0.2,
                               callbacks=[EarlyStopping(patience=3, restore_best_weights=True)], verbose=0)
                lstm_loss = float(history.history["loss"][-1])
                lstm_path = f"{Path(model_out).stem}_lstm.h5"
                lstm_model.save(lstm_path)
                logging.info("Trained LSTM sequence model: final loss=%.4f, saved to %s", lstm_loss, lstm_path)
        except Exception as ex:
            logging.warning("LSTM training failed: %s", ex)
    else:
        logging.warning("TensorFlow not available; LSTM model will be skipped")

    # Save hybrid model artifact
    artifact = {
        "iforest": if_model,
        "features": features,
        "lstm_path": lstm_path,
        "anomaly_rate": float(if_anomaly_rate),
        "trained_at": time.time(),
    }
    joblib.dump(artifact, model_out)
    logging.info("Trained L3 hybrid model (IsolationForest + LSTM), saved to %s", model_out)
    conn.close()
    return artifact, lstm_loss if lstm_loss else if_anomaly_rate


def predict_file(input_path: str, model_path: str, out_path: Optional[str] = None, dataset_path: str = DEFAULT_DATASET) -> int:
    if not SKLEARN_AVAILABLE:
        logging.error("scikit-learn or joblib not available. Install via `pip install scikit-learn joblib pandas`. ")
        return 0

    if not os.path.exists(model_path):
        logging.error("Model file not found: %s", model_path)
        return 0

    artifact = joblib.load(model_path)
    if_model = artifact.get("iforest")
    lstm_path = artifact.get("lstm_path")
    features = artifact.get("features", ["l1_score", "flow_bytes_s", "flow_packets_s", "syn_flag", "dst_port", "protocol"])
    dataset = {r["ip"]: r for r in load_context_dataset(dataset_path)}

    # Load LSTM model if available
    lstm_model = None
    if lstm_path and TENSORFLOW_AVAILABLE:
        try:
            from tensorflow.keras.models import load_model
            lstm_model = load_model(lstm_path)
        except Exception as ex:
            logging.warning("Could not load LSTM model from %s: %s", lstm_path, ex)

    preds = 0
    out_file = open(out_path, "w", encoding="utf-8") if out_path else None

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            feat = np.array([extract_features_from_record(rec)])
            
            # Stage 1: IsolationForest anomaly scoring
            anomaly_score = float(if_model.decision_function(feat)[0]) if if_model else 0.0
            anomaly_flag = anomaly_score < -0.1
            
            # Stage 2: LSTM sequence prediction (optional)
            lstm_score = None
            if lstm_model:
                try:
                    # Reshape feature vector to sequence
                    seq = feat.reshape(1, 1, len(features))
                    lstm_pred = float(lstm_model.predict(seq, verbose=0)[0][0])
                    lstm_score = lstm_pred
                except Exception:
                    lstm_score = None

            # Final hybrid decision: anomaly detected OR high LSTM score
            hybrid_alert = anomaly_flag or (lstm_score is not None and lstm_score > 0.5)

            src = rec.get("srcIp") or rec.get("src_ip") or rec.get("source ip")
            dst = rec.get("dstIp") or rec.get("dst_ip") or rec.get("destination ip")
            cross_info = dataset.get(src) or dataset.get(dst)
            cross_status = cross_info.get("status") if cross_info else None

            out = {
                "isolation_forest_score": anomaly_score,
                "isolation_forest_anomaly": anomaly_flag,
                "lstm_sequence_score": lstm_score,
                "hybrid_alert": hybrid_alert,
                "cross_reference": {
                    "matched_context": cross_info,
                    "status": cross_status,
                },
                "record": rec,
            }
            if out_file:
                out_file.write(json.dumps(out, ensure_ascii=False) + "\n")
            preds += 1

    if out_file:
        out_file.close()

    logging.info("Predicted %d records using L3 hybrid model (IsolationForest + LSTM) from %s", preds, model_path)
    return preds


def report(db_path: str, dataset_path: str = DEFAULT_DATASET, top_n: int = 10) -> Dict[str, Any]:
    conn = init_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM events")
    total = cur.fetchone()[0]
    cur.execute("SELECT label, count(*) FROM events GROUP BY label")
    by_label = {row[0]: row[1] for row in cur.fetchall()}
    cur.execute("SELECT ip, seen_count, last_seen FROM contexts ORDER BY seen_count DESC LIMIT ?", (top_n,))
    top_contexts = [dict(ip=r[0], seen_count=r[1], last_seen=datetime.fromtimestamp(r[2]).isoformat() if r[2] else None) for r in cur.fetchall()]
    conn.close()

    dataset = load_context_dataset(dataset_path)
    blacklist_count = sum(1 for r in dataset if r.get("status") in ("blacklisted", "blocked"))
    return {
        "total_events": total,
        "by_label": by_label,
        "top_contexts": top_contexts,
        "dataset_summary": {
            "records": len(dataset),
            "blacklist_count": blacklist_count,
        },
    }


def generate_incident_report(db_path: str, dataset_path: str = DEFAULT_DATASET, output_path: Optional[str] = None, max_groups: int = 10) -> Dict[str, Any]:
    conn = init_db(db_path)
    cur = conn.cursor()
    cur.execute("SELECT ip, meta_json FROM contexts")
    contexts = {row[0]: json.loads(row[1] or "{}") for row in cur.fetchall()}

    cur.execute("SELECT raw_json, label FROM events ORDER BY timestamp DESC")
    events = []
    for raw_json, label in cur.fetchall():
        try:
            event = json.loads(raw_json)
        except Exception:
            continue
        src = event.get("srcIp") or event.get("src_ip") or event.get("source ip")
        dst = event.get("dstIp") or event.get("dst_ip") or event.get("destination ip")
        if not src and not dst:
            continue
        events.append({"src": src, "dst": dst, "record": event, "label": label})

    incident_groups = {}
    for event in events:
        for ip in (event["src"], event["dst"]):
            if not ip:
                continue
            group = incident_groups.setdefault(ip, {"event_count": 0, "label_count": 0, "samples": [], "related_ips": set(), "geo": None, "accounts": set()})
            group["event_count"] += 1
            group["label_count"] += int(event["label"])
            group["samples"].append(event["record"])
            other_ip = event["dst"] if ip == event["src"] else event["src"]
            if other_ip:
                group["related_ips"].add(other_ip)
            if event["record"].get("account"):
                group["accounts"].add(event["record"].get("account"))
            if event["record"].get("geolocation"):
                group["geo"] = event["record"].get("geolocation")

    ranked = sorted(incident_groups.items(), key=lambda kv: (kv[1]["label_count"], kv[1]["event_count"]), reverse=True)[:max_groups]
    dataset = {r["ip"]: r for r in load_context_dataset(dataset_path)}

    incidents = []
    for idx, (ip, data) in enumerate(ranked, start=1):
        evidence = data["samples"][:3]
        context = contexts.get(ip, {})
        dataset_record = dataset.get(ip, {})
        pattern = []
        if data["label_count"] > 1:
            pattern.append("multiple high-risk events")
        if len(data["related_ips"]) > 1:
            pattern.append("clustered attacker infrastructure")
        if dataset_record.get("status"):
            pattern.append(f"dataset status={dataset_record.get('status')}")
        if context.get("last_risk_score") and context["last_risk_score"] >= 8:
            pattern.append("persistently high risk score")

        incidents.append({
            "incident_id": f"L3-INC-{idx:02d}",
            "primary_ip": ip,
            "severity": "critical" if data["label_count"] >= 2 or dataset_record.get("status") == "blacklisted" else "high",
            "summary": f"Related incident cluster centered on {ip} with {data['event_count']} events and {data['label_count']} confirmed risk hits.",
            "details": {
                "dataset_status": dataset_record.get("status"),
                "geolocation": dataset_record.get("geolocation") or data.get("geo"),
                "accounts": sorted(list(data["accounts"]))[:3],
                "related_ips": sorted(list(data["related_ips"]))[:5],
                "sample_events": evidence,
            },
            "common_pattern": pattern or ["single suspicious cluster"],
            "recommended_action": [
                "Block or ban primary IP at the edge firewall",
                "Quarantine associated accounts and force credential reset",
                "Add primary IP and related IP cluster to L3 context dataset blacklist",
                "Monitor the ASN/geolocation cluster for follow-up access attempts"
            ],
        })

    incident_report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": "L3 hybrid incident report for linked attack clusters and repeating risk factors.",
        "incident_count": len(incidents),
        "incidents": incidents,
        "dataset_records": len(dataset),
        "top_blacklist_ips": [r["ip"] for r in load_context_dataset(dataset_path) if r.get("status") == "blacklisted"][0:5],
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(incident_report, f, indent=2, ensure_ascii=False)
        logging.info("Saved incident report to %s", output_path)

    conn.close()
    return incident_report


def ingest_l2(input_path: str, db_path: str, derive_label_threshold: int = 7) -> Tuple[int, int]:
    """Ingest L2 JSONL, store events and update contexts.

    derive_label_threshold: risk_score >= threshold -> label=1 (malicious), else 0
    Returns: (events_ingested, contexts_updated)
    """
    conn = init_db(db_path)
    cur = conn.cursor()
    events = 0
    contexts = 0

    def upsert_context(ip: str, meta: Dict[str, Any]):
        nonlocal contexts
        now = time.time()
        cur.execute("SELECT seen_count, meta_json FROM contexts WHERE ip=?", (ip,))
        row = cur.fetchone()
        if row:
            seen_count = row[0] + 1
            try:
                existing = json.loads(row[1]) if row[1] else {}
            except Exception:
                existing = {}
            # merge simple counters
            merged = {**existing, **meta}
            cur.execute("UPDATE contexts SET last_seen=?, seen_count=?, meta_json=? WHERE ip=?", (now, seen_count, json.dumps(merged), ip))
        else:
            cur.execute("INSERT INTO contexts(ip, last_seen, seen_count, meta_json) VALUES(?,?,?,?)", (ip, now, 1, json.dumps(meta)))
            contexts += 1

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue

            ts = time.time()
            src = record.get("srcIp") or record.get("src_ip") or record.get("source ip")
            dst = record.get("dstIp") or record.get("dst_ip") or record.get("destination ip")
            l2 = record.get("l2_analysis") or {}
            # l2_analysis may be string
            if isinstance(l2, str):
                try:
                    l2 = json.loads(l2)
                except Exception:
                    l2 = {}

            risk = None
            try:
                if l2 and l2.get("risk_score") is not None:
                    risk = int(l2.get("risk_score"))
            except Exception:
                try:
                    risk = int(record.get("riskScore") or record.get("risk_score"))
                except Exception:
                    risk = None

            label = 1 if (risk is not None and risk >= derive_label_threshold) else 0

            cur.execute("INSERT INTO events(timestamp, src_ip, dst_ip, raw_json, label) VALUES(?,?,?,?,?)",
                        (ts, src, dst, json.dumps(record), label))

            # build simple context metadata
            meta = {
                "last_l1_score": record.get("l1Score") or record.get("l1_score") or 0,
                "last_risk_score": risk,
            }
            if src:
                upsert_context(src, meta)
            if dst and dst != src:
                upsert_context(dst, meta)

            events += 1

    conn.commit()
    conn.close()
    logging.info("Ingested %d events, updated %d new contexts", events, contexts)
    return events, contexts


def build_feature_dataframe(conn: sqlite3.Connection) -> Optional[pd.DataFrame]:
    cur = conn.cursor()
    cur.execute("SELECT id, timestamp, src_ip, dst_ip, raw_json, label FROM events")
    rows = cur.fetchall()
    if not rows:
        return None

    records = []
    for _id, ts, src, dst, raw_json, label in rows:
        try:
            raw = json.loads(raw_json)
        except Exception:
            raw = {}

        # extract numeric features with safe conversion
        def num(k):
            v = raw.get(k)
            try:
                return float(v) if v is not None else 0.0
            except Exception:
                return 0.0

        feat = {
            "id": _id,
            "src_ip": src,
            "dst_ip": dst,
            "l1_score": num("l1Score") or num("l1_score"),
            "flow_bytes_s": num("flowBytesPerSec") or num("flow bytes/s") or num("flow_bytes_s"),
            "flow_packets_s": num("flowPacketsPerSec") or num("flow packets/s") or num("flow_packets_s"),
            "syn_flag": num("synFlagCount") or num("syn flag") or num("syn_flag") or 0,
            "dst_port": int(raw.get("dstPort") or raw.get("dst_port") or 0),
            "protocol": int(raw.get("protocol") or 0),
            "label": int(label),
        }
        records.append(feat)

    df = pd.DataFrame.from_records(records)
    if df.empty:
        return None

    # fillna and basic preprocessing
    df.fillna(0, inplace=True)
    return df


def parse_args():
    p = argparse.ArgumentParser(description="L3 Agent: context DB + hybrid IsolationForest + optional LSTM security model")
    sub = p.add_subparsers(dest="cmd")

    ing = sub.add_parser("ingest", help="Ingest L2 JSONL into context DB")
    ing.add_argument("--input", "-i", required=True)
    ing.add_argument("--db", default=DEFAULT_DB)
    ing.add_argument("--threshold", type=int, default=7, help="risk_score threshold to consider positive label")
    ing.add_argument("--dataset", default=DEFAULT_DATASET, help="L3 dataset context path")

    tr = sub.add_parser("train", help="Train hybrid model from DB")
    tr.add_argument("--db", default=DEFAULT_DB)
    tr.add_argument("--model-out", default=DEFAULT_MODEL)
    tr.add_argument("--dataset", default=DEFAULT_DATASET)

    pr = sub.add_parser("predict", help="Predict with saved hybrid model")
    pr.add_argument("--input", "-i", required=True)
    pr.add_argument("--model", required=True)
    pr.add_argument("--out", help="output JSONL of predictions")
    pr.add_argument("--dataset", default=DEFAULT_DATASET)

    rep = sub.add_parser("report", help="Show DB summary and dataset counts")
    rep.add_argument("--db", default=DEFAULT_DB)
    rep.add_argument("--dataset", default=DEFAULT_DATASET)

    ir = sub.add_parser("incident-report", help="Generate interconnected L3 incident report")
    ir.add_argument("--db", default=DEFAULT_DB)
    ir.add_argument("--dataset", default=DEFAULT_DATASET)
    ir.add_argument("--out", default="L3_output")
    ir.add_argument("--max-groups", type=int, default=10, help="Number of top incident clusters to include")

    sync = sub.add_parser("update-dataset", help="Sync flagged events into the L3 dataset context")
    sync.add_argument("--db", default=DEFAULT_DB)
    sync.add_argument("--dataset", default=DEFAULT_DATASET)
    sync.add_argument("--min-label", type=int, default=1)

    aut = sub.add_parser("autonext", help="Ingest, train, predict (convenience)")
    aut.add_argument("--input", "-i", required=True)
    aut.add_argument("--db", default=DEFAULT_DB)
    aut.add_argument("--model-out", default=DEFAULT_MODEL)
    aut.add_argument("--pred-out", default="l3_preds.jsonl")
    aut.add_argument("--dataset", default=DEFAULT_DATASET)

    return p.parse_args()


def main():
    args = parse_args()
    if args.cmd == "ingest":
        ingest_l2(args.input, args.db, derive_label_threshold=args.threshold)
    elif args.cmd == "train":
        train_model(args.db, model_out=args.model_out, dataset_path=args.dataset)
    elif args.cmd == "predict":
        predict_file(args.input, args.model, out_path=args.out, dataset_path=args.dataset)
    elif args.cmd == "report":
        rep = report(args.db, dataset_path=args.dataset)
        print(json.dumps(rep, indent=2))
    elif args.cmd == "incident-report":
        report_data = generate_incident_report(
            args.db,
            dataset_path=args.dataset,
            output_path=args.out,
            max_groups=args.max_groups,
        )
        print(json.dumps(report_data, indent=2))
    elif args.cmd == "update-dataset":
        synced = sync_events_to_dataset(args.db, dataset_path=args.dataset, min_label=args.min_label)
        print(json.dumps({"synced": synced, "dataset": args.dataset}, indent=2))
    elif args.cmd == "autonext":
        ingest_l2(args.input, args.db)
        train_model(args.db, model_out=args.model_out, dataset_path=args.dataset)
        predict_file(args.input, args.model_out, out_path=args.pred_out, dataset_path=args.dataset)
    else:
        print("No command specified. Use --help for usage.")


if __name__ == "__main__":
    main()
