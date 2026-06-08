import json
import math
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pandas as pd

HOST = "127.0.0.1"
PORT = 8000


# Try to auto-detect the most recent L1/L2 output files in the workspace.
def find_latest_file(patterns):
    candidates = []
    for pat in patterns:
        candidates.extend(list(Path('.').glob(pat)))
    if not candidates:
        return None
    # pick newest by mtime
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    return latest


# Common default patterns to look for
# Prefer explicit runtime filenames if present (frontend uses these):
preferred_l1 = Path("l1_runtime_output.jsonl")
preferred_l1_alt = Path("l1_runtime_output.JSONL")
L3_REPORT_PATH = Path("L3_output")
L3_LEGACY_REPORT_PATH = Path("l3_incident_report.json")
if preferred_l1.exists():
    INPUT_FILE_L1 = preferred_l1
elif preferred_l1_alt.exists():
    INPUT_FILE_L1 = preferred_l1_alt
else:
    INPUT_FILE_L1 = find_latest_file(["l1_output*.jsonl", "l1_*.jsonl", "l1-output*.jsonl"]) or Path("l1_output2.jsonl")

# L2 prefers the canonical L2 filename user provided (case-insensitive fallback)
preferred_l2 = Path("l2_output1-6PP.JSONL")
preferred_l2_alt = Path("l2_output1-6PP.jsonl")
if preferred_l2.exists():
    INPUT_FILE_L2 = preferred_l2
elif preferred_l2_alt.exists():
    INPUT_FILE_L2 = preferred_l2_alt
else:
    INPUT_FILE_L2 = find_latest_file(["l2_output*.jsonl", "l2_*.jsonl", "l2-output*.jsonl"]) or Path("l2_output3PP.jsonl")
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def pick(log, *keys, default=None):
    for key in keys:
        if key in log and log[key] not in (None, ""):
            return log[key]
    return default


def parse_l2_analysis(raw_value):
    if isinstance(raw_value, dict):
        return raw_value
    if isinstance(raw_value, str) and raw_value.strip():
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return {}
    return {}


def parse_timestamp(value):
    if not value:
        return None

    text = str(value).strip()
    for fmt in (
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue

    parsed = pd.to_datetime(text, errors="coerce")
    if pd.isna(parsed):
        return None
    return parsed.to_pydatetime()


def load_l3_report():
    path = L3_REPORT_PATH if L3_REPORT_PATH.exists() else (L3_LEGACY_REPORT_PATH if L3_LEGACY_REPORT_PATH.exists() else None)
    if path is None:
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def map_l3_incident_to_alert(incident, generated_at):
    related_ips = incident.get("details", {}).get("related_ips", []) or []
    return {
        "flowId": incident.get("incident_id"),
        "timestamp": generated_at,
        "srcIp": incident.get("primary_ip"),
        "srcPort": None,
        "dstIp": related_ips[0] if related_ips else None,
        "dstPort": None,
        "protocol": None,
        "protocolName": "L3",
        "severity": incident.get("severity", "UNKNOWN").upper(),
        "status": "open",
        "label": "L3",
        "l1Score": None,
        "flowDuration": None,
        "flowBytesPerSec": None,
        "flowPacketsPerSec": None,
        "totalFwdPackets": None,
        "totalBwdPackets": None,
        "packetLengthMean": None,
        "synFlagCount": None,
        "pshFlagCount": None,
        "ackFlagCount": None,
        "riskScore": 9 if incident.get("severity", "").lower() == "critical" else 8,
        "confidence": 0.85,
        "attackType": incident.get("common_pattern", ["L3 cluster"])[0],
        "explanation": incident.get("summary"),
        "recommendation": (" ".join(incident.get("recommended_action", [])) or "Review the incident cluster and apply containment."),
        "incidentDetails": incident,
    }


def build_l3_summary(report):
    incidents = report.get("incidents", []) or []
    total = len(incidents)
    critical = sum(1 for incident in incidents if incident.get("severity", "").lower() == "critical")
    high = sum(1 for incident in incidents if incident.get("severity", "").lower() == "high")
    avg_risk = round(sum(9 if incident.get("severity", "").lower() == "critical" else 8 for incident in incidents) / total, 2) if total else None
    return {
        "totalAlerts": total,
        "highRiskAlerts": high + critical,
        "criticalSeverityAlerts": critical,
        "averageRisk": avg_risk,
        "averageConfidence": 0.85 if total else None,
        "latestEvent": report.get("generated_at"),
        "severityBreakdown": {
            "CRITICAL": critical,
            "HIGH": high,
        },
        "attackTypeBreakdown": top_counts([map_l3_incident_to_alert(i, report.get("generated_at")) for i in incidents], "attackType", 10),
        "protocolBreakdown": [{"label": "L3", "value": total}] if total else [],
        "topSourceIps": top_counts([map_l3_incident_to_alert(i, report.get("generated_at")) for i in incidents], "srcIp", 10),
        "topDestinationPorts": top_counts([map_l3_incident_to_alert(i, report.get("generated_at")) for i in incidents], "dstPort", 10),
    }


def build_l3_filters(report):
    incidents = report.get("incidents", []) or []
    return {
        "severity": sorted({incident.get("severity", "UNKNOWN").upper() for incident in incidents}),
        "attackType": sorted({pattern for incident in incidents for pattern in incident.get("common_pattern", [])}),
        "protocol": ["L3"],
    }


def normalize_record(log, source="l2"):
    protocol_value = to_number(pick(log, "protocol"))
    timestamp = parse_timestamp(pick(log, "timestamp"))
    record = {
        "flowId": pick(log, "flow id", "flow_id"),
        "timestamp": timestamp.isoformat() if timestamp else None,
        "srcIp": pick(log, "source ip", "src_ip"),
        "srcPort": pick(log, "source port", "src_port"),
        "dstIp": pick(log, "destination ip", "dst_ip"),
        "dstPort": pick(log, "destination port", "dst_port"),
        "protocol": protocol_value,
        "protocolName": PROTOCOL_MAP.get(protocol_value, str(protocol_value) if protocol_value is not None else "Unknown"),
        "severity": str(pick(log, "severity", default="UNKNOWN")).upper(),
        "status": pick(log, "status", default="unknown"),
        "label": pick(log, "label", default="unknown"),
        "l1Score": to_number(pick(log, "l1_score")),
        "flowDuration": to_number(pick(log, "flow duration", "flow_duration")),
        "flowBytesPerSec": to_number(pick(log, "flow bytes/s", "flow_bytes_s")),
        "flowPacketsPerSec": to_number(pick(log, "flow packets/s", "flow_packets_s")),
        "totalFwdPackets": to_number(pick(log, "total fwd packets", "total_fwd_packets")),
        "totalBwdPackets": to_number(pick(log, "total backward packets", "total_backward_packets")),
        "packetLengthMean": to_number(pick(log, "packet length mean", "packet_length_mean")),
        "synFlagCount": to_number(pick(log, "syn flag count", "syn_flag_count")),
        "pshFlagCount": to_number(pick(log, "psh flag count", "psh_flag_count")),
        "ackFlagCount": to_number(pick(log, "ack flag count", "ack_flag_count")),
    }

    if source == "l2":
        l2 = parse_l2_analysis(log.get("l2_analysis"))
        record.update(
            {
                "riskScore": to_number(l2.get("risk_score")),
                "confidence": to_number(l2.get("confidence_score")),
                "attackType": l2.get("attack_type") or "Unknown",
                "explanation": l2.get("explanation") or "No explanation provided.",
                "recommendation": l2.get("recommendation") or "No recommendation provided.",
            }
        )
    else:
        label = str(pick(log, "label", default="L1 Review")).strip()
        if not label or label.upper() == "BENIGN":
            label = "L1 Review"
        record.update(
            {
                "riskScore": to_number(pick(log, "l1_score")),
                "confidence": 0,
                "attackType": label,
                "explanation": "This flow was surfaced by the L1 engine for analyst review.",
                "recommendation": "Inspect the flow details and correlate with related alerts.",
            }
        )

    return record


def to_number(value):
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isfinite(number) and number.is_integer():
        return int(number)
    return number if math.isfinite(number) else None


def risk_band(score):
    if score is None:
        return "Unknown"
    if score <= 3:
        return "Low"
    if score <= 6:
        return "Guarded"
    if score <= 8:
        return "Elevated"
    if score <= 10:
        return "High"
    return "Critical"


def load_alerts(source="l2"):
    input_file = INPUT_FILE_L1 if source == "l1" else INPUT_FILE_L2
    if not input_file.exists():
        return []

    alerts = []
    with input_file.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                raw_log = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = normalize_record(raw_log, source=source)
            alert["riskBand"] = risk_band(alert["riskScore"])
            alert["trafficVolume"] = (alert["flowBytesPerSec"] or 0) + (alert["flowPacketsPerSec"] or 0)
            alerts.append(alert)

    alerts.sort(
        key=lambda item: (
            item["riskScore"] is None,
            -(item["riskScore"] or -1),
            -(item["confidence"] or -1),
        )
    )
    return alerts


def build_summary(alerts):
    total_alerts = len(alerts)
    high_risk = [alert for alert in alerts if (alert["riskScore"] or 0) >= 8]
    critical = [alert for alert in alerts if alert["severity"] == "CRITICAL"]
    avg_risk = round(sum((alert["riskScore"] or 0) for alert in alerts) / total_alerts, 2) if total_alerts else None
    avg_confidence = (
        round(sum((alert["confidence"] or 0) for alert in alerts) / total_alerts, 2) if total_alerts else None
    )
    timestamps = [alert["timestamp"] for alert in alerts if alert["timestamp"]]

    return {
        "totalAlerts": total_alerts,
        "highRiskAlerts": len(high_risk),
        "criticalSeverityAlerts": len(critical),
        "averageRisk": avg_risk,
        "averageConfidence": avg_confidence,
        "latestEvent": max(timestamps) if timestamps else None,
        "severityBreakdown": count_by(alerts, "severity", SEVERITY_ORDER),
        "attackTypeBreakdown": top_counts(alerts, "attackType", 10),
        "protocolBreakdown": top_counts(alerts, "protocolName", 10),
        "topSourceIps": top_counts(alerts, "srcIp", 10),
        "topDestinationPorts": top_counts(alerts, "dstPort", 10),
    }


def count_by(alerts, key, ordered_keys=None):
    counts = {}
    for alert in alerts:
        value = alert.get(key) or "Unknown"
        counts[value] = counts.get(value, 0) + 1

    if not ordered_keys:
        return counts

    ordered_counts = {name: counts.get(name, 0) for name in ordered_keys if name in counts or counts.get(name, 0) > 0}
    for key_name, value in counts.items():
        if key_name not in ordered_counts:
            ordered_counts[key_name] = value
    return ordered_counts


def top_counts(alerts, key, limit):
    counts = count_by(alerts, key)
    sorted_items = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    return [{"label": str(label), "value": value} for label, value in sorted_items]


def apply_filters(alerts, query):
    severities = set(query.get("severity", []))
    attack_types = set(query.get("attackType", []))
    protocols = set(query.get("protocol", []))
    only_high = query.get("onlyHigh", ["false"])[0].lower() == "true"
    search = query.get("search", [""])[0].strip().lower()

    risk_min = safe_int(query.get("riskMin", ["0"])[0], 0)
    risk_max = safe_int(query.get("riskMax", ["100"])[0], 100)
    confidence_min = safe_int(query.get("confidenceMin", ["0"])[0], 0)
    confidence_max = safe_int(query.get("confidenceMax", ["100"])[0], 100)

    filtered = []
    for alert in alerts:
        if severities and alert["severity"] not in severities:
            continue
        if attack_types and alert["attackType"] not in attack_types:
            continue
        if protocols and alert["protocolName"] not in protocols:
            continue

        risk_score = alert["riskScore"] if alert["riskScore"] is not None else -1
        confidence = alert["confidence"] if alert["confidence"] is not None else -1
        if not (risk_min <= risk_score <= risk_max):
            continue
        if not (confidence_min <= confidence <= confidence_max):
            continue
        if only_high and (alert["riskScore"] or 0) < 8:
            continue

        if search:
            haystack = " ".join(
                str(alert.get(key) or "")
                for key in ("flowId", "srcIp", "dstIp", "srcPort", "dstPort", "attackType", "protocolName")
            ).lower()
            if search not in haystack:
                continue

        filtered.append(alert)

    return filtered


def safe_int(value, fallback):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


class AlertAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return self.respond_json({"status": "ok"})

        if parsed.path == "/api/l1":
            alerts = load_alerts("l1")
            source_name = "L1"
            query = parse_qs(parsed.query)
            filtered = apply_filters(alerts, query)
            payload = {
                "source": source_name,
                "summary": build_summary(filtered),
                "datasetSummary": build_summary(alerts),
                "alerts": filtered,
                "filters": {
                    "severity": sorted({alert["severity"] for alert in alerts}),
                    "attackType": sorted({alert["attackType"] for alert in alerts}),
                    "protocol": sorted({alert["protocolName"] for alert in alerts}),
                },
            }
            return self.respond_json(payload)

        if parsed.path in ("/api/l2", "/api/alerts"):
            alerts = load_alerts("l2")
            source_name = "L2"
            query = parse_qs(parsed.query)
            filtered = apply_filters(alerts, query)
            payload = {
                "source": source_name,
                "summary": build_summary(filtered),
                "datasetSummary": build_summary(alerts),
                "alerts": filtered,
                "filters": {
                    "severity": sorted({alert["severity"] for alert in alerts}),
                    "attackType": sorted({alert["attackType"] for alert in alerts}),
                    "protocol": sorted({alert["protocolName"] for alert in alerts}),
                },
            }
            return self.respond_json(payload)

        if parsed.path == "/api/l3":
            report = load_l3_report()
            incidents = report.get("incidents", []) or []
            alerts = [map_l3_incident_to_alert(incident, report.get("generated_at")) for incident in incidents]
            query = parse_qs(parsed.query)
            filtered = apply_filters(alerts, query)
            payload = {
                "source": "L3",
                "summary": build_l3_summary(report),
                "datasetSummary": {
                    "totalAlerts": report.get("dataset_records", 0),
                    "blacklistCount": report.get("dataset_records", 0),
                },
                "alerts": filtered,
                "filters": build_l3_filters(report),
            }
            return self.respond_json(payload)

        return self.respond_json({"error": "Not found"}, status=404)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, format_string, *args):
        return

    def respond_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), AlertAPIHandler)
    print(f"API server running at http://{HOST}:{PORT}")
    print(f"Using L1 input file: {INPUT_FILE_L1} (exists={INPUT_FILE_L1.exists()})")
    print(f"Using L2 input file: {INPUT_FILE_L2} (exists={INPUT_FILE_L2.exists()})")
    server.serve_forever()


if __name__ == "__main__":
    main()
