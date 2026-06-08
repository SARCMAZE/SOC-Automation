import sys
import argparse
from datetime import datetime
import statistics

# Prefer faster JSON where available
try:
    import ujson as _json
except Exception:
    import json as _json

# Force UTF-8 (prevents Windows encoding crashes)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 80, 443, 8080, 8443}


def parse_args():
    p = argparse.ArgumentParser(description="L1 Balanced: fast deterministic L1 filter")
    p.add_argument("--input", "-i", default=r"C:\\Users\\SHREYAS KUMAR\\Desktop\\projcts\\Major_Project\\Combined_CIC_Data.json")
    p.add_argument("--output", "-o", default=r"C:\\Users\\SHREYAS KUMAR\\Downloads\\l1_output6PP.jsonl")
    p.add_argument("--stats", default=r"C:\\Users\\SHREYAS KUMAR\\Downloads\\l1_stats6PP.txt")
    p.add_argument("--sample-every", type=int, default=10)
    # Relaxed default between previous (6) and stricter (10)
    p.add_argument("--min-score", type=int, default=8)
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def safe_float(value, default=0.0):
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def log_time(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def severity_from_score(score):
    if score >= 12:
        return "HIGH"
    if score >= 9:
        return "MEDIUM"
    return "LOW"


def calculate_score(nums, dst_port):
    # nums: dict of numeric fields already parsed
    score = 0

    flow_bytes_s = nums.get("flow bytes/s", 0)
    flow_packets_s = nums.get("flow packets/s", 0)
    syn_flag = nums.get("syn flag count", 0)
    rst_flag = nums.get("rst flag count", 0)
    pkt_std = nums.get("packet length std", 0)
    down_up_ratio = nums.get("down/up ratio", 0)
    fwd_pkt_len_mean = nums.get("fwd packet length mean", 0)
    bwd_pkt_len_mean = nums.get("bwd packet length mean", 0)
    flow_iat_mean = nums.get("flow iat mean", 0)
    flow_iat_std = nums.get("flow iat std", 0)
    fwd_iat_total = nums.get("fwd iat total", 0)
    active_mean = nums.get("active mean", 0)
    idle_mean = nums.get("idle mean", 0)
    fin_flag = nums.get("fin flag count", 0)
    urg_flag = nums.get("urg flag count", 0)
    psh_flag = nums.get("psh flag count", 0)
    fwd_packets = nums.get("total fwd packets", 0)
    bwd_packets = nums.get("total backward packets", 0)
    total_packets = fwd_packets + bwd_packets

    # Core signals
    # Relaxed byte thresholds to surface more candidate flows
    if flow_bytes_s > 700_000:
        score += 3
    elif flow_bytes_s > 300_000:
        score += 2
    elif flow_bytes_s > 150_000:
        score += 1

    # Loosen packet-rate thresholds slightly
    if flow_packets_s > 900:
        score += 2
    elif flow_packets_s > 450:
        score += 1

    # More sensitive SYN detection
    if syn_flag > 4:
        score += 2
    elif syn_flag > 2:
        score += 1

    if dst_port in SENSITIVE_PORTS:
        score += 1
    if dst_port in {22, 23, 3389, 445}:
        score += 1

    # Support signals
    if rst_flag > 4:
        score += 1
    if pkt_std > 350:
        score += 1
    if down_up_ratio > 8:
        score += 1
    if total_packets > 200:
        score += 1
    if urg_flag > 0:
        score += 2
    if fin_flag > 10:
        score += 1
    if psh_flag > 20:
        score += 1

    # Timing signals
    if flow_iat_mean and flow_packets_s > 500 and flow_iat_mean < 300:
        score += 1
    if flow_iat_std > 150_000:
        score += 1
    if fwd_iat_total and fwd_packets > 100 and fwd_iat_total < 500:
        score += 1

    if idle_mean and active_mean and active_mean > 0:
        if idle_mean / active_mean > 8:
            score += 1

    # Packet size signals
    if fwd_pkt_len_mean and fwd_pkt_len_mean < 8 and fwd_packets > 30:
        score += 1
    if bwd_pkt_len_mean > 2000:
        score += 1

    if fwd_pkt_len_mean and bwd_pkt_len_mean and fwd_pkt_len_mean > 0:
        if (bwd_pkt_len_mean / fwd_pkt_len_mean) > 15:
            score += 1

    # Boost conditions
    if syn_flag > 5 and flow_packets_s > 800:
        score += 2
    if dst_port in SENSITIVE_PORTS and total_packets > 200:
        score += 1
    if flow_bytes_s > 400_000 and flow_packets_s > 900 and syn_flag > 4:
        score += 2
    if urg_flag > 0 and dst_port in SENSITIVE_PORTS:
        score += 2
    if rst_flag > 4 and syn_flag > 3:
        score += 1

    return int(score)


def process_logs(input_file, output_file, stats_file, sample_every=10, min_score=6, verbose=False):
    start = datetime.now()
    if verbose:
        log_time("L1 Processing + Stats Collection Started")

    stat_keys = [
        "flow bytes/s", "flow packets/s", "syn flag count",
        "rst flag count", "packet length std", "down/up ratio",
        "fwd packet length mean", "bwd packet length mean",
        "flow iat mean", "flow iat std", "fwd iat total",
        "active mean", "idle mean",
    ]

    stats = {k: [] for k in stat_keys}
    stats["total_packets"] = []
    port_counts = {}
    protocol_counts = {}

    count = 0
    flagged = 0

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f_in, \
         open(output_file, "w", encoding="utf-8") as f_out:

        for line in f_in:
            line = line.strip()
            if not line:
                continue

            # Support files that are JSON arrays or JSON-lines
            if line.startswith("[") and line.endswith("]"):
                try:
                    items = _json.loads(line)
                except Exception:
                    continue
                for it in items:
                    # push back to processing loop
                    raw = it
                    try:
                        count += 1
                        process_single(raw, stats, stat_keys, port_counts, protocol_counts,
                                       f_out, sample_every, min_score)
                        flagged += 0  # process_single handles counting via return but avoid duplicate complexity
                    except Exception:
                        continue
                continue

            try:
                raw = _json.loads(line)
            except Exception:
                # skip invalid JSON lines
                continue

            count += 1
            did_flag = process_single(raw, stats, stat_keys, port_counts, protocol_counts,
                                      f_out, sample_every, min_score)
            if did_flag:
                flagged += 1

            if count % 50000 == 0 and verbose:
                elapsed = datetime.now() - start
                log_time(f"Processed: {count:,} | Flagged: {flagged:,} | Elapsed: {elapsed}")

    # Save stats summary
    lines_out = ["=" * 60, f"L1 STATS REPORT - {datetime.now()}", "=" * 60,
                 f"Total Processed: {count:,}", f"Total Flagged: {flagged:,}"]

    # Add simple numeric summaries
    for k in stat_keys:
        arr = stats.get(k, [])
        if arr:
            try:
                lines_out.append(f"{k}: count={len(arr)} median={statistics.median(arr):.2f} mean={statistics.mean(arr):.2f}")
            except Exception:
                pass

    lines_out.append("Top destination ports:")
    for p, c in sorted(port_counts.items(), key=lambda x: -x[1])[:10]:
        lines_out.append(f"  {p}: {c}")

    full_output = "\n".join(lines_out)

    print("\n" + full_output)

    try:
        with open(stats_file, "w", encoding="utf-8", errors="ignore") as sf:
            sf.write(full_output)
    except Exception:
        pass

    if verbose:
        log_time("Output + Stats saved")
        log_time("All Done!")


def process_single(log, stats, stat_keys, port_counts, protocol_counts, f_out, sample_every, min_score):
    # Pre-parse numeric fields once
    nums = {}
    for k in stat_keys:
        nums[k] = safe_float(log.get(k, 0))

    nums["total fwd packets"] = safe_float(log.get("total fwd packets", 0))
    nums["total backward packets"] = safe_float(log.get("total backward packets", 0))

    # Destination port
    try:
        dst_port = int(safe_float(log.get("destination port", 0)))
    except Exception:
        dst_port = 0

    # Sampling for stats
    # Use a stable sample decision based on a hash of source/destination to avoid bias
    sample_key = (str(log.get("source ip", "")) + ":" + str(log.get("destination ip", "")))
    # Very cheap sampling: use last char code
    if (hash(sample_key) % sample_every) == 0:
        for k in stat_keys:
            stats[k].append(nums.get(k, 0))
        stats["total_packets"].append(nums.get("total fwd packets", 0) + nums.get("total backward packets", 0))
        port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
        proto = str(log.get("protocol", "unknown"))
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    score = calculate_score(nums, dst_port)

    # Extra conditional boost rule (deterministic)
    if score < min_score:
        if nums.get("flow bytes/s", 0) > 150_000 and nums.get("flow packets/s", 0) > 500 and nums.get("syn flag count", 0) > 1:
            score += 1

    flagged = False
    if score >= min_score:
        flagged = True

    if flagged:
        output_log = {
            "src_ip": log.get("source ip"),
            "dst_ip": log.get("destination ip"),
            "dst_port": dst_port,
            "protocol": log.get("protocol"),
            "timestamp": log.get("timestamp"),
            "flow_bytes_s": nums.get("flow bytes/s", 0),
            "flow_packets_s": nums.get("flow packets/s", 0),
            "total_packets": nums.get("total fwd packets", 0) + nums.get("total backward packets", 0),
            "l1_score": int(score),
            "severity": severity_from_score(score),
            "status": "flagged",
        }
        try:
            f_out.write(_json.dumps(output_log, ensure_ascii=False) + "\n")
        except Exception:
            # last resort: fallback to python json
            import json
            f_out.write(json.dumps(output_log, ensure_ascii=False) + "\n")

    return flagged


if __name__ == "__main__":
    args = parse_args()
    process_logs(args.input, args.output, args.stats, sample_every=args.sample_every, min_score=args.min_score, verbose=args.verbose)