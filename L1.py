# l1_agent_optimized.py

import json
from datetime import datetime

INPUT_FILE = r"C:\Users\SHREYAS KUMAR\Downloads\Combined_CIC_Data.json"
OUTPUT_FILE = r"C:\Users\SHREYAS KUMAR\Downloads\l1_output2.jsonl"

SENSITIVE_PORTS = {21, 22, 23, 3389, 445}


# ---------------------------
# Helper Functions
# ---------------------------

def get_float(log, key):
    try:
        return float(log.get(key, 0))
    except:
        return 0


def log_time(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


# ---------------------------
# Advanced Scoring Logic
# ---------------------------

def calculate_score(log):
    score = 0

    flow_bytes_s = get_float(log, "flow bytes/s")
    flow_packets_s = get_float(log, "flow packets/s")
    syn_flag = get_float(log, "syn flag count")
    rst_flag = get_float(log, "rst flag count")
    pkt_std = get_float(log, "packet length std")
    down_up_ratio = get_float(log, "down/up ratio")

    total_packets = (
        get_float(log, "total fwd packets") +
        get_float(log, "total backward packets")
    )

    dst_port = int(get_float(log, "destination port"))

    # ---------------- STRONG SIGNALS ----------------

    # 1. High traffic burst + high packet rate (DDoS-like)
    if flow_bytes_s > 200000 and flow_packets_s > 1500:
        score += 4

    # 2. SYN + high packets (scan/brute force)
    if syn_flag > 0 and total_packets > 80:
        score += 3

    # 3. RST + SYN together (failed connections pattern)
    if rst_flag > 0 and syn_flag > 0:
        score += 2

    # 4. Sensitive port + abnormal packet variance
    if dst_port in SENSITIVE_PORTS and pkt_std > 250:
        score += 3

    # 5. Data imbalance + high bytes (exfiltration hint)
    if down_up_ratio > 4 and flow_bytes_s > 150000:
        score += 3

    # ---------------- WEAK SIGNALS ----------------

    if pkt_std > 300:
        score += 1

    if total_packets > 120:
        score += 1

    if dst_port in SENSITIVE_PORTS:
        score += 1

    return score


# ---------------------------
# Main Processing
# ---------------------------

def process_logs():
    start_time = datetime.now()
    log_time("🚀 L1 Processing Started")

    with open(INPUT_FILE, "r") as f_in, open(OUTPUT_FILE, "w") as f_out:
        count = 0
        flagged = 0

        for line in f_in:
            try:
                log = json.loads(line)
                count += 1

                # 🔥 Sampling (skip 50%)
                if count % 2 == 0:
                    continue

                score = calculate_score(log)

                # 🔥 STRICT FILTER (KEY CHANGE)
                if score >= 6:
                    log["l1_score"] = score

                    if score >= 9:
                        log["severity"] = "HIGH"
                    elif score >= 7:
                        log["severity"] = "MEDIUM"
                    else:
                        log["severity"] = "LOW"

                    log["status"] = "flagged"

                    f_out.write(json.dumps(log) + "\n")
                    flagged += 1

                # Progress update every 50k logs
                if count % 50000 == 0:
                    log_time(f"Processed: {count} | Flagged: {flagged}")

            except:
                continue

    end_time = datetime.now()

    log_time("✅ L1 Processing Completed")
    log_time(f"Total Processed: {count}")
    log_time(f"Total Flagged: {flagged}")
    log_time(f"Execution Time: {end_time - start_time}")


if __name__ == "__main__":
    process_logs()