import json
from datetime import datetime

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC AI Dashboard", layout="wide")

st.title("SOC AI Dashboard")
st.caption("Threat monitoring, alert triage, and L2 analysis in one view")

INPUT_FILE = "l2_output3PP.jsonl"
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
        return pd.NaT

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

    return pd.to_datetime(text, errors="coerce")


@st.cache_data(show_spinner=False)
def load_data():
    rows = []

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        for line in file:
            try:
                log = json.loads(line)
            except json.JSONDecodeError:
                continue

            l2 = parse_l2_analysis(log.get("l2_analysis"))
            protocol = pick(log, "protocol")

            row = {
                "flow_id": pick(log, "flow id", "flow_id"),
                "timestamp": parse_timestamp(pick(log, "timestamp")),
                "src_ip": pick(log, "source ip", "src_ip"),
                "src_port": pick(log, "source port", "src_port"),
                "dst_ip": pick(log, "destination ip", "dst_ip"),
                "dst_port": pick(log, "destination port", "dst_port"),
                "protocol": protocol,
                "protocol_name": PROTOCOL_MAP.get(protocol, str(protocol) if protocol is not None else "Unknown"),
                "severity": str(pick(log, "severity", default="UNKNOWN")).upper(),
                "status": pick(log, "status", default="unknown"),
                "label": pick(log, "label", default="unknown"),
                "l1_score": pd.to_numeric(pick(log, "l1_score"), errors="coerce"),
                "risk_score": pd.to_numeric(l2.get("risk_score"), errors="coerce"),
                "confidence": pd.to_numeric(l2.get("confidence_score"), errors="coerce"),
                "attack_type": l2.get("attack_type") or "Unknown",
                "explanation": l2.get("explanation") or "No explanation provided.",
                "recommendation": l2.get("recommendation") or "No recommendation provided.",
                "flow_duration": pd.to_numeric(pick(log, "flow duration", "flow_duration"), errors="coerce"),
                "flow_bytes_s": pd.to_numeric(pick(log, "flow bytes/s", "flow_bytes_s"), errors="coerce"),
                "flow_packets_s": pd.to_numeric(pick(log, "flow packets/s", "flow_packets_s"), errors="coerce"),
                "total_fwd_packets": pd.to_numeric(pick(log, "total fwd packets", "total_fwd_packets"), errors="coerce"),
                "total_bwd_packets": pd.to_numeric(pick(log, "total backward packets", "total_backward_packets"), errors="coerce"),
                "packet_length_mean": pd.to_numeric(pick(log, "packet length mean", "packet_length_mean"), errors="coerce"),
                "syn_flag_count": pd.to_numeric(pick(log, "syn flag count", "syn_flag_count"), errors="coerce"),
                "psh_flag_count": pd.to_numeric(pick(log, "psh flag count", "psh_flag_count"), errors="coerce"),
                "ack_flag_count": pd.to_numeric(pick(log, "ack flag count", "ack_flag_count"), errors="coerce"),
            }
            rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["severity"] = pd.Categorical(df["severity"], categories=SEVERITY_ORDER, ordered=True)
    df["risk_band"] = pd.cut(
        df["risk_score"],
        bins=[-1, 3, 6, 8, 10, float("inf")],
        labels=["Low", "Guarded", "Elevated", "High", "Critical"],
    )
    df["traffic_volume"] = df["flow_bytes_s"].fillna(0) + df["flow_packets_s"].fillna(0)
    return df.sort_values(by=["risk_score", "confidence"], ascending=[False, False], na_position="last")


df = load_data()

if df.empty:
    st.warning(f"No data found in {INPUT_FILE}.")
    st.stop()

total_alerts = len(df)
total_high_risk = int((df["risk_score"].fillna(0) >= 8).sum())
total_critical_severity = int((df["severity"].astype(str) == "CRITICAL").sum())

st.sidebar.header("Filters")

severity_options = [value for value in SEVERITY_ORDER if value in df["severity"].astype(str).unique()]
severity_filter = st.sidebar.multiselect(
    "Severity",
    options=severity_options,
    default=severity_options,
)

attack_options = sorted(df["attack_type"].dropna().unique().tolist())
attack_filter = st.sidebar.multiselect(
    "Attack type",
    options=attack_options,
    default=attack_options,
)

protocol_options = sorted(df["protocol_name"].dropna().unique().tolist())
protocol_filter = st.sidebar.multiselect(
    "Protocol",
    options=protocol_options,
    default=protocol_options,
)

risk_min, risk_max = st.sidebar.slider("Risk score", 0, 100, (0, 100))
confidence_min, confidence_max = st.sidebar.slider("Confidence", 0, 100, (0, 100))

search_text = st.sidebar.text_input("IP / port / flow search")
only_high_priority = st.sidebar.checkbox("Only show high priority alerts", value=False)

filtered_df = df[
    df["severity"].astype(str).isin(severity_filter)
    & df["attack_type"].isin(attack_filter)
    & df["protocol_name"].isin(protocol_filter)
    & df["risk_score"].fillna(-1).between(risk_min, risk_max)
    & df["confidence"].fillna(-1).between(confidence_min, confidence_max)
].copy()

if only_high_priority:
    filtered_df = filtered_df[filtered_df["risk_score"].fillna(0) >= 8]

if search_text:
    search_mask = (
        filtered_df["src_ip"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_df["dst_ip"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_df["flow_id"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_df["dst_port"].astype(str).str.contains(search_text, case=False, na=False)
        | filtered_df["src_port"].astype(str).str.contains(search_text, case=False, na=False)
    )
    filtered_df = filtered_df[search_mask]

if filtered_df.empty:
    st.info("No alerts match the current filters.")
    st.stop()

latest_seen = filtered_df["timestamp"].max()
avg_risk = filtered_df["risk_score"].mean()
avg_confidence = filtered_df["confidence"].mean()
high_risk_count = int((filtered_df["risk_score"].fillna(0) >= 8).sum())
critical_count = int((filtered_df["severity"].astype(str) == "CRITICAL").sum())

metric_cols = st.columns(6)
metric_cols[0].metric("Total dataset", f"{total_alerts:,}")
metric_cols[1].metric("Filtered alerts", f"{len(filtered_df):,}")
metric_cols[2].metric("High risk", f"{high_risk_count:,}", delta=f"of {total_high_risk:,} total")
metric_cols[3].metric("Critical severity", f"{critical_count:,}", delta=f"of {total_critical_severity:,} total")
metric_cols[4].metric("Avg risk", f"{avg_risk:.1f}" if pd.notna(avg_risk) else "N/A")
metric_cols[5].metric("Latest event", latest_seen.strftime("%d %b %Y %H:%M") if pd.notna(latest_seen) else "Unknown")

st.caption(
    f"Showing {len(filtered_df):,} of {total_alerts:,} alerts. "
    f"High-risk alerts in current view: {high_risk_count:,}. "
    f"Average confidence: {avg_confidence:.1f}" if pd.notna(avg_confidence) else
    f"Showing {len(filtered_df):,} of {total_alerts:,} alerts."
)

st.divider()

overview_tab, hotspots_tab, triage_tab, data_tab = st.tabs(
    ["Overview", "Hotspots", "Triage", "Data Explorer"]
)

with overview_tab:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity distribution")
        severity_counts = (
            filtered_df["severity"]
            .astype(str)
            .value_counts()
            .reindex(SEVERITY_ORDER, fill_value=0)
        )
        st.bar_chart(severity_counts)

    with col2:
        st.subheader("Attack type distribution")
        st.bar_chart(filtered_df["attack_type"].value_counts().head(10))

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Top destination ports")
        st.bar_chart(filtered_df["dst_port"].astype(str).value_counts().head(10))

    with col4:
        st.subheader("Top source IPs")
        st.bar_chart(filtered_df["src_ip"].value_counts().head(10))

    trend_df = (
        filtered_df.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .set_index("timestamp")[["risk_score", "confidence"]]
    )
    if not trend_df.empty:
        st.subheader("Risk and confidence over time")
        st.line_chart(trend_df)

with hotspots_tab:
    left, right = st.columns([1.2, 1])

    with left:
        st.subheader("Traffic pattern map")
        scatter_df = filtered_df.rename(
            columns={
                "flow_packets_s": "Packets/s",
                "flow_bytes_s": "Bytes/s",
                "risk_score": "Risk score",
            }
        )
        st.scatter_chart(
            scatter_df,
            x="Packets/s",
            y="Bytes/s",
            color="Risk score",
        )

    with right:
        st.subheader("Risk bands")
        st.bar_chart(filtered_df["risk_band"].astype(str).value_counts())

        protocol_mix = filtered_df["protocol_name"].value_counts()
        if not protocol_mix.empty:
            st.subheader("Protocol mix")
            st.bar_chart(protocol_mix)

    suspicious_pairs = (
        filtered_df.groupby(["src_ip", "dst_ip"], dropna=False)
        .agg(
            alerts=("flow_id", "count"),
            avg_risk=("risk_score", "mean"),
            max_confidence=("confidence", "max"),
            top_port=("dst_port", lambda values: values.mode().iloc[0] if not values.mode().empty else None),
        )
        .reset_index()
        .sort_values(by=["avg_risk", "alerts"], ascending=[False, False])
    )
    st.subheader("Most suspicious source-destination pairs")
    st.dataframe(suspicious_pairs.head(15), use_container_width=True, hide_index=True)

with triage_tab:
    triage_df = filtered_df.sort_values(
        by=["risk_score", "confidence", "traffic_volume"],
        ascending=[False, False, False],
        na_position="last",
    ).reset_index(drop=True)

    st.subheader("Priority queue")
    st.dataframe(
        triage_df[
            [
                "timestamp",
                "severity",
                "attack_type",
                "risk_score",
                "confidence",
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol_name",
                "status",
            ]
        ].head(100),
        use_container_width=True,
        hide_index=True,
    )

    selected_index = st.selectbox(
        "Inspect alert",
        options=triage_df.index,
        format_func=lambda idx: (
            f"{triage_df.loc[idx, 'attack_type']} | "
            f"{triage_df.loc[idx, 'src_ip']} -> {triage_df.loc[idx, 'dst_ip']}:{triage_df.loc[idx, 'dst_port']} | "
            f"risk {triage_df.loc[idx, 'risk_score']}"
        ),
    )

    selected_alert = triage_df.loc[selected_index]
    detail_cols = st.columns(3)
    detail_cols[0].metric("Selected risk", selected_alert["risk_score"])
    detail_cols[1].metric("Selected confidence", selected_alert["confidence"])
    detail_cols[2].metric("L1 score", selected_alert["l1_score"])

    st.markdown("**Explanation**")
    st.write(selected_alert["explanation"])

    st.markdown("**Recommendation**")
    st.write(selected_alert["recommendation"])

    st.markdown("**Connection summary**")
    summary_df = pd.DataFrame(
        [
            {"Field": "Flow ID", "Value": selected_alert["flow_id"]},
            {"Field": "Timestamp", "Value": selected_alert["timestamp"]},
            {"Field": "Source", "Value": f"{selected_alert['src_ip']}:{selected_alert['src_port']}"},
            {"Field": "Destination", "Value": f"{selected_alert['dst_ip']}:{selected_alert['dst_port']}"},
            {"Field": "Protocol", "Value": selected_alert["protocol_name"]},
            {"Field": "Flow bytes/s", "Value": selected_alert["flow_bytes_s"]},
            {"Field": "Flow packets/s", "Value": selected_alert["flow_packets_s"]},
            {"Field": "Avg packet length", "Value": selected_alert["packet_length_mean"]},
            {"Field": "SYN / PSH / ACK", "Value": f"{selected_alert['syn_flag_count']} / {selected_alert['psh_flag_count']} / {selected_alert['ack_flag_count']}"},
        ]
    )
    st.dataframe(summary_df, use_container_width=True, hide_index=True)

with data_tab:
    st.subheader("Detailed alerts table")
    st.dataframe(filtered_df, use_container_width=True, hide_index=True)

    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Download filtered alerts as CSV",
        data=csv_data,
        file_name="filtered_alerts.csv",
        mime="text/csv",
    )
