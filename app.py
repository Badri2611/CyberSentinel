import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import socket
import requests
import time
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="CyberSentinel Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #f8f9fa;
        font-family: 'Inter', sans-serif;
    }
    h1, h2, h3 {
        color: #2c3e50;
    }
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
        background-color: #007bff;
        color: white;
    }
    .metric-card {
        background-color: white;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    .scanner-header {
        background: linear-gradient(90deg, #11998e 0%, #38ef7d 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# ================= SIDEBAR NAVIGATION =================
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9103/9103233.png", width=80)
    st.title("CyberSentinel 🛡️")
    st.caption("Advanced Defense Suite")
    
    st.markdown("---")
    app_mode = st.radio("Select Module", ["🛑 Network Defense Log", "🌐 Advanced URL Scanner"])
    st.markdown("---")

# ================= UTILS: Network Model =================
MODEL_FILE = "model.pkl"
COLUMNS_FILE = "columns.pkl"

@st.cache_resource
def get_model(force_retrain=False):
    if not force_retrain and os.path.exists(MODEL_FILE) and os.path.exists(COLUMNS_FILE):
        return joblib.load(MODEL_FILE), joblib.load(COLUMNS_FILE), False

    try:
        df = pd.read_csv("train_test.csv", low_memory=False)
    except FileNotFoundError:
        return None, None, False

    label_cols = [c for c in df.columns if "label" in c.lower()]
    if not label_cols: return None, None, False
        
    df["Attack_Label"] = (df[label_cols[0]].astype(str).str.upper() != "BENIGN").astype(int)
    df.drop(columns=[label_cols[0]], inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].clip(-1e6, 1e6)

    X = df
    y = df.pop("Attack_Label")
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, stratify=y)

    model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)
    
    joblib.dump(model, MODEL_FILE)
    joblib.dump(X.columns, COLUMNS_FILE)
    return model, X.columns, True

# ================= MODULE 1: NETWORK DEFENSE =================
if app_mode == "🛑 Network Defense Log":
    st.title("Network Traffic Analysis")
    st.markdown("Detect anomalies and potential cyber attacks in network flow.")

    with st.sidebar:
        st.header("Settings")
        retrain = st.checkbox("Force Retrain Model")
        uploaded_file = st.file_uploader("Upload Traffic Log (CSV)", type=["csv"])

    model, cols, new_train = get_model(retrain)
    
    if new_train: st.success("Model retrained successfully!")
    elif not model: 
        st.error("Training failed. Check 'train_test.csv'.")
        st.stop()

    if uploaded_file:
        data = pd.read_csv(uploaded_file)
        aligned = pd.DataFrame()
        for c in cols:
            aligned[c] = pd.to_numeric(data[c], errors="coerce") if c in data.columns else 0
        aligned.replace([np.inf, -np.inf], np.nan, inplace=True)
        aligned.fillna(0, inplace=True)

        probs = model.predict_proba(aligned)[:, 1]
        aligned["Risk"] = ["Harmful" if p >= 0.7 else "Suspicious" if p >= 0.35 else "Safe" for p in probs]

        # Dashboard
        safe = (aligned["Risk"] == "Safe").sum()
        sus = (aligned["Risk"] == "Suspicious").sum()
        harm = (aligned["Risk"] == "Harmful").sum()
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Safe", safe, delta_color="normal")
        c2.metric("Suspicious", sus, delta_color="off")
        c3.metric("Harmful", harm, delta_color="inverse")

        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Traffic Composition")
            counts = aligned["Risk"].value_counts()
            fig, ax = plt.subplots()
            ax.pie(counts, labels=counts.index, autopct='%1.1f%%', colors=["#2ecc71", "#f1c40f", "#e74c3c"])
            st.pyplot(fig)
        
        with col2:
            st.subheader("Detailed Logs")
            st.dataframe(aligned[["Risk"]].join(data), height=300)

    else:
        st.info("Upload a CSV file to begin analysis.")


# ================= MODULE 2: URL SCANNER =================
elif app_mode == "🌐 Advanced URL Scanner":
    st.markdown("""
        <div class='scanner-header'>
            <h2>🌐 Advanced Network Scanner</h2>
            <p>Port scanning, packet tracking, and detailed reconnaissance.</p>
        </div>
    """, unsafe_allow_html=True)
    
    target_url = st.text_input("Enter Target URL", "https://google.com")
    
    if st.button("🚀 Start Deep Scan"):
        if not target_url.startswith("http"):
            st.error("Please include http:// or https://")
        else:
            try:
                parsed = urlparse(target_url)
                domain = parsed.netloc
                ip = socket.gethostbyname(domain)
                
                info_col, scan_col = st.columns([1, 2])
                
                with info_col:
                    st.info(f"**Target Host:** {domain}")
                    st.success(f"**Target IP:** {ip}")
                    
                    # === PORT SCANNER ===
                    st.subheader("🔓 Port Scanner")
                    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
                    open_ports = []
                    
                    status_text = st.empty()
                    status_text.text("Scanning common ports...")
                    
                    def scan_port(port):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        return port if result == 0 else None

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        results = executor.map(scan_port, common_ports)
                        for p in results:
                            if p: open_ports.append(p)
                    
                    if open_ports:
                        st.write("**Open Ports Found:**")
                        for p in open_ports:
                            st.write(f"- Port {p} [OPEN]")
                    else:
                        st.warning("No common open ports detected (likely firewalled).")
                        
                with scan_col:
                    # === TRAFFIC TRACKER ===
                    st.subheader("📶 50-Packet Traffic Traffic Log")
                    st.caption(f"Capturing 50 probes from {domain}...")
                    
                    packet_data = []
                    latencies = []
                    
                    progress_bar = st.progress(0)
                    chart_placeholder = st.empty()
                    
                    for i in range(50):
                        progress_bar.progress((i + 1) * 2)
                        
                        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        try:
                            start = time.time()
                            r = requests.get(target_url, timeout=2)
                            end = time.time()
                            lat = (end - start) * 1000
                            size = len(r.content)
                            status = r.status_code
                        except:
                            lat = 0
                            size = 0
                            status = "TIMEOUT"
                        
                        packet_data.append({
                            "Seq_ID": i + 1,
                            "Timestamp": timestamp,
                            "Source": "Client (Local)",
                            "Destination": ip,
                            "Status_Code": status,
                            "Latency_ms": round(lat, 2),
                            "Bytes": size
                        })
                        latencies.append(lat)
                        time.sleep(0.1) # Simulate packet gap
                    
                    # Real-time Chart
                    fig, ax = plt.subplots(figsize=(8, 3))
                    ax.plot(latencies, color='#e74c3c', linewidth=1)
                    ax.fill_between(range(len(latencies)), latencies, color='#e74c3c', alpha=0.1)
                    ax.set_title("Packet Latency Flow")
                    ax.set_ylabel("ms")
                    chart_placeholder.pyplot(fig)
                    
                    st.success("Packet capture complete.")

                # === REPORTING ===
                st.markdown("---")
                st.subheader("📥 Download Intelligence Report")
                
                df_packets = pd.DataFrame(packet_data)
                
                # Create Report Text
                report_content = f"""
CYBERSENTINEL - SCAN REPORT
===========================
Target: {target_url}
Domain: {domain}
IP Address: {ip}
Scan Date: {datetime.now()}
===========================

[OPEN PORTS DETECTED]
{', '.join(map(str, open_ports)) if open_ports else "None detected"}

[TRAFFIC ANALYSIS SUMMARY]
Total Packets: 50
Avg Latency: {df_packets['Latency_ms'].mean():.2f} ms
Max Latency: {df_packets['Latency_ms'].max():.2f} ms
Total Bytes Recv: {df_packets['Bytes'].sum()}

[DETAILED PACKET LOG]
{df_packets.to_string(index=False)}
                """
                
                col_d1, col_d2 = st.columns(2)
                col_d1.download_button(
                    label="Download Report (TXT)",
                    data=report_content,
                    file_name="scan_report.txt",
                    mime="text/plain"
                )
                col_d2.download_button(
                    label="Download Packet Log (CSV)",
                    data=df_packets.to_csv(index=False),
                    file_name="packet_traffic_log.csv",
                    mime="text/csv"
                )

            except Exception as e:
                st.error(f"Scan failed: {e}")
