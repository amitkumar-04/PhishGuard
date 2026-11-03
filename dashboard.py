import streamlit as st
import json
import os
import re
import requests
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"
HISTORY_FILE = "scan_history.json"

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="PhishGuard | Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}
h1, h2, h3 {
    color: #00ff9c !important;
}
div[data-testid="stMetric"] {
    background-color: #151f30;
    border: 1px solid #26364d;
    padding: 18px;
    border-radius: 12px;
}
div[data-testid="stMetricValue"] {
    color: #00ff9c;
}
.stButton > button {
    background-color: #00c982;
    color: #06130d;
    border-radius: 8px;
    border: none;
    font-weight: bold;
    padding: 0.6rem 1.5rem;
}
.stButton > button:hover {
    background-color: #00ff9c;
    color: #000000;
}
div[data-testid="stTextInput"] input {
    background-color: #151f30;
    color: white;
    border: 1px solid #30435e;
    border-radius: 8px;
}
hr {
    border-color: #26364d;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.markdown("# 🛡️ PhishGuard")
st.markdown("### AI-Assisted Phishing URL Detection")
st.caption("Hybrid security analysis powered by heuristic rules and VirusTotal threat intelligence.")

st.divider()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.title("🛡️ PhishGuard")
    st.markdown("### Security Console")
    st.caption("Version 2.0")
    st.divider()
    st.markdown("**Detection Modules**")
    st.write("🟢 Heuristic Engine")
    st.write("🟢 VirusTotal API")
    st.write("🟢 Scan History")
    st.divider()
    st.caption("Educational cybersecurity project")

# ---------------- VIRUSTOTAL FUNCTION ----------------
def scan_virustotal(target_url):

    if not VT_API_KEY:
        return None, "API key missing. Please check your .env file."

    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.post(
            VT_URL,
            headers=headers,
            data={"url": target_url},
            timeout=30
        )

        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]

            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30
            )

            if result.status_code == 200:
                return result.json()["data"]["attributes"], None

            return None, f"Analysis retrieval failed: {result.status_code}"

        if response.status_code == 401:
            return None, "Invalid VirusTotal API key."

        if response.status_code == 429:
            return None, "VirusTotal rate limit reached. Try later."

        return None, f"VirusTotal returned error {response.status_code}."

    except requests.exceptions.Timeout:
        return None, "Request timed out."

    except requests.exceptions.RequestException:
        return None, "Could not connect to VirusTotal."

    except (KeyError, ValueError):
        return None, "Unexpected VirusTotal response."


# ---------------- HEURISTIC ENGINE ----------------
def analyze_url(target_url):

    score = 0
    indicators = []

    parsed = urlparse(target_url)
    domain = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    # IP address in hostname
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain):
        score += 40
        indicators.append("IP address used (+40)")

    # HTTPS check
    if parsed.scheme.lower() != "https":
        score += 10
        indicators.append("HTTPS not used (+10)")

    # Suspicious domain keywords
    keywords = [
        "login", "verify", "secure",
        "account", "update", "free",
        "bonus", "banking", "signin"
    ]

    if any(word in domain for word in keywords):
        score += 20
        indicators.append("Suspicious domain word (+20)")

    # Suspicious URL paths
    suspicious_paths = [
        "login", "verify", "password",
        "confirm", "signin", "update"
    ]

    if any(word in path for word in suspicious_paths):
        score += 10
        indicators.append("Suspicious URL path (+10)")

    score = min(score, 100)

    if score < 30:
        risk = "Low Risk"
    elif score < 60:
        risk = "Medium Risk"
    else:
        risk = "High Risk"

    return score, risk, indicators


# ---------------- URL INPUT ----------------
st.markdown("## 🔍 URL Threat Scanner")
st.write("Enter a website URL to perform a security assessment.")

url = st.text_input(
    "Target URL",
    placeholder="https://example.com"
)

scan_clicked = st.button("🚀 Scan URL", use_container_width=True)

# ---------------- SCAN EXECUTION ----------------
if scan_clicked:

    target = url.strip()

    if not target:
        st.error("Please enter a URL.")

    else:

        parsed = urlparse(target)

        if parsed.scheme.lower() not in ["http", "https"] or not parsed.hostname:
            st.error("Invalid URL. Enter a complete URL starting with http:// or https://")

        else:

            with st.spinner("Analyzing URL with PhishGuard engines..."):

                score, risk, indicators = analyze_url(target)
                vt_data, vt_error = scan_virustotal(target)

            st.divider()
            st.markdown("## 📊 Security Assessment")

            col1, col2, col3 = st.columns(3)

            col1.metric("Heuristic Score", f"{score}/100")
            col2.metric("Risk Classification", risk)

            if vt_data:
                stats = vt_data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                status = vt_data.get("status", "unknown")
            else:
                malicious = 0
                suspicious = 0
                status = "Unavailable"

            col3.metric("VT Malicious Detections", malicious)

            if risk == "High Risk":
                st.error("🚨 High Risk: This URL has multiple suspicious indicators.")
            elif risk == "Medium Risk":
                st.warning("⚠️ Medium Risk: Exercise caution with this URL.")
            else:
                st.success("🟢 Low Risk: No major heuristic indicators detected.")

            # Heuristic indicators
            st.markdown("### 🧠 Heuristic Analysis")

            if indicators:
                for item in indicators:
                    st.warning(item)
            else:
                st.success("No obvious suspicious heuristic indicators found.")

            # VirusTotal results
            st.markdown("### 🌐 VirusTotal Intelligence")

            if vt_data:

                vt_col1, vt_col2, vt_col3 = st.columns(3)

                vt_col1.metric("Malicious", malicious)
                vt_col2.metric("Suspicious", suspicious)
                vt_col3.metric("Analysis Status", status)

                if status != "completed":
                    st.info("VirusTotal analysis is still processing.")
                elif malicious > 0:
                    st.error("VirusTotal engines flagged this URL as malicious.")
                elif suspicious > 0:
                    st.warning("Some engines flagged this URL as suspicious.")
                else:
                    st.success("No malicious detections reported in this analysis.")

            else:
                st.warning(vt_error)

            # Save history
            record = {
                "url": target,
                "score": score,
                "risk": risk,
                "indicators": indicators,
                "vt_malicious": malicious,
                "vt_suspicious": suspicious,
                "vt_status": status,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            if os.path.exists(HISTORY_FILE):
                try:
                    with open(HISTORY_FILE, "r") as file:
                        history = json.load(file)
                except (json.JSONDecodeError, OSError):
                    history = []
            else:
                history = []

            history.append(record)

            with open(HISTORY_FILE, "w") as file:
                json.dump(history, file, indent=4)

            st.success("✅ Scan saved to history.")

# ---------------- SCAN HISTORY ----------------
st.divider()
st.markdown("## 📜 Scan History")

if os.path.exists(HISTORY_FILE):

    try:
        with open(HISTORY_FILE, "r") as file:
            history = json.load(file)

        if history:

            total_scans = len(history)
            high_risk_count = sum(
                1 for item in history
                if item.get("risk") == "High Risk"
            )

            metric1, metric2 = st.columns(2)
            metric1.metric("Total Scans", total_scans)
            metric2.metric("High Risk URLs", high_risk_count)

            for item in reversed(history):

                with st.expander(f"🌐 {item.get('url', 'Unknown URL')}"):

                    st.write("Heuristic Score:", item.get("score", "N/A"), "/100")
                    st.write("Risk Level:", item.get("risk", "N/A"))
                    st.write("VT Malicious:", item.get("vt_malicious", "N/A"))
                    st.write("VT Suspicious:", item.get("vt_suspicious", "N/A"))
                    st.caption("Scanned on: " + item.get("date", "Unknown"))

        else:
            st.info("No scan history available.")

    except (json.JSONDecodeError, OSError):
        st.error("Unable to read scan history.")

else:
    st.info("No scan history available.")

# ---------------- FOOTER ----------------
st.divider()
st.caption(
    "PhishGuard | Educational Security Tool | "
    "Heuristic scores are not probabilities. "
    "No scanner can guarantee a URL is safe."
)