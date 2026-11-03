import streamlit as st
import json
import os
import re
import requests
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishGuard")
st.subheader("Phishing URL Detection System")

st.write("Enter a URL below to analyze its security.")

url = st.text_input(
    "Enter Website URL",
    placeholder="https://example.com"
)


# ---------------------------------
# VirusTotal URL Analysis Function
# ---------------------------------
def scan_virustotal(url):

    if not VT_API_KEY:
        return None, "API key missing. Check your .env file."

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.post(
            VT_URL,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            analysis_id = data["data"]["id"]

            # Fetch analysis results
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30
            )

            if result.status_code == 200:
                analysis = result.json()
                attributes = analysis["data"]["attributes"]

                return attributes, None

            return None, f"Analysis request failed ({result.status_code})."

        elif response.status_code == 401:
            return None, "Invalid VirusTotal API key."

        elif response.status_code == 429:
            return None, "VirusTotal rate limit reached. Try again later."

        else:
            return None, f"VirusTotal error: {response.status_code}"

    except requests.exceptions.Timeout:
        return None, "VirusTotal request timed out."

    except requests.exceptions.RequestException:
        return None, "Could not connect to VirusTotal."

    except (KeyError, ValueError):
        return None, "Unexpected response from VirusTotal."


# ---------------------------------
# PhishGuard Heuristic Scanner
# ---------------------------------
if st.button("Scan URL"):

    if url.strip():

        # Basic URL validation
        parsed = urlparse(url.strip())

        if not parsed.scheme or not parsed.netloc:
            st.error("Enter a valid URL including https:// or http://")

        else:

            score = 0
            indicators = []

            domain = parsed.hostname or ""
            domain = domain.lower()
            path = parsed.path.lower()

            # 1. IP Address Detection
            ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

            if re.match(ip_pattern, domain):
                score += 40
                indicators.append("IP address used (+40)")

            # 2. HTTPS Detection
            if parsed.scheme.lower() != "https":
                score += 10
                indicators.append("HTTPS not used (+10)")

            # 3. Suspicious Domain Keywords
            keywords = [
                "login", "verify", "secure",
                "account", "update", "free",
                "bonus", "banking", "signin"
            ]

            if any(word in domain for word in keywords):
                score += 20
                indicators.append(
                    "Suspicious domain word (+20)"
                )

            # 4. Suspicious URL Path
            suspicious_paths = [
                "login", "verify", "password",
                "confirm", "signin", "update"
            ]

            if any(word in path for word in suspicious_paths):
                score += 10
                indicators.append(
                    "Suspicious URL path (+10)"
                )

            # Limit score to 100
            score = min(score, 100)

            # Risk Level
            if score < 30:
                risk = "Low Risk"
            elif score < 60:
                risk = "Medium Risk"
            else:
                risk = "High Risk"

            # ---------------------------------
            # Display Local Results
            # ---------------------------------
            st.divider()
            st.header("🛡️ PhishGuard Scan Report")

            st.metric("Heuristic Risk Score", f"{score}/100")

            if risk == "Low Risk":
                st.success(f"Risk Level: {risk}")
            elif risk == "Medium Risk":
                st.warning(f"Risk Level: {risk}")
            else:
                st.error(f"Risk Level: {risk}")

            st.subheader("Detected Indicators")

            if indicators:
                for item in indicators:
                    st.warning(item)
            else:
                st.success(
                    "No obvious suspicious indicators found."
                )

            # ---------------------------------
            # VirusTotal Results
            # ---------------------------------
            st.divider()
            st.header("🌐 VirusTotal Threat Intelligence")

            with st.spinner("Checking VirusTotal..."):
                vt_data, vt_error = scan_virustotal(url.strip())

            vt_malicious = 0
            vt_suspicious = 0
            vt_status = "Unavailable"

            if vt_data:

                stats = vt_data.get("stats", {})

                vt_malicious = stats.get("malicious", 0)
                vt_suspicious = stats.get("suspicious", 0)

                vt_status = vt_data.get("status", "unknown")

                st.write("Analysis Status:", vt_status)

                col1, col2 = st.columns(2)

                col1.metric("Malicious Detections", vt_malicious)
                col2.metric("Suspicious Detections", vt_suspicious)

                if vt_status != "completed":
                    st.info(
                        "VirusTotal analysis is still processing. "
                        "Results may not be complete yet."
                    )

                elif vt_malicious > 0:
                    st.error(
                        "⚠️ VirusTotal detected malicious engines!"
                    )

                elif vt_suspicious > 0:
                    st.warning(
                        "Some engines marked this URL as suspicious."
                    )

                else:
                    st.success(
                        "No malicious detections reported "
                        "in this analysis."
                    )

            else:
                st.warning(vt_error)

            # ---------------------------------
            # Save Scan History
            # ---------------------------------
            history_file = "scan_history.json"

            record = {
                "url": url.strip(),
                "score": score,
                "risk": risk,
                "indicators": indicators,
                "vt_malicious": vt_malicious,
                "vt_suspicious": vt_suspicious,
                "vt_status": vt_status,
                "date": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            }

            if os.path.exists(history_file):
                try:
                    with open(history_file, "r") as file:
                        history = json.load(file)
                except (json.JSONDecodeError, OSError):
                    history = []
            else:
                history = []

            history.append(record)

            with open(history_file, "w") as file:
                json.dump(history, file, indent=4)

            st.success("Scan saved to history!")

    else:
        st.error("Please enter a URL.")


# ---------------------------------
# Scan History
# ---------------------------------
st.divider()
st.header("📜 Scan History")

if os.path.exists("scan_history.json"):

    try:
        with open("scan_history.json", "r") as file:
            history = json.load(file)

        for item in reversed(history):

            st.write("🌐 URL:", item["url"])

            if "score" in item:
                st.write(
                    "Heuristic Risk Score:",
                    item["score"],
                    "/100"
                )
                st.write("Risk Level:", item["risk"])

            if "vt_malicious" in item:
                st.write(
                    "VirusTotal Malicious:",
                    item["vt_malicious"]
                )
                st.write(
                    "VirusTotal Suspicious:",
                    item["vt_suspicious"]
                )

            st.caption("Date: " + item["date"])
            st.divider()

    except (json.JSONDecodeError, OSError):
        st.error("Could not read scan history.")

else:
    st.info("No scan history available.")


# ---------------------------------
# Footer
# ---------------------------------
st.caption(
    "PhishGuard uses heuristic analysis and VirusTotal "
    "threat intelligence. Neither guarantees a URL is safe."
)