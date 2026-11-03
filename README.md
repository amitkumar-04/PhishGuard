🛡️ PhishGuard – AI-Assisted Phishing URL Detector

PhishGuard is a Python-based web application designed to detect potentially malicious and phishing URLs using heuristic analysis and VirusTotal threat intelligence.

🚀 Features

- URL scanning and phishing detection
- Heuristic-based risk analysis
- Risk score (0–100)
- Low, Medium, and High risk classification
- VirusTotal threat intelligence integration
- Detection of suspicious URL patterns
- Scan history tracking
- Interactive Streamlit dashboard

🛠️ Technologies Used

- Python
- Streamlit
- VirusTotal API
- Requests
- Python-dotenv

📥 Installation

1. Clone the repository:
   
   git clone https://github.com/amitkumar-04/PhishGuard.git

2. Navigate to the project folder:
   
   cd PhishGuard

3. Install dependencies:
   
   pip install streamlit requests python-dotenv

4. Configure your VirusTotal API key in a ".env" file:
   
   VT_API_KEY=your_api_key_here

▶️ Run the Application

python -m streamlit run dashboard.py

⚠️ Disclaimer

PhishGuard is an educational cybersecurity project. Its heuristic scores are not probabilities, and no scanner can guarantee that a URL is safe.

👨‍💻 Author

Amit Kumar

🚀 Live Demo

Try PhishGuard here: https://phishguard-e2gsckx36kwlq2nzpwv4ne.streamlit.app/


💻 Source Code: https://github.com/amitkumar-04/PhishGuard
