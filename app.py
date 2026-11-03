from urllib.parse import urlparse, parse_qs
import ipaddress


def check_url(url):

    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "banking",
        "password",
        "account"
    ]

    url = url.strip()

    # Parse URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

    except ValueError:
        return "Invalid URL", 0, ["Malformed URL"]

    # Validate URL
    if parsed_url.scheme not in ("http", "https") or not domain:
        return "Invalid URL", 0, ["Invalid URL format"]

    domain = domain.lower()

    # 1. Check IP address
    try:
        ipaddress.ip_address(domain)
        score += 40
        reasons.append("IP address used (+40)")
    except ValueError:
        pass

    # 2. Check @ symbol
    if "@" in parsed_url.netloc:
        score += 30
        reasons.append("@ symbol found (+30)")

    # 3. Check suspicious words in domain
    if any(word in domain for word in suspicious_words):
        score += 20
        reasons.append("Suspicious domain word (+20)")

    # 4. Check URL length
    if len(url) >= 75:
        score += 10
        reasons.append("Unusually long URL (+10)")

    # 5. Check HTTP
    if parsed_url.scheme == "http":
        score += 10
        reasons.append("HTTPS not used (+10)")

    # 6. Check suspicious subdomains
    if len(domain.split(".")) >= 5:
        score += 10
        reasons.append("Too many subdomains (+10)")

    # 7. Check Punycode domain
    if "xn--" in domain:
        score += 10
        reasons.append("Punycode domain detected (+10)")

    # 8. Check suspicious query parameters
    query_params = parse_qs(parsed_url.query)

    risky_params = [
        "redirect",
        "return",
        "next",
        "continue"
    ]

    if any(param in query_params for param in risky_params):
        score += 10
        reasons.append("Suspicious query parameter (+10)")

    # 9. Check suspicious URL path
    suspicious_path_words = [
        "login",
        "verify",
        "password",
        "account"
    ]

    if any(word in parsed_url.path.lower()
           for word in suspicious_path_words):
        score += 10
        reasons.append("Suspicious URL path (+10)")

    # Maximum score
    score = min(score, 100)

    # Risk classification
    if score >= 60:
        risk = "High Risk"
    elif score >= 30:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    return risk, score, reasons


# Main program
if __name__ == "__main__":
    url = input("Enter a URL: ")

    risk, score, reasons = check_url(url)

    print("\n--- PhishGuard Scan Report ---")
    print("Risk Level:", risk)
    print("Risk Score:", str(score) + "/100")

    print("\nDetected Indicators:")

    if reasons:
        for reason in reasons:
            print("-", reason)
    else:
        print("No obvious suspicious indicators found.")