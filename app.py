import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Phishing URL Detector")
st.write("Check a URL for common phishing indicators.")

def analyze_url(url):
    url = url.strip()
    if not url:
        return 0, ["Please enter a URL."]

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    score = 0
    reasons = []

    if not host or "." not in host:
        return 100, ["Invalid or suspicious hostname."]

    if parsed.scheme != "https":
        score += 1
        reasons.append("URL does not use HTTPS")

    if "@" in url:
        score += 2
        reasons.append("Contains @ symbol")

    try:
        ipaddress.ip_address(host)
        score += 3
        reasons.append("Uses an IP address instead of a domain")
    except ValueError:
        pass

    if len(url) > 75:
        score += 1
        reasons.append("Unusually long URL")

    if host.count(".") >= 3:
        score += 1
        reasons.append("Contains multiple subdomains")

    if "-" in host:
        score += 1
        reasons.append("Domain contains hyphens")

    if re.search(
        r"login|verify|account|secure|update|"
        r"password|signin|wallet",
        url,
        re.I
    ):
        score += 1
        reasons.append("Contains words commonly used in phishing URLs")

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("Contains an internationalized domain label")

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "ow.ly"
    ]
    if any(host == d or host.endswith("." + d)
           for d in shorteners):
        score += 2
        reasons.append("Uses a URL shortening service")

    return score, reasons


url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com"
)

if st.button("Analyze URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        score, reasons = analyze_url(url)

        st.subheader("Analysis Result")
        st.write(f"Risk indicator score: {score}/12+")

        if score >= 4:
            st.error("⚠️ Suspicious URL indicators detected")
        elif score >= 2:
            st.warning("⚠️ Some suspicious indicators detected")
        else:
            st.success("No major indicators detected by these checks")

        if reasons:
            st.write("Indicators found:")
            for reason in reasons:
                st.write(f"- {reason}")
        else:
            st.write("No indicators detected.")

        st.caption(
            "This is a basic rule-based demo, not a trained ML model. "
            "A low score does not guarantee that a URL is safe."
        )
