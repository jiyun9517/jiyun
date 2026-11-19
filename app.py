import re
import socket
from urllib.parse import urlparse, urljoin
import joblib
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
import streamlit as st

st.set_page_config(page_title="QR 보안 판별 AI", page_icon="🛡️")

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "free", "gift", "confirm", "signin", "cmd"
]
SUSPICIOUS_TLDS = (
    ".xyz", ".tk", ".top", ".click", ".icu",
    ".ml", ".ga", ".cf", ".gq", ".pw", ".work"
)

URL_FEATURE_NAMES = [
    "url_length", "domain_length", "dot_count", "has_at",
    "hyphen_count", "suspicious_word_count", "is_ip", "is_https",
    "slash_count", "digit_count", "upper_ratio", "has_suspicious_tld",
]

HTML_FEATURE_NAMES = [
    "html_reachable", "hidden_iframe_count", "external_link_count",
    "form_count", "password_input_count", "script_count",
]

ALL_FEATURE_NAMES = URL_FEATURE_NAMES + HTML_FEATURE_NAMES

def extract_url_features(url):
    url = str(url).strip()
    url_for_parse = url if "://" in url or url.startswith("//") else "http://" + url
    parsed = urlparse(url_for_parse)
    domain = parsed.netloc.lower()

    url_length = len(url)
    domain_length = len(domain)
    dot_count = url.count(".")
    has_at = 1 if "@" in url else 0
    hyphen_count = url.count("-")
    lower_url = url.lower()
    suspicious_word_count = sum(1 for w in SUSPICIOUS_WORDS if w in lower_url)
    is_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$", domain) else 0
    is_https = 1 if lower_url.startswith("https://") else 0
    slash_count = url.count("/")
    digit_count = sum(1 for ch in url if ch.isdigit())
    upper_count = sum(1 for ch in url if ch.isupper())
    upper_ratio = (upper_count / url_length) if url_length > 0 else 0.0
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    return [
        url_length, domain_length, dot_count, has_at,
        hyphen_count, suspicious_word_count, is_ip, is_https,
        slash_count, digit_count, round(upper_ratio, 4), has_suspicious_tld,
    ]

def extract_html_features(url, timeout=3.0):
    url = str(url).strip()
    target_url = url if url.startswith(("http://", "https://")) else "http://" + url
    base_domain = urlparse(target_url).netloc.lower()
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")

        hidden_iframe_count = 0
        for iframe in soup.find_all("iframe"):
            style = (iframe.get("style") or "").replace(" ", "").lower()
            width = str(iframe.get("width") or "").strip()
            height = str(iframe.get("height") or "").strip()
            if (
                iframe.has_attr("hidden")
                or "display:none" in style
                or "visibility:hidden" in style
                or width in ["0", "0px"]
                or height in ["0", "0px"]
            ):
                hidden_iframe_count += 1

        external_link_count = 0
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full_href = urljoin(resp.url, href)
            link_domain = urlparse(full_href).netloc.lower()
            if link_domain and base_domain and link_domain != base_domain:
                external_link_count += 1

        form_count = len(soup.find_all("form"))
        password_input_count = len(soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)}))
        script_count = len(soup.find_all("script"))

        return [1, hidden_iframe_count, external_link_count, form_count, password_input_count, script_count]
    except Exception:
        return [0, 0, 0, 0, 0, 0]

def check_domain_exists(url):
    url = str(url).strip()
    target_url = url if url.startswith(("http://", "https://")) else "http://" + url
    domain = urlparse(target_url).netloc.split(":")[0].lower()
    if not domain:
        return False
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

@st.cache_resource
def load_model():
    return joblib.load("hybrid_url_html_model.pkl")

model = load_model()

st.title("🛡️ QR · URL 피싱 위험도 판별 AI")
st.write("검사할 링크(URL)를 입력하면 URL 패턴과 웹페이지 구조를 분석해 위험도를 알려줍니다.")

url_input = st.text_input("검사할 URL 입력", placeholder="https://example.com")

if st.button("위험도 검사하기"):
    target = url_input.strip()
    if not target:
        st.warning("URL을 먼저 입력해 주세요.")
    else:
        with st.spinner("분석 중..."):
            url_feats = extract_url_features(target)
            html_feats = extract_html_features(target, timeout=3.0)
            combined = url_feats + html_feats
            feat_df = pd.DataFrame([combined], columns=ALL_FEATURE_NAMES)

            is_html_ok = html_feats[0] == 1
            domain_alive = check_domain_exists(target)

            if (not is_html_ok) and (not domain_alive):
                st.info("⚠️ 존재하지 않거나 만료/삭제된 링크로 보입니다. (도메인 조회 실패)")
            else:
                risk_prob = float(model.predict_proba(feat_df)[0][1] * 100)
                html_bonus = 0.0
                reasons = []

                if html_feats[1] > 0:
                    html_bonus += 15.0
                    reasons.append(f"숨겨진 iframe {html_feats[1]}개 감지")
                if html_feats[4] > 0 and url_feats[7] == 0:
                    html_bonus += 15.0
                    reasons.append("HTTP 환경에서 비밀번호 입력칸 감지")
                if (not is_html_ok) and domain_alive:
                    reasons.append("웹페이지 응답 없음(접속 제한 또는 일시 오류 가능)")

                final_risk = min(100.0, risk_prob + html_bonus)
                if final_risk >= 40.0:
                    st.error(f"🚨 위험 (최종 위험도 {final_risk:.1f}% / 모델 {risk_prob:.1f}%)")
                else:
                    st.success(f"✅ 안전 (최종 위험도 {final_risk:.1f}% / 모델 {risk_prob:.1f}%)")

                if reasons:
                    st.write("**참고/탐지 근거:** " + ", ".join(reasons))
