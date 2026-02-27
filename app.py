import streamlit as st
import pickle
import numpy as np
import re
import math
import cv2
from PIL import Image
from urllib.parse import urlparse

# ------------------------
# PAGE CONFIG
# ------------------------
st.set_page_config(page_title="Phishing Detection System", page_icon="🔐")

# ------------------------
# LOAD MODELS
# ------------------------
text_model = pickle.load(open("text_fraud_model.pkl", "rb"))
vectorizer = pickle.load(open("text_vectorizer.pkl", "rb"))
url_model = pickle.load(open("url_fraud_model.pkl", "rb"))

# ------------------------
# URL FEATURE FUNCTIONS
# ------------------------
def calculate_entropy(string):
    if len(string) == 0:
        return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log2(p) for p in prob])
    return entropy

def extract_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    url_length = len(url)
    has_ip_address = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 0
    dot_count = url.count(".")
    https_flag = 1 if url.startswith("https") else 0
    url_entropy = calculate_entropy(url)
    token_count = len(re.split(r"[./?=&-]", url))
    subdomain_count = domain.count(".") - 1 if domain.count(".") > 0 else 0
    query_param_count = query.count("&") + 1 if query else 0
    tld = domain.split(".")[-1] if "." in domain else ""
    tld_length = len(tld)
    path_length = len(path)
    has_hyphen_in_domain = 1 if "-" in domain else 0
    number_of_digits = sum(c.isdigit() for c in url)
    tld_popularity = 1
    suspicious_file_extension = 1 if path.endswith((".exe", ".zip", ".rar", ".scr")) else 0
    domain_name_length = len(domain)
    percentage_numeric_chars = (number_of_digits / url_length) if url_length > 0 else 0

    return np.array([[url_length, has_ip_address, dot_count, https_flag, url_entropy,
                      token_count, subdomain_count, query_param_count, tld_length,
                      path_length, has_hyphen_in_domain, number_of_digits, tld_popularity,
                      suspicious_file_extension, domain_name_length, percentage_numeric_chars]])

# ------------------------
# TITLE
# ------------------------
st.title("🔐 Advanced Phishing Detection System")
st.write("Detect phishing in Email, SMS, URL and QR Codes using Hybrid AI Model")

# ------------------------
# INPUT TYPE SELECTION
# ------------------------
option = st.selectbox(
    "Select Input Type",
    ["Email", "SMS", "URL", "QR Code", "Live QR Camera"]
)

# ============================================================
# EMAIL / SMS SECTION
# ============================================================
if option in ["Email", "SMS"]:
    user_text = st.text_area(f"Enter {option} Content")

    if st.button("Check Now"):
        if user_text.strip() == "":
            st.warning("Please enter some text.")
        else:
            text_vector = vectorizer.transform([user_text])
            text_pred = text_model.predict(text_vector)[0]

            if text_pred == 1:
                st.error("⚠️ PHISHING / SPAM DETECTED")
            else:
                st.success("✅ SAFE MESSAGE")

# ============================================================
# URL SECTION
# ============================================================
elif option == "URL":
    user_url = st.text_input("Enter URL")

    if st.button("Check URL"):
        if user_url.strip() == "":
            st.warning("Please enter a URL.")
        else:
            url_features = extract_url_features(user_url)
            url_pred = url_model.predict(url_features)[0]

            if url_pred == 1:
                st.error("⚠️ PHISHING URL DETECTED")
            else:
                st.success("✅ SAFE URL")

# ============================================================
# QR CODE FROM FILE
# ============================================================
elif option == "QR Code":
    uploaded_file = st.file_uploader("Upload QR Code Image", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded QR Code", use_column_width=True)

        img = np.array(image)
        img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)

        if data:
            st.success(f"QR Content Detected: {data}")

            if "http" in data:
                url_features = extract_url_features(data)
                url_pred = url_model.predict(url_features)[0]

                if url_pred == 1:
                    st.error("⚠️ PHISHING URL DETECTED")
                else:
                    st.success("✅ SAFE URL")
            else:
                st.info("QR contains text data.")
        else:
            st.error("❌ No QR Code detected in image.")

# ============================================================
# LIVE CAMERA QR SCANNER
# ============================================================
elif option == "Live QR Camera":
    st.info("Click Start to scan QR codes in real-time using your camera.")
    start_camera = st.button("Start Camera")

    if start_camera:
        cap = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()

        stframe = st.empty()

        while True:
            ret, frame = cap.read()
            if not ret:
                st.error("Failed to access camera.")
                break

            data, bbox, _ = detector.detectAndDecode(frame)

            display_frame = frame.copy()

            if bbox is not None:
                n_lines = len(bbox)
                for i in range(n_lines):
                    pt1 = tuple(bbox[i][0])
                    pt2 = tuple(bbox[(i + 1) % n_lines][0])
                    cv2.line(display_frame, pt1, pt2, color=(0, 255, 0), thickness=2)

            if data:
                cv2.putText(display_frame, f"{data}", (50, 50),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)

                # URL check if URL present
                if "http" in data:
                    url_features = extract_url_features(data)
                    url_pred = url_model.predict(url_features)[0]

                    if url_pred == 1:
                        st.warning("⚠️ PHISHING URL DETECTED")
                    else:
                        st.success("✅ SAFE URL")
                else:
                    st.info("QR contains text data.")

            stframe.image(cv2.cvtColor(display_frame, cv2.COLOR_BGR2RGB), channels="RGB")

        cap.release()