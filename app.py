import streamlit as st
from detection import classify_url_ml, classify_url_virustotal

st.set_page_config(page_title="🛡️ URL Security Scanner", layout="centered")
st.title("🔐 Malicious URL & File Hash Detector")

st.markdown("""
<style>
div.stButton > button {
    background-color: #4CAF50;
    color: white;
    border-radius: 10px;
    padding: 0.5em 1em;
}
</style>
""", unsafe_allow_html=True)

url = st.text_input("🔎 Enter a URL to analyze")

method = st.radio("Choose detection method:", ["Machine Learning", "VirusTotal"])

if st.button("Analyze URL"):
    if url:
        with st.spinner("Analyzing..."):
            result = classify_url_ml(url) if method == "Machine Learning" else classify_url_virustotal(url)
            st.success(f"🧠 Prediction: {result}")
    else:
        st.warning("❗ Please enter a valid URL.")

st.write("⚠️ Note: VirusTotal focuses on malware & phishing. It may not detect defacement or rare threats.")
