import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import resample
import requests
import os
from dotenv import load_dotenv

# Load API key
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# Load and balance dataset
df = pd.read_csv("data.csv")
df["label"] = df["type"].str.lower()  # Ensure label is lowercase

# Balance all classes
classes = df["label"].unique()
class_counts = df["label"].value_counts()
max_samples = class_counts.max()

balanced_df = pd.concat([
    resample(df[df["label"] == label], replace=True, n_samples=max_samples, random_state=42)
    for label in classes
])

# Train ML model
vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))
X_vec = vectorizer.fit_transform(balanced_df["url"])
y = balanced_df["label"]
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_vec, y)

# ML classification
def classify_url_ml(url):
    vec = vectorizer.transform([url])
    prediction = clf.predict(vec)[0]
    proba = clf.predict_proba(vec).max()
    return f"{prediction.capitalize()} (Confidence: {proba:.2f})"

# VirusTotal classification (original working version)
def classify_url_virustotal(url):
    headers = {"x-apikey": API_KEY}
    res = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    if res.status_code == 200:
        analysis_id = res.json()["data"]["id"]
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if report.status_code == 200:
            stats = report.json()["data"]["attributes"]["stats"]
            if stats["malicious"] > 0:
                return "Malicious (VirusTotal)"
            return "Safe (VirusTotal)"
    return "VirusTotal lookup failed"
