# 🛡️ Malicious URL & File Hash Detector

A simple Streamlit app that detects whether a URL is **malicious or safe** using:
- A trained **Machine Learning model** based on a labeled dataset.
- The **VirusTotal API** for real-time threat intelligence.

---
<img width="1373" alt="Screenshot 2025-05-25 at 8 05 38 PM" src="https://github.com/user-attachments/assets/a0411c67-8881-4ee2-b672-e6ca0ef25297" />

## 🔍 Features

- 🔐 **Machine Learning Detection**: Uses character-level TF-IDF and Random Forest to classify URLs.
- 🧪 **VirusTotal Lookup**: Checks URL reputation using VirusTotal’s public API.
- 💡 Real-time feedback with confidence scores.
- ⚠️ Clear disclaimer: VirusTotal may not detect defacement or uncommon threats.

---

## 🛠️ Setup Instructions

Install Dependencies
I recommend using a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Prepare Environment
Create a .env file in the root directory and add your VirusTotal API key:
```
VT_API_KEY=your_virustotal_api_key
```

Dataset
Ensure data.csv is available in the root folder. The file should have:

URL column: the URL string.
Label column: safe, malicious, etc.
You can also preprocess this into data.numbers or your preferred format.

🚀 Running the App
```
streamlit run app.py
```

🧠 Model Details

Vectorizer: TfidfVectorizer with char_wb analyzer, n-grams (3,5)
Classifier: RandomForestClassifier
Balancing: Resampling to equalize class distribution
📁 Project Structure
```
.
├── app.py              # Streamlit front-end
├── detection.py        # Model training & detection logic
├── data.csv            # URL dataset (not uploaded if in .gitignore)
├── .env                # VirusTotal API key (excluded from git)
├── .gitignore
└── README.md
```

⚠️ Disclaimer

This project is for educational and research purposes only. The ML model is based on a static dataset and may not generalize well to evolving threats. VirusTotal may miss certain categories like defacement.
