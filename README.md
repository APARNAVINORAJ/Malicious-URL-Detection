# Malicious URL Detection

A machine-learning web application that classifies URLs as **safe** or **malicious/phishing** by analysing 30 structural, content, and domain-based features extracted in real time.

---

## Features

| Category | Examples |
|---|---|
| URL structure | IP usage, length, shortener services, `@` symbol, `//` redirect |
| Domain properties | HTTPS, prefix/suffix hyphens, sub-domain count, registration length |
| Page content | Favicon origin, form actions, script/link tags, iframes, pop-ups |
| External signals | WHOIS age, DNS records, website traffic rank, Google index |

The model is a **Gradient Boosting Classifier** (scikit-learn) trained on a labelled dataset of ~10 000 URLs.

---

## Project Structure

```
Malicious-URL-Detection/
├── app.py                  # Flask web application & REST API
├── feature.py              # 30-feature extractor (FeatureExtraction class)
├── train_model.py          # Model training script → produces model.pkl
├── malicious.csv           # Labelled dataset (1 = safe, -1 = malicious)
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Jinja2 web interface template
└── static/
    ├── styles.css          # Custom CSS
    └── wallpaper.jpg       # Background image
```

---

## Quick Start

### 1. Create a virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the model

```bash
python train_model.py
```

This reads `malicious.csv`, trains a Gradient Boosting Classifier, prints evaluation metrics, and saves `model.pkl`.

### 4. Run the app

```bash
python app.py
```

Open your browser at **http://localhost:5000**.

---

## REST API

In addition to the web UI, a JSON endpoint is available for programmatic use.

**Endpoint:** `POST /api/check`

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "is_safe": true,
  "safe_probability": 0.93,
  "safe_pct": 93.0
}
```

**Example with curl:**
```bash
curl -s -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

---

## Model Performance

Typical results on a 20 % hold-out test set:

| Metric | Score |
|---|---|
| Accuracy | ~97 % |
| Precision (malicious) | ~96 % |
| Recall (malicious) | ~97 % |
| F1-score (malicious) | ~97 % |

*(Run `python train_model.py` to see exact metrics for your data.)*

---

## Tech Stack

- **Backend:** Python 3.10+, Flask 2.x, scikit-learn, pandas, NumPy
- **Feature extraction:** requests, BeautifulSoup4, python-whois, googlesearch-python
- **Frontend:** Bootstrap 4, Vanilla JS
- **Production server:** Waitress (Windows) / Gunicorn (Linux/macOS)

---

## Production Deployment (optional)

**Windows (Waitress):**
```bash
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

**Linux / macOS (Gunicorn):**
```bash
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```
