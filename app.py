import ipaddress
import logging
import os
import re

import numpy as np
import pickle
import warnings
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from urllib.parse import urlparse

warnings.filterwarnings('ignore')
from feature import FeatureExtraction
from database import init_db, save_scan, get_recent_scans, get_stats
from threat_intel import check_virustotal

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    logger.info("Model loaded from %s", MODEL_PATH)
except FileNotFoundError:
    logger.error("model.pkl not found. Run `python train_model.py`.")
    model = None

# ---------------------------------------------------------------------------
# SHAP explainer (optional — gracefully skipped if shap not installed)
# ---------------------------------------------------------------------------
shap_explainer = None
if model is not None:
    try:
        import shap
        shap_explainer = shap.TreeExplainer(model)
        logger.info("SHAP explainer ready")
    except Exception as _e:
        logger.warning("SHAP unavailable: %s", _e)


def _to_python(obj):
    """Recursively convert numpy types to native Python types for JSON serialisation."""
    import numpy as np
    if isinstance(obj, dict):
        return {k: _to_python(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_python(i) for i in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    return obj


def compute_shap(features_array, features_dict):
    if shap_explainer is None:
        return None
    try:
        sv = shap_explainer.shap_values(features_array)
        # GBC binary: sv may be ndarray (n,30) or list of two arrays
        if isinstance(sv, list):
            values = sv[1][0] if len(sv) > 1 else sv[0][0]
        else:
            values = sv[0]
        names  = list(features_dict.keys())
        pairs  = sorted(zip(names, values.tolist()), key=lambda x: abs(x[1]), reverse=True)
        return [
            {"feature": n, "value": round(v, 4),
             "direction": "safe" if v > 0 else "malicious"}
            for n, v in pairs[:8]
        ]
    except Exception as exc:
        logger.warning("SHAP computation failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# App + DB + SocketIO
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "urlguard-dev-secret")
init_db()

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Rule-based pre-filter
# ---------------------------------------------------------------------------
_SHORTENER_RE = re.compile(
    r'bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|shorte\.st|'
    r'adf\.ly|bitly\.com|tiny\.cc|is\.gd|clck\.ru|cutt\.ly',
    re.IGNORECASE
)


def _rule_based_check(url: str):
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        return {"url": url, "is_safe": False, "safe_probability": 0.0,
                "safe_pct": 0.0,
                "rule_triggered": "Raw IP address used instead of domain name",
                "features": None, "shap": None, "threat_intel": None}
    except ValueError:
        pass
    if "@" in url:
        return {"url": url, "is_safe": False, "safe_probability": 0.05,
                "safe_pct": 5.0,
                "rule_triggered": "@ symbol detected — credential-hiding phishing pattern",
                "features": None, "shap": None, "threat_intel": None}
    if _SHORTENER_RE.search(url):
        return {"url": url, "is_safe": False, "safe_probability": 0.1,
                "safe_pct": 10.0,
                "rule_triggered": "URL shortener detected — destination unknown",
                "features": None, "shap": None, "threat_intel": None}
    return None


# ---------------------------------------------------------------------------
# Background scan (runs in thread, emits Socket.IO events)
# ---------------------------------------------------------------------------
def run_scan_background(sid, url):
    def progress(pct, msg):
        socketio.emit("scan_progress", {"pct": pct, "msg": msg}, to=sid)

    try:
        progress(10, "Checking security rules...")
        rule = _rule_based_check(url)
        if rule:
            threat = check_virustotal(url)
            rule["threat_intel"] = threat
            save_scan(url=url, is_safe=rule["is_safe"],
                      safe_probability=rule["safe_probability"],
                      rule_triggered=rule["rule_triggered"])
            progress(100, "Analysis complete")
            socketio.emit("scan_result", rule, to=sid)
            return

        progress(25, "Fetching page content...")
        obj = FeatureExtraction(url)

        progress(55, "Extracting 30 features...")
        features_list = obj.getFeaturesList()
        features_dict = obj.getFeaturesDict()

        progress(70, "Checking threat intelligence...")
        threat = check_virustotal(url)

        progress(83, "Running ML model...")
        arr        = np.array(features_list).reshape(1, 30)
        pred_class = model.predict(arr)[0]
        proba      = model.predict_proba(arr)[0]
        safe_prob  = float(proba[1]) if pred_class == 1 else float(proba[0])
        is_safe    = pred_class == 1

        progress(93, "Computing explanation (SHAP)...")
        shap_data = compute_shap(arr, features_dict)

        result = _to_python({
            "url":              url,
            "is_safe":          is_safe,
            "safe_probability": safe_prob,
            "safe_pct":         round(safe_prob * 100, 2),
            "rule_triggered":   None,
            "features":         features_dict,
            "shap":             shap_data,
            "threat_intel":     threat,
        })

        save_scan(url=url, is_safe=is_safe, safe_probability=safe_prob,
                  features=features_dict)

        progress(100, "Analysis complete!")
        socketio.emit("scan_result", result, to=sid)

    except Exception as exc:
        logger.exception("Scan error for %s", url)
        socketio.emit("scan_error", {"message": str(exc)}, to=sid)


# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------
@socketio.on("scan_url")
def handle_scan(data):
    sid = request.sid
    url = (data.get("url") or "").strip()
    if not url:
        emit("scan_error", {"message": "Please enter a URL."})
        return
    if model is None:
        emit("scan_error", {"message": "Model not loaded. Run train_model.py first."})
        return
    logger.info("WS scan: %s", url)
    socketio.start_background_task(run_scan_background, sid, url)


# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/bulk", methods=["GET", "POST"])
def bulk():
    if request.method == "POST":
        raw  = request.form.get("urls", "")
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            return render_template("bulk.html", error="Please enter at least one URL.")
        results = []
        for url in urls[:50]:
            try:
                rule = _rule_based_check(url)
                if rule:
                    results.append(rule)
                    save_scan(url=url, is_safe=rule["is_safe"],
                              safe_probability=rule["safe_probability"],
                              rule_triggered=rule["rule_triggered"])
                    continue
                obj           = FeatureExtraction(url)
                features_list = obj.getFeaturesList()
                features_dict = obj.getFeaturesDict()
                arr           = np.array(features_list).reshape(1, 30)
                pred_class    = model.predict(arr)[0]
                proba         = model.predict_proba(arr)[0]
                safe_prob     = float(proba[1]) if pred_class == 1 else float(proba[0])
                is_safe       = pred_class == 1
                r = {"url": url, "is_safe": is_safe,
                     "safe_probability": safe_prob,
                     "safe_pct": round(safe_prob * 100, 2)}
                results.append(r)
                save_scan(url=url, is_safe=is_safe, safe_probability=safe_prob,
                          features=features_dict)
            except Exception as exc:
                results.append({"url": url, "is_safe": None,
                                 "safe_pct": None, "error": str(exc)})
        return render_template("bulk.html", results=results)
    return render_template("bulk.html")


@app.route("/history")
def history():
    return render_template("history.html", scans=get_recent_scans(100))


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", stats=get_stats())


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    if model is None:
        return jsonify({"error": "Model not loaded."}), 503
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must contain 'url'."}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL must not be empty."}), 400
    try:
        rule = _rule_based_check(url)
        if rule:
            save_scan(url=url, is_safe=rule["is_safe"],
                      safe_probability=rule["safe_probability"],
                      rule_triggered=rule["rule_triggered"])
            return jsonify(rule)
        obj           = FeatureExtraction(url)
        features_list = obj.getFeaturesList()
        features_dict = obj.getFeaturesDict()
        arr           = np.array(features_list).reshape(1, 30)
        pred_class    = model.predict(arr)[0]
        proba         = model.predict_proba(arr)[0]
        safe_prob     = float(proba[1]) if pred_class == 1 else float(proba[0])
        is_safe       = pred_class == 1
        result = {"url": url, "is_safe": is_safe,
                  "safe_probability": safe_prob,
                  "safe_pct": round(safe_prob * 100, 2),
                  "features": features_dict}
        save_scan(url=url, is_safe=is_safe, safe_probability=safe_prob,
                  features=features_dict)
        return jsonify(result)
    except Exception as exc:
        logger.exception("API error for %s", url)
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
