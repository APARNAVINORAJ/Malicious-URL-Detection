"""
train_model.py
--------------
Trains a Gradient Boosting Classifier on malicious.csv and saves the model
to model.pkl.  Run once before starting the Flask app.

Usage:
    python train_model.py
"""

import os
import pickle
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, "malicious.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

# ---------------------------------------------------------------------------
# Feature columns — must match the order in feature.py getFeaturesList()
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport",
]
TARGET_COL = "class"


def load_data(path: str) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    X = df[FEATURE_COLS].values
    y = df[TARGET_COL].values
    return X, y


def train(X_train, y_train) -> GradientBoostingClassifier:
    clf = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
    )
    clf.fit(X_train, y_train)
    return clf


def evaluate(clf, X_test, y_test) -> None:
    y_pred = clf.predict(X_test)
    print("\n=== Evaluation Results ===")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Malicious (-1)", "Safe (1)"]))
    print("Confusion Matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))


def main():
    print(f"Loading data from: {DATA_PATH}")
    X, y = load_data(DATA_PATH)
    print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Class distribution: Safe={int((y==1).sum())}  Malicious={int((y==-1).sum())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain set: {len(X_train)}  |  Test set: {len(X_test)}")

    print("\nTraining Gradient Boosting Classifier ...")
    clf = train(X_train, y_train)

    evaluate(clf, X_test, y_test)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
