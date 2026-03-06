import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import json
import os

# ─── FEATURE EXTRACTION ───────────────────────────────────────────────────────

FEATURE_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.INTERNET",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
]

FEATURE_MALWARE_PATTERNS = [
    "Device Fingerprinting",
    "Overlay Attack",
    "Accessibility Abuse",
    "SMS Stealer",
    "Screen Recording",
    "Emulator Detection",
    "Dynamic Code Loading",
    "Silent Install",
]

FEATURE_TAINT_PATHS = [
    "SMS to Network Exfiltration",
    "Location to Network",
    "Credentials to Network",
    "Credentials to Log",
    "Device ID to Network",
    "Contacts to Network",
    "Microphone to File",
    "Camera to Network",
]


def extract_features(scan_results):
    """Convert scan results into a numeric feature vector for ML."""
    features = []

    # Permission features (binary: 0 or 1)
    all_perms = scan_results.get("all_permissions", [])
    for perm in FEATURE_PERMISSIONS:
        features.append(1 if perm in all_perms else 0)

    # Malware pattern features (binary)
    malware_names = [m["name"] for m in scan_results.get("findings", {}).get("malware", [])]
    for pattern in FEATURE_MALWARE_PATTERNS:
        features.append(1 if pattern in malware_names else 0)

    # Taint path features (binary)
    taint_names = [t["name"] for t in scan_results.get("findings", {}).get("taint", [])]
    for path in FEATURE_TAINT_PATHS:
        features.append(1 if path in taint_names else 0)

    # Numeric features
    findings = scan_results.get("findings", {})
    counts = scan_results.get("counts", {})
    features.append(len(all_perms))                                      # total permissions
    features.append(len(findings.get("dangerous_combos", [])))           # combo count
    features.append(len(findings.get("secrets", [])))                    # secrets count
    features.append(len(findings.get("taint", [])))                      # taint paths
    features.append(len(findings.get("malware", [])))                    # malware indicators
    features.append(len(findings.get("owasp", [])))                      # owasp findings
    features.append(counts.get("CRITICAL", 0))                          # critical count
    features.append(counts.get("HIGH", 0))                              # high count
    features.append(scan_results.get("risk_score", 0))                  # risk score

    return features


# ─── TRAINING DATA ────────────────────────────────────────────────────────────
# Each sample: (permissions, malware_patterns, taint_paths, numeric_features, label)
# Labels: CLEAN, BANKING_TROJAN, SPYWARE, RANSOMWARE, ADWARE, DROPPER

def build_training_data():
    """
    Synthetic training data based on real malware family characteristics.
    Each row is a feature vector matching extract_features() output.
    """
    X = []
    y = []

    # ── CLEAN APPS (low permissions, no malware patterns) ──
    for _ in range(60):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        # Random safe permissions
        for i in [4]:  # INTERNET only
            row[i] = 1
        row += [1, 0, 0, 0, 0, 0, 0, 1, np.random.randint(0, 15)]
        X.append(row)
        y.append("CLEAN")

    # Slightly more permissions but still clean
    for _ in range(40):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [4, 5, 9]:  # INTERNET, CAMERA, READ_STORAGE
            row[i] = 1
        row += [3, 0, 1, 0, 0, 1, 0, 2, np.random.randint(10, 30)]
        X.append(row)
        y.append("CLEAN")

    # ── BANKING TROJANS (SMS + INTERNET + overlay + accessibility) ──
    for _ in range(50):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [0, 1, 2, 4, 12]:  # SMS permissions + INTERNET + SYSTEM_ALERT
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [1, 2, 3]:  # Overlay, Accessibility, SMS Stealer
            row[perm_offset + i] = 1
        taint_offset = perm_offset + len(FEATURE_MALWARE_PATTERNS)
        for i in [0, 2]:  # SMS to Network, Credentials to Network
            row[taint_offset + i] = 1
        row += [8, 2, 3, 2, 3, 2, 4, 3, np.random.randint(75, 100)]
        X.append(row)
        y.append("BANKING_TROJAN")

    for _ in range(30):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [0, 2, 4, 11, 12]:  # RECEIVE_SMS + INTERNET + BOOT + ALERT
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [3, 1]:  # SMS Stealer + Overlay
            row[perm_offset + i] = 1
        taint_offset = perm_offset + len(FEATURE_MALWARE_PATTERNS)
        row[taint_offset + 0] = 1  # SMS to Network
        row += [6, 1, 2, 1, 2, 1, 3, 2, np.random.randint(70, 95)]
        X.append(row)
        y.append("BANKING_TROJAN")

    # ── SPYWARE (location + mic + camera + contacts + fingerprinting) ──
    for _ in range(50):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [3, 4, 5, 6, 7, 8, 15]:  # CONTACTS + INTERNET + CAMERA + AUDIO + LOCATION x2 + CALL_LOG
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [0, 2, 4]:  # Device Fingerprinting + Accessibility + Screen Recording
            row[perm_offset + i] = 1
        taint_offset = perm_offset + len(FEATURE_MALWARE_PATTERNS)
        for i in [1, 4, 5, 7]:  # Location + DeviceID + Contacts + Camera to Network
            row[taint_offset + i] = 1
        row += [10, 3, 2, 4, 3, 2, 3, 4, np.random.randint(75, 100)]
        X.append(row)
        y.append("SPYWARE")

    for _ in range(30):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [4, 6, 7, 11]:  # INTERNET + AUDIO + LOCATION + BOOT
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [0, 4]:  # Fingerprinting + Screen Recording
            row[perm_offset + i] = 1
        taint_offset = perm_offset + len(FEATURE_MALWARE_PATTERNS)
        for i in [1, 4]:  # Location + DeviceID to Network
            row[taint_offset + i] = 1
        row += [5, 1, 1, 2, 2, 1, 2, 3, np.random.randint(60, 85)]
        X.append(row)
        y.append("SPYWARE")

    # ── RANSOMWARE (storage + encryption patterns) ──
    for _ in range(40):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [4, 9, 10, 19, 11]:  # INTERNET + STORAGE x2 + MANAGE_STORAGE + BOOT
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [6, 7]:  # Dynamic Code + Silent Install
            row[perm_offset + i] = 1
        row += [7, 2, 2, 1, 2, 1, 3, 3, np.random.randint(80, 100)]
        X.append(row)
        y.append("RANSOMWARE")

    # ── ADWARE (internet + lots of permissions but no sensitive ones) ──
    for _ in range(40):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [4, 9, 7]:  # INTERNET + STORAGE + LOCATION
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        row[perm_offset + 0] = 1  # Device Fingerprinting
        taint_offset = perm_offset + len(FEATURE_MALWARE_PATTERNS)
        row[taint_offset + 4] = 1  # DeviceID to Network
        row += [4, 1, 2, 1, 1, 1, 1, 2, np.random.randint(30, 65)]
        X.append(row)
        y.append("ADWARE")

    # ── DROPPER (install packages + dynamic code + boot) ──
    for _ in range(40):
        row = [0] * (len(FEATURE_PERMISSIONS) + len(FEATURE_MALWARE_PATTERNS) + len(FEATURE_TAINT_PATHS))
        for i in [4, 11, 13]:  # INTERNET + BOOT + REQUEST_INSTALL
            row[i] = 1
        perm_offset = len(FEATURE_PERMISSIONS)
        for i in [5, 6, 7]:  # Emulator Detection + Dynamic Code + Silent Install
            row[perm_offset + i] = 1
        row += [5, 1, 1, 1, 3, 1, 2, 2, np.random.randint(65, 90)]
        X.append(row)
        y.append("DROPPER")

    return np.array(X, dtype=float), np.array(y)


# ─── CLASSIFIER ───────────────────────────────────────────────────────────────

class AnirodMLClassifier:

    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.trained = False
        self._train()

    def _train(self):
        X, y = build_training_data()
        y_encoded = self.label_encoder.fit_transform(y)
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight="balanced"
        )
        self.model.fit(X, y_encoded)
        self.trained = True

    def predict(self, scan_results):
        if not self.trained:
            return None
        features = extract_features(scan_results)
        features_array = np.array(features, dtype=float).reshape(1, -1)
        prediction_encoded = self.model.predict(features_array)[0]
        probabilities = self.model.predict_proba(features_array)[0]
        predicted_label = self.label_encoder.inverse_transform([prediction_encoded])[0]
        confidence = round(float(probabilities[prediction_encoded]) * 100, 1)

        # Top 3 predictions
        top_indices = np.argsort(probabilities)[::-1][:3]
        top_predictions = []
        for idx in top_indices:
            label = self.label_encoder.inverse_transform([idx])[0]
            prob = round(float(probabilities[idx]) * 100, 1)
            if prob > 0:
                top_predictions.append({"label": label, "confidence": prob})

        return {
            "verdict": predicted_label,
            "confidence": confidence,
            "top_predictions": top_predictions,
            "risk_level": _verdict_to_risk(predicted_label),
            "description": _verdict_description(predicted_label),
            "color": _verdict_color(predicted_label),
        }


def _verdict_to_risk(verdict):
    mapping = {
        "CLEAN": "LOW",
        "ADWARE": "MEDIUM",
        "BANKING_TROJAN": "CRITICAL",
        "SPYWARE": "CRITICAL",
        "RANSOMWARE": "CRITICAL",
        "DROPPER": "HIGH",
    }
    return mapping.get(verdict, "MEDIUM")


def _verdict_description(verdict):
    mapping = {
        "CLEAN": "No malware patterns detected. App appears legitimate.",
        "ADWARE": "App shows aggressive advertising behavior and tracks your device ID.",
        "BANKING_TROJAN": "App matches banking trojan patterns. Can steal SMS OTPs and overlay fake login screens.",
        "SPYWARE": "App exhibits spyware behavior. Tracks location, contacts, and device activity.",
        "RANSOMWARE": "App shows ransomware characteristics. May encrypt files and demand payment.",
        "DROPPER": "App is designed to silently install other malicious apps on your device.",
    }
    return mapping.get(verdict, "Unknown malware family.")


def _verdict_color(verdict):
    mapping = {
        "CLEAN": "#16a34a",
        "ADWARE": "#d97706",
        "BANKING_TROJAN": "#dc2626",
        "SPYWARE": "#dc2626",
        "RANSOMWARE": "#dc2626",
        "DROPPER": "#ea580c",
    }
    return mapping.get(verdict, "#64748b")


# Singleton — train once, reuse
_classifier_instance = None

def get_classifier():
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = AnirodMLClassifier()
    return _classifier_instance


if __name__ == "__main__":
    print("[*] Training ML classifier...")
    clf = AnirodMLClassifier()
    print("[+] Training complete!")

    # Quick self-test
    test_cases = [
        {"name": "Banking Trojan test", "all_permissions": [
            "android.permission.READ_SMS", "android.permission.INTERNET",
            "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_BOOT_COMPLETED"
        ], "findings": {"malware": [{"name": "SMS Stealer"}, {"name": "Overlay Attack"}],
                        "taint": [{"name": "SMS to Network Exfiltration"}],
                        "dangerous_combos": [{"name": "OTP Banking Theft Combo"}],
                        "secrets": [], "owasp": []},
         "counts": {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0}, "risk_score": 95},

        {"name": "Clean app test", "all_permissions": ["android.permission.INTERNET"],
         "findings": {"malware": [], "taint": [], "dangerous_combos": [], "secrets": [], "owasp": []},
         "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0}, "risk_score": 5},

        {"name": "Spyware test", "all_permissions": [
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET",
            "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        ], "findings": {"malware": [{"name": "Device Fingerprinting"}, {"name": "Screen Recording"}],
                        "taint": [{"name": "Location to Network"}, {"name": "Contacts to Network"}],
                        "dangerous_combos": [{"name": "Real Time Tracking Combo"}],
                        "secrets": [], "owasp": []},
         "counts": {"CRITICAL": 3, "HIGH": 3, "MEDIUM": 1, "LOW": 0}, "risk_score": 88},
    ]

    print()
    for test in test_cases:
        result = clf.predict(test)
        print(f"  {test['name']}")
        print(f"  → {result['verdict']} ({result['confidence']}% confidence)")
        print(f"  → Top 3: {result['top_predictions']}")
        print()
