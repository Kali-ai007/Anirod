import zipfile
import re
import os
import sys
from datetime import datetime
from androguard.misc import AnalyzeAPK
from ml_classifier import get_classifier
from ai_explainer import explain_scan

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE": {"risk": "HIGH", "description": "Can read ALL files on your device including photos, videos and documents", "category": "Storage"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"risk": "HIGH", "description": "Can write, modify or delete ANY file on your device storage", "category": "Storage"},
    "android.permission.READ_MEDIA_IMAGES": {"risk": "HIGH", "description": "Can access all your photos and images", "category": "Media"},
    "android.permission.READ_MEDIA_VIDEO": {"risk": "HIGH", "description": "Can access all your videos", "category": "Media"},
    "android.permission.CAMERA": {"risk": "CRITICAL", "description": "Can take photos and videos using your camera even silently", "category": "Camera"},
    "android.permission.RECORD_AUDIO": {"risk": "CRITICAL", "description": "Can record audio using your microphone at any time", "category": "Microphone"},
    "android.permission.ACCESS_FINE_LOCATION": {"risk": "CRITICAL", "description": "Can track your precise GPS location in real time", "category": "Location"},
    "android.permission.ACCESS_COARSE_LOCATION": {"risk": "HIGH", "description": "Can track your approximate location via WiFi and cell towers", "category": "Location"},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"risk": "CRITICAL", "description": "Can track your location EVEN when the app is closed", "category": "Location"},
    "android.permission.READ_CONTACTS": {"risk": "HIGH", "description": "Can read your entire contacts list", "category": "Contacts"},
    "android.permission.READ_SMS": {"risk": "CRITICAL", "description": "Can read ALL your text messages including OTP and 2FA codes", "category": "SMS"},
    "android.permission.SEND_SMS": {"risk": "CRITICAL", "description": "Can send SMS messages from your phone", "category": "SMS"},
    "android.permission.RECEIVE_SMS": {"risk": "CRITICAL", "description": "Can intercept incoming SMS messages including bank OTP codes", "category": "SMS"},
    "android.permission.READ_CALL_LOG": {"risk": "HIGH", "description": "Can see all your call history", "category": "Phone"},
    "android.permission.INTERNET": {"risk": "MEDIUM", "description": "Can send data over the internet", "category": "Network"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"risk": "MEDIUM", "description": "App starts automatically every time you reboot your phone", "category": "System"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"risk": "HIGH", "description": "Can draw over other apps — used in overlay attacks to steal passwords", "category": "System"},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"risk": "CRITICAL", "description": "Full access to ALL files on device", "category": "Storage"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"risk": "CRITICAL", "description": "Can silently install other apps on your device", "category": "System"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "description": "Can monitor and control everything on your screen — used by spyware", "category": "Accessibility"},
}

DANGEROUS_COMBOS = [
    {"name": "Data Exfiltration Combo", "permissions": ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can READ your files AND send them over internet. Classic data theft."},
    {"name": "OTP Banking Theft Combo", "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can read your SMS OTP codes AND send them to attackers. Banking trojans use this exact combo."},
    {"name": "Silent Camera Spyware Combo", "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can silently take photos and videos AND upload them to a remote server."},
    {"name": "Microphone Surveillance Combo", "permissions": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can record your conversations AND upload the recordings silently."},
    {"name": "Real Time Tracking Combo", "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can track your precise GPS location AND report it to a server in real time."},
    {"name": "Persistent Background Spy Combo", "permissions": ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"], "risk": "HIGH", "description": "App starts automatically on reboot AND has internet access. Runs silently forever."},
    {"name": "SMS Full Intercept Combo", "permissions": ["android.permission.RECEIVE_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can receive, send AND exfiltrate SMS. Full SMS hijacking capability."},
    {"name": "Contact Harvesting Combo", "permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"], "risk": "CRITICAL", "description": "App can read your entire contacts list AND upload it to a remote server."},
]

SECRET_PATTERNS = [
    {"name": "Hardcoded API Key", "pattern": r'(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']', "risk": "CRITICAL", "description": "A hardcoded API key was found. Attackers can extract this from your APK."},
    {"name": "Hardcoded Password", "pattern": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "risk": "CRITICAL", "description": "A hardcoded password was found. Anyone who decompiles your APK can read this."},
    {"name": "AWS Access Key", "pattern": r'AKIA[0-9A-Z]{16}', "risk": "CRITICAL", "description": "An Amazon AWS access key was found."},
    {"name": "Google API Key", "pattern": r'AIza[0-9A-Za-z\-_]{35}', "risk": "CRITICAL", "description": "A Google API key found hardcoded."},
    {"name": "Firebase URL", "pattern": r'https://[a-z0-9-]+\.firebaseio\.com', "risk": "HIGH", "description": "A Firebase database URL was found."},
    {"name": "HTTP Not HTTPS", "pattern": r'http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168)', "risk": "HIGH", "description": "App is connecting over unencrypted HTTP."},
    {"name": "Private Key Block", "pattern": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "risk": "CRITICAL", "description": "A private cryptographic key was found inside the APK."},
    {"name": "JWT Token", "pattern": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "risk": "CRITICAL", "description": "A hardcoded JWT token was found."},
]

CODE_PATTERNS = [
    {"name": "SSL Verification Disabled", "pattern": r'(?i)(setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts)', "risk": "CRITICAL", "description": "SSL certificate verification is disabled. Allows man-in-the-middle attacks."},
    {"name": "App is Debuggable", "pattern": r'android:debuggable\s*=\s*["\']true["\']', "risk": "HIGH", "description": "App is set to debuggable=true."},
    {"name": "Backup Enabled", "pattern": r'android:allowBackup\s*=\s*["\']true["\']', "risk": "MEDIUM", "description": "App data backup is enabled. Sensitive data can be extracted via ADB."},
    {"name": "JavaScript in WebView", "pattern": r'(?i)setJavaScriptEnabled\s*\(\s*true\s*\)', "risk": "HIGH", "description": "JavaScript enabled in WebView."},
    {"name": "Weak Encryption MD5", "pattern": r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "risk": "HIGH", "description": "MD5 is broken and should never be used for security purposes."},
    {"name": "Weak Encryption SHA1", "pattern": r'(?i)MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "risk": "MEDIUM", "description": "SHA-1 is deprecated and weak."},
    {"name": "World Readable File", "pattern": r'(?i)MODE_WORLD_READABLE', "risk": "HIGH", "description": "Files created with world-readable permissions."},
    {"name": "SQL Injection Risk", "pattern": r'(?i)(rawQuery|execSQL)\s*\(\s*["\'][^"\']*\s*\+', "risk": "HIGH", "description": "User input concatenated directly into SQL queries."},
]

OWASP_PATTERNS = [
    {"id": "M1", "name": "Improper Credential Usage", "pattern": r'(?i)(username|user_name)\s*[=:]\s*["\']([^\"\']{3,})["\']', "risk": "CRITICAL", "description": "Hardcoded username found.", "ref": "OWASP M1"},
    {"id": "M5", "name": "Insecure Communication", "pattern": r'http://(?!localhost|127\.0\.0\.1|10\.\d+|192\.168)', "risk": "CRITICAL", "description": "App communicates over unencrypted HTTP.", "ref": "OWASP M5"},
    {"id": "M7", "name": "Insufficient Binary Protections", "pattern": r'android:debuggable\s*=\s*["\']true["\']', "risk": "HIGH", "description": "App is debuggable.", "ref": "OWASP M7"},
    {"id": "M8", "name": "Security Misconfiguration", "pattern": r'android:allowBackup\s*=\s*["\']true["\']', "risk": "MEDIUM", "description": "App backup enabled.", "ref": "OWASP M8"},
    {"id": "M9", "name": "Insecure Data Storage", "pattern": r'(?i)(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getSharedPreferences)', "risk": "HIGH", "description": "Insecure data storage.", "ref": "OWASP M9"},
    {"id": "M10", "name": "Insufficient Cryptography", "pattern": r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "risk": "HIGH", "description": "Broken MD5 cryptography in use.", "ref": "OWASP M10"},
]

URL_PATTERNS = [
    {"name": "HTTP URL", "pattern": r'http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9\-_\.?=&%]*', "risk": "HIGH", "description": "Unencrypted HTTP endpoint found."},
    {"name": "HTTPS URL", "pattern": r'https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9\-_\.?=&%]*', "risk": "LOW", "description": "HTTPS endpoint found."},
    {"name": "API Endpoint", "pattern": r'["\'/]api/v?[0-9]*/[a-zA-Z0-9\-_/]+', "risk": "MEDIUM", "description": "API endpoint hardcoded in app."},
    {"name": "Firebase URL", "pattern": r'https://[a-z0-9-]+\.firebaseio\.com', "risk": "HIGH", "description": "Firebase database URL found."},
    {"name": "AWS S3 Bucket", "pattern": r'https?://[a-z0-9\-]+\.s3\.amazonaws\.com', "risk": "HIGH", "description": "AWS S3 bucket URL found."},
    {"name": "IP Address", "pattern": r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?', "risk": "HIGH", "description": "Hardcoded IP address used as server endpoint."},
]

MALWARE_PATTERNS = [
    {"name": "Device Fingerprinting", "pattern": r'(?i)(getDeviceId|getImei|getSubscriberId|getSimSerialNumber)', "risk": "HIGH", "description": "App collects unique device identifiers. Common in stalkerware.", "category": "Surveillance"},
    {"name": "Overlay Attack", "pattern": r'(?i)(TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_OVERLAY|SYSTEM_ALERT_WINDOW)', "risk": "CRITICAL", "description": "App can draw over other apps. Used by banking trojans.", "category": "Banking Trojan"},
    {"name": "Accessibility Abuse", "pattern": r'(?i)(AccessibilityService|onAccessibilityEvent|performGlobalAction)', "risk": "CRITICAL", "description": "App uses Accessibility Service. Abused by keyloggers and spyware.", "category": "Spyware"},
    {"name": "SMS Stealer", "pattern": r'(?i)(SmsManager|sendTextMessage|SMS_RECEIVED)', "risk": "CRITICAL", "description": "SMS interception pattern. Banking trojans steal OTP codes this way.", "category": "Banking Trojan"},
    {"name": "Screen Recording", "pattern": r'(?i)(MediaProjection|createVirtualDisplay|captureScreen)', "risk": "CRITICAL", "description": "Screen capture capability.", "category": "Spyware"},
    {"name": "Emulator Detection", "pattern": r'(?i)(isEmulator|Build\.FINGERPRINT.*generic)', "risk": "HIGH", "description": "App detects emulators to hide behavior during analysis.", "category": "Anti-Analysis"},
    {"name": "Dynamic Code Loading", "pattern": r'(?i)(DexClassLoader|PathClassLoader|dalvik\.system)', "risk": "HIGH", "description": "App loads code at runtime.", "category": "Evasion"},
    {"name": "Silent Install", "pattern": r'(?i)(installPackage|PackageInstaller|REQUEST_INSTALL_PACKAGES)', "risk": "CRITICAL", "description": "App can silently install other packages.", "category": "Dropper"},
]

# ─── MONTH 2: TAINT SOURCES & SINKS ──────────────────────────────────────────

TAINT_SOURCES = {
    "SMS":         ["getMessageBody", "getOriginatingAddress", "SMS_RECEIVED", "SmsMessage"],
    "Location":    ["getLatitude", "getLongitude", "getLastKnownLocation", "onLocationChanged", "requestLocationUpdates"],
    "Contacts":    ["ContactsContract", "CONTENT_URI", "getContentResolver"],
    "Credentials": ["getPassword", "getQueryParameter", "getCredentials"],
    "Camera":      ["takePicture", "onPictureTaken", "acquireLatestImage", "ImageReader"],
    "Microphone":  ["startRecording", "AudioRecord", "MediaRecorder"],
    "DeviceInfo":  ["getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber", "getAndroidId"],
}

TAINT_SINKS = {
    "HTTP_Transmit": ["HttpURLConnection", "OkHttpClient", "openConnection", "getOutputStream", "execute"],
    "File_Write":    ["FileOutputStream", "openFileOutput", "FileWriter"],
    "SMS_Send":      ["sendTextMessage", "sendMultipartTextMessage", "SmsManager"],
    "Log_Leak":      ["Log.d", "Log.e", "Log.i", "Log.v", "Log.w"],
    "Database":      ["execSQL", "rawQuery", "insert", "update"],
    "SharedPrefs":   ["putString", "putInt", "apply", "commit"],
}

TAINT_PATHS = [
    {"name": "SMS to Network Exfiltration",   "source": "SMS",         "sink": "HTTP_Transmit", "risk": "CRITICAL", "description": "SMS data (OTP/messages) flows into network transmission. Classic banking trojan behavior."},
    {"name": "Location to Network",           "source": "Location",    "sink": "HTTP_Transmit", "risk": "CRITICAL", "description": "GPS location data flows into network calls. App is transmitting your real-time location."},
    {"name": "Credentials to Network",        "source": "Credentials", "sink": "HTTP_Transmit", "risk": "CRITICAL", "description": "User credentials flow into network calls. Password may be transmitted insecurely."},
    {"name": "Credentials to Log",            "source": "Credentials", "sink": "Log_Leak",      "risk": "HIGH",     "description": "Credentials flow into log statements. Passwords visible in device logs."},
    {"name": "Device ID to Network",          "source": "DeviceInfo",  "sink": "HTTP_Transmit", "risk": "HIGH",     "description": "Device identifiers flow into network calls. App is fingerprinting and tracking your device."},
    {"name": "Contacts to Network",           "source": "Contacts",    "sink": "HTTP_Transmit", "risk": "CRITICAL", "description": "Contact data flows into network calls. Your contacts list is being uploaded."},
    {"name": "Microphone to File",            "source": "Microphone",  "sink": "File_Write",    "risk": "CRITICAL", "description": "Audio recording flows into file write. App is saving recordings to device storage."},
    {"name": "Credentials to Database",       "source": "Credentials", "sink": "Database",      "risk": "HIGH",     "description": "Credentials stored in local database unencrypted."},
    {"name": "SMS to Log Leak",               "source": "SMS",         "sink": "Log_Leak",      "risk": "HIGH",     "description": "SMS content flows into log output. OTP codes may be visible in device logs."},
    {"name": "Camera to Network",             "source": "Camera",      "sink": "HTTP_Transmit", "risk": "CRITICAL", "description": "Camera data flows into network calls. Photos or video may be uploaded silently."},
    {"name": "Device ID to Database",         "source": "DeviceInfo",  "sink": "Database",      "risk": "HIGH",     "description": "Device identifiers stored in local database."},
    {"name": "Location to File",              "source": "Location",    "sink": "File_Write",    "risk": "HIGH",     "description": "Location data written to file. Can be accessed by other apps."},
]


class AnirodScanner:

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.filename = os.path.basename(apk_path)
        self.findings = {
            "permissions": [],
            "dangerous_combos": [],
            "secrets": [],
            "code_issues": [],
            "owasp": [],
            "urls": [],
            "malware": [],
            "taint": [],
            "ml": None,
            "ai_explanation": None,
        }
        self.file_contents = {}
        self.all_permissions = []
        self.method_calls = []
        self.androguard_apk = None
        self.androguard_dx = None

    def scan(self):
        print(f"[*] Starting Anirod scan on: {self.filename}")
        androguard_ok = self._extract_apk_androguard()
        if not androguard_ok:
            if not self._extract_apk():
                return None
        self._scan_permissions()
        self._scan_dangerous_combos()
        self._scan_secrets()
        self._scan_code_issues()
        self._scan_owasp()
        self._scan_urls()
        self._scan_malware()
        self._scan_taint()
        self._scan_ml()
        self._scan_ai()
        results = self._build_results()
        print(f"[+] Scan complete! Risk Score: {results['risk_score']}/100")
        return results

    def _extract_apk_androguard(self):
        try:
            print(f"[*] Using Androguard bytecode analysis...")
            a, d, dx = AnalyzeAPK(self.apk_path)
            self.all_permissions = a.get_permissions()
            print(f"[*] Androguard found {len(self.all_permissions)} permissions")
            all_strings = []
            if d:
                dexes = d if isinstance(d, list) else [d]
                for dex in dexes:
                    for string in dex.get_strings():
                        all_strings.append(string)
            self.method_calls = []
            if dx:
                for method in dx.get_methods():
                    self.method_calls.append(str(method.get_method()))
            self.file_contents["__androguard_strings__"] = "\n".join(all_strings)
            self.file_contents["__androguard_methods__"] = "\n".join(self.method_calls)
            with zipfile.ZipFile(self.apk_path, "r") as apk:
                for name in apk.namelist():
                    if any(name.endswith(ext) for ext in [".xml", ".json", ".properties", ".txt"]):
                        try:
                            content = apk.read(name).decode("utf-8", errors="ignore")
                            self.file_contents[name] = content
                        except Exception:
                            pass
            print(f"[*] Androguard extracted {len(all_strings)} strings from bytecode")
            self.androguard_apk = a
            self.androguard_dx = dx
            return True
        except Exception as e:
            print(f"[!] Androguard failed: {e}")
            print(f"[*] Falling back to ZIP analysis...")
            return False

    def _extract_apk(self):
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                for name in apk.namelist():
                    if any(name.endswith(ext) for ext in ['.xml', '.java', '.kt', '.smali', '.json', '.properties', '.txt']):
                        try:
                            content = apk.read(name).decode('utf-8', errors='ignore')
                            self.file_contents[name] = content
                        except Exception:
                            pass
            print(f"[*] Extracted {len(self.file_contents)} readable files from APK")
            return True
        except zipfile.BadZipFile:
            print(f"[!] Error: Not a valid APK file")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def _scan_permissions(self):
        if not self.all_permissions:
            manifest_content = self.file_contents.get('AndroidManifest.xml', '')
            if not manifest_content:
                return
            permission_pattern = r'uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']'
            self.all_permissions = re.findall(permission_pattern, manifest_content)
        for perm in self.all_permissions:
            if perm in DANGEROUS_PERMISSIONS:
                info = DANGEROUS_PERMISSIONS[perm]
                self.findings["permissions"].append({
                    "permission": perm,
                    "short_name": perm.split(".")[-1],
                    "risk": info["risk"],
                    "description": info["description"],
                    "category": info["category"]
                })

    def _scan_dangerous_combos(self):
        for combo in DANGEROUS_COMBOS:
            if all(p in self.all_permissions for p in combo["permissions"]):
                self.findings["dangerous_combos"].append({
                    "name": combo["name"],
                    "risk": combo["risk"],
                    "description": combo["description"],
                    "permissions": [p.split(".")[-1] for p in combo["permissions"]]
                })

    def _scan_secrets(self):
        secret_counts = {}
        for filename, content in self.file_contents.items():
            for pattern_info in SECRET_PATTERNS:
                matches = re.findall(pattern_info["pattern"], content)
                if matches:
                    name = pattern_info["name"]
                    if name not in secret_counts:
                        secret_counts[name] = {
                            "name": name,
                            "risk": pattern_info["risk"],
                            "description": pattern_info["description"],
                            "file": filename,
                            "occurrences": 0
                        }
                    secret_counts[name]["occurrences"] += len(matches)
        self.findings["secrets"] = list(secret_counts.values())

    def _scan_code_issues(self):
        for filename, content in self.file_contents.items():
            for pattern_info in CODE_PATTERNS:
                matches = re.findall(pattern_info["pattern"], content)
                if matches:
                    self.findings["code_issues"].append({
                        "name": pattern_info["name"],
                        "risk": pattern_info["risk"],
                        "description": pattern_info["description"],
                        "file": filename,
                        "occurrences": len(matches)
                    })
                    break

    def _scan_owasp(self):
        for filename, content in self.file_contents.items():
            for p in OWASP_PATTERNS:
                if re.findall(p["pattern"], content):
                    if not any(f["ref"] == p["ref"] for f in self.findings["owasp"]):
                        self.findings["owasp"].append({
                            "id": p["id"],
                            "name": p["name"],
                            "risk": p["risk"],
                            "description": p["description"],
                            "ref": p["ref"],
                            "file": filename
                        })

    def _scan_urls(self):
        seen = set()
        for filename, content in self.file_contents.items():
            for p in URL_PATTERNS:
                for match in re.findall(p["pattern"], content):
                    url = match if isinstance(match, str) else match[0]
                    url = url.strip("\"'")
                    if url not in seen and len(url) > 8:
                        seen.add(url)
                        self.findings["urls"].append({
                            "name": p["name"],
                            "url": url,
                            "risk": p["risk"],
                            "description": p["description"],
                            "file": filename
                        })
            if len(self.findings["urls"]) >= 20:
                break

    def _scan_malware(self):
        for filename, content in self.file_contents.items():
            for p in MALWARE_PATTERNS:
                matches = re.findall(p["pattern"], content)
                if matches and not any(f["name"] == p["name"] for f in self.findings["malware"]):
                    self.findings["malware"].append({
                        "name": p["name"],
                        "risk": p["risk"],
                        "description": p["description"],
                        "category": p["category"],
                        "file": filename,
                        "occurrences": len(matches)
                    })

    def _scan_taint(self):
        # Build one big search corpus from all extracted content
        corpus = "\n".join(self.file_contents.values())

        # Detect which sources are present
        detected_sources = {}
        for source_name, keywords in TAINT_SOURCES.items():
            found = [kw for kw in keywords if kw in corpus]
            if found:
                detected_sources[source_name] = found

        # Detect which sinks are present
        detected_sinks = {}
        for sink_name, keywords in TAINT_SINKS.items():
            found = [kw for kw in keywords if kw in corpus]
            if found:
                detected_sinks[sink_name] = found

        # Match known taint paths
        for path in TAINT_PATHS:
            if path["source"] in detected_sources and path["sink"] in detected_sinks:
                self.findings["taint"].append({
                    "name": path["name"],
                    "risk": path["risk"],
                    "description": path["description"],
                    "source": path["source"],
                    "sink": path["sink"],
                    "source_hits": detected_sources[path["source"]],
                    "sink_hits": detected_sinks[path["sink"]],
                })

    def _scan_ai(self):
        try:
            print(f"[*] Generating AI explanation via Mistral 7B...")
            interim = {
                "filename": self.filename,
                "risk_score": 0,
                "grade": "UNKNOWN",
                "ml": self.findings.get("ml"),
            "ai_explanation": self.findings.get("ai_explanation"),
                "findings": self.findings,
                "counts": {}
            }
            explanation = explain_scan(interim)
            self.findings["ai_explanation"] = explanation
            if explanation:
                print(f"[+] AI explanation generated!")
        except Exception as e:
            print(f"[!] AI error: {e}")
            self.findings["ai_explanation"] = None

    def _scan_ml(self):
        try:
            clf = get_classifier()
            interim = {
                "all_permissions": self.all_permissions,
                "findings": self.findings,
                "counts": {
                    "CRITICAL": sum(1 for f in self.findings.values() if isinstance(f, list) for x in f if isinstance(x, dict) and x.get("risk") == "CRITICAL"),
                    "HIGH": sum(1 for f in self.findings.values() if isinstance(f, list) for x in f if isinstance(x, dict) and x.get("risk") == "HIGH"),
                    "MEDIUM": 0,
                    "LOW": 0
                },
                "risk_score": 0
            }
            self.findings["ml"] = clf.predict(interim)
        except Exception as e:
            print(f"[!] ML classifier error: {e}")
            self.findings["ml"] = None

    def _build_results(self):
        all_findings = (
            self.findings["permissions"] +
            self.findings["dangerous_combos"] +
            self.findings["secrets"] +
            self.findings["code_issues"] +
            self.findings["owasp"] +
            self.findings["malware"] +
            self.findings["taint"]
        )
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            level = f.get("risk", "LOW")
            counts[level] = counts.get(level, 0) + 1

        score = min(100, (
            counts["CRITICAL"] * 25 +
            counts["HIGH"] * 10 +
            counts["MEDIUM"] * 5 +
            counts["LOW"] * 1
        ))

        if score >= 75:
            grade = "CRITICAL"
            grade_color = "#dc2626"
            summary = "This app has severe security issues and should NOT be used."
        elif score >= 50:
            grade = "HIGH RISK"
            grade_color = "#ea580c"
            summary = "This app has serious vulnerabilities that need immediate attention."
        elif score >= 25:
            grade = "MEDIUM RISK"
            grade_color = "#d97706"
            summary = "This app has some security concerns. Review before using."
        elif score > 0:
            grade = "LOW RISK"
            grade_color = "#16a34a"
            summary = "Relatively safe but has minor issues."
        else:
            grade = "SAFE"
            grade_color = "#15803d"
            summary = "No obvious security issues detected."

        return {
            "filename": self.filename,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": score,
            "grade": grade,
            "grade_color": grade_color,
            "summary": summary,
            "counts": counts,
            "total_issues": len(all_findings),
            "findings": self.findings,
            "all_permissions": self.all_permissions,
            "analysis_engine": "Androguard 4.x (Bytecode)" if self.androguard_apk else "ZIP (Fallback)",
            "ml": self.findings.get("ml"),
            "ai_explanation": self.findings.get("ai_explanation")
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <apk_file> [--verbose]")
        sys.exit(1)

    apk_path = sys.argv[1]
    verbose = "--verbose" in sys.argv

    if not os.path.exists(apk_path):
        print(f"[!] File not found: {apk_path}")
        sys.exit(1)

    scanner = AnirodScanner(apk_path)
    results = scanner.scan()

    if not results:
        print("[!] Scan failed.")
        sys.exit(1)

    print("\n=== ANIROD RESULTS ===")
    print(f"Engine:      {results['analysis_engine']}")
    print(f"Permissions: {len(results['findings']['permissions'])}")
    print(f"Score:       {results['risk_score']} / 100")
    print(f"Grade:       {results['grade']}")
    print(f"OWASP:       {len(results['findings']['owasp'])}")
    print(f"Malware:     {len(results['findings']['malware'])}")
    print(f"URLs:        {len(results['findings']['urls'])}")
    print(f"Secrets:     {len(results['findings']['secrets'])}")
    print(f"Combos:      {len(results['findings']['dangerous_combos'])}")
    print(f"Taint Paths: {len(results['findings']['taint'])}")
    ml = results.get("ml")
    if ml:
        print(f"ML Verdict:  {ml['verdict']} ({ml['confidence']}% confidence)")
    ai = results.get("ai_explanation")
    if ai:
        print(f"\nAI Analysis: {ai[:200]}...")

    if verbose:
        print("\n--- DANGEROUS COMBOS ---")
        if results['findings']['dangerous_combos']:
            for c in results['findings']['dangerous_combos']:
                print(f"  [{c['risk']}] {c['name']}")
                print(f"  Permissions: {', '.join(c['permissions'])}")
                print(f"  {c['description']}\n")
        else:
            print("  None detected.")

        print("--- TAINT ANALYSIS ---")
        if results['findings']['taint']:
            for t in results['findings']['taint']:
                print(f"  [{t['risk']}] {t['name']}")
                print(f"  Flow: {t['source']} --> {t['sink']}")
                print(f"  {t['description']}\n")
        else:
            print("  None detected.")

        print("--- MALWARE INDICATORS ---")
        if results['findings']['malware']:
            for m in results['findings']['malware']:
                print(f"  [{m['risk']}] {m['name']} ({m['category']})")
                print(f"  {m['description']}\n")
        else:
            print("  None detected.")

        print("--- OWASP FINDINGS ---")
        if results['findings']['owasp']:
            for o in results['findings']['owasp']:
                print(f"  [{o['risk']}] {o['ref']} - {o['name']}")
                print(f"  {o['description']}\n")
        else:
            print("  None detected.")

        print("--- SECRETS ---")
        if results['findings']['secrets']:
            for s in results['findings']['secrets']:
                print(f"  [{s['risk']}] {s['name']} ({s['occurrences']} occurrence(s))")
                print(f"  {s['description']}\n")
        else:
            print("  None detected.")
