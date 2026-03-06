import zipfile
import xml.etree.ElementTree as ET
import re
import os
import json
from datetime import datetime
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.apk import APK

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE": {
        "risk": "HIGH",
        "description": "Can read ALL files on your device including photos, videos and documents",
        "category": "Storage"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "risk": "HIGH",
        "description": "Can write, modify or delete ANY file on your device storage",
        "category": "Storage"
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "risk": "HIGH",
        "description": "Can access all your photos and images",
        "category": "Media"
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "risk": "HIGH",
        "description": "Can access all your videos",
        "category": "Media"
    },
    "android.permission.CAMERA": {
        "risk": "CRITICAL",
        "description": "Can take photos and videos using your camera even silently",
        "category": "Camera"
    },
    "android.permission.RECORD_AUDIO": {
        "risk": "CRITICAL",
        "description": "Can record audio using your microphone at any time",
        "category": "Microphone"
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "risk": "CRITICAL",
        "description": "Can track your precise GPS location in real time",
        "category": "Location"
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "risk": "HIGH",
        "description": "Can track your approximate location via WiFi and cell towers",
        "category": "Location"
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "risk": "CRITICAL",
        "description": "Can track your location EVEN when the app is closed — 24/7 tracking",
        "category": "Location"
    },
    "android.permission.READ_CONTACTS": {
        "risk": "HIGH",
        "description": "Can read your entire contacts list",
        "category": "Contacts"
    },
    "android.permission.READ_SMS": {
        "risk": "CRITICAL",
        "description": "Can read ALL your text messages including OTP and 2FA codes",
        "category": "SMS"
    },
    "android.permission.SEND_SMS": {
        "risk": "CRITICAL",
        "description": "Can send SMS messages from your phone",
        "category": "SMS"
    },
    "android.permission.RECEIVE_SMS": {
        "risk": "CRITICAL",
        "description": "Can intercept incoming SMS messages including bank OTP codes",
        "category": "SMS"
    },
    "android.permission.READ_CALL_LOG": {
        "risk": "HIGH",
        "description": "Can see all your call history",
        "category": "Phone"
    },
    "android.permission.INTERNET": {
        "risk": "MEDIUM",
        "description": "Can send data over the internet — dangerous combined with other permissions",
        "category": "Network"
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "risk": "MEDIUM",
        "description": "App starts automatically every time you reboot your phone",
        "category": "System"
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "HIGH",
        "description": "Can draw over other apps — used in overlay attacks to steal passwords",
        "category": "System"
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "risk": "CRITICAL",
        "description": "Full access to ALL files on device — most powerful storage permission",
        "category": "Storage"
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "risk": "CRITICAL",
        "description": "Can silently install other apps on your device",
        "category": "System"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "risk": "CRITICAL",
        "description": "Can monitor and control everything on your screen — used by spyware",
        "category": "Accessibility"
    },
}

SECRET_PATTERNS = [
    {
        "name": "Hardcoded API Key",
        "pattern": r'(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
        "risk": "CRITICAL",
        "description": "A hardcoded API key was found. Attackers can extract this from your APK and abuse your services."
    },
    {
        "name": "Hardcoded Password",
        "pattern": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
        "risk": "CRITICAL",
        "description": "A hardcoded password was found. Anyone who decompiles your APK can read this."
    },
    {
        "name": "AWS Access Key",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "risk": "CRITICAL",
        "description": "An Amazon AWS access key was found. Gives attackers access to your cloud."
    },
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "risk": "CRITICAL",
        "description": "A Google API key found hardcoded. Can be abused for unauthorized usage."
    },
    {
        "name": "Firebase URL",
        "pattern": r'https://[a-z0-9-]+\.firebaseio\.com',
        "risk": "HIGH",
        "description": "A Firebase database URL was found. Ensure your Firebase rules are not public."
    },
    {
        "name": "HTTP Not HTTPS",
        "pattern": r'http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168)',
        "risk": "HIGH",
        "description": "App is connecting over unencrypted HTTP. All data can be intercepted by hackers."
    },
    {
        "name": "Private Key Block",
        "pattern": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        "risk": "CRITICAL",
        "description": "A private cryptographic key was found inside the APK. Extremely dangerous."
    },
    {
        "name": "JWT Token",
        "pattern": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "risk": "CRITICAL",
        "description": "A hardcoded JWT token was found. Attackers can authenticate as a real user."
    },
]

CODE_PATTERNS = [
    {
        "name": "SSL Verification Disabled",
        "pattern": r'(?i)(setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts)',
        "risk": "CRITICAL",
        "description": "SSL certificate verification is disabled. Allows man-in-the-middle attacks."
    },
    {
        "name": "App is Debuggable",
        "pattern": r'android:debuggable\s*=\s*["\']true["\']',
        "risk": "HIGH",
        "description": "App is set to debuggable=true. Attackers can attach a debugger and inspect the app."
    },
    {
        "name": "Backup Enabled",
        "pattern": r'android:allowBackup\s*=\s*["\']true["\']',
        "risk": "MEDIUM",
        "description": "App data backup is enabled. Sensitive data can be extracted via ADB backup."
    },
    {
        "name": "JavaScript in WebView",
        "pattern": r'(?i)setJavaScriptEnabled\s*\(\s*true\s*\)',
        "risk": "HIGH",
        "description": "JavaScript enabled in WebView. Attackers can execute scripts in your app."
    },
    {
        "name": "Weak Encryption MD5",
        "pattern": r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
        "risk": "HIGH",
        "description": "MD5 is broken and should never be used for security purposes."
    },
    {
        "name": "Weak Encryption SHA1",
        "pattern": r'(?i)MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
        "risk": "MEDIUM",
        "description": "SHA-1 is deprecated and weak. Use SHA-256 or stronger."
    },
    {
        "name": "World Readable File",
        "pattern": r'(?i)MODE_WORLD_READABLE',
        "risk": "HIGH",
        "description": "Files created with world-readable permissions. Other apps can read your data."
    },
    {
        "name": "SQL Injection Risk",
        "pattern": r'(?i)(rawQuery|execSQL)\s*\(\s*["\'][^"\']*\s*\+',
        "risk": "HIGH",
        "description": "User input is being concatenated directly into SQL queries."
    },
]

DANGEROUS_COMBOS = [
    {
        "permissions": ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.INTERNET"],
        "risk": "CRITICAL",
        "name": "Data Exfiltration Combo",
        "description": "App can READ your files AND send them over internet. Classic data theft — your photos, videos, documents can all be stolen!"
    },
    {
        "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "risk": "CRITICAL",
        "name": "OTP Banking Theft Combo",
        "description": "App can read your SMS OTP codes AND send them to attackers. Banking trojans use this exact combo."
    },
    {
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "risk": "CRITICAL",
        "name": "Silent Camera Spyware Combo",
        "description": "App can silently take photos and videos AND upload them to a remote server."
    },
    {
        "permissions": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "risk": "CRITICAL",
        "name": "Microphone Surveillance Combo",
        "description": "App can record your conversations AND upload the recordings silently."
    },
    {
        "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        "risk": "CRITICAL",
        "name": "Real Time Tracking Combo",
        "description": "App can track your precise GPS location AND report it to a server in real time."
    },
    {
        "permissions": ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"],
        "risk": "HIGH",
        "name": "Persistent Background Spy Combo",
        "description": "App starts automatically on reboot AND has internet access. Runs silently forever."
    },
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
        }
        self.file_contents = {}
        self.all_permissions = []

    def scan(self):
        print(f"[*] Starting Anirod scan on: {self.filename}")
        if not self._extract_apk():
            return None
        self._scan_permissions()
        self._scan_dangerous_combos()
        self._scan_secrets()
        self._scan_code_issues()
        results = self._build_results()
        print(f"[+] Scan complete! Risk Score: {results['risk_score']}/100")
        return results

    def _extract_apk(self):
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                for name in apk.namelist():
                    if any(name.endswith(ext) for ext in
                           ['.xml', '.java', '.kt', '.smali', '.json', '.properties', '.txt']):
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
        manifest_content = self.file_contents.get('AndroidManifest.xml', '')
        if not manifest_content:
            return
        permission_pattern = r'uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']'
        found_permissions = re.findall(permission_pattern, manifest_content)
        self.all_permissions = found_permissions
        for perm in found_permissions:
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
        for filename, content in self.file_contents.items():
            for pattern_info in SECRET_PATTERNS:
                matches = re.findall(pattern_info["pattern"], content)
                if matches:
                    self.findings["secrets"].append({
                        "name": pattern_info["name"],
                        "risk": pattern_info["risk"],
                        "description": pattern_info["description"],
                        "file": filename,
                        "occurrences": len(matches)
                    })
                    break

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

    def _build_results(self):
        all_findings = (
            self.findings["permissions"] +
            self.findings["dangerous_combos"] +
            self.findings["secrets"] +
            self.findings["code_issues"]
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
            "all_permissions": self.all_permissions
        }
