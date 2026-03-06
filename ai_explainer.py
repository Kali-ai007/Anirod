import requests
import os

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "192.168.56.1")
OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
MODEL = os.getenv("OLLAMA_MODEL", "mistral")
OLLAMA_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate"

MODEL = "mistral"

def explain_scan(results):
    """Send scan results to Mistral 7B and get plain English explanation."""

    findings_summary = []

    if results.get("ml"):
        ml = results["ml"]
        findings_summary.append(f"ML Verdict: {ml['verdict']} ({ml['confidence']}% confidence)")

    for combo in results.get("findings", {}).get("dangerous_combos", []):
        findings_summary.append(f"Dangerous combo: {combo['name']}")

    for t in results.get("findings", {}).get("taint", []):
        findings_summary.append(f"Taint path: {t['source']} leaks to {t['sink']}")

    for m in results.get("findings", {}).get("malware", []):
        findings_summary.append(f"Malware pattern: {m['name']} ({m['category']})")

    for o in results.get("findings", {}).get("owasp", []):
        findings_summary.append(f"OWASP: {o['ref']} - {o['name']}")

    prompt = f"""You are a mobile security expert. Analyze this Android APK scan and explain the risks in plain English for a non-technical user. Be direct, specific, and explain what an attacker could actually DO with these vulnerabilities.

App: {results.get('filename', 'Unknown')}
Risk Score: {results.get('risk_score', 0)}/100
Grade: {results.get('grade', 'Unknown')}

Security Findings:
{chr(10).join(f'- {f}' for f in findings_summary)}

Write a 3-4 sentence plain English summary explaining:
1. What this app can do to the user
2. What the biggest threat is
3. Whether they should use this app

Keep it simple, no jargon, speak directly to the user."""

    try:
        response = requests.post(
            