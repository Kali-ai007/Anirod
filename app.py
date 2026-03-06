from pdf_report import generate_pdf
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
import json
from datetime import datetime
from scanner import AnirodScanner

app = Flask(__name__)
app.secret_key = "anirod-secret-key"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
DATABASE = os.path.join(os.path.dirname(__file__), 'database', 'anirod.db')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)


def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            risk_score INTEGER,
            grade TEXT,
            total_issues INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            results_json TEXT
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(results):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans
        (filename, scan_date, risk_score, grade, total_issues,
         critical_count, high_count, medium_count, low_count, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        results['filename'],
        results['scan_date'],
        results['risk_score'],
        results['grade'],
        results['total_issues'],
        results['counts']['CRITICAL'],
        results['counts']['HIGH'],
        results['counts']['MEDIUM'],
        results['counts']['LOW'],
        json.dumps(results)
    ))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY scan_date DESC')
    scans = [dict(row) for row in c.fetchall()]
    conn.close()
    return scans


def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if row:
        data = dict(row)
        data['results'] = json.loads(data['results_json'])
        return data
    return None


def get_stats():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scans')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scans WHERE grade = "CRITICAL"')
    critical = c.fetchone()[0]
    c.execute('SELECT AVG(risk_score) FROM scans')
    avg_score = c.fetchone()[0] or 0
    c.execute('SELECT SUM(total_issues) FROM scans')
    total_issues = c.fetchone()[0] or 0
    conn.close()
    return {
        "total_scans": total,
        "critical_apps": critical,
        "avg_risk_score": round(avg_score, 1),
        "total_issues_found": total_issues
    }


@app.route('/')
def index():
    scans = get_all_scans()[:5]
    stats = get_stats()
    return render_template('index.html', scans=scans, stats=stats)


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        if 'apk_file' not in request.files:
            flash('No file uploaded!', 'error')
            return redirect(url_for('scan'))
        file = request.files['apk_file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(url_for('scan'))
        if not file.filename.lower().endswith('.apk'):
            flash('Only APK files are allowed!', 'error')
            return redirect(url_for('scan'))
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        try:
            scanner = AnirodScanner(filepath)
            results = scanner.scan()
            if results is None:
                flash('Failed to scan APK — file may be corrupted.', 'error')
                return redirect(url_for('scan'))
            scan_id = save_scan(results)
            os.remove(filepath)
            flash('Scan completed successfully!', 'success')
            return redirect(url_for('results', scan_id=scan_id))
        except Exception as e:
            flash(f'Scan error: {str(e)}', 'error')
            return redirect(url_for('scan'))
    return render_template('scan.html')


@app.route('/results/<int:scan_id>')
def results(scan_id):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        flash('Scan not found!', 'error')
        return redirect(url_for('index'))
    return render_template('results.html', scan=scan_data, results=scan_data['results'])


@app.route('/history')
def history():
    scans = get_all_scans()
    return render_template('history.html', scans=scans)


@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    flash('Scan deleted.', 'success')
    return redirect(url_for('history'))


@app.route('/demo')
def demo():
    demo_results = {
        "filename": "suspicious_app_demo.apk",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": 85,
        "grade": "CRITICAL",
        "grade_color": "#dc2626",
        "summary": "This app has severe security issues and should NOT be used.",
        "counts": {"CRITICAL": 3, "HIGH": 4, "MEDIUM": 2, "LOW": 1},
        "total_issues": 10,
        "analysis_engine": "Androguard 4.x (Bytecode)",
        "ml": {"verdict": "BANKING_TROJAN", "confidence": 91.5, "color": "#dc2626", "description": "App matches banking trojan patterns. Can steal SMS OTPs and overlay fake login screens.", "top_predictions": [{"label": "BANKING_TROJAN", "confidence": 91.5}, {"label": "SPYWARE", "confidence": 5.0}, {"label": "DROPPER", "confidence": 3.5}]},
        "all_permissions": [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
        "findings": {
            "permissions": [
                {
                    "permission": "android.permission.READ_EXTERNAL_STORAGE",
                    "short_name": "READ_EXTERNAL_STORAGE",
                    "risk": "HIGH",
                    "description": "Can read ALL files on your device including photos and videos",
                    "category": "Storage"
                },
                {
                    "permission": "android.permission.READ_SMS",
                    "short_name": "READ_SMS",
                    "risk": "CRITICAL",
                    "description": "Can read ALL your text messages including OTP codes",
                    "category": "SMS"
                },
                {
                    "permission": "android.permission.CAMERA",
                    "short_name": "CAMERA",
                    "risk": "CRITICAL",
                    "description": "Can take photos and videos silently",
                    "category": "Camera"
                },
            ],
            "dangerous_combos": [
                {
                    "name": "Data Exfiltration Combo",
                    "risk": "CRITICAL",
                    "description": "App can READ your files AND send them over internet. Your photos, videos, documents can all be stolen!",
                    "permissions": ["READ_EXTERNAL_STORAGE", "INTERNET"]
                },
                {
                    "name": "OTP Banking Theft Combo",
                    "risk": "CRITICAL",
                    "description": "App can read your SMS OTP codes AND send them to attackers.",
                    "permissions": ["READ_SMS", "INTERNET"]
                }
            ],
            "secrets": [
                {
                    "name": "Hardcoded API Key",
                    "risk": "CRITICAL",
                    "description": "A hardcoded API key found. Attackers can extract this from your APK.",
                    "file": "res/values/strings.xml",
                    "occurrences": 1
                },
                {
                    "name": "HTTP Not HTTPS",
                    "risk": "HIGH",
                    "description": "App connecting over unencrypted HTTP.",
                    "file": "assets/config.json",
                    "occurrences": 3
                }
            ],
            "taint": [
                {
                    "name": "SMS to Network Exfiltration",
                    "risk": "CRITICAL",
                    "description": "SMS data flows into network transmission. Classic banking trojan behavior.",
                    "source": "SMS",
                    "sink": "HTTP_Transmit",
                    "source_hits": ["getMessageBody", "SMS_RECEIVED"],
                    "sink_hits": ["HttpURLConnection", "openConnection"]
                },
                {
                    "name": "Credentials to Network",
                    "risk": "CRITICAL",
                    "description": "User credentials flow into network calls. Password may be transmitted insecurely.",
                    "source": "Credentials",
                    "sink": "HTTP_Transmit",
                    "source_hits": ["getPassword"],
                    "sink_hits": ["getOutputStream"]
                }
            ],
            "malware": [
                {
                    "name": "SMS Stealer",
                    "risk": "CRITICAL",
                    "description": "SMS interception pattern. Banking trojans steal OTP codes this way.",
                    "category": "Banking Trojan",
                    "file": "__androguard_methods__",
                    "occurrences": 3
                },
                {
                    "name": "Device Fingerprinting",
                    "risk": "HIGH",
                    "description": "App collects unique device identifiers. Common in stalkerware.",
                    "category": "Surveillance",
                    "file": "__androguard_methods__",
                    "occurrences": 2
                }
            ],
            "owasp": [
                {
                    "id": "M5",
                    "name": "Insecure Communication",
                    "risk": "CRITICAL",
                    "description": "App communicates over unencrypted HTTP.",
                    "ref": "OWASP M5",
                    "file": "__androguard_strings__"
                }
            ],
            "code_issues": [
                {
                    "name": "SSL Verification Disabled",
                    "risk": "CRITICAL",
                    "description": "SSL certificate verification disabled. Man-in-the-middle attacks are possible.",
                    "file": "smali/com/app/HttpClient.smali",
                    "occurrences": 1
                },
                {
                    "name": "App is Debuggable",
                    "risk": "HIGH",
                    "description": "App set to debuggable=true. Attackers can attach a debugger.",
                    "file": "AndroidManifest.xml",
                    "occurrences": 1
                }
            ]
        }
    }
    scan_id = save_scan(demo_results)
    flash('Demo scan loaded! This shows what a real scan looks like.', 'success')
    return redirect(url_for('results', scan_id=scan_id))

@app.route('/report/<int:scan_id>')
def download_report(scan_id):
    from flask import send_file
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        flash('Scan not found!', 'error')
        return redirect(url_for('index'))
    buffer = generate_pdf(scan_data['results'])
    filename = f"anirod_report_{scan_data['filename'].replace('.apk','')}.pdf"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("  🛡️  ANIROD Android Security Scanner")
    print("="*50)
    print("  Running at: http://localhost:5000")
    print("  Demo:       http://localhost:5000/demo")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
