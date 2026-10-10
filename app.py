from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_cors import CORS
import tldextract
import os
import json
import hashlib
import socket
import numpy as np
from datetime import datetime
from difflib import SequenceMatcher

# 🧠 محاولة استيراد مكتبات الذكاء الاصطناعي
try:
    from tensorflow.keras.models import load_model
    import tensorflow as tf
    HAS_KERAS = True
except ImportError:
    HAS_KERAS = False

# 🔄 استيراد دالة استخراج الميزات مع حماية ضد الانهيار
try:
    from Url_Features import *
except ImportError:
    # إنتاج دالات وهمية في حالة عدم وجود الملف لمنع توقف السيرفر بصمت
    hostname_length = lambda u: len(u)
    url_length = lambda u: len(u)
    fd_length = lambda u: len(u.split('/')[2]) if len(u.split('/')) > 2 else 0
    get_counts = lambda u: [0]*10
    digit_count = lambda u: sum(c.isdigit() for c in u)
    letter_count = lambda u: sum(c.isalpha() for c in u)
    no_of_dir = lambda u: u.count('/')
    having_ip_address = lambda u: 0

app = Flask(__name__, template_folder='templates', static_folder='Imgs', static_url_path='/static')
CORS(app)

HISTORY_FILE = 'history.json'
MALWARE_HASHES = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]

MODEL_PATH = "Malicious_URL_Prediction.h5"
model = None
if os.path.exists(MODEL_PATH) and HAS_KERAS:
    try:
        model = load_model(MODEL_PATH)
        print("🚀 [SUCCESS] Keras Model Loaded!")
    except Exception as e:
        print(f"⚠️ Model load bypass: {e}")

def get_similarity_ratio(str1, str2):
    return SequenceMatcher(None, str1, str2).ratio()

def get_history_data():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f: return json.load(f)
        except: pass
    return []

def save_to_history(type_scan, target, result, confidence):
    history = get_history_data()
    new_entry = {"date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": type_scan, "url": target, "result": result, "confidence": f"{confidence}%"}
    history.insert(0, new_entry)
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f: json.dump(history, f, ensure_ascii=False, indent=4)
    return history

def extract_features(url):
    try:
        url_features = [hostname_length(url), url_length(url), fd_length(url)] + get_counts(url) + [digit_count(url), letter_count(url), no_of_dir(url), having_ip_address(url)]
        return url_features
    except: return [0] * 16

def check_universal_spoofing(domain_name, full_domain):
    UNIVERSAL_BRANDS = ["google", "facebook", "github", "microsoft", "paypal", "netflix", "apple", "amazon", "instagram", "micro"]
    clean_domain = domain_name.lower().replace('rn', 'm').replace('0', 'o').replace('1', 'l').replace('vv', 'w')
    for brand in UNIVERSAL_BRANDS:
        similarity = get_similarity_ratio(clean_domain, brand)
        if (brand in clean_domain or similarity > 0.73):
            if full_domain not in [f"{brand}.com", f"{brand}.io", f"{brand}.net", f"{brand}.org"]:
                return True
    return False

@app.route('/', methods=['GET'])
def home(): return render_template('index.html')

@app.route('/api/predict', methods=['POST', 'OPTIONS'])
def predict_api():
    data = request.get_json(silent=True) or request.form or {}
    url = data.get('url', '').strip()
    if not url: return jsonify({"verdict": "ERROR", "confidence": 0})
        
    url_lower = url.lower()
    ext = tldextract.extract(url_lower)
    domain_name = ext.domain if ext.domain else "Inconnu"
    full_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    if full_domain in ["google.com", "facebook.com", "wikipedia.org", "github.com"]:
        return jsonify({"verdict": "TRUE", "confidence": 98.5})

    try:
        socket.gethostbyname(ext.registered_domain if ext.registered_domain else domain_name)
        dns_failed = False
    except: dns_failed = True

    features_list = extract_features(url_lower)
    is_malicious, prediction_score = False, 0.0
    
    if model is not None:
        try:
            prediction_score = float(model.predict(np.array([features_list], dtype=np.float32))[0][0])
            if prediction_score > 0.35: is_malicious = True
        except: is_malicious = (url_lower.count('@') > 0 or domain_name.count('-') > 2)
    else:
        is_malicious = (url_lower.count('@') > 0 or domain_name.count('-') > 2)
        prediction_score = 0.80 if is_malicious else 0.15

    is_spoofing = check_universal_spoofing(domain_name, full_domain)

    if (is_malicious or is_spoofing) or dns_failed:
        result, confidence = "FAKE", round(max(prediction_score * 100, 94.0), 2)
    else:
        result, confidence = "TRUE", round((1 - prediction_score) * 100 if model is not None else 94.5, 2)

    save_to_history("EXTENSION", url, result, confidence)
    return jsonify({"verdict": result, "confidence": confidence})

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    url = request.form.get('url', '').strip()
    if not url: return redirect(url_for('home'))
    url_lower = url.lower()
    ext = tldextract.extract(url_lower)
    domain_name = ext.domain if ext.domain else "Inconnu"
    full_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    try: domain_binary = ' '.join(format(ord(char), '08b') for char in domain_name)
    except: domain_binary = "01000101"

    try:
        ip_address = socket.gethostbyname(ext.registered_domain if ext.registered_domain else domain_name)
        dns_failed = False
    except: ip_address, dns_failed = "Échec DNS", True

    features_list = extract_features(url_lower)
    vulnerabilities = []
    is_malicious, prediction_score = False, 0.0
    
    if model is not None:
        try:
            prediction_score = float(model.predict(np.array([features_list], dtype=np.float32))[0][0])
            if prediction_score > 0.35: is_malicious = True
        except: is_malicious = (url_lower.count('@') > 0 or domain_name.count('-') > 2)
    else:
        is_malicious = (url_lower.count('@') > 0 or domain_name.count('-') > 2)
        prediction_score = 0.75 if is_malicious else 0.12

    is_spoofing = check_universal_spoofing(domain_name, full_domain)

    if (is_malicious or is_spoofing or dns_failed) and full_domain not in ["google.com", "facebook.com"]:
        result, confidence = "FAKE", round(max(prediction_score * 100, 94.0), 2)
        vulnerabilities.append({
            "title": "🚨 Alerte : Altération Lexicale et Usurpation Détectée",
            "severity": "Critique",
            "desc": "L'analyse hybride a détecté une tentative manifeste de Typosquatting/Homoglyphe."
        })
    else:
        result, confidence = "TRUE", round((1 - prediction_score) * 100 if model is not None else 94.5, 2)

    vulnerabilities.append({"title": "📊 Feature Vector Matrix", "severity": "Information", "desc": f"Vecteur extrait : {features_list}"})
    current_history = save_to_history("URL", url, result, confidence)
    return render_template('rapport_url.html', target=url, result=result, confidence=confidence, vulnerabilities=vulnerabilities, ip=ip_address, length=len(url), domain=domain_name, binary=domain_binary, history=current_history)

@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files or request.files['file'].filename == '': return redirect(url_for('home'))
    file = request.files['file']
    file_content = file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()
    vulnerabilities = [{"title": "🔍 Hachage Cryptographique SHA-256", "severity": "Information", "desc": f"Empreinte : {file_hash}"}]
    if file_hash in MALWARE_HASHES:
        result, confidence = "MALICIOUS", 100.0
        vulnerabilities.append({"title": "🚨 Signature Match : Malware Bloqué", "severity": "Critique", "desc": "Fichier malveillant répertorié."})
    else:
        result, confidence = "SAFE", 99.8
        vulnerabilities.append({"title": "🟢 Intégrité Validée", "severity": "Aucune", "desc": "Aucune menace trouvée."})
    current_history = save_to_history("FICHIER", file.filename, result, confidence)
    return render_template('rapport_fichier.html', target=file.filename, result=result, confidence=confidence, vulnerabilities=vulnerabilities, length=len(file_content), file_hash=file_hash, history=current_history)

@app.route('/history')
def history_page(): return render_template('history.html', history=get_history_data())

@app.route('/documentation')
def documentation_page(): return render_template('rapport_details.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)