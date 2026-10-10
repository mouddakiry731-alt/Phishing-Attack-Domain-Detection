document.getElementById('checkBtn').addEventListener('click', async () => {
    const resultBox = document.getElementById('result-box');
    resultBox.style.display = "block";
    resultBox.innerText = "Analyse en cours... ⏳";
    resultBox.className = "";

    // 1. قراءة رابط الصفحة لي حالها المستخدم دابا ف كروم
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
        resultBox.innerText = "Erreur de lecture de l'onglet.";
        return;
    }
    const currentUrl = tab.url;

    // 2. إرسال الرابط لـ Flask API
    try {
        const response = await fetch('http://127.0.0.1:5000/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });
        
        const data = await response.json();
        
        // 3. عرض النتيجة بألوان متناسقة ومطابقة لبيانات Flask
        if (data.verdict === 'TRUE') {
            resultBox.innerText = `✅ URL Sûre ! (Score: ${data.confidence}%)`;
            resultBox.className = "safe";
        } else {
            resultBox.innerText = `🚨 URL Malveillante ! (Score: ${data.confidence}%)`;
            resultBox.className = "danger";
        }
    } catch (error) {
        resultBox.innerText = "❌ Connexion au serveur Flask échouée !";
    }
});