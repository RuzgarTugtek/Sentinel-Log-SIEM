import time, os, re
from collections import defaultdict
from flask import Flask, render_template_string, Response

app = Flask(__name__)

# Analiz Verileri
supheli_ipler = defaultdict(int)
BRUTE_FORCE_SINIRI = 3
SQLI_IMZA = re.compile(r"(?i)(UNION SELECT|DROP TABLE|' OR '1'='1|--)")
PATH_TRAVERSAL_IMZA = re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd)")

def log_analiz_et(satir):
    try:
        p = satir.split(" - ")
        if len(p) < 3: return None
        ip, istek, durum = p[0].strip(), p[1].strip(), p[2].strip()
        tehdit = []
        if SQLI_IMZA.search(istek): tehdit.append("SQL Injection")
        if PATH_TRAVERSAL_IMZA.search(istek): tehdit.append("Path Traversal")
        if durum in ["401", "403", "404"]:
            supheli_ipler[ip] += 1
            if supheli_ipler[ip] >= BRUTE_FORCE_SINIRI:
                tehdit.append(f"Brute Force ({supheli_ipler[ip]} Hata)")
                supheli_ipler[ip] = 0
        if tehdit: return {"ip": ip, "t": " | ".join(tehdit), "d": istek}
        return None
    except: return None

def canli_akis():
    log = "sunucu_akis.log"
    if not os.path.exists(log): open(log, 'w').close()
    with open(log, 'r', encoding='utf-8') as f:
        f.seek(0, 2)
        while True:
            s = f.readline()
            if not s: time.sleep(0.1); continue
            a = log_analiz_et(s.strip())
            if a:
                yield f"data: <div class='alert'>🚨 <b>{a['ip']}</b> -> {a['t']} <br><small>{a['d']}</small></div>\n\n"

HTML = """
<!DOCTYPE html><html><head><title>SIEM</title><style>
body { background: #000; color: #0f0; font-family: monospace; padding: 20px; }
.alert { border-left: 5px solid red; padding: 10px; background: #111; margin: 5px 0; }
</style></head><body><h1>🛡️ SIEM RADAR</h1><div id="c"></div>
<script>
new EventSource("/stream").onmessage = function(e) { document.getElementById("c").innerHTML = e.data + document.getElementById("c").innerHTML; };
</script></body></html>
"""

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/stream')
def stream(): return Response(canli_akis(), mimetype="text/event-stream")

if __name__ == '__main__':
    print("\n" + "!"*30)
    print("!!! BURASI CALISIYOR !!!")
    print("ADRES: http://127.0.0.1:5001")
    print("!"*30 + "\n")
    app.run(debug=False, threaded=True, host='127.0.0.1', port=5001)