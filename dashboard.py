from flask import Flask, render_template_string
import mysql.connector

app = Flask(__name__)

def get_data():
    db = mysql.connector.connect(
        host="localhost",
        port=3307,
        user="root",
        password="root123",
        database="vulndb"
    )
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM vulnerabilites ORDER BY score_cvss DESC")
    vulns = cursor.fetchall()
    cursor.execute("SELECT criticite, COUNT(*) as total FROM vulnerabilites GROUP BY criticite")
    stats = cursor.fetchall()
    return vulns, stats

@app.route('/')
def index():
    vulns, stats = get_data()
    html = """
    <html><head><title>Vulnerability Dashboard</title>
    <style>
        body { font-family: Arial; background: #1a1a2e; color: white; padding: 20px; }
        h1 { color: #e94560; }
        .stats { display: flex; gap: 20px; margin-bottom: 30px; }
        .card { background: #16213e; padding: 20px; border-radius: 10px; text-align: center; min-width: 150px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; padding: 10px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #16213e; }
        tr:hover { background: #16213e; }
        .critique { color: #e94560; font-weight: bold; }
        .haute { color: #f5a623; font-weight: bold; }
        .moyenne { color: #f8e71c; font-weight: bold; }
        .faible { color: #7ed321; font-weight: bold; }
    </style></head><body>
    <h1>🛡️ Vulnerability Management Dashboard</h1>
    <div class="stats">
    {% for s in stats %}
        <div class="card">
            <h2>{{ s.total }}</h2>
            <p>{{ s.criticite }}</p>
        </div>
    {% endfor %}
    </div>
    <table>
        <tr><th>IP</th><th>Port</th><th>Service</th><th>CVE</th><th>CVSS</th><th>Criticité</th><th>Statut</th><th>Date</th></tr>
        {% for v in vulns %}
        <tr>
            <td>{{ v.ip }}</td>
            <td>{{ v.port }}</td>
            <td>{{ v.service }}</td>
            <td>{{ v.cve_id or 'N/A' }}</td>
            <td>{{ v.score_cvss or 'N/A' }}</td>
            <td class="{{ v.criticite.lower() if v.criticite else '' }}">{{ v.criticite }}</td>
            <td>{{ v.statut }}</td>
            <td>{{ v.date_detection }}</td>
        </tr>
        {% endfor %}
    </table>
    </body></html>
    """
    return render_template_string(html, vulns=vulns, stats=stats)

if __name__ == '__main__':
    app.run(debug=True, port=5000)