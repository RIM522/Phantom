from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
import os

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

def load_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def get_scan():
    return jsonify(load_json('../phantom_red/scan_results.json'))

@app.route('/api/intel')
def get_intel():
    return jsonify(load_json('../phantom_intel/intel_results.json'))

@app.route('/api/alerts')
def get_alerts():
    return jsonify(load_json('../phantom_blue/blue_alerts.json'))

@app.route('/api/killchain')
def get_killchain():
    return jsonify(load_json('../phantom_map/kill_chain.json'))

@app.route('/api/exploits')
def get_exploits():
    return jsonify(load_json('../phantom_red/exploit_results.json'))

@app.route('/api/bruteforce')
def get_bruteforce():
    return jsonify(load_json('../phantom_red/bruteforce_results.json'))

@app.route('/api/summary')
@app.route('/api/summary')
def get_summary():
    alerts = load_json('../phantom_blue/blue_alerts.json')
    scan = load_json('../phantom_red/scan_results.json')
    intel = load_json('../phantom_intel/intel_results.json')
    kill_chain = load_json('../phantom_map/kill_chain.json')
    exploits = load_json('../phantom_red/exploit_results.json')
    bruteforce = load_json('../phantom_red/bruteforce_results.json')

    total_ports = 0
    for host, data in scan.items():
        total_ports += len(data.get('ports', []))

    critical_cves = 0
    for host, services in intel.items():
        for service in services:
            for cve in service.get('cves', []):
                if cve.get('severity') == 'CRITICAL':
                    critical_cves += 1

    successful_exploits = sum(1 for e in exploits if e.get('success'))
    successful_bf = sum(1 for b in bruteforce if b.get('success'))

    return jsonify({
        "total_alerts": len(alerts),
        "total_ports": total_ports,
        "critical_cves": critical_cves,
        "kill_chain_steps": len(kill_chain),
        "successful_exploits": successful_exploits,
        "successful_bruteforce": successful_bf,
        "red_score": len(alerts) * 10 + critical_cves * 20 + successful_exploits * 50,
        "blue_score": len(alerts) * 8
    })
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
