from flask import request, jsonify
import threading
import csv
import io
from client_insights import ClientInsights

from classifier import RealTimeClassifier
def register_csv_routes(app, socketio): 
    
    engine = RealTimeClassifier()
    engine.load_bundle()
    client_insights = ClientInsights()

    app.csv_results = []
    app.csv_summary = None

    def safe_float(d, *keys):
        for k in keys:
            v = d.get(k)
            if v is not None:
                try: return float(v)
                except: pass
        return 0.0

    def heuristic(row):
        dest_port    = int(safe_float(row, 'Dst Port', 'Destination Port'))
        avg_pkt      = safe_float(row, 'Average Packet Size', 'avg_packet_size', 'pkt_size_avg')
        max_idle     = safe_float(row, 'Flow IAT Max', 'flow_iat_max')
        pkt_var      = safe_float(row, 'Bwd Packet Length Std', 'bwd_pkt_len_std')
        fwd_rate     = safe_float(row, 'Fwd Packets/s', 'fwd_pkts_s')
        syn          = safe_float(row, 'SYN Flag Count', 'syn_flag_count')
        ack          = safe_float(row, 'ACK Flag Count', 'ack_flag_count')
        rst          = safe_float(row, 'RST Flag Count', 'rst_flag_count')

        if ack > 4000 and avg_pkt > 1500 and pkt_var > 2000:
            return 'Heartbleed'
        if dest_port == 21:
            return 'FTP-Patator - Attempted' if avg_pkt <= 5 else 'FTP-Patator'
        if dest_port == 22:
            return 'SSH-Patator - Attempted' if avg_pkt <= 5 else 'SSH-Patator'
        if dest_port == 8080:
            return 'Botnet - Attempted' if avg_pkt <= 5 else 'Botnet'
        if avg_pkt <= 5:
            if fwd_rate > 10000:
                return 'Infiltration - Portscan' if syn == 2 else 'Portscan'
            if fwd_rate > 200:
                return 'Infiltration - Attempted' if rst >= 1 else 'DoS GoldenEye - Attempted'
            if syn >= 7: return 'DoS Slowhttptest - Attempted'
            if syn == 3:
                if ack == 0: return 'DoS Slowloris - Attempted'
                if ack == 2 and max_idle > 30000000: return 'DoS Hulk - Attempted'
            if syn == 2:
                if max_idle > 5300000: return 'Web Attack - Brute Force - Attempted'
                if max_idle > 5000000: return 'Web Attack - XSS - Attempted'
                return 'Web Attack - SQL Injection - Attempted'
            return 'BENIGN'
        if pkt_var == 0 and avg_pkt > 5:
            if max_idle > 80000000: return 'DoS Slowhttptest'
            if max_idle > 40000000: return 'DoS Slowloris'
            if max_idle > 30000000 and 150 < avg_pkt < 190 and 50 < ack < 80:
                return 'Infiltration'
        if dest_port in [80, 443]:
            if ack > 150:
                if 700 < avg_pkt < 800 and 300 < pkt_var < 400: return 'Web Attack - XSS'
                if 300 < avg_pkt < 450 and 300 < pkt_var < 450: return 'Web Attack - Brute Force'
            if 200 < avg_pkt < 300 and 800 < pkt_var < 1000:
                return 'Web Attack - SQL Injection - Attempted' if ack >= 10 else 'Web Attack - SQL Injection'
        if avg_pkt > 600 and pkt_var > 1500:
            if max_idle < 500000: return 'DoS Hulk'
            return 'DDoS' if pkt_var > 3000 else 'DoS GoldenEye'
        return 'BENIGN'

    def threat_category(label):
        if label == 'BENIGN': return 'Normal'
        if label == 'Anomaly': return 'Anomaly'
        if label in ['Dead Service', 'TCP Handshake Anomaly', 'Keep Alive Timeout', 'Packet Size Anomaly']:
            return 'Misconfigured'
        if label in ['Portscan', 'Infiltration', 'Infiltration - Attempted', 'Infiltration - Portscan'] or 'Attempted' in label:
            return 'Suspicious'
        return 'Attack-like'

    def process_in_background(rows):
        results = []
        summary = {'Normal': 0, 'Misconfigured': 0, 'Suspicious': 0, 'Attack-like': 0, 'Anomaly': 0, 'total': 0}
        total = len(rows)
        BATCH = 500

        for i, row in enumerate(rows):
            label, category = engine.predict_live(
                row,
                use_anomaly=False
            )

            normalized = {
                'protocol': row.get('Protocol', 0),
                'dst_port': row.get('Dst Port', 0),
                'src_port': row.get('Src Port', 0),

                'syn_flag_cnt': row.get('SYN Flag Count', 0),
                'ack_flag_cnt': row.get('ACK Flag Count', 0),
                'rst_flag_cnt': row.get('RST Flag Count', 0),
                'fin_flag_cnt': row.get('FIN Flag Count', 0),

                'down_up_ratio': row.get('Down/Up Ratio', 0),
                'flow_iat_mean': row.get('Flow IAT Mean', 0),
                'flow_iat_std': row.get('Flow IAT Std', 0),

                'psh_flag_cnt': row.get('PSH Flag Count', 0)
            }

            insights = client_insights.compute(row, category) 
            insights = client_insights.compute(normalized, category)
            
            orig     = row.get('Label', row.get('label', '')).strip()

            summary[category] += 1
            summary['total']  += 1
            results.append({
                'Src IP': row.get('Src IP', row.get('Source IP', 'N/A')),
                'Src Port': row.get('Src Port', row.get('Source Port', 'N/A')),
                'Dst IP': row.get('Dst IP', row.get('Destination IP', 'N/A')),
                'Dst Port': row.get('Dst Port', row.get('Destination Port', 'N/A')),
                'Protocol': row.get('Protocol', 'N/A'),

                'Predicted Label': label,
                'Predicted Category': category,

                'Original Label': orig,
                'Client Insights': insights
            })

            if len(results) > 1000:
                results = results[-5000:]

            if (i + 1) % BATCH == 0 or (i + 1) == total:
                progress = round(((i + 1) / total) * 100)

                socketio.emit(
                    'csv_progress',
                    {
                        'progress': progress,
                        'processed': i + 1,
                        'total': total
                    }
                )

        app.csv_results = results
        app.csv_summary = summary

        socketio.emit(
            'csv_done',
            {
                'summary': summary,
                'total': len(results)
            }
        )

    @app.route('/upload_csv', methods=['POST'])
    def upload_csv():
        file = request.files.get('file')

        if not file:
            return jsonify({'error': 'No file provided'}), 400

        try:
            content = file.read().decode('utf-8', errors='ignore')
            rows = list(csv.DictReader(io.StringIO(content))) [:10000]
            total_rows = len(rows)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

        threading.Thread(
            target=process_in_background,
            args=(rows,),
            daemon=True
        ).start()

        return jsonify({
            'status': 'processing',
            'total': len(rows),
            'limit': 50000
        })

    @app.route('/csv_rows')
    def csv_rows():
        page = int(request.args.get('page', 0))

        PAGE_SIZE = 1000

        start = page * PAGE_SIZE
        end = start + PAGE_SIZE

        return jsonify({
            'rows': app.csv_results[start:end]
        })


