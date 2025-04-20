import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.linear_model import LogisticRegression
import pickle
import sys
from collections import defaultdict
import time
from threading import Thread
from flask import Flask, render_template, jsonify
import queue
import traceback
import hashlib
import matplotlib.pyplot as plt

# Try importing Scapy
try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, conf
except ImportError:
    print("Error: Scapy is not installed. Install it with 'pip install scapy'.")
    print("Run this script as administrator for packet capture.")
    sys.exit(1)

app = Flask(__name__)
data_queue = queue.Queue()  # No limit, store all packets
app.logger.setLevel('DEBUG')

# Configuration
train_model = False
dataset_path = "KDDTrain+.csv"

# Check Scapy configuration
print("Scapy configuration:")
print(f"L2socket: {conf.L2socket}")
print(f"L3socket: {conf.L3socket}")

# Load or train model, scaler, and encoders
try:
    if train_model:
        df = pd.read_csv(dataset_path)
        features = [
            'protocol_type', 'service', 'count', 'serror_rate', 'srv_serror_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate'
        ]
        X = df[features]
        y = df['label'].apply(lambda x: 1 if x != 'normal' else 0)

        encoders = {}
        for col in ['protocol_type', 'service']:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col])
            encoders[col] = le

        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)

        clf = LogisticRegression(class_weight='balanced', random_state=42, max_iter=1000)
        clf.fit(X_scaled, y)

        with open("ids_model.pkl", "wb") as f:
            pickle.dump(clf, f)
        with open("scaler.pkl", "wb") as f:
            pickle.dump(scaler, f)
        for col in ['protocol_type', 'service']:
            with open(f"encoder_{col}.pkl", "wb") as f:
                pickle.dump(encoders[col], f)
        print("Model trained and saved successfully.")
    else:
        with open("ids_model.pkl", "rb") as f:
            clf = pickle.load(f)
        with open("scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
        encoders = {}
        for col in ['protocol_type', 'service']:
            with open(f"encoder_{col}.pkl", "rb") as f:
                encoders[col] = pickle.load(f)
except FileNotFoundError as e:
    print(f"Error: Missing file {e}. Ensure {dataset_path} or pickle files are in the directory.")
    sys.exit(1)

features = [
    'protocol_type', 'service', 'count', 'serror_rate', 'srv_serror_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate'
]

packet_window = []
window_size = 10
connection_counts = defaultdict(int)
serror_counts = defaultdict(int)
srv_serror_counts = defaultdict(int)
dst_host_serror_counts = defaultdict(int)
dst_host_srv_serror_counts = defaultdict(int)
last_prediction_time = time.time()

protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
port_to_service = {80: 'http', 21: 'ftp', 23: 'telnet', 25: 'smtp', 53: 'domain', 443: 'https', 0: 'eco_i'}
for port in range(1024, 65536):
    port_to_service[port] = 'http'

def extract_features():
    if not packet_window:
        return None
    pkt = packet_window[-1]
    try:
        dst_ip = pkt[IP].dst if IP in pkt else '0.0.0.0'
    except Exception as e:
        print(f"Error extracting IP from packet: {e}")
        return None

    dst_port = 0
    if TCP in pkt:
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        dst_port = pkt[UDP].dport
    elif ICMP in pkt:
        dst_port = 0

    input_data = {
        'protocol_type': protocol_map.get(pkt[IP].proto if IP in pkt else 6, 'tcp'),
        'service': port_to_service.get(dst_port, 'other'),
        'count': connection_counts[dst_ip],
        'serror_rate': serror_counts[dst_ip] / max(1, connection_counts[dst_ip]),
        'srv_serror_rate': srv_serror_counts[f"{dst_ip}:{dst_port}"] / max(1, sum(1 for p in packet_window if IP in p and p[IP].dst == dst_ip and (p[TCP].dport if TCP in p else 0) == dst_port)),
        'dst_host_serror_rate': dst_host_serror_counts[dst_ip] / max(1, connection_counts[dst_ip]),
        'dst_host_srv_serror_rate': dst_host_srv_serror_counts[f"{dst_ip}:{dst_port}"] / max(1, sum(1 for p in packet_window if IP in p and p[IP].dst == dst_ip and (p[TCP].dport if TCP in p else 0) == dst_port))
    }
    input_data['count'] = np.log1p(input_data['count'])  # Apply log transformation as in training
    print(f"Extracted features: {input_data}")
    return input_data

def process_packet(pkt):
    global packet_window, last_prediction_time
    if IP not in pkt:
        return
    packet_hash = hashlib.md5(str(pkt.summary()).encode()).hexdigest()
    if any(hashlib.md5(str(p.summary()).encode()).hexdigest() == packet_hash for p in packet_window):
        return  # Skip duplicate
    packet_window.append(pkt)
    if len(packet_window) > window_size:
        packet_window.pop(0)
    try:
        dst_ip = pkt[IP].dst
        connection_counts[dst_ip] += 1
    except Exception as e:
        print(f"Error processing packet IP: {e}")
        return
    if TCP in pkt and pkt[TCP].flags & 0x02 and not (pkt[TCP].flags & 0x10):  # SYN without ACK
        serror_counts[dst_ip] += 1
        srv_key = f"{dst_ip}:{pkt[TCP].dport}"
        srv_serror_counts[srv_key] += 1
        dst_host_serror_counts[dst_ip] += 1
        dst_host_srv_serror_counts[srv_key] += 1
    current_time = time.time()
    if len(packet_window) >= 1 or (current_time - last_prediction_time) >= 1:
        input_data = extract_features()
        if input_data:
            for col in ['protocol_type', 'service']:
                try:
                    input_data[col] = encoders[col].transform([input_data[col]])[0]
                except ValueError:
                    print(f"Warning: Unknown {col}: {input_data[col]}. Setting to -1.")
                    input_data[col] = -1
            input_features = pd.DataFrame([input_data[f] for f in features], index=features).T
            try:
                sample_scaled = scaler.transform(input_features)
                probs = clf.predict_proba(sample_scaled)
                prediction = (probs[:, 1] > 0.5).astype(int)
                result = {
                    'raw_data': input_data,
                    'scaled_features': sample_scaled[0].tolist(),
                    'probabilities': probs[0].tolist(),
                    'prediction': "Attack (Alert)" if prediction[0] == 1 else "Normal (OK)",
                    'time': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                data_queue.put(result)
                app.logger.debug(f"Queued data: {result}")
            except Exception as e:
                print(f"Error during prediction: {e}")
                app.logger.error(f"Prediction error: {e}")
            last_prediction_time = current_time

def start_sniffing():
    print("Starting real-time packet capture...")
    try:
        sniff(prn=process_packet, filter="ip", store=0)
    except RuntimeError as e:
        if "winpcap is not installed" in str(e).lower():
            print("Warning: Npcap/WinPcap not installed. Falling back to layer 3 socket.")
            print("Install Npcap from https://npcap.com/#download for layer 2 sniffing.")
            try:
                conf.L2socket = conf.L3socket
                sniff(prn=process_packet, filter="ip", store=0)
            except Exception as e:
                print(f"Error during layer 3 sniffing: {e}")
                sys.exit(1)
        else:
            print(f"Error during packet capture: {e}")
            sys.exit(1)
    except PermissionError:
        print("Error: Packet capture requires administrative privileges. Run as administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during packet capture: {e}")
        sys.exit(1)

def process_pcap(file_path):
    print(f"Processing PCAP file: {file_path}")
    try:
        packets = rdpcap(file_path)
        for pkt in packets:
            process_packet(pkt)
    except FileNotFoundError:
        print(f"Error: PCAP file {file_path} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing PCAP: {e}")
        sys.exit(1)

@app.route('/')
def index():
    app.logger.debug("Serving index.html")
    return render_template('index.html')

@app.route('/data')
def get_data():
    app.logger.debug("Accessing /data route")
    try:
        data_list = []
        while not data_queue.empty():
            data = data_queue.get()
            # Convert NumPy types to native Python types
            def convert_numpy(obj):
                if isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, dict):
                    return {k: convert_numpy(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_numpy(v) for v in obj]
                return obj
            data = convert_numpy(data)
            data_list.append(data)
        if data_list:
            app.logger.debug(f"Serving data: {data_list}")
            return jsonify(data_list)
        app.logger.debug("No data in queue, returning empty JSON")
        return jsonify([])
    except Exception as e:
        app.logger.error(f"Error in /data route: {str(e)} - Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.logger.debug("Starting Flask application")
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    app.logger.debug("Sniff thread started")
    app.run(debug=True, host='0.0.0.0', port=5000)