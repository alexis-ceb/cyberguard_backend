from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import sniff, IP
import threading
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
CORS(app)  
packets = []
packets_by_second = defaultdict(int)

def capture_traffic():
    def process_packet(packet):
        if IP in packet:
            timestamp = datetime.fromtimestamp(packet.time)
            second = timestamp.replace(microsecond=0)
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packets.append({
                'id': len(packets) + 1,
                'time': second.isoformat(),
                'timestamp': packet.time,
                'sender_ip': ip_src,
                'receiver_ip': ip_dst,
                'size_bytes': len(packet)
            })
            packets_by_second[second] += 1

    sniff(prn=process_packet, filter="ip")

def get_packets_by_second(count):
    now = datetime.now().replace(microsecond=0) 
    start_time = now - timedelta(seconds=count - 1)
    result = []
    for i in range(count):
        current_second = start_time + timedelta(seconds=i)
        result.append({
            'time': current_second.isoformat(),
            'value': packets_by_second[current_second]
        })
    return result

@app.route('/', methods=['GET'])
def home():
    return 'Hi from API!'

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    count = request.args.get('count', default=10, type=int)
    return jsonify([packet for packet in packets[-count:]])

@app.route('/api/traffic_by_second', methods=['GET'])
def get_traffic_by_second():
    seconds = request.args.get('seconds', default=10, type=int)
    return jsonify(get_packets_by_second(seconds))

if __name__ == '__main__':
    threading.Thread(target=capture_traffic, daemon=True).start()
    app.run(debug=False, port=3210)
