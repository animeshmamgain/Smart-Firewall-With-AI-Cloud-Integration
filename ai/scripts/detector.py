import sys
import time
import json
import signal
import socket
import fcntl
import struct
from pathlib import Path
import os
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
from collections import defaultdict, deque

import numpy as np
import joblib
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

def get_ip_address(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return "127.0.0.1"

INTERFACE = os.getenv("SFW_INTERFACE", "enp0s8")
VICTIM_IP       = get_ip_address(INTERFACE)
WINDOW_SEC      = 10
SCORE_INTERVAL  = 2.0
ALERT_COOLDOWN  = 5.0

MIN_PACKETS_FOR_RULES      = 10
MIN_PACKETS_FOR_PREDICTION = 30
PORT_SCAN_RULE_THRESHOLD   = 30

EXCLUDE_SRC_IPS = {VICTIM_IP, "127.0.0.1"}

CLASS_THRESHOLDS = {
    "port_scan":       0.65,
    "brute_force_ssh": 0.65,
    "brute_force_ftp": 0.65,
    "dos_flood":       0.65,
    "dos_slow":        0.45,
    "benign":          1.01,
}

ACTION_MAP = {
    "port_scan":       "block",
    "brute_force_ssh": "block",
    "brute_force_ftp": "block",
    "dos_flood":       "rate_limit",
    "dos_slow":        "rate_limit",
}

BASE_DIR    = Path(__file__).resolve().parent.parent.parent
AI_DIR      = BASE_DIR / "ai"
SHARED_DIR  = BASE_DIR / "shared"
MODEL_PATH  = AI_DIR / "models" / "sfw_model.joblib"
EVENTS_PATH = SHARED_DIR / "events.jsonl"
HEARTBEAT_PATH = SHARED_DIR / "heartbeat.txt"

packet_buffer = defaultdict(deque)
last_alert    = {}
running       = True

def packet_handler(pkt):
    if IP not in pkt:
        return
    src_ip = pkt[IP].src
    if src_ip in EXCLUDE_SRC_IPS:
        return
    
    info = {
        "ts":    float(pkt.time),
        "size":  len(pkt),
        "dst":   pkt[IP].dst,
        "dport": None,
        "flags": None,
        "proto": "OTHER",
    }
    if TCP in pkt:
        info["dport"] = pkt[TCP].dport
        info["flags"] = int(pkt[TCP].flags)
        info["proto"] = "TCP"
    elif UDP in pkt:
        info["dport"] = pkt[UDP].dport
        info["proto"] = "UDP"
    elif ICMP in pkt:
        info["proto"] = "ICMP"
    
    packet_buffer[src_ip].append(info)

def evict_old(buf, now, window_sec):
    cutoff = now - window_sec
    while buf and buf[0]["ts"] < cutoff:
        buf.popleft()

def compute_features(pkts):
    if len(pkts) < 2:
        return None
    
    timestamps = [p["ts"] for p in pkts]
    sizes      = [p["size"] for p in pkts]
    dst_ports  = [p["dport"] for p in pkts if p["dport"] is not None]
    dst_ips    = [p["dst"] for p in pkts]
    flows      = [(p["dst"], p["dport"]) for p in pkts if p["dport"] is not None]
    
    syn_count = sum(1 for p in pkts if p["flags"] is not None and p["flags"] & 0x02 and not (p["flags"] & 0x10))
    rst_count = sum(1 for p in pkts if p["flags"] is not None and p["flags"] & 0x04)
    tcp_count = sum(1 for p in pkts if p["proto"] == "TCP")
    udp_count = sum(1 for p in pkts if p["proto"] == "UDP")
    
    iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0.0]
    
    return {
        "pkt_count":        len(pkts),
        "byte_count":       sum(sizes),
        "unique_dst_ports": len(set(dst_ports)),
        "unique_dst_ips":   len(set(dst_ips)),
        "syn_count":        syn_count,
        "syn_ratio":        syn_count / len(pkts),
        "rst_count":        rst_count,
        "mean_pkt_size":    float(np.mean(sizes)),
        "std_pkt_size":     float(np.std(sizes)),
        "mean_iat":         float(np.mean(iats)),
        "flow_count":       len(set(flows)),
        "tcp_udp_ratio":    tcp_count / max(tcp_count + udp_count, 1),
    }

def rule_based_detect(features):
    pkts  = features["pkt_count"]
    ports = features["unique_dst_ports"]
    syn   = features["syn_count"]
    syn_r = features["syn_ratio"]
    flows = features["flow_count"]
    iat   = features["mean_iat"]
    
    if ports >= PORT_SCAN_RULE_THRESHOLD:
        return ("port_scan", 1.0, "rule_high_port_count")
    if pkts >= 5000:
        return ("dos_flood", 1.0, "rule_volumetric")
    if syn >= 1000 and syn_r >= 0.6:
        return ("dos_flood", 1.0, "rule_syn_flood")
    if flows >= 100 and pkts < 2000 and iat > 0.01:
        return ("dos_slow", 0.95, "rule_slow_dos")
    return None

def emit_alert(src_ip, predicted_class, confidence, features, source):
    if predicted_class == "benign":
        return None
    
    threshold = CLASS_THRESHOLDS.get(predicted_class, 0.65)
    if confidence < threshold:
        return None
    
    now = time.time()
    key = (src_ip, predicted_class)
    if key in last_alert and (now - last_alert[key]) < ALERT_COOLDOWN:
        return None
    last_alert[key] = now
    
    event = {
        "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "src_ip":             src_ip,
        "dst_ip":             VICTIM_IP,
        "attack_type":        predicted_class,
        "confidence":         round(float(confidence), 3),
        "detection_source":   source,
        "evidence": {
            "pkt_count":        features["pkt_count"],
            "unique_dst_ports": features["unique_dst_ports"],
            "syn_ratio":        round(features["syn_ratio"], 3),
            "flow_count":       features["flow_count"],
            "window_sec":       WINDOW_SEC,
        },
        "recommended_action": ACTION_MAP.get(predicted_class, "alert"),
    }
    
    if EVENTS_PATH.exists() and EVENTS_PATH.stat().st_size > 5 * 1024 * 1024:
        EVENTS_PATH.write_text("")
        
    with open(EVENTS_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    return event

def score_loop(model, feature_cols):
    print(f"[{time.strftime('%H:%M:%S')}] Detector running on {INTERFACE}.")
    print(f"[{time.strftime('%H:%M:%S')}] Min pkts: rules={MIN_PACKETS_FOR_RULES}, ML={MIN_PACKETS_FOR_PREDICTION}")
    print(f"[{time.strftime('%H:%M:%S')}] Events -> {EVENTS_PATH}\n")
    
    while running:
        time.sleep(SCORE_INTERVAL)
        now = time.time()
        ts  = time.strftime("%H:%M:%S")

        try:
            HEARTBEAT_PATH.write_text(str(now))
        except Exception:
            pass
        
        for src_ip in list(packet_buffer.keys()):
            buf = packet_buffer[src_ip]
            evict_old(buf, now, WINDOW_SEC)
            
            if len(buf) < MIN_PACKETS_FOR_RULES:
                continue
            
            features = compute_features(list(buf))
            if features is None:
                continue
            
            rule_result = rule_based_detect(features)
            if rule_result is not None:
                label, conf, rule_name = rule_result
                print(f"[{ts}] RULE  src={src_ip:15s} pred={label:18s} conf={conf:.2f} via={rule_name} pkts={features['pkt_count']} ports={features['unique_dst_ports']}")
                event = emit_alert(src_ip, label, conf, features, source="rule")
                if event:
                    print(f"           -> emitted: {label} ({event['recommended_action']})")
                continue
            
            if len(buf) < MIN_PACKETS_FOR_PREDICTION:
                continue
            
            X = np.array([[features[c] for c in feature_cols]])
            probs = model.predict_proba(X)[0]
            idx   = int(np.argmax(probs))
            pred  = model.classes_[idx]
            conf  = float(probs[idx])
            
            threshold = CLASS_THRESHOLDS.get(pred, 0.65)
            is_alert  = (pred != "benign") and (conf >= threshold)
            tag = "ALERT" if is_alert else "     "
            
            print(f"[{ts}] {tag} src={src_ip:15s} pred={pred:18s} conf={conf:.3f} (thr={threshold:.2f}) pkts={features['pkt_count']}")
            
            if is_alert:
                event = emit_alert(src_ip, pred, conf, features, source="ml")
                if event:
                    print(f"           -> emitted: {pred} ({event['recommended_action']})")

def signal_handler(signum, frame):
    global running
    print(f"\n[{time.strftime('%H:%M:%S')}] Shutting down...")
    running = False

def main():
    EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVENTS_PATH.touch()
    
    print(f"[{time.strftime('%H:%M:%S')}] Loading model from {MODEL_PATH}")
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    feature_cols = artifact["feature_cols"]
    print(f"[{time.strftime('%H:%M:%S')}] Model loaded. Classes: {list(model.classes_)}")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    sniffer = AsyncSniffer(iface=INTERFACE, filter="ip", prn=packet_handler, store=False)
    sniffer.start()
    print(f"[{time.strftime('%H:%M:%S')}] Sniffer started on {INTERFACE}")
    
    try:
        score_loop(model, feature_cols)
    finally:
        sniffer.stop()
        print(f"[{time.strftime('%H:%M:%S')}] Detector stopped cleanly.")

if __name__ == "__main__":
    main()
