import sys
import os
import ctypes
import subprocess
from scapy.all import sniff, Ether, IP, TCP, UDP
from datetime import datetime
import time

try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout)

OWN_MAC = "CC:6B:1E:9D:66:C3"
LOG_PATH = "../logs/traffic_logs.txt"
last_alert_time = {}

# List of trusted MACs
KNOWN_MACS = [
    OWN_MAC.upper(),
    "A4:CE:00:12:34:56",  
    "00:11:22:33:44:55"
]

def show_popup(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 1)
    except Exception as e:
        print(f"[!] Popup error: {e}")


def disconnect_wifi():
    try:
        subprocess.call("netsh wlan disconnect", shell=True)
        print("[*] Wi-Fi disconnected.")
    except Exception as e:
        print(f"[!] Could not disconnect Wi-Fi: {e}")


def classify_packet(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "Unknown"


def log_entry(text, is_alert=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {text}"
    print(entry)

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

    alert_key = text.split(":")[0]
    now = time.time()
    if is_alert and (alert_key not in last_alert_time or now - last_alert_time[alert_key] > 10):
        show_popup("⚠️ ALERT: Suspicious Targeting Detected", text)
        last_alert_time[alert_key] = now


def process_packet(packet):
    try:
        proto = classify_packet(packet)
        src = packet[Ether].src.strip().upper() if packet.haslayer(Ether) else "UNKNOWN"
        dst = packet[Ether].dst.strip().upper() if packet.haslayer(Ether) else "UNKNOWN"
        own_mac = OWN_MAC.strip().upper()

        text = f"{proto} packet from {src} to {dst}"
        log_entry(text)

        # Alert on unknown MAC targeting this machine
        if dst == own_mac and src not in KNOWN_MACS:
            log_entry(f"❗ Eavesdropping or Probing Detected from unknown MAC {src} → this system", is_alert=True)
            disconnect_wifi()

    except Exception as e:
        print(f"[!] Packet processing error: {e}")


def main():
    print(f"[+] Defender started. Monitoring for suspicious traffic targeting MAC: {OWN_MAC}")
    iface = input("Enter network interface (e.g., Wi-Fi or Ethernet): ").strip()
    sniff(iface=iface, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
