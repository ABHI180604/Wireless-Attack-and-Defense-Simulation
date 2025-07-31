
import os
import subprocess
import time
import csv

from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp

CSV_FILE = "pcap_captures/airodump_output-01.csv"
SPOOFED_ATTACKER_MAC = "A8:42:A1:60:F0:B0"

def enable_monitor_mode(interface):
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iwconfig {interface} mode monitor")
    os.system(f"sudo ifconfig {interface} up")
    print("[+] Monitor mode enabled.")

def scan_networks(interface):
    print("[*] Starting scan. Press Ctrl+C after a few seconds to stop and continue.")
    try:
        os.makedirs("pcap_captures", exist_ok=True)
        os.system("rm -f pcap_captures/airodump_output*")  # Clear old CSVs
        subprocess.call(f"sudo airodump-ng -w pcap_captures/airodump_output --output-format csv {interface}", shell=True)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped.")

def parse_networks():
    networks = []
    try:
        with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
        split_index = next(i for i, line in enumerate(lines) if line.strip().startswith("Station MAC"))

        for line in lines[1:split_index]:
            if not line.strip():
                continue
            fields = line.strip().split(",")
            if len(fields) >= 14 and fields[13].strip() != "":
                bssid = fields[0].strip()
                channel = fields[3].strip()
                power = fields[8].strip()
                essid = fields[13].strip()
                networks.append((bssid, channel, power, essid))
        return networks
    except Exception as e:
        print(f"[!] Failed to parse CSV: {e}")
        return []

def simulate_attack(target_mac, interface):
    packet = (
        Ether(src=SPOOFED_ATTACKER_MAC, dst=target_mac) /
        IP(dst="172.20.10.13", src="192.168.195.128") /
        UDP(dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    print(f"[+] Simulating spoofed eavesdropping packets to {target_mac} via {interface}...")
    for i in range(10):
        sendp(packet, iface=interface, verbose=False)
        time.sleep(0.5)
    print("[+] Attack simulation complete.")

def main():
    print("[*] Available Network Interfaces:")
    os.system("iwconfig")
    enable = input("Do you want to enable monitor mode? (yes/no): ").strip().lower()
    iface = input("Enter monitor-mode interface (e.g., wlan0): ").strip()

    if enable == "yes":
        enable_monitor_mode(iface)

    scan_networks(iface)

    print("[*] Parsing networks...")
    networks = parse_networks()
    if not networks:
        print("[!] No networks found.")
        return

    for i, net in enumerate(networks):
        print(f"[{i}] BSSID: {net[0]}, ESSID: {net[3]}, CH: {net[1]}, PWR: {net[2]}")

    choice = int(input("Select network to attack [0-{}]: ".format(len(networks)-1)))
    target_bssid = networks[choice][0]

    victim_mac = input("Enter victim MAC address (target device): ").strip().upper()
    simulate_attack(victim_mac, iface)

if __name__ == "__main__":
    main()
